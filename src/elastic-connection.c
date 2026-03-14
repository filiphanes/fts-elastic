/* Copyright (c) 2006-2014 Dovecot authors, see the included COPYING file */
/* Copyright (c) 2014 Joshua Atkins <josh@ascendantcom.com> */
/* Copyright (c) 2019-2020 Filip Hanes <filip.hanes@gmail.com> */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "str.h"
#include "strescape.h"
#include "ioloop.h"
#include "istream.h"
#include "mail-namespace.h"
#include "mail-storage-private.h"
#include "http-url.h"
#include "http-client.h"
#include "settings.h"
#include "fts-elastic-plugin.h"
#include "elastic-connection.h"

#include <stdio.h>


/* Results accumulated across cursor pages for one SQL call */
struct elastic_search_context {
    pool_t pool;
    int found;
    struct elastic_result ***results_r;

    /* number of SELECT columns: 2 = uid,box  3 = uid,box,SCORE() */
    int n_cols;

    /* TSV parse state (reset per page) */
    bool header_seen;

    /* cursor value from last TSV page, p_strdup'd into pool */
    const char *cursor;

    /* result accumulation, keyed by box_guid */
    HASH_TABLE(char *, struct elastic_result *) results_hash;
    ARRAY(struct elastic_result *) results_array;
};


struct elastic_connection {
    struct event *event;
    struct mail_namespace *ns;
    const char *username;

    /* ElasticSearch HTTP API information */
    char *http_host;
    const char *basic_auth_username;
    const char *basic_auth_pass;
    in_port_t http_port;
    char *http_base_path;
    char *http_failure;
    int request_status;

    /* index name extracted from http_base_path (e.g. "m") */
    char *index_name;
    /* /_sql?format=tsv path, respecting any proxy prefix */
    char *sql_path;

    /* for streaming processing of results */
    struct istream *payload;
    struct io *io;

    enum elastic_post_type post_type;

    /* context for the current search */
    struct elastic_search_context *ctx;

    /* if we should send ?refresh=true on update _bulk requests */
    unsigned int refresh_on_update:1;
    unsigned int debug:1;
    unsigned int http_ssl:1;
};


int elastic_connection_init(const struct fts_elastic_settings *set,
                            struct mail_namespace *ns,
                            struct elastic_connection **conn_r,
                            const char **error_r,
                            struct event *event_parent)
{
    f_debug("start");
    struct elastic_connection *conn = NULL;
    struct http_url *http_url = NULL;
    const char *error = NULL;

    if (error_r == NULL || set == NULL || conn_r == NULL) {
        i_debug("fts_elastic: error initialising ElasticSearch connection");
        f_debug("return -1");
        return -1;
    }

    /* validate the url */
    if (http_url_parse(set->url, NULL, HTTP_URL_ALLOW_USERINFO_PART,
                pool_datastack_create(), &http_url, &error) < 0) {
        *error_r = t_strdup_printf(
            "fts_elastic: Failed to parse HTTP url: %s", error);
        f_debug("return -1");
        return -1;
    }

    conn = i_new(struct elastic_connection, 1);
    conn->event = event_create(event_parent);
    conn->ctx = i_new(struct elastic_search_context, 1);
    conn->ns = ns;
    conn->username = ns->owner ? ns->owner->username : "-";
    conn->http_host = i_strdup(http_url->host.name);

    if (http_url->user != NULL && http_url->password != NULL) {
        conn->basic_auth_username = i_strdup(http_url->user);
        conn->basic_auth_pass = i_strdup(http_url->password);
    }

    conn->http_port = http_url->port;
    conn->http_base_path = i_strdup(http_url->path);
    conn->http_ssl = http_url->have_ssl;
    conn->debug = set->debug;
    conn->refresh_on_update = set->refresh_on_update;

    /* Derive index name and SQL endpoint from the URL path.
     * http_url->path is like "/m/" or "/prefix/m/".
     * Strip trailing slash, then strip the last path segment (index name),
     * leaving the root prefix. */
    {
        const char *path = http_url->path;
        size_t len = strlen(path);

        /* strip trailing slash */
        if (len > 0 && path[len - 1] == '/') len--;

        /* find start of last segment (the index name) */
        size_t seg_start = len;
        while (seg_start > 0 && path[seg_start - 1] != '/') seg_start--;

        /* index_name = path[seg_start..len) */
        conn->index_name = i_strndup(path + seg_start, len - seg_start);

        /* sql_path = path[0..seg_start) + "_sql?format=tsv" */
        conn->sql_path = i_strdup_printf("%.*s_sql?format=tsv",
                                         (int)seg_start, path);
    }

    /* guard against init being called multiple times */
    if (elastic_http_client == NULL) {
        settings_event_add_filter_name(conn->event, FTS_ELASTIC_FILTER);
        if (http_client_init_private_auto(conn->event, &elastic_http_client,
                                          &error) < 0) {
            *error_r = t_strdup(error);
            return -1;
        }
    }

    *conn_r = conn;

    f_debug("return 0");
    return 0;
}


void elastic_connection_deinit(struct elastic_connection *conn)
{
    f_debug("start");
    if (conn != NULL) {
        i_free(conn->http_host);
        i_free(conn->http_base_path);
        i_free(conn->index_name);
        i_free(conn->sql_path);
        i_free(conn->ctx);
        event_unref(&conn->event);
        i_free(conn);
    }
    f_debug("end");
}

const char *elastic_connection_get_index(struct elastic_connection *conn)
{
    return conn->index_name;
}

/* Checks response status code from _bulk request */
static void
elastic_connection_bulk_response(const struct http_response *response,
                                   struct elastic_connection *conn)
{
    f_debug("start");
    if (response != NULL && conn != NULL) {
        /* 200 OK, 204 continue */
        if (response->status / 100 != 2) {
            i_error("fts_elastic: Indexing failed: %s", response->reason);
            conn->request_status = -1;
        }
    }
    f_debug("end");
}

/* Parse one TSV data row and add its uid/box/score to ctx->results_hash */
static void
elastic_connection_parse_tsv_row(struct elastic_search_context *ctx,
                                  const char *line)
{
    /* columns: uid \t box [\t SCORE()] */
    const char *p = line;
    const char *tab;
    uint32_t uid;

    /* parse uid */
    tab = strchr(p, '\t');
    if (tab == NULL) return;
    char *uid_str = t_strndup(p, (size_t)(tab - p));
    if (str_to_uint32(uid_str, &uid) < 0 || uid == 0) {
        i_warning("fts_elastic: invalid uid in SQL result row: %s", line);
        return;
    }

    /* parse box guid */
    p = tab + 1;
    const char *box_start = p;
    tab = (ctx->n_cols >= 3) ? strchr(p, '\t') : NULL;
    size_t box_len = (tab != NULL) ? (size_t)(tab - box_start) : strlen(box_start);
    if (box_len == 0) {
        i_warning("fts_elastic: empty box guid in SQL result row: %s", line);
        return;
    }
    char *box_guid = p_strndup(ctx->pool, box_start, box_len);

    /* find or create elastic_result for this box */
    struct elastic_result *result = hash_table_lookup(ctx->results_hash, box_guid);
    if (result == NULL) {
        result = p_new(ctx->pool, struct elastic_result, 1);
        result->box_guid = box_guid;
        p_array_init(&result->uids, ctx->pool, 32);
        p_array_init(&result->scores, ctx->pool, 32);
        hash_table_insert(ctx->results_hash, box_guid, result);
        array_push_back(&ctx->results_array, &result);
    }

    seq_range_array_add(&result->uids, uid);
    ctx->found++;

    /* parse score if present */
    if (ctx->n_cols >= 3 && tab != NULL) {
        float score = (float)strtod(tab + 1, NULL);
        if (score > 0.0f) {
            struct fts_score_map *sm = array_append_space(&result->scores);
            sm->uid = uid;
            sm->score = score;
        }
    }
}

/* Process available lines from the SQL TSV payload stream */
static void
elastic_connection_sql_payload_input(struct elastic_connection *conn)
{
    f_debug("start");
    const char *line;

    while ((line = i_stream_read_next_line(conn->payload)) != NULL) {
        /* first line is the TSV header row — skip it */
        if (!conn->ctx->header_seen) {
            conn->ctx->header_seen = TRUE;
            continue;
        }

        if (*line == '\0')
            continue;

        /* count tabs to tell data rows from the cursor token */
        int ntabs = 0;
        for (const char *c = line; *c != '\0'; c++)
            if (*c == '\t') ntabs++;

        if (ntabs == conn->ctx->n_cols - 1) {
            elastic_connection_parse_tsv_row(conn->ctx, line);
        } else if (ntabs == 0) {
            /* cursor appended by ES after the last data row */
            conn->ctx->cursor = p_strdup(conn->ctx->pool, line);
        }
    }

    if (conn->payload->stream_errno != 0) {
        i_error("fts_elastic: SQL payload read error: %s",
                i_stream_get_error(conn->payload));
        conn->request_status = -1;
    }

    if (conn->payload->eof || conn->payload->stream_errno != 0) {
        io_remove(&conn->io);
        i_stream_unref(&conn->payload);
    }
    f_debug("end");
}

/* HTTP response handler for SQL requests */
static void
elastic_connection_sql_response(const struct http_response *response,
                                struct elastic_connection *conn)
{
    f_debug("start");
    if (response->status / 100 != 2) {
        i_error("fts_elastic: SQL request failed: %d %s",
                response->status, response->reason);
        conn->request_status = -1;
        return;
    }

    if (response->payload == NULL) {
        i_error("fts_elastic: SQL response: empty payload");
        conn->request_status = -1;
        return;
    }

    i_stream_ref(response->payload);
    conn->payload = response->payload;
    conn->io = io_add_istream(response->payload,
                    elastic_connection_sql_payload_input, conn);
    elastic_connection_sql_payload_input(conn);
    f_debug("end");
}

/* Callback from HTTP request — dispatches by post_type */
static void
elastic_connection_http_response(const struct http_response *response,
                                 struct elastic_connection *conn)
{
    f_debug("start");
    if (response != NULL && conn != NULL) {
        switch (conn->post_type) {
        case ELASTIC_POST_TYPE_SQL:
            elastic_connection_sql_response(response, conn);
            break;
        case ELASTIC_POST_TYPE_BULK:
            elastic_connection_bulk_response(response, conn);
            break;
        case ELASTIC_POST_TYPE_REFRESH:
        case ELASTIC_POST_TYPE_DELETE:
        case ELASTIC_POST_TYPE_DELETE_BY_QUERY:
            /* not implemented */
            break;
        }
    }
    f_debug("end");
}

/* Performs HTTP POST/DELETE request with callback */
int elastic_connection_post(struct elastic_connection *conn,
                            const char *path, string_t *data)
{
    f_debug("start");
    struct http_client_request *http_req = NULL;
    struct istream *post_payload = NULL;
    const char *method = "POST";

    if (conn == NULL || path == NULL || data == NULL) {
        i_error("fts_elastic: connection_post: critical error during POST");
        f_debug("return -1");
        return -1;
    }

    if (conn->post_type == ELASTIC_POST_TYPE_DELETE) {
        method = "DELETE";
    }

    http_req = http_client_request(elastic_http_client, method, conn->http_host,
                                   path, elastic_connection_http_response, conn);
    http_client_request_set_port(http_req, conn->http_port);
    http_client_request_set_ssl(http_req, conn->http_ssl);
    http_client_request_add_header(http_req, "Content-Type", "application/json");
    if (conn->basic_auth_username != NULL && conn->basic_auth_pass != NULL) {
        http_client_request_set_auth_simple(http_req, conn->basic_auth_username,
                                             conn->basic_auth_pass);
    }

    post_payload = i_stream_create_from_buffer(data);
    http_client_request_set_payload(http_req, post_payload, TRUE);
    i_stream_unref(&post_payload);
    http_client_request_submit(http_req);

    conn->request_status = 0;
    http_client_wait(elastic_http_client);

    f_debug("return %d", conn->request_status);
    return conn->request_status;
}

/* Performs elastic _bulk request, checking only response status */
int elastic_connection_bulk(struct elastic_connection *conn, string_t *cmd)
{
    f_debug("start");
    const char *path = NULL;

    if (conn == NULL || cmd == NULL) {
        i_error("fts_elastic: connection_bulk: conn or cmd is NULL");
        f_debug("return -1");
        return -1;
    }

    conn->post_type = ELASTIC_POST_TYPE_BULK;
    path = t_strconcat(conn->http_base_path, "_bulk"
                        "?routing=", conn->username,
                        conn->refresh_on_update ? "&refresh=true" : "",
                        NULL);
    elastic_connection_post(conn, path, cmd);
    f_debug("return %d", conn->request_status);
    return conn->request_status;
}


int elastic_connection_refresh(struct elastic_connection *conn)
{
    f_debug("start");
    const char *path = NULL;
    string_t *query = t_str_new_const("", 0);

    if (conn == NULL) {
        i_error("fts_elastic: refresh: critical error");
        f_debug("return -1");
        return -1;
    }

    conn->post_type = ELASTIC_POST_TYPE_REFRESH;
    path = t_strconcat(conn->http_base_path, "_refresh", NULL);
    elastic_connection_post(conn, path, query);

    if (conn->request_status < 0) {
        f_debug("return -1");
        return -1;
    }

    f_debug("return 0");
    return 0;
}

/* Append a JSON-encoded string value (for embedding SQL in JSON body) */
static void
str_append_json_string(string_t *dest, const char *s)
{
    str_append_c(dest, '"');
    for (; *s != '\0'; s++) {
        if (*s == '"')       str_append(dest, "\\\"");
        else if (*s == '\\') str_append(dest, "\\\\");
        else if (*s == '\n') str_append(dest, "\\n");
        else if (*s == '\r') str_append(dest, "\\r");
        else if (*s == '\t') str_append(dest, "\\t");
        else str_append_c(dest, *s);
    }
    str_append_c(dest, '"');
}

/* Execute an ES SQL query via /_sql?format=tsv.
 * n_cols: 2 = SELECT uid, box  (no scores)
 *         3 = SELECT uid, box, SCORE()
 * Follows cursor pages automatically to handle >10000 results.
 * Returns total hit count, or -1 on error. */
int elastic_connection_sql(struct elastic_connection *conn, pool_t pool,
                           string_t *sql, int n_cols,
                           struct elastic_result ***results_r)
{
    f_debug("start");

    if (conn == NULL || sql == NULL || results_r == NULL) {
        i_error("fts_elastic: sql: invalid arguments");
        return -1;
    }

    /* initialise context — results_hash/results_array persist across pages */
    i_zero(conn->ctx);
    conn->ctx->pool = pool;
    conn->ctx->n_cols = n_cols;
    conn->ctx->results_r = results_r;
    conn->ctx->found = 0;
    conn->ctx->cursor = NULL;
    conn->ctx->header_seen = FALSE;
    p_array_init(&conn->ctx->results_array, pool, 8);
    hash_table_create(&conn->ctx->results_hash, pool, 0, str_hash, strcmp);

    conn->post_type = ELASTIC_POST_TYPE_SQL;
    i_free_and_null(conn->http_failure);

    /* build initial request body: {"query":"<sql>","fetch_size":10000}
     * Note: /_sql does not support ?routing= so searches fan out to all shards.
     * Correctness is ensured by the WHERE user='...' clause in every query. */
    string_t *body = str_new(default_pool, str_len(sql) + 64);
    str_append(body, "{\"query\":");
    str_append_json_string(body, str_c(sql));
    str_append(body, ",\"fetch_size\":10000}");

    elastic_connection_post(conn, conn->sql_path, body);
    str_free(&body);

    if (conn->request_status < 0)
        goto done;

    /* follow cursor pages until exhausted */
    while (conn->ctx->cursor != NULL) {
        const char *cursor = conn->ctx->cursor;
        conn->ctx->cursor = NULL;
        conn->ctx->header_seen = FALSE;

        string_t *cursor_body = str_new(default_pool, 256);
        str_append(cursor_body, "{\"cursor\":");
        /* cursor is a base64 blob — just JSON-quote it without escaping */
        str_append_c(cursor_body, '"');
        str_append(cursor_body, cursor);
        str_append_c(cursor_body, '"');
        str_append(cursor_body, "}");

        elastic_connection_post(conn, conn->sql_path, cursor_body);
        str_free(&cursor_body);

        if (conn->request_status < 0)
            goto done;
    }

done:
    /* NULL-terminate the results array */
    array_append_zero(&conn->ctx->results_array);
    *results_r = array_front_modifiable(&conn->ctx->results_array);
    hash_table_destroy(&conn->ctx->results_hash);

    if (conn->request_status < 0) {
        f_debug("return -1");
        return -1;
    }

    f_debug("return %d", conn->ctx->found);
    return conn->ctx->found;
}

/* Performs elastic delete-by-query */
int elastic_connection_delete_by_query(struct elastic_connection *conn,
                                       pool_t pool, string_t *query)
{
    f_debug("start");
    const char *path = NULL;

    if (conn == NULL || query == NULL) {
        i_error("fts_elastic: delete_by_query: conn or query is NULL");
        f_debug("return -1");
        return -1;
    }

    i_zero(conn->ctx);
    conn->ctx->pool = pool;
    conn->post_type = ELASTIC_POST_TYPE_DELETE_BY_QUERY;

    i_free_and_null(conn->http_failure);

    path = t_strconcat(conn->http_base_path, "_delete_by_query?routing=",
                       conn->username, NULL);
    elastic_connection_post(conn, path, query);

    if (conn->request_status < 0) {
        f_debug("return -1");
        return -1;
    }

    f_debug("return 0");
    return 0;
}
