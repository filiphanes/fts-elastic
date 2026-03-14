#ifndef ELASTIC_CONNECTION_H
#define ELASTIC_CONNECTION_H

#include "seq-range-array.h"
#include "http-client.h"
#include "fts-api.h"
#include "fts-elastic-settings.h"

struct elastic_connection;

enum elastic_post_type {
    ELASTIC_POST_TYPE_BULK = 0,
    ELASTIC_POST_TYPE_SQL,
    ELASTIC_POST_TYPE_REFRESH,
    ELASTIC_POST_TYPE_DELETE,
    ELASTIC_POST_TYPE_DELETE_BY_QUERY,
};

struct elastic_result {
    const char *box_guid;

    ARRAY_TYPE(seq_range) uids;
    ARRAY_TYPE(fts_score_map) scores;
};

struct elastic_search_context;

int elastic_connection_init(const struct fts_elastic_settings *set,
                            struct mail_namespace *ns,
                            struct elastic_connection **conn_r,
                            const char **error_r,
                            struct event *parent);

void elastic_connection_deinit(struct elastic_connection *conn);

const char *elastic_connection_get_index(struct elastic_connection *conn);

int elastic_connection_post(struct elastic_connection *conn,
                            const char *path, string_t *cmd);

int elastic_connection_bulk(struct elastic_connection *conn, string_t *cmd);

int elastic_connection_refresh(struct elastic_connection *conn);

/* Execute an ES SQL query and return results grouped by box_guid.
 * n_cols: 2 = SELECT uid, box  (no scores)
 *         3 = SELECT uid, box, SCORE()
 * Handles cursor pagination automatically for >10000 results.
 * Returns number of hits, or -1 on error. */
int elastic_connection_sql(struct elastic_connection *conn,
                           pool_t pool, string_t *sql, int n_cols,
                           struct elastic_result ***results_r);

int elastic_connection_delete_by_query(struct elastic_connection *conn,
                                       pool_t pool, string_t *query);

#endif
