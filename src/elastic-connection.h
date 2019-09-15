#ifndef ELASTIC_CONNECTION_H
#define ELASTIC_CONNECTION_H

#include "seq-range-array.h"
#include "http-client.h"
#include "fts-api.h"
#include <json-c/json.h>

struct fts_elastic_settings;
struct elastic_connection;

enum elastic_post_type {
    ELASTIC_POST_TYPE_UPDATE = 0,
    ELASTIC_POST_TYPE_SELECT,
    ELASTIC_POST_TYPE_LAST_UID,
    ELASTIC_POST_TYPE_REFRESH,
};

struct elastic_result {
    const char *box_id;

    ARRAY_TYPE(seq_range) uids;
    ARRAY_TYPE(fts_score_map) scores;
};

int elastic_connection_init(const struct fts_elastic_settings *set,
                            struct elastic_connection **conn_r,
                            const char **error_r);

void elastic_connection_deinit(struct elastic_connection *conn);


int elastic_connection_update(struct elastic_connection *conn, string_t *cmd);

int elastic_connection_post(struct elastic_connection *conn,
                            const char *url, string_t *cmd);

void json_parse_array(json_object *jobj, char *key,
                      struct elastic_connection *conn);

void elastic_connection_last_uid_json(struct elastic_connection *conn,
                                      char *key, struct json_object *val);

void elastic_connection_select_json(struct elastic_connection *conn,
                                    char *key, struct json_object *val);


void jobj_parse(struct elastic_connection *conn, json_object *jobj);


int32_t elastic_connection_last_uid(struct elastic_connection *conn,
                                    string_t *query, const char *box_guid);

struct http_client_request*
elastic_connection_http_request(struct elastic_connection *conn, const char *url);

int32_t elastic_connection_refresh(struct elastic_connection *conn);

int32_t elastic_connection_select(struct elastic_connection *conn, pool_t pool,
    string_t *query, const char *box, struct elastic_result ***box_results_r);

#endif