#ifndef FTS_ELASTIC_SETTINGS_H
#define FTS_ELASTIC_SETTINGS_H

#define FTS_ELASTIC_FILTER "fts_elastic"

struct fts_elastic_settings {
    pool_t pool;            /* must be first for the settings parser */
    const char *url;	    /* base URL to an ElasticSearch instance */
    unsigned int bulk_size; /* maximum size of values indexed in _bulk requests default=5MB */
    bool refresh_on_update;	/* if we want add ?refresh=true to elastic query*/
    bool refresh_by_fts;	/* if we want to allow refresh http request called by fts plugin */
    bool debug;			    /* whether or not debug is set */
    bool use_sql;		    /* use elastic sql rest api, which returns smaller results */
};

extern const struct setting_parser_info fts_elastic_setting_parser_info;
int fts_elastic_settings_get(struct event *event,
			  const struct setting_parser_info *info,
			  const struct fts_elastic_settings **set,
			  const char **error_r);

#endif
