#ifndef fts_elastic_PLUGIN_H
#define fts_elastic_PLUGIN_H

#include "module-context.h"
#include "mail-user.h"
#include "fts-api-private.h"

#define FTS_ELASTIC_USER_CONTEXT(obj) \
    MODULE_CONTEXT(obj, fts_elastic_user_module)

#ifndef i_zero
#define i_zero(p) \
	memset(p, 0 + COMPILE_ERROR_IF_TRUE(sizeof(p) > sizeof(void *)), sizeof(*(p)))
#endif

struct fts_elastic_settings {
    const char *url;	    /* base URL to an ElasticSearch instance */
    const char *rawlog_dir; /* directory where raw http request and response will be saved */
    const char *basic_auth_username; /* username for basic auth in ElasticSearch */
    const char *basic_auth_pass;	 /* password for basic auth in ElasticSearch */
    unsigned int bulk_size; /* maximum size of values indexed in _bulk requests default=5MB */
    bool refresh_on_update;	/* if we want add ?refresh=true to elastic query*/
    bool refresh_by_fts;	/* if we want to allow refresh http request called by fts plugin */
    bool debug;			    /* whether or not debug is set */
};

struct fts_elastic_user {
    union mail_user_module_context module_ctx;	/* mail user context */
    struct fts_elastic_settings set; 		/* loaded settings */
};

extern const char *fts_elastic_plugin_dependencies[];
extern struct fts_backend fts_backend_elastic;
extern MODULE_CONTEXT_DEFINE(fts_elastic_user_module, &mail_user_module_register);
extern struct http_client *elastic_http_client;

void fts_elastic_plugin_init(struct module *module);
void fts_elastic_plugin_deinit(void);

#endif

#if defined(DOVECOT_PREREQ) && DOVECOT_PREREQ(2,3)
#else
#   define str_append_max(str, data, size) str_append_n(str, data, size);
#endif

#if !defined(FUNC_START)
#ifndef DEBUG
#define FUNC_START() ((void)0)
#define FUNC_IN() ((void)0)
#define FUNC_END() ((void)0)
#define FUNC_END_RET(ignore) ((void)0)
#define FUNC_END_RET_INT(ignore) ((void)0)
#else
#define FUNC_START()		i_debug("%s:%d %s() start", __FILE__, __LINE__, __FUNCTION__)
#define FUNC_IN()			i_debug("%s:%d %s() in", __FILE__, __LINE__, __FUNCTION__)
#define FUNC_END()			i_debug("%s:%d %s() end", __FILE__, __LINE__, __FUNCTION__)
#define FUNC_END_RET(r)		i_debug("%s:%d %s() return %s", __FILE__, __LINE__, __FUNCTION__, r)
#define FUNC_END_RET_INT(r)	i_debug("%s:%d %s() return %d", __FILE__, __LINE__, __FUNCTION__, (int)r)
#endif
#endif
