#ifndef fts_elastic_PLUGIN_H
#define fts_elastic_PLUGIN_H

#include "module-context.h"
#include "mail-user.h"
#include "fts-api-private.h"

#define FTS_ELASTIC_LABEL "fts-elastic"

#define FTS_ELASTIC_USER_CONTEXT(obj) \
    MODULE_CONTEXT(obj, fts_elastic_user_module)
#define FTS_ELASTIC_USER_CONTEXT_REQUIRE(obj) \
    MODULE_CONTEXT_REQUIRE(obj, fts_elastic_user_module)

#ifndef i_zero
#define i_zero(p) \
	memset(p, 0 + COMPILE_ERROR_IF_TRUE(sizeof(p) > sizeof(void *)), sizeof(*(p)))
#endif

struct fts_elastic_user {
    union mail_user_module_context module_ctx;	/* mail user context */
    const struct fts_elastic_settings *set;	/* loaded settings */
};

extern const char *fts_elastic_plugin_dependencies[];
extern struct fts_backend fts_backend_elastic;
extern MODULE_CONTEXT_DEFINE(fts_elastic_user_module, &mail_user_module_register);
extern struct http_client *elastic_http_client;

int fts_elastic_mail_user_get(struct mail_user *user,
                              struct event *event,
                              struct fts_elastic_user **fuser_r,
                              const char **error_r);

void fts_elastic_plugin_init(struct module *module);
void fts_elastic_plugin_deinit(void);

#endif

#if ((DOVECOT_VERSION_MAJOR << 24) + (DOVECOT_VERSION_MINOR << 16) + DOVECOT_VERSION_MICRO < ((2) << 24) + ((3) << 16) + (18))
#undef DOVECOT_PREREQ
#define DOVECOT_PREREQ(maj, min, micro) \
       ((DOVECOT_VERSION_MAJOR << 24) + \
        (DOVECOT_VERSION_MINOR << 16) + \
        DOVECOT_VERSION_MICRO >= ((maj) << 24) + ((min) << 16) + (micro))
#endif

#if defined(DOVECOT_PREREQ) && DOVECOT_PREREQ(2,3,0)
#else
#   define str_append_max(str, data, size) str_append_n(str, data, size);
#endif

//#define DEBUG 1
#ifdef DEBUG
# ifdef __clang__
#  define f_debug(format, ...)	i_debug("%s:%d %s() "format, __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)
# else
#  define f_debug(format, ...)	i_debug("%s:%d %s() "format, __FILE__, __LINE__, __FUNCTION__ __VA_OPT__(,) __VA_ARGS__)
# endif /* __clang__ */
#else
# define f_debug(ignore, ...) ((void)0)
#endif /* DEBUG */
