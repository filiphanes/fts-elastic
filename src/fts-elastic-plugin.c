/* Copyright (c) 2006-2012 Dovecot authors, see the included COPYING file */
/* Copyright (c) 2014 Joshua Atkins <josh@ascendantcom.com> */
/* Copyright (c) 2019-2020 Filip Hanes <filip.hanes@gmail.com> */

#include "lib.h"
#include "array.h"
#include "http-client.h"
#include "mail-user.h"
#include "mail-storage-hooks.h"
#include "fts-user.h"
#include "fts-elastic-plugin.h"

#include <stdlib.h>

const char *fts_elastic_plugin_version = DOVECOT_ABI_VERSION;
struct http_client *elastic_http_client = NULL;

struct fts_elastic_user_module fts_elastic_user_module =
    MODULE_CONTEXT_INIT(&mail_user_module_register);

static int
fts_elastic_plugin_init_settings(struct mail_user *user,
                                 struct fts_elastic_settings *set,
                                 const char *str)
{
    FUNC_START();
    const char *const *tmp;

    /* validate our parameters */
    if (user == NULL || set == NULL) {
        i_error("fts_elastic: critical error initialisation");
        return -1;
    }

    if (str == NULL) {
        str = "";
    }

    set->bulk_size = 5*1024*1024; /* 5 MB */
    set->refresh_by_fts = TRUE;
    set->refresh_on_update = FALSE;

    tmp = t_strsplit_spaces(str, " ");
    for (; *tmp != NULL; tmp++) {
        if (strncmp(*tmp, "url=", 4) == 0) {
            set->url = p_strdup(user->pool, *tmp + 4);
        } else if (strcmp(*tmp, "debug") == 0) {
            set->debug = TRUE;
		} else if (strncmp(*tmp, "rawlog_dir=", 11) == 0) {
			set->rawlog_dir = p_strdup(user->pool, *tmp + 11);
		} else if (strncmp(*tmp, "bulk_size=", 10) == 0) {
			if (str_to_uint(*tmp+10, &set->bulk_size) < 0 || set->bulk_size == 0) {
				i_error("fts_elastic: bulk_size='%s' must be a positive integer", *tmp+10);
                return -1;
			}
		} else if (strncmp(*tmp, "refresh=", 8) == 0) {
			if (strcmp(*tmp + 8, "never") == 0) {
				set->refresh_on_update = FALSE;
				set->refresh_by_fts = FALSE;
			} else if (strcmp(*tmp + 8, "update") == 0) {
				set->refresh_on_update = TRUE;
			} else if (strcmp(*tmp + 8, "fts") == 0) {
				set->refresh_by_fts = TRUE;
			} else {
				i_error("fts_elastic: Invalid setting for refresh: %s", *tmp+8);
				return -1;
			}
        } else {
            i_error("fts_elastic: Invalid setting: %s", *tmp);
            return -1;
        }
    }

    FUNC_END();
    return 0;
}

static void fts_elastic_mail_user_deinit(struct mail_user *user)
{
    struct fts_elastic_user *fuser = FTS_ELASTIC_USER_CONTEXT_REQUIRE(user);

    fts_mail_user_deinit(user);
    fuser->module_ctx.super.deinit(user);
}

static void fts_elastic_mail_user_create(struct mail_user *user, const char *env)
{
    FUNC_START();
    struct mail_user_vfuncs *v = user->vlast;
    struct fts_elastic_user *fuser = NULL;
    const char *error;

    /* validate our parameters */
    if (user == NULL || env == NULL) {
        i_error("fts_elastic: critical error during mail user creation");
        return;
    }

    fuser = p_new(user->pool, struct fts_elastic_user, 1);
    if (fts_elastic_plugin_init_settings(user, &fuser->set, env) < 0) {
        /* invalid settings, disabling */
        return;
    }

    if (fts_mail_user_init(user, FALSE, &error) < 0) {
        i_error("fts_elastic: %s", error);
        return;
    }

    fuser->module_ctx.super = *v;
    user->vlast = &fuser->module_ctx.super;
    v->deinit = fts_elastic_mail_user_deinit;

    MODULE_CONTEXT_SET(user, fts_elastic_user_module, fuser);
    FUNC_END();
}

static void fts_elastic_mail_user_created(struct mail_user *user)
{
    FUNC_START();
    const char *env = NULL;

    /* validate our parameters */
    if (user == NULL) {
        i_error("fts_elastic: critical error during mail user creation");
    } else {
        env = mail_user_plugin_getenv(user, "fts_elastic");

        if (env != NULL) {
            fts_elastic_mail_user_create(user, env);
        }
    }
    FUNC_END();
}

static struct mail_storage_hooks fts_elastic_mail_storage_hooks = {
    .mail_user_created = fts_elastic_mail_user_created
};

void fts_elastic_plugin_init(struct module *module)
{
    FUNC_START();
    fts_backend_register(&fts_backend_elastic);
    mail_storage_hooks_add(module, &fts_elastic_mail_storage_hooks);
    FUNC_END();
}

void fts_elastic_plugin_deinit(void)
{
    FUNC_START();
    fts_backend_unregister(fts_backend_elastic.name);
    mail_storage_hooks_remove(&fts_elastic_mail_storage_hooks);
    if (elastic_http_client != NULL)
		http_client_deinit(&elastic_http_client);

    FUNC_END();
}

const char *fts_elastic_plugin_dependencies[] = { "fts", NULL };
