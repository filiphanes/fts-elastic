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
#include "settings.h"
#include "fts-elastic-settings.h"

#include <stdlib.h>

const char *fts_elastic_plugin_version = DOVECOT_ABI_VERSION;
struct http_client *elastic_http_client = NULL;

struct fts_elastic_user_module fts_elastic_user_module =
    MODULE_CONTEXT_INIT(&mail_user_module_register);

#if defined(DOVECOT_PREREQ) && DOVECOT_PREREQ(2,3,17)
static void fts_elastic_mail_user_deinit(struct mail_user *user)
{
    struct fts_elastic_user *fuser = FTS_ELASTIC_USER_CONTEXT_REQUIRE(user);

    fuser->module_ctx.super.deinit(user);
}
#endif

static struct event_category event_category_fts_elastic = {
	.name = FTS_ELASTIC_LABEL,
	.parent = &event_category_fts
};

static int fts_elastic_mail_user_get(struct mail_user *user,
                                     struct event *event,
                                     struct fts_elastic_user **fuser_r,
                                     const char **error_r)
{
    struct fts_elastic_user *fuser;
    struct fts_elastic_settings *set;

    /* allocate per-user context */
    fuser = p_new(user->pool, struct fts_elastic_user, 1);

    /* parse plugin settings from the tagged event */
    if (settings_get(event,
                     &fts_elastic_setting_parser_info,
                     0, &set, error_r) < 0) {
        return -1;
    }
    fuser->set = set;

    /* initialize the core FTS user with the same event */
    if (fts_mail_user_init(user, event, FALSE, error_r) < 0) {
        return -1;
    }

    *fuser_r = fuser;
    return 0;
}

static void fts_elastic_mail_user_created(struct mail_user *user)
{
    struct mail_user_vfuncs *v = user->vlast;
    struct event *ev = event_create(user->event);
    struct fts_elastic_user *fuser;
    const char *error;

    /* scope settings lookup to fts_elastic */
    event_add_category(ev, &event_category_fts_elastic);

    /* pull in per-user config and init core FTS */
    if (fts_elastic_mail_user_get(user, ev, &fuser, &error) < 0) {
        event_unref(&ev);
        return;
    }

    /* chain into dovecot’s vfunc stack */
    fuser->module_ctx.super = *v;
    user->vlast = &fuser->module_ctx.super;
    v->deinit = fts_elastic_mail_user_deinit;
}

static struct mail_storage_hooks fts_elastic_mail_storage_hooks = {
    .mail_user_created = fts_elastic_mail_user_created
};

void fts_elastic_plugin_init(struct module *module)
{
    f_debug("start");
    fts_backend_register(&fts_backend_elastic);
    mail_storage_hooks_add(module, &fts_elastic_mail_storage_hooks);
    f_debug("end");
}

void fts_elastic_plugin_deinit(void)
{
    f_debug("start");
    fts_backend_register(&fts_backend_elastic);
    fts_backend_unregister(fts_backend_elastic.name);
    mail_storage_hooks_remove(&fts_elastic_mail_storage_hooks);
    if (elastic_http_client != NULL)
		http_client_deinit(&elastic_http_client);

    f_debug("end");
}

const char *fts_elastic_plugin_dependencies[] = { "fts", NULL };
