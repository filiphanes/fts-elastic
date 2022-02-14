/* Copyright (c) 2006-2014 Dovecot authors, see the included COPYING file */
/* Copyright (c) 2014 Joshua Atkins <josh@ascendantcom.com> */
/* Copyright (c) 2019-2020 Filip Hanes <filip.hanes@gmail.com> */

#include <ctype.h>
#include <syslog.h>
#include <unistd.h>
#include <inttypes.h>
#include <limits.h>

#include "lib.h"
#include "array.h"
#include "str.h"
#include "hash.h"
#include "strescape.h"
#include "seq-range-array.h"
#include "unichar.h"
#include "mail-storage-private.h"
#include "mailbox-list-private.h"
#include "mail-search.h"
#include "fts-api.h"
#include "fts-elastic-plugin.h"
#include "elastic-connection.h"

/* values that must be replaced in field names */
static const char *elastic_field_replace_chars = ".#*\"";
static const char *escape_hex_chars = "0123456789abcdefABCDEF";

struct elastic_fts_backend {
    struct fts_backend backend;
    struct elastic_connection *conn;
};

struct elastic_fts_field {
	char *key;
	string_t *value;
};

struct elastic_fts_backend_update_context {
    struct fts_backend_update_context ctx;

    struct mailbox *prev_box;
    char box_guid[MAILBOX_GUID_HEX_LENGTH + 1];
    const char *username;
    
    uint32_t uid;

    /* used to build multi-part messages. */
    string_t *current_key;
    buffer_t *current_value;

	ARRAY(struct elastic_fts_field) fields;

    /* build a json string for bulk indexing */
    string_t *json_request;

    unsigned int body_open:1;
    unsigned int documents_added:1;
    unsigned int expunges:1;
};

static const char *elastic_field_prepare(const char *field)
{
    FUNC_START();
    int i;

    for (i = 0; elastic_field_replace_chars[i] != '\0'; i++) {
        field = t_str_replace(field, elastic_field_replace_chars[i], '_');
    }

    return t_str_lcase(field);
}

/* copied and edited from https://github.com/json-c/json-c/blob/1934eddf2968a103e943b2938558c1a07054e26f/json_object.c#L106 */
static void str_append_json_escaped(string_t *dest, const char *data, size_t len)
{
    FUNC_START();
    // i_debug("escaping \"%s\" with size %zu", data, len);
    size_t pos = 0, start = 0;
    unsigned char c;

	while (len--) {
		c = data[pos];
		switch(c) {
		case '\n':
		case '\r':
		case '\t':
		case '"':
		case '\f':
		case '\\':
		case '\b':
			if(start < pos)
				buffer_append(dest, data + start, pos - start);

			if(c == '\n') str_append(dest, "\\n");
			else if(c == '\r') str_append(dest, "\\r");
			else if(c == '\t') str_append(dest, "\\t");
			else if(c == '"') str_append(dest, "\\\"");
			else if(c == '\f') str_append(dest, "\\f");
			else if(c == '\\') str_append(dest, "\\\\");
			else if(c == '\b') str_append(dest, "\\b");

			start = ++pos;
			break;
		default:
			if(c < ' ') {
				if(start < pos)
					buffer_append(dest, data + start, pos - start);

				str_printfa(dest, "\\u00%c%c",
                            escape_hex_chars[c >> 4],
                            escape_hex_chars[c & 0xf]);

				start = ++pos;
			} else {
				pos++;
            }
		}
	}
	if (start < pos)
		buffer_append(dest, data + start, pos - start);
    FUNC_END();
}

static struct fts_backend *fts_backend_elastic_alloc(void)
{
    FUNC_START();
    struct elastic_fts_backend *backend;

    backend = i_new(struct elastic_fts_backend, 1);
    backend->backend = fts_backend_elastic;

    return &backend->backend;
    FUNC_END();
}

static int
fts_backend_elastic_init(struct fts_backend *_backend, const char **error_r)
{
    FUNC_START();
    struct elastic_fts_backend *backend = (struct elastic_fts_backend *)_backend;
    struct fts_elastic_user *fuser = NULL;

    /* ensure our backend is provided */
    if (_backend == NULL) {
        *error_r = "fts_elastic: error during backend initialisation";
        return -1;
    }

    if ((fuser = FTS_ELASTIC_USER_CONTEXT(_backend->ns->user)) == NULL) {
        *error_r = "Invalid fts_elastic setting";
        return -1;
    }

    FUNC_END();
    return elastic_connection_init(&fuser->set, _backend->ns, &backend->conn, error_r);
}

static void
fts_backend_elastic_deinit(struct fts_backend *_backend)
{
    FUNC_START();
    i_free(_backend);
    FUNC_END();
}

static void
fts_backend_elastic_bulk_end(struct elastic_fts_backend_update_context *_ctx)
{
    FUNC_START();
    struct elastic_fts_backend_update_context *ctx =
        (struct elastic_fts_backend_update_context *)_ctx;
	const struct elastic_fts_field *field;

    /* ensure we have a context */
    if (_ctx == NULL) {
        return;
    }

    array_foreach(&ctx->fields, field) {
        if (str_len(field->value) > 0) {
            str_append(ctx->json_request, ",\"");
            str_append(ctx->json_request, field->key);
            str_append(ctx->json_request, "\":\"");
            str_append_json_escaped(ctx->json_request,
                    str_c(field->value), str_len(field->value));
            str_append(ctx->json_request, "\"");
            /* keys are reused in following bulk items */
            buffer_set_used_size(field->value, 0);
        }
    }

    /* close up this line in the bulk request */
    str_append(ctx->json_request, "}\n");

    /* clean-up for the next message */
    buffer_set_used_size(ctx->current_key, 0);
    buffer_set_used_size(ctx->current_value, 0);
    ctx->body_open = FALSE;
    FUNC_END();
}

static int
fts_backend_elastic_get_last_uid(struct fts_backend *_backend,
                                 struct mailbox *box,
                                 uint32_t *last_uid_r)
{
    FUNC_START();
    static const char JSON_LAST_UID[] =
        "{"
            "\"sort\":{"
                "\"uid\":\"desc\""
            "},"
            "\"query\":{"
                "\"bool\":{"
                    "\"filter\":["
                        "{\"term\":{\"user\":\"%s\"}},"
                        "{\"term\":{\"box\":\"%s\"}}"
                    "]"
                "}"
            "},"
            "\"_source\":false,"
            "\"size\":1"
        "}\n";

    struct elastic_fts_backend *backend = (struct elastic_fts_backend *)_backend;
    struct fts_index_header hdr;
    const char *box_guid = NULL;
    pool_t pool;
    string_t *query;
    struct fts_result *result;
    int ret;

    /* ensure our backend has been initialised */
    if (_backend == NULL || box == NULL || last_uid_r == NULL) {
        i_error("fts_elastic: critical error in get_last_uid");
        return -1;
    }

    /**
     * assume the dovecot index will always match ours for uids. this saves
     * on repeated calls to ES, particularly noticable when fts_autoindex=true.
     *
     * this has a couple of side effects:
     *  1. if the ES index has been blown away, this will return a valid
     *     last_uid that matches Dovecot and it won't realise we need updating
     *  2. if data has been indexed by Dovecot but missed by ES (outage, etc)
     *     then it won't ever make it to the ES index either.
     *
     * TODO: find a better way to implement this
     **/
    if (fts_index_get_header(box, &hdr)) {
        *last_uid_r = hdr.last_indexed_uid;
        return 0;
    } 

    if (fts_mailbox_get_guid(box, &box_guid) < 0) {
        i_error("fts_elastic: get_last_uid: failed to get mbox guid");
        return -1;
    }


    pool = pool_alloconly_create("elastic search", 1024);
    query = str_new(pool, 256);
    str_printfa(query, JSON_LAST_UID,
        _backend->ns->owner != NULL ? _backend->ns->owner->username : "-",
        box_guid);

    result = p_new(pool, struct fts_result, 1);
    result->box = box;
    p_array_init(&result->definite_uids, pool, 2);
    p_array_init(&result->maybe_uids, pool, 2);
    p_array_init(&result->scores, pool, 2);

    ret = elastic_connection_search(backend->conn, pool, query, result);
    if (seq_range_count(&result->definite_uids) > 0) {
        struct seq_range_iter iter;
        seq_range_array_iter_init(&iter, &result->definite_uids);
        seq_range_array_iter_nth(&iter, 0, last_uid_r);
    } else {
        /* no uid found because they are not indexed yet */
        *last_uid_r = 0;
    }

    pool_unref(&pool);
    str_free(&query);

    if (ret < 0)
        return -1;

    fts_index_set_last_uid(box, *last_uid_r);
    FUNC_END();
    return 0;
}

static struct fts_backend_update_context *
fts_backend_elastic_update_init(struct fts_backend *_backend)
{
    FUNC_START();
    struct elastic_fts_backend_update_context *ctx;

    ctx = i_new(struct elastic_fts_backend_update_context, 1);
    ctx->ctx.backend = _backend;

    /* allocate strings for building messages and multi-part messages
     * with a sensible initial size. */
    ctx->current_key = str_new(default_pool, 64);
    ctx->current_value = str_new(default_pool, 1024 * 64);
    ctx->json_request = str_new(default_pool, 1024 * 64);
    ctx->username = _backend->ns->owner ? _backend->ns->owner->username : "-";
	i_array_init(&ctx->fields, 16);

    FUNC_END();
    return &ctx->ctx;
}

static int
fts_backend_elastic_update_deinit(struct fts_backend_update_context *_ctx)
{
    FUNC_START();
    struct elastic_fts_backend_update_context *ctx =
        (struct elastic_fts_backend_update_context *)_ctx;
    struct elastic_fts_backend *backend = NULL;
	struct elastic_fts_field *field;

    /* validate our input parameters */
    if (_ctx == NULL || _ctx->backend == NULL) {
        i_error("fts_elastic: critical error in update_deinit");
        return -1;
    }

    backend = (struct elastic_fts_backend *)_ctx->backend;

    /* clean-up: expunges don't need as much clean-up */
    if (!ctx->expunges) {
        /* this gets called when the last message is finished, so close it up */
        fts_backend_elastic_bulk_end(ctx);

        /* cleanup */
        i_zero(&ctx->box_guid);
        str_free(&ctx->current_key);
        str_free(&ctx->current_value);
        array_foreach_modifiable(&ctx->fields, field) {
            str_free(&field->value);
            i_free(field->key);
        }
    	array_free(&ctx->fields);
    }

    /* perform the actual post */
    if (ctx->documents_added)
        elastic_connection_bulk(backend->conn, ctx->json_request);

    /* global clean-up */
    str_free(&ctx->json_request); 
    i_free(ctx);
    
    FUNC_END();
    return 0;
}

static void
fts_backend_elastic_update_set_mailbox(struct fts_backend_update_context *_ctx,
                                       struct mailbox *box)
{
    FUNC_START();
    struct elastic_fts_backend_update_context *ctx =
        (struct elastic_fts_backend_update_context *)_ctx;
    const char *box_guid = NULL;

    if (_ctx == NULL) {
        i_error("fts_elastic: update_set_mailbox: context was NULL");
        return;
    }

    /* update_set_mailbox has been called but the previous uid is not 0;
     * clean up from our previous mailbox indexing. */
    if (ctx->uid != 0) {
        fts_index_set_last_uid(ctx->prev_box, ctx->uid);
        ctx->uid = 0;
    }

    if (box != NULL) {
        if (fts_mailbox_get_guid(box, &box_guid) < 0) {
            i_debug("fts_elastic: update_set_mailbox: fts_mailbox_get_guid failed");
            _ctx->failed = TRUE;
        }

        /* store the current mailbox we're on in our state struct */
        i_assert(strlen(box_guid) == sizeof(ctx->box_guid) - 1);
        memcpy(ctx->box_guid, box_guid, sizeof(ctx->box_guid) - 1);
    } else {
        /* a box of null appears to indicate that indexing is complete. */
        i_zero(&ctx->box_guid);
    }

    FUNC_END();
    ctx->prev_box = box;
}

static void
elastic_add_update_field(struct elastic_fts_backend_update_context *ctx)
{
    FUNC_START();
	struct elastic_fts_field *field;

	/* there are only a few fields. this lookup is fast enough. */
	array_foreach_modifiable(&ctx->fields, field) {
		if (strcasecmp(field->key, str_c(ctx->current_key)) == 0) {
            /* append on new line if adding to existing value */
            if (str_len(field->value) > 0) {
                str_append(field->value, "\n");
            }
			str_append_str(field->value, ctx->current_value);
            return;
        }
	}

	field = i_new(struct elastic_fts_field, 1);
	field->key = i_strdup(str_c(ctx->current_key));
	field->value = str_new(default_pool, 256);
    str_append_str(field->value, ctx->current_value);
	array_append(&ctx->fields, field, 1);

    FUNC_END();
    return;
}

static void
fts_backend_elastic_bulk_start(struct elastic_fts_backend_update_context *_ctx,
                               const char *action_name)
{
    FUNC_START();
    struct elastic_fts_backend_update_context *ctx =
        (struct elastic_fts_backend_update_context *)_ctx;

    /* add the header that starts the bulk transaction */
    /* _id consists of uid/box_guid/user */
    str_printfa(ctx->json_request, "{\"%s\":{\"_id\":\"%u/%s/%s\"}}\n",
                            action_name, ctx->uid, ctx->box_guid, ctx->username);

    /* track that we've added documents */
    ctx->documents_added = TRUE;

    /* expunges don't need anything more than the action line */
    if (!ctx->expunges) {
        /* add first fields; these are static on every message. */
        str_printfa(ctx->json_request,
                    "{\"uid\":%d,"
                    "\"box\":\"%s\","
                    "\"user\":\"%s\""
                    ,
                    ctx->uid,
                    ctx->box_guid,
		            ctx->username
                    );
    }
    FUNC_END();
}

static void
fts_backend_elastic_uid_changed(struct fts_backend_update_context *_ctx,
                                uint32_t uid)
{
    FUNC_START();
    struct elastic_fts_backend_update_context *ctx =
        (struct elastic_fts_backend_update_context *)_ctx;
    struct elastic_fts_backend *backend =
        (struct elastic_fts_backend *)_ctx->backend;
	struct fts_elastic_user *fuser =
        FTS_ELASTIC_USER_CONTEXT(_ctx->backend->ns->user);

    if (ctx->documents_added) {
        /* this is the end of an old message. nb: the last message to be indexed
         * will not reach here but will instead be caught in update_deinit. */
        fts_backend_elastic_bulk_end(ctx);
    }

    /* chunk up our requests in to reasonable sizes */
    if (str_len(ctx->json_request) > fuser->set.bulk_size) {  
        /* do an early post */
        elastic_connection_bulk(backend->conn, ctx->json_request);

        /* reset our tracking variables */
        buffer_set_used_size(ctx->json_request, 0);
    }
    
    ctx->uid = uid;
    
    fts_backend_elastic_bulk_start(ctx, "index");
    FUNC_END();
}

static bool
fts_backend_elastic_header_want(const char *name)
{
    FUNC_START();
	return
        strcasecmp(name, "Date") == 0 ||
        strcasecmp(name, "From") == 0 ||
        strcasecmp(name, "To") == 0 ||
        strcasecmp(name, "Cc") == 0 ||
        strcasecmp(name, "Bcc") == 0 ||
        strcasecmp(name, "Subject") == 0 ||
        strcasecmp(name, "Sender") == 0 ||
        strcasecmp(name, "Message-ID") == 0;
}

static bool
fts_backend_elastic_update_set_build_key(struct fts_backend_update_context *_ctx,
                                         const struct fts_backend_build_key *key)
{
    FUNC_START();
    struct elastic_fts_backend_update_context *ctx =
        (struct elastic_fts_backend_update_context *)_ctx;

    if (_ctx == NULL || key == NULL) {
        return FALSE;
    }

    /* if the uid doesn't match our expected one, we've moved on to a new message */
    if (key->uid != ctx->uid) {
        fts_backend_elastic_uid_changed(_ctx, key->uid);
    }

    switch (key->type) {
    case FTS_BACKEND_BUILD_KEY_HDR:
    case FTS_BACKEND_BUILD_KEY_MIME_HDR:
        /* Index only wanted headers */
        if (fts_backend_elastic_header_want(key->hdr_name))
            str_append(ctx->current_key, elastic_field_prepare(key->hdr_name));

        break;
    case FTS_BACKEND_BUILD_KEY_BODY_PART:
        if (!ctx->body_open) {
            ctx->body_open = TRUE;
            str_append(ctx->current_key, "body");
        }

        break;
    case FTS_BACKEND_BUILD_KEY_BODY_PART_BINARY:
        i_unreached();
    }

    FUNC_END();
    return TRUE;
}

/* build more message body */
static int
fts_backend_elastic_update_build_more(struct fts_backend_update_context *_ctx,
                                      const unsigned char *data, size_t size)
{
    FUNC_START();
    struct elastic_fts_backend_update_context *ctx =
        (struct elastic_fts_backend_update_context *)_ctx;

    if (_ctx == NULL) {
        i_error("fts_elastic: update_build_more: critical error building message body");
        return -1;
    }

    buffer_append(ctx->current_value, (const char *)data, size);
    FUNC_END();
    return 0;
}

static void
fts_backend_elastic_update_unset_build_key(struct fts_backend_update_context *_ctx)
{
    FUNC_START();
    struct elastic_fts_backend_update_context *ctx =
        (struct elastic_fts_backend_update_context *)_ctx;

    if (_ctx == NULL) {
        i_error("fts_elastic: unset_build_key _ctx is NULL");
        return;
    }

    /* field is complete, add it to our update fields if not empty. */
    if (str_len(ctx->current_key) > 0) {
        elastic_add_update_field(ctx);
        buffer_set_used_size(ctx->current_key, 0);
    }
    buffer_set_used_size(ctx->current_value, 0);
    FUNC_END();
}

static void
fts_backend_elastic_update_expunge(struct fts_backend_update_context *_ctx,
                                   uint32_t uid)
{
    FUNC_START();
    /* fix imapc to call update_expunge with each expunged uid */
    struct elastic_fts_backend_update_context *ctx =
        (struct elastic_fts_backend_update_context *)_ctx;

    /* update the context to note that there have been expunges */
    ctx->expunges = TRUE;
    ctx->uid = uid;

    /* add the delete action */
    fts_backend_elastic_bulk_start(ctx, "delete");
    FUNC_END();
}

static int fts_backend_elastic_refresh(struct fts_backend *_backend)
{
    FUNC_START();
    struct elastic_fts_backend *backend =
        (struct elastic_fts_backend *)_backend;
	struct fts_elastic_user *fuser =
        FTS_ELASTIC_USER_CONTEXT(_backend->ns->user);

    if (fuser->set.refresh_by_fts) {
        elastic_connection_refresh(backend->conn);
    }
    FUNC_END();
    return 0;
}

/* delete uids in bulk */
static int
fts_backend_elastic_expunge_uids(struct fts_backend *_backend,
                                 struct mailbox *box,
                                 ARRAY_TYPE(seq_range) uids)
{
    FUNC_START();
    uint32_t uid;
    unsigned int i;
    struct seq_range_iter iter;
    struct fts_backend_update_context *update_ctx =
                fts_backend_elastic_update_init(_backend);

    fts_backend_elastic_update_set_mailbox(update_ctx, box);

    seq_range_array_iter_init(&iter, &uids);
    i = 0;
    while (seq_range_array_iter_nth(&iter, i++, &uid)) {
        fts_backend_elastic_update_expunge(update_ctx, uid);
    }
    fts_backend_elastic_update_deinit(update_ctx);

    FUNC_END();
    return 0;
}

/* implement proper rescan */
static int fts_backend_elastic_rescan(struct fts_backend *_backend)
{
    FUNC_START();
    struct elastic_fts_backend *backend = (struct elastic_fts_backend *)_backend;
    pool_t pool;
    string_t *query;
    string_t *existing_guids;
    const char *username = "-";
    struct mailbox *box = NULL;
	const char *box_guid;
    uint32_t uid;
    struct fts_result *result;
    ARRAY_TYPE(seq_range) uids;
    ARRAY_TYPE(seq_range) expunged_uids;
    int ret = 0;

    /* ensure our backend has been initialised */
    if (_backend == NULL) {
        i_error("fts_elastic: critical error in rescan");
        return -1;
    }

    pool = pool_alloconly_create("elastic rescan", 32*1024);
    query = str_new(pool, 256);
    existing_guids = str_new(pool, 512);
    p_array_init(&uids, pool, 4*1024);
    p_array_init(&expunged_uids, pool, 512);
    result = p_new(pool, struct fts_result, 1);
    p_array_init(&result->definite_uids, pool, 8*1024);
    p_array_init(&result->maybe_uids, pool, 2);
    p_array_init(&result->scores, pool, 2);
    if (backend->backend.ns->owner) {
        username = backend->backend.ns->owner->username;
    }

	struct seq_range_iter iter;
	const struct mailbox_info *info;
    struct mailbox_status status;
	const enum mailbox_list_iter_flags iter_flags =
		(enum mailbox_list_iter_flags)
		(MAILBOX_LIST_ITER_NO_AUTO_BOXES |
		 MAILBOX_LIST_ITER_RETURN_NO_FLAGS);
	struct mailbox_list_iterate_context *list_iter =
            mailbox_list_iter_init(backend->backend.ns->list, "*", iter_flags);

    // go throught existing boxes
	while ((info = mailbox_list_iter_next(list_iter)) != NULL) {
        if (box != NULL)
            mailbox_free(&box);

        enum mail_error error;
        const char *errstr;
        box = mailbox_alloc(backend->backend.ns->list, info->vname, (enum mailbox_flags)0);
        if (mailbox_open(box) < 0) {
#if defined(DOVECOT_PREREQ) && DOVECOT_PREREQ(2,3,0)
    		errstr = mailbox_get_last_internal_error(box, &error);
#else
    		errstr = mailbox_get_last_error(box, &error);
#endif
            if (error == MAIL_ERROR_NOTFOUND)
                ret = 0;
            else {
                i_error("fts_elastic: Couldn't open mailbox %s: %s",
                    mailbox_get_vname(box), errstr);
                ret = -1;
            }
            continue;
        }
        if (mailbox_sync(box, (enum mailbox_sync_flags)0) < 0) {
#if defined(DOVECOT_PREREQ) && DOVECOT_PREREQ(2,3,0)
    		errstr = mailbox_get_last_internal_error(box, &error);
#else
    		errstr = mailbox_get_last_error(box, &error);
#endif
            i_error("fts_elastic: Failed to sync mailbox %s: %s",
                mailbox_get_vname(box), errstr);
            continue;
        }

        array_clear(&uids);

        if (mailbox_get_status(box, STATUS_MESSAGES, &status) < 0){
            i_error("fts_elastic: Failed to get status for mailbox %s",
                    mailbox_get_vname(box));
            continue;
        }

        if (status.messages > 0) T_BEGIN {
            ARRAY_TYPE(seq_range) seqs;
            t_array_init(&seqs, 2);
            seq_range_array_add_range(&seqs, 1, status.messages);
            mailbox_get_uid_range(box, &seqs, &uids);
        } T_END;

        /* get the mailbox guid */
        if (fts_mailbox_get_guid(box, &box_guid) < 0) {
            i_error("fts_elastic: Failed to get guid for mailbox %s",
                    mailbox_get_vname(box));
            continue;
        }
        str_printfa(existing_guids, "\"%s\",", box_guid);

        result->box = box;
    	array_clear(&result->definite_uids);

        /* build json query for user box */
        buffer_set_used_size(query, 0);
        str_printfa(query,
            "{"
                "\"query\":{"
                    "\"bool\":{"
                        "\"filter\":["
                            "{\"term\":{\"user\":\"%s\"}},"
                            "{\"term\":{\"box\":\"%s\"}}"
                        "]"
                    "}"
                "},"
                "\"_source\":false,"
                "\"size\":10000"
            "}\n",
            username, box_guid);

        // download all uids for all boxes from elastic
        // we need scroll request because we don't know in advance
        // how many messages are actually in elastic
        // the point of rescan is to remove expunges and fix elastic
        ret = elastic_connection_search_scroll(backend->conn, pool, query, result);
        if (ret < 0) {
            i_error("fts_elastic: Failed to search uids in elastic for mailbox %s",
                    mailbox_get_vname(box));
            continue;
        }
        array_clear(&expunged_uids);
        array_append_array(&expunged_uids, &result->definite_uids);

        /* find not existing uids (expunged) and delete them */
        seq_range_array_remove_seq_range(&expunged_uids, &uids);
        fts_backend_elastic_expunge_uids(_backend, box, expunged_uids);

        /* find missing and set last uid before first missing uid */
        seq_range_array_remove_seq_range(&uids, &result->definite_uids);
        seq_range_array_iter_init(&iter, &uids);
        if (seq_range_array_iter_nth(&iter, 0, &uid)) {
            fts_index_set_last_uid(box, uid-1);
        }
    }
	(void)mailbox_list_iter_deinit(&list_iter);
    if (box != NULL)
        mailbox_free(&box);

    /* DELETE all other non existing mailboxes user */
    if (str_len(existing_guids) > 0) {
        /* remove trailing ',' */
        str_delete(existing_guids, str_len(existing_guids) - 1, 1);
    }
    buffer_set_used_size(query, 0);
    str_printfa(query,
        "{"
            "\"query\":{"
                "\"bool\":{"
                    "\"filter\":{\"term\":{\"user\":\"%s\"}},"
                    "\"must_not\":{\"terms\":{\"box\":[%s]}}"
                "}"
            "}"
        "}\n", username, str_c(existing_guids));
    ret = elastic_connection_delete_by_query(backend->conn, pool, query);

    /* cleanup */
    pool_unref(&pool);
    str_free(&query);
    str_free(&existing_guids);
	array_free(&uids);
	array_free(&expunged_uids);

    if (ret < 0)
        return -1;
    FUNC_END();
    return ret;
}

static int fts_backend_elastic_optimize(struct fts_backend *backend ATTR_UNUSED)
{
    FUNC_START();
    return 0;
}

static bool
elastic_add_definite_query(string_t *_fields, string_t *_fields_not,
                           string_t *value, struct mail_search_arg *arg)
{
    FUNC_START();
    string_t *fields = NULL;

    /* validate our input */
    if (_fields == NULL || _fields_not == NULL || value == NULL || arg == NULL) {
        i_error("fts_elastic: critical error while building query");
        return FALSE;
    }

    if (arg->match_not) {
        fields = _fields_not;
        i_info("fts_elastic: arg->match_not is true");
    } else {
        fields = _fields;
    }

    switch (arg->type) {
    case SEARCH_TEXT:
        /* we don't actually have to do anything here; leaving the fields
         * array blank is sufficient to cause full text search with ES */

        break;
    case SEARCH_BODY:
        /* SEARCH_BODY has a hdr_field_name of null. we append a comma here 
         * because body can be selected in addition to other fields. it's 
         * trimmed later before being passed to ES if it's the last element. */
        str_append(fields, "\"body\",");

        break;
    case SEARCH_HEADER: /* fall through */
    case SEARCH_HEADER_ADDRESS: /* fall through */
    case SEARCH_HEADER_COMPRESS_LWSP:
        if (!fts_header_want_indexed(arg->hdr_field_name)) {
            i_debug("fts_elastic: field %s was skipped", arg->hdr_field_name);
            return FALSE;
        }
        str_printfa(fields, "\"%s\",", elastic_field_prepare(arg->hdr_field_name));

        break;
    default:
        return FALSE;
    }

    FUNC_END();
    return TRUE;
}

static bool
elastic_add_definite_query_args(string_t *fields, string_t *fields_not,
                                string_t *value, struct mail_search_arg *arg)
{
    FUNC_START();
    bool field_added = FALSE;

    if (fields == NULL || value == NULL || arg == NULL) {
        i_error("fts_elastic: critical error while building query");

        return FALSE;
    }

    for (; arg != NULL; arg = arg->next) {
        /* multiple fields have an initial arg of nothing useful and subargs */
        if (arg->value.subargs != NULL) {
            field_added = elastic_add_definite_query_args(fields, fields_not, value,
                arg->value.subargs);
        }

        if (elastic_add_definite_query(fields, fields_not, value, arg)) {
            /* the value is the same for every arg passed, only add the value
             * to our search json once. */
            if (!field_added) {
                /* we always want to add the value */
                str_append_json_escaped(value,
                        arg->value.str, strlen(arg->value.str));
            }

            /* this is important to set. if this is FALSE, Dovecot will fail
             * over to its regular built-in search to produce results for
             * this argument. */
            arg->match_always = TRUE;
            field_added = TRUE;
        }
    }

    FUNC_END();
    return field_added;
}

static int
fts_backend_elastic_lookup(struct fts_backend *_backend, struct mailbox *box,
                           struct mail_search_arg *args,
                           enum fts_lookup_flags flags,
                           struct fts_result *result_r)
{
    FUNC_START();
    static const char JSON_MULTI_MATCH[] = 
        "{\"multi_match\":{"
            "\"query\":\"%s\","
            "\"operator\":\"%s\","
            "\"fields\":[%s]"
        "}}";

    struct elastic_fts_backend *backend = (struct elastic_fts_backend *)_backend;
    const char *operator_arg = (flags & FTS_LOOKUP_FLAG_AND_ARGS) ? "and" : "or";
	struct mailbox_status status;
    const char *box_guid = NULL;

    /* temp variables */
    pool_t pool = pool_alloconly_create("fts elastic search", 8*1024);
    int32_t ret = -1;
    /* json query building */
    string_t *query = str_new(pool, 1024);
    string_t *match_query = str_new(pool, 1024);
    string_t *fields = str_new(pool, 1024);
    string_t *fields_not = str_new(pool, 1024);

    /* validate our input */
    if (_backend == NULL || box == NULL || args == NULL || result_r == NULL) {
        i_error("fts_elastic: critical error during lookup");
        return -1;
    }

    /* get the mailbox guid */
    if (fts_mailbox_get_guid(box, &box_guid) < 0){
        FUNC_END_RET_INT(-1);
        return -1;
    }
    mailbox_get_open_status(box, STATUS_MESSAGES, &status);

    /* attempt to build the match_query */
    if (!elastic_add_definite_query_args(fields, fields_not, match_query, args)) {
        FUNC_END_RET_INT(-1);
        return -1;
    }

    /* remove the trailing ',' */
    str_delete(fields, str_len(fields) - 1, 1);
    str_delete(fields_not, str_len(fields_not) - 1, 1);

    /* if no fields were added, add some sensible default fields */
    if (str_len(fields) == 0 && str_len(fields_not) == 0) {
        str_append(fields, "\"from\",\"to\",\"cc\",\"bcc\",\"sender\",\"subject\",\"body\"");
    }

    /* generate json search query */
    str_append(query, "{\"query\":{\"bool\":{\"filter\":[");
    str_printfa(query, "{\"term\":{\"user\":\"%s\"}},"
                     "{\"term\":{\"box\": \"%s\"}}]",
                        _backend->ns->owner != NULL ? _backend->ns->owner->username : "",
                        box_guid);

    if (str_len(fields) > 0) {
        str_append(query, ",\"must\":[");
        str_printfa(query, JSON_MULTI_MATCH, str_c(match_query),
                               operator_arg, str_c(fields));
        str_append(query, "]");
    }

    if (str_len(fields_not) > 0) {
        str_append(query, ",\"must_not\":[");
        str_printfa(query, JSON_MULTI_MATCH, str_c(match_query),
                               operator_arg, str_c(fields_not));
        str_append(query, "]");
    }

    /* default ES is limited to 10,000 results */
    str_append(query, "}}, \"size\":10000, \"_source\":false}\n");

    /* build our fts_result return */
    result_r->box = box;
    result_r->scores_sorted = FALSE;

    if (status.messages > 10000) {
        ret = elastic_connection_search_scroll(backend->conn, pool, query, result_r);
    } else {
        ret = elastic_connection_search(backend->conn, pool, query, result_r);
    }

    /* FTS_LOOKUP_FLAG_NO_AUTO_FUZZY says that exact matches for non-fuzzy searches
     * should go to maybe_uids instead of definite_uids. */
    ARRAY_TYPE(seq_range) uids_tmp;
    if ((flags & FTS_LOOKUP_FLAG_NO_AUTO_FUZZY) != 0) {
        uids_tmp = result_r->definite_uids;
        result_r->definite_uids = result_r->maybe_uids;
        result_r->maybe_uids = uids_tmp;
    }

    /* clean-up */
    pool_unref(&pool);
    FUNC_END_RET_INT(ret);
    return ret;
}

struct fts_backend fts_backend_elastic = {
    .name = "elastic",
    .flags = FTS_BACKEND_FLAG_FUZZY_SEARCH,

    {
        fts_backend_elastic_alloc,
        fts_backend_elastic_init,
        fts_backend_elastic_deinit,
        fts_backend_elastic_get_last_uid,
        fts_backend_elastic_update_init,
        fts_backend_elastic_update_deinit,
        fts_backend_elastic_update_set_mailbox,
        fts_backend_elastic_update_expunge,
        fts_backend_elastic_update_set_build_key,
        fts_backend_elastic_update_unset_build_key,
        fts_backend_elastic_update_build_more,
        fts_backend_elastic_refresh,
        fts_backend_elastic_rescan,
        fts_backend_elastic_optimize,
        fts_backend_default_can_lookup,
        fts_backend_elastic_lookup,
        NULL,
        NULL
    }
};
