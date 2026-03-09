/* Copyright (c) 2026 Filip Hanes <filip.hanes@gmail.com> */

#include "lib.h"
#include "settings.h"
#include "settings-parser.h"
#include "fts-elastic-settings.h"
#undef DEF
#define DEF(type, name) SETTING_DEFINE_STRUCT_##type(\
      FTS_ELASTIC_FILTER"_"#name, name, struct fts_elastic_settings)

static const struct setting_define fts_elastic_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = FTS_ELASTIC_FILTER },
    DEF(STR, url),
    DEF(BOOL, debug),
    DEF(UINT, bulk_size),
    DEF(BOOL, refresh_by_fts),
    DEF(BOOL, refresh_on_update),
    SETTING_DEFINE_LIST_END
};

static const struct fts_elastic_settings fts_elastic_default_settings = {
    .url = "",
    .debug = FALSE,
    .bulk_size = 5*1024*1024,
    .refresh_by_fts = TRUE,
    .refresh_on_update = FALSE,
};

static const struct setting_keyvalue fts_elastic_default_settings_keyvalue[] = {
	{ FTS_ELASTIC_FILTER"/http_client_max_idle_time", "5s" },
	{ FTS_ELASTIC_FILTER"/http_client_max_parallel_connections", "1" },
	{ FTS_ELASTIC_FILTER"/http_client_max_pipelined_requests", "1" },
	{ FTS_ELASTIC_FILTER"/http_client_request_max_redirects", "1" },
	{ FTS_ELASTIC_FILTER"/http_client_request_max_attempts", "3" },
	{ FTS_ELASTIC_FILTER"/http_client_connect_timeout", "5s" },
	{ FTS_ELASTIC_FILTER"/http_client_request_timeout", "60s" },
	{ NULL, NULL }
};

const struct setting_parser_info fts_elastic_setting_parser_info = {
	.name = FTS_ELASTIC_FILTER,
	.plugin_dependency = "lib21_fts_elastic_plugin",

    .defines = fts_elastic_setting_defines,
    .defaults = &fts_elastic_default_settings,
	.default_settings = fts_elastic_default_settings_keyvalue,

    .struct_size = sizeof(struct fts_elastic_settings),
    .pool_offset1 = 1 + offsetof(struct fts_elastic_settings, pool),
};

int fts_elastic_settings_get(struct event *event,
			  const struct setting_parser_info *info,
			  const struct fts_elastic_settings **set_r,
			  const char **error_r)
{
	if (settings_get(event, info, 0, set_r, error_r) < 0)
		return -1;

	const char *url = (*set_r)->url;
	if (*url == '\0') {
		*error_r = "fts_elastic_url is required";
		settings_free(*set_r);
		return -1;
	}

	return 0;
}
