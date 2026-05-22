/* Copyright (c) 2026 Filip Hanes <filip.hanes@gmail.com> */

#include "lib.h"
#include "settings-parser.h"
#include "fts-elastic-settings.h"

const struct setting_parser_info *fts_elastic_settings_set_infos[] = {
	&fts_elastic_setting_parser_info,
	NULL
};

const char *fts_elastic_settings_version = DOVECOT_ABI_VERSION;
