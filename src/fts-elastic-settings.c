#ifdef FTS_DOVECOT24

#include "lib.h"
#include "settings.h"
#include "settings-parser.h"
#include "fts-elastic-plugin.h"
#undef DEF
#define DEF(type, name) \
  SETTING_DEFINE_STRUCT_##type(FTS_ELASTIC_LABEL"_"#name, name, \
                              struct fts_elastic_settings)

static const struct setting_define fts_elastic_setting_defines[] = {
    DEF(STR, url),
    DEF(BOOL, debug),
    DEF(STR, rawlog_dir),
    DEF(UINT, bulk_size),
    DEF(BOOL, refresh_by_fts),
    DEF(BOOL, refresh_on_update),
    SETTING_DEFINE_LIST_END
};

static const struct fts_elastic_settings fts_elastic_default_settings = {
    .url = "",
    .debug = FALSE,
    .rawlog_dir = "",
    .bulk_size = 5*1024*1024,
    .refresh_by_fts = TRUE,
    .refresh_on_update = FALSE,
};

const struct setting_parser_info fts_elastic_setting_parser_info = {
    .name = FTS_ELASTIC_LABEL,
    .defines = fts_elastic_setting_defines,
    .defaults = &fts_elastic_default_settings,
    .struct_size = sizeof(struct fts_elastic_settings),
    .pool_offset1 = 1 + offsetof(struct fts_elastic_settings, pool),
};

const char *fts_elastic_settings_version = DOVECOT_ABI_VERSION;

const struct setting_parser_info *fts_elastic_settings_set_infos[] = {
    &fts_elastic_setting_parser_info,
    NULL
};

#endif
