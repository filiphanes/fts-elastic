AM_CFLAGS= \
    $(CPPFLAGS) \
    -I$(abs_dovecotdir)/src/plugins/fts \
    $(LIBDOVECOT_INCLUDE)


lib21_fts_elastic_plugin_la_LDFLAGS = -module -avoid-version

lib21_fts_elastic_plugin_ladir = $(dovecot_pkglibdir)
lib21_fts_elastic_plugin_la_LTLIBRARIES = lib21_fts_elastic_plugin.la
lib21_fts_elastic_plugin_la_SOURCES = fts-elastic-plugin.c fts-backend-elastic.c elastic-connection.c fts-elastic-settings.c

# Settings module for doveconf config validation
libfts_elastic_settings_la_LDFLAGS = -module -avoid-version
libfts_elastic_settings_ladir = $(dovecot_pkglibdir)/settings
libfts_elastic_settings_la_LTLIBRARIES = libfts_elastic_settings.la
libfts_elastic_settings_la_SOURCES = fts-elastic-settings-module.c fts-elastic-settings.c
