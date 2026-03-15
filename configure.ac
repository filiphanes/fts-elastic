#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.53])
AC_INIT([fts-elastic], [2.0.0], [https://github.com/filiphanes/fts-elastic])
AM_INIT_AUTOMAKE([no-define foreign tar-ustar])
AC_OUTPUT(Makefile src/Makefile)
AC_CONFIG_SRCDIR([src])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([dummy-config.h])
AM_MAINTAINER_MODE

# Don't clobber Dovecot package versions
AC_DEFINE_UNQUOTED(fts_elastic_NAME, "$PACKAGE_NAME",
        [Define to the full name of fts-elastic for Dovecot.])
AC_DEFINE_UNQUOTED(fts_elastic_VERSION, "$PACKAGE_VERSION",
        [Define to the version of fts-elastic for Dovecot.])

# Couple with Dovecot
#

DC_DOVECOT
AS_VERSION_COMPARE([2.4.0], [$DOVECOT_VERSION], [], [],
    [AC_MSG_ERROR([Dovecot >= 2.4.0 is required (found $DOVECOT_VERSION). Use fts-elastic 0.x for Dovecot 2.3.])])
DC_DOVECOT_MODULEDIR
LIBDOVECOT_INCLUDE="$LIBDOVECOT_INCLUDE $LIBDOVECOT_STORAGE_INCLUDE"
CFLAGS="$DOVECOT_CFLAGS -I\$(top_srcdir)"
LIBS="$DOVECOT_LIBS"
AC_SUBST(LIBDOVECOT_INCLUDE)
# Allow shared objects
LT_INIT
AC_ENABLE_SHARED
AC_DISABLE_STATIC

# Checks for programs.
AC_PROG_CC

# Check for json-c headers and library (handle Homebrew on macOS)
JSON_CFLAGS=""
JSON_LDFLAGS=""
AC_MSG_CHECKING([for json-c/json.h])
for dir in /opt/homebrew/include /usr/local/include /usr/include /include; do
    if test -f "$dir/json-c/json.h"; then
        JSON_CFLAGS="-I$dir"
        # Also check for corresponding lib directory
        libdir=$(echo "$dir" | sed 's/include/lib/')
        if test -d "$libdir" -o -d "/opt/homebrew/opt/json-c/lib"; then
            JSON_LDFLAGS="-L/opt/homebrew/opt/json-c/lib"
        fi
        break
    fi
done
if test -n "$JSON_CFLAGS"; then
    AC_MSG_RESULT([found in $JSON_CFLAGS])
    CPPFLAGS="$CPPFLAGS $JSON_CFLAGS"
    LDFLAGS="$LDFLAGS $JSON_LDFLAGS"
else
    AC_MSG_ERROR([json-c/json.h not found. Install json-c or set CPPFLAGS])
fi

# Checks for libraries.
AC_SEARCH_LIBS([json_object_from_file], [json json-c], [], [ AC_MSG_ERROR([no json-c available]) ])
AC_SEARCH_LIBS([json_object_object_get_ex], [json json-c], [ AC_DEFINE([JSON_HAS_GET_EX], [1], [Define if we have json_object_object_get_ex])], [])

# Checks for header files.
AC_CHECK_HEADERS([inttypes.h stdlib.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_CHECK_FUNCS([memset])

AC_OUTPUT

echo
echo "Install prefix       : $prefix"
echo "Lib install prefix   : $dovecot_pkglibdir"
