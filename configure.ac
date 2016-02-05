AC_INIT([mod_psm], [1.0.0], [rme@escaux.com])
AC_PREREQ([2.68])

AC_CONFIG_SRCDIR([src/mod_psm.c])
AC_CONFIG_HEADERS([src/config.h])

AM_INIT_AUTOMAKE([subdir-objects no-define])

m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
LT_INIT

AC_CONFIG_MACRO_DIR([m4])

# Configuration files
AC_CONFIG_FILES([Makefile
                 src/Makefile])

# Arguments
AC_ARG_WITH([apxs], [AS_HELP_STRING([--with-apxs],
    [Use APXS executable [default=check]])],
    [request_apxs=$withval], [request_apxs=check])
# Check programs
AC_PROG_CC
AC_PROG_LIBTOOL

# extern, we need to find where the apxs is. which then
# can tell us the various directories we need.
#
if test x"$request_apxs" = "xcheck"; then
    AC_PATH_PROG([APXS], [apxs])
    if test "x${APXS}" = "x"; then
        AC_MSG_ERROR([no APXS installation found])
    fi
else
    APXS="$request_apxs"
    AC_MSG_NOTICE("using APXS=$APXS as configured")
fi

LDFLAGS="$LDFLAGS -L$($APXS -q libdir)"
CPPFLAGS="$CPPFLAGS -I$($APXS -q includedir) -I$($APXS -q APR_INCLUDEDIR)"
export SYSCONF_DIR="$($APXS -q sysconfdir)"
export LIBEXEC_DIR="$($APXS -q LIBEXECDIR)"

# Check for libraries
AC_CHECK_LIB(jansson, json_loadb,,
    AC_MSG_ERROR([please install Jansson library]))

AC_CHECK_LIB(hiredis, redisReconnect,,
    AC_MSG_ERROR([please install Hiredis library]))

# Checks for header files.
AC_CHECK_HEADERS([ \
])

# substitution in generated files
AC_SUBST(SYSCONF_DIR)
AC_SUBST(LIBEXEC_DIR)

AC_OUTPUT

AC_MSG_NOTICE([summary of build options:

    Version:        ${VERSION}
    Host type:      ${host}
    APXS:           ${APXS}
    C compiler:     ${CC}
    CFLAGS:         ${CFLAGS}
    WARNCFLAGS:     ${WARNCFLAGS}
    LDFLAGS:        ${LDFLAGS}
    LIBS:           ${LIBS}
    CPPFLAGS:       ${CPPFLAGS}
    a2enmod         ${A2ENMOD:--}
])
