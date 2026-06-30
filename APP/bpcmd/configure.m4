# -*- Autoconf -*- bpcmd app configure fragment (m4_include'd by ./configure.ac).

AC_ARG_ENABLE([app-bpcmd],
  [AS_HELP_STRING([--enable-app-bpcmd], [build the bpcmd app (APP/bpcmd)])],
  [enable_app_bpcmd=$enableval], [enable_app_bpcmd=])
test -z "$enable_app_bpcmd" && enable_app_bpcmd=$contrib_default

AS_IF([test "x$enable_app_bpcmd" = xyes], [contrib_selected=yes])

AM_CONDITIONAL([ENABLE_APP_BPCMD], [test "x$enable_app_bpcmd" = xyes])
AC_CONFIG_FILES([APP/bpcmd/Makefile])
contrib_status="$contrib_status
    APP/bpcmd ....... $enable_app_bpcmd"
