# -*- Autoconf -*- bpsh app configure fragment (m4_include'd by ./configure.ac).

AC_ARG_ENABLE([app-bpsh],
  [AS_HELP_STRING([--enable-app-bpsh], [build the bpsh app (APP/bpsh)])],
  [enable_app_bpsh=$enableval], [enable_app_bpsh=])
test -z "$enable_app_bpsh" && enable_app_bpsh=$contrib_default

AS_IF([test "x$enable_app_bpsh" = xyes], [contrib_selected=yes])

AM_CONDITIONAL([ENABLE_APP_BPSH], [test "x$enable_app_bpsh" = xyes])
AC_CONFIG_FILES([APP/bpsh/Makefile])
contrib_status="$contrib_status
    APP/bpsh ........ $enable_app_bpsh"
