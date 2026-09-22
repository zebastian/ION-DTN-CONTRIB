# -*- Autoconf -*- bptun app configure fragment (m4_include'd by ./configure.ac).

AC_ARG_ENABLE([app-bptun],
  [AS_HELP_STRING([--enable-app-bptun], [build the bptun app (APP/bptun)])],
  [enable_app_bptun=$enableval], [enable_app_bptun=])
test -z "$enable_app_bptun" && enable_app_bptun=$contrib_default

# TUN/TAP is Linux's; elsewhere the app is left out even under --enable-all.
AS_IF([test "x$enable_app_bptun" = xyes],
  [AC_CHECK_HEADER([linux/if_tun.h], [],
     [AS_IF([test "x$enable_all" = xyes],
        [AC_MSG_WARN([no linux/if_tun.h; not building APP/bptun])
         enable_app_bptun=no],
        [AC_MSG_ERROR([APP/bptun needs linux/if_tun.h (Linux TUN/TAP)])])])])

AS_IF([test "x$enable_app_bptun" = xyes], [contrib_selected=yes])

AM_CONDITIONAL([ENABLE_APP_BPTUN], [test "x$enable_app_bptun" = xyes])
AC_CONFIG_FILES([APP/bptun/Makefile])
contrib_status="$contrib_status
    APP/bptun ....... $enable_app_bptun"
