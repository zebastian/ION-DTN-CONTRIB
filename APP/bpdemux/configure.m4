# -*- Autoconf -*- bpdemux app configure fragment (m4_include'd by ./configure.ac).

AC_ARG_ENABLE([app-bpdemux],
  [AS_HELP_STRING([--enable-app-bpdemux],
     [build the bpdemux data-label demux (APP/bpdemux)])],
  [enable_app_bpdemux=$enableval], [enable_app_bpdemux=])
test -z "$enable_app_bpdemux" && enable_app_bpdemux=$contrib_default

# bpdemuxd reads and rewrites ION's Bundle record, so it needs a release
# whose bpP.h copy is exact: 4.1.4 or later, the first to install ion.pc;
# elsewhere it is left out of --enable-all.
AS_IF([test "x$enable_app_bpdemux" = xyes],
  [bpdemux_ion_ok=no
   AS_IF([test -r "${ion_prefix}/lib/pkgconfig/ion.pc"],
     [AS_VERSION_COMPARE([$ion_version], [4.1.4], [], [bpdemux_ion_ok=yes],
        [bpdemux_ion_ok=yes])])
   AS_IF([test "x$bpdemux_ion_ok" = xno],
     [AS_IF([test "x$enable_all" = xyes],
        [AC_MSG_WARN([ION $ion_version is older than 4.1.4; not building APP/bpdemux])
         enable_app_bpdemux=no],
        [AC_MSG_ERROR([APP/bpdemux needs ION 4.1.4 or later (found $ion_version).])])])])

AS_IF([test "x$enable_app_bpdemux" = xyes], [contrib_selected=yes])

AM_CONDITIONAL([ENABLE_APP_BPDEMUX],
  [test "x$enable_app_bpdemux" = xyes])
AC_CONFIG_FILES([APP/bpdemux/Makefile])
contrib_status="$contrib_status
    APP/bpdemux ..... $enable_app_bpdemux"
