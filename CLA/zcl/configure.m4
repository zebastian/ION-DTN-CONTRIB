# -*- Autoconf -*- zcl CLA configure fragment (m4_include'd by ./configure.ac).

AC_ARG_ENABLE([cla-zcl],
  [AS_HELP_STRING([--enable-cla-zcl], [build the zstd compressing tunnel CLA (CLA/zcl)])],
  [enable_cla_zcl=$enableval], [enable_cla_zcl=])
test -z "$enable_cla_zcl" && enable_cla_zcl=$contrib_default

AS_IF([test "x$enable_cla_zcl" = xyes], [
  contrib_selected=yes
  AC_CHECK_PROG([PKG_CONFIG], [pkg-config], [pkg-config], [no])
  AS_IF([test "x$PKG_CONFIG" != xno && $PKG_CONFIG --exists 'libzstd >= 1.4.0'],
    [ZSTD_CFLAGS=`$PKG_CONFIG --cflags libzstd`
     ZSTD_LIBS=`$PKG_CONFIG --libs libzstd`],
    [AC_CHECK_HEADER([zstd.h], [],
       [AC_MSG_ERROR([libzstd (>= 1.4.0) not found. Install libzstd-dev, or pass --disable-cla-zcl.])])
     AC_CHECK_LIB([zstd], [ZSTD_compressStream2], [ZSTD_LIBS=-lzstd],
       [AC_MSG_ERROR([libzstd lacks ZSTD_compressStream2 (needs >= 1.4.0). Install libzstd-dev, or pass --disable-cla-zcl.])])
     ZSTD_CFLAGS=])
])
AC_SUBST([ZSTD_CFLAGS])
AC_SUBST([ZSTD_LIBS])

AM_CONDITIONAL([ENABLE_CLA_ZCL], [test "x$enable_cla_zcl" = xyes])
AC_CONFIG_FILES([CLA/zcl/Makefile])
contrib_status="$contrib_status
    CLA/zcl ......... $enable_cla_zcl"
