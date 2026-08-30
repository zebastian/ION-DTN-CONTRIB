# -*- Autoconf -*- TCPCLv4 CLA configure fragment (m4_include'd by ./configure.ac).

AC_ARG_ENABLE([cla-tcpv4],
  [AS_HELP_STRING([--enable-cla-tcpv4], [build the TCPCLv4 CLA (CLA/tcpv4)])],
  [enable_cla_tcpv4=$enableval], [enable_cla_tcpv4=])
test -z "$enable_cla_tcpv4" && enable_cla_tcpv4=$contrib_default

AS_IF([test "x$enable_cla_tcpv4" = xyes], [
  contrib_selected=yes
  AC_CHECK_PROG([PKG_CONFIG], [pkg-config], [pkg-config], [no])
  AS_IF([test "x$PKG_CONFIG" = xno],
    [AC_MSG_ERROR([pkg-config not found; needed to locate gnutls.])])
  AS_IF([$PKG_CONFIG --atleast-version=3.6.5 gnutls], [],
    [AC_MSG_ERROR([GnuTLS >= 3.6.5 (TLS 1.3) not found. Install libgnutls28-dev, or pass --disable-cla-tcpv4.])])
  TCPV4_CFLAGS=`$PKG_CONFIG --cflags gnutls`
  TCPV4_LIBS=`$PKG_CONFIG --libs gnutls`
])
AC_SUBST([TCPV4_CFLAGS])
AC_SUBST([TCPV4_LIBS])

AM_CONDITIONAL([ENABLE_CLA_TCPV4], [test "x$enable_cla_tcpv4" = xyes])
AC_CONFIG_FILES([CLA/tcpv4/Makefile])
contrib_status="$contrib_status
    CLA/tcpv4 ....... $enable_cla_tcpv4"
