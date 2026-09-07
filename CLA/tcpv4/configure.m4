# -*- Autoconf -*- TCPCLv4 CLA configure fragment (m4_include'd by ./configure.ac).

AC_ARG_ENABLE([cla-tcpv4],
  [AS_HELP_STRING([--enable-cla-tcpv4], [build the TCPCLv4 CLA (CLA/tcpv4)])],
  [enable_cla_tcpv4=$enableval], [enable_cla_tcpv4=])
test -z "$enable_cla_tcpv4" && enable_cla_tcpv4=$contrib_default

# RFC 9174 4.4.3 mandates TLS 1.3; which library provides it is the CLA's
# own business, since all of its use of one is confined behind
# CLA/tcpv4/src/tcpv4tls.h and implemented in one tcpv4tls_<backend>.c.
AC_ARG_WITH([tcpv4-tls],
  [AS_HELP_STRING([--with-tcpv4-tls=BACKEND],
    [TLS backend for the TCPCLv4 CLA: gnutls, mbedtls, or auto (default:
     auto, which prefers gnutls)])],
  [tcpv4_tls=$withval], [tcpv4_tls=auto])

AC_ARG_VAR([MBEDTLS_CFLAGS], [C compiler flags for Mbed TLS])
AC_ARG_VAR([MBEDTLS_LIBS], [linker flags for Mbed TLS])

tcpv4_tls_found=
tcpv4_tls_note=

AS_IF([test "x$enable_cla_tcpv4" = xyes], [
  contrib_selected=yes
  AS_CASE([$tcpv4_tls], [gnutls|mbedtls|auto], [],
    [AC_MSG_ERROR([--with-tcpv4-tls: unknown backend "$tcpv4_tls"; use gnutls, mbedtls or auto.])])
  AC_CHECK_PROG([PKG_CONFIG], [pkg-config], [pkg-config], [no])

  # GnuTLS speaks TLS 1.3 from 3.6.5 on.
  AS_IF([test "x$tcpv4_tls" = xgnutls || test "x$tcpv4_tls" = xauto], [
    AC_MSG_CHECKING([for GnuTLS >= 3.6.5 (TLS 1.3)])
    AS_IF([test "x$PKG_CONFIG" != xno && $PKG_CONFIG --atleast-version=3.6.5 gnutls],
      [AC_MSG_RESULT([yes])
       TCPV4_CFLAGS=`$PKG_CONFIG --cflags gnutls`
       TCPV4_LIBS=`$PKG_CONFIG --libs gnutls`
       tcpv4_tls_found=gnutls],
      [AC_MSG_RESULT([no])
       AS_IF([test "x$tcpv4_tls" = xgnutls],
         [AC_MSG_ERROR([GnuTLS >= 3.6.5 (TLS 1.3) not found. Install libgnutls28-dev, build against Mbed TLS with --with-tcpv4-tls=mbedtls, or pass --disable-cla-tcpv4.])])])
  ])

  # Mbed TLS speaks TLS 1.3 from 3.6 on, and only when the build was
  # configured for it; its pkg-config data says neither, so the headers are
  # asked directly.  The CLA shares one TLS configuration between the
  # handshakes of concurrent sessions, so the threading layer has to be in
  # the build as well - as it is in the usual distribution packages.
  AS_IF([test "x$tcpv4_tls_found" = x], [
   AS_IF([test "x$tcpv4_tls" = xmbedtls || test "x$tcpv4_tls" = xauto], [
    AS_IF([test "x$MBEDTLS_LIBS" != x || test "x$MBEDTLS_CFLAGS" != x],
      [tcpv4_mbedtls_cflags="$MBEDTLS_CFLAGS"
       tcpv4_mbedtls_libs="$MBEDTLS_LIBS"],
      [AS_IF([test "x$PKG_CONFIG" != xno && $PKG_CONFIG --exists mbedtls],
        [tcpv4_mbedtls_cflags=`$PKG_CONFIG --cflags mbedtls mbedx509 mbedcrypto`
         tcpv4_mbedtls_libs=`$PKG_CONFIG --libs mbedtls mbedx509 mbedcrypto`],
        [tcpv4_mbedtls_cflags=
         tcpv4_mbedtls_libs="-lmbedtls -lmbedx509 -lmbedcrypto"])])
    AC_MSG_CHECKING([for Mbed TLS >= 3.6 with TLS 1.3 and threading])
    tcpv4_save_CPPFLAGS="$CPPFLAGS"
    tcpv4_save_LIBS="$LIBS"
    CPPFLAGS="$CPPFLAGS $tcpv4_mbedtls_cflags"
    LIBS="$tcpv4_mbedtls_libs $LIBS"
    AC_LINK_IFELSE(
      [AC_LANG_PROGRAM([[#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#if MBEDTLS_VERSION_NUMBER < 0x03060000
#error "Mbed TLS is older than 3.6"
#endif
#ifndef MBEDTLS_SSL_PROTO_TLS1_3
#error "Mbed TLS was built without TLS 1.3"
#endif
#ifndef MBEDTLS_THREADING_C
#error "Mbed TLS was built without the threading layer"
#endif
]], [[mbedtls_ssl_context ssl;
      mbedtls_ssl_init(&ssl);
      mbedtls_ssl_free(&ssl);]])],
      [AC_MSG_RESULT([yes])
       TCPV4_CFLAGS="$tcpv4_mbedtls_cflags"
       TCPV4_LIBS="$tcpv4_mbedtls_libs"
       tcpv4_tls_found=mbedtls],
      [AC_MSG_RESULT([no])])
    CPPFLAGS="$tcpv4_save_CPPFLAGS"
    LIBS="$tcpv4_save_LIBS"
    AS_IF([test "x$tcpv4_tls_found" = x && test "x$tcpv4_tls" = xmbedtls],
      [AC_MSG_ERROR([Mbed TLS >= 3.6, built with MBEDTLS_SSL_PROTO_TLS1_3 and MBEDTLS_THREADING_C, not found. Point at one with MBEDTLS_CFLAGS/MBEDTLS_LIBS or PKG_CONFIG_PATH, build against GnuTLS with --with-tcpv4-tls=gnutls, or pass --disable-cla-tcpv4.])])
   ])
  ])

  AS_IF([test "x$tcpv4_tls_found" = x],
    [AC_MSG_ERROR([No TLS 1.3 library found for the TCPCLv4 CLA (RFC 9174 4.4.3 requires one). Install libgnutls28-dev or Mbed TLS >= 3.6, or pass --disable-cla-tcpv4.])])
  tcpv4_tls_note=" (TLS: $tcpv4_tls_found)"
])
AC_SUBST([TCPV4_CFLAGS])
AC_SUBST([TCPV4_LIBS])

AM_CONDITIONAL([ENABLE_CLA_TCPV4], [test "x$enable_cla_tcpv4" = xyes])
AM_CONDITIONAL([TCPV4_TLS_MBEDTLS], [test "x$tcpv4_tls_found" = xmbedtls])
AC_CONFIG_FILES([CLA/tcpv4/Makefile])
contrib_status="$contrib_status
    CLA/tcpv4 ....... $enable_cla_tcpv4$tcpv4_tls_note"
