# -*- Autoconf -*- QUIC CLA configure fragment (m4_include'd by ./configure.ac).

AC_ARG_ENABLE([cla-quic],
  [AS_HELP_STRING([--enable-cla-quic], [build the QUIC CLA (CLA/quic)])],
  [enable_cla_quic=$enableval], [enable_cla_quic=])
test -z "$enable_cla_quic" && enable_cla_quic=$contrib_default

AS_IF([test "x$enable_cla_quic" = xyes], [
  contrib_selected=yes
  AC_CHECK_PROG([PKG_CONFIG], [pkg-config], [pkg-config], [no])
  AS_IF([test "x$PKG_CONFIG" = xno],
    [AC_MSG_ERROR([pkg-config not found; needed to locate ngtcp2/gnutls.])])
  quic_mods="libngtcp2 libngtcp2_crypto_gnutls gnutls"
  AS_IF([$PKG_CONFIG --exists "$quic_mods"], [],
    [AC_MSG_ERROR([ngtcp2 + GnuTLS not found. Install libngtcp2-dev libngtcp2-crypto-gnutls-dev libgnutls28-dev, or pass --disable-cla-quic.])])
  QUIC_CFLAGS=`$PKG_CONFIG --cflags $quic_mods`
  QUIC_LIBS=`$PKG_CONFIG --libs $quic_mods`
])
AC_SUBST([QUIC_CFLAGS])
AC_SUBST([QUIC_LIBS])

AM_CONDITIONAL([ENABLE_CLA_QUIC], [test "x$enable_cla_quic" = xyes])
AC_CONFIG_FILES([CLA/quic/Makefile])
contrib_status="$contrib_status
    CLA/quic ........ $enable_cla_quic"
