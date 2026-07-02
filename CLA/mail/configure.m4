# -*- Autoconf -*- Mail CLA configure fragment (m4_include'd by ./configure.ac).

AC_ARG_ENABLE([cla-mail],
  [AS_HELP_STRING([--enable-cla-mail], [build the mail SMTP/POP3 CLA (CLA/mail)])],
  [enable_cla_mail=$enableval], [enable_cla_mail=])
test -z "$enable_cla_mail" && enable_cla_mail=$contrib_default

AS_IF([test "x$enable_cla_mail" = xyes], [
  contrib_selected=yes
  AC_CHECK_PROG([PKG_CONFIG], [pkg-config], [pkg-config], [no])
  AS_IF([test "x$PKG_CONFIG" = xno],
    [AC_MSG_ERROR([pkg-config not found; needed to locate libcurl.])])
  AS_IF([$PKG_CONFIG --exists libcurl], [],
    [AC_MSG_ERROR([libcurl not found. Install libcurl4-openssl-dev, or pass --disable-cla-mail.])])
  CURL_CFLAGS=`$PKG_CONFIG --cflags libcurl`
  CURL_LIBS=`$PKG_CONFIG --libs libcurl`
])
AC_SUBST([CURL_CFLAGS])
AC_SUBST([CURL_LIBS])

AM_CONDITIONAL([ENABLE_CLA_MAIL], [test "x$enable_cla_mail" = xyes])
AC_CONFIG_FILES([CLA/mail/Makefile])
contrib_status="$contrib_status
    CLA/mail ........ $enable_cla_mail"
