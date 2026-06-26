# -*- Autoconf -*- MySQL CLA configure fragment (m4_include'd by ./configure.ac).

AC_ARG_ENABLE([cla-mysql],
  [AS_HELP_STRING([--enable-cla-mysql], [build the MySQL CLA (CLA/mysql)])],
  [enable_cla_mysql=$enableval], [enable_cla_mysql=])
test -z "$enable_cla_mysql" && enable_cla_mysql=$contrib_default

AS_IF([test "x$enable_cla_mysql" = xyes], [
  contrib_selected=yes
  AC_CHECK_PROGS([MYSQL_CONFIG], [mariadb_config mysql_config], [no])
  AS_IF([test "x$MYSQL_CONFIG" = xno],
    [AC_MSG_ERROR([Neither mariadb_config nor mysql_config found. Install libmariadb-dev (or libmysqlclient-dev), or pass --disable-cla-mysql.])])
  MYSQL_CFLAGS=`$MYSQL_CONFIG --include 2>/dev/null`
  AS_IF([test -z "$MYSQL_CFLAGS"], [MYSQL_CFLAGS=`$MYSQL_CONFIG --cflags`])
  MYSQL_LIBS=`$MYSQL_CONFIG --libs`
  save_CPPFLAGS="$CPPFLAGS"
  CPPFLAGS="$CPPFLAGS $MYSQL_CFLAGS"
  AC_CHECK_HEADER([mysql.h], [],
    [AC_MSG_ERROR([mysql.h not found via $MYSQL_CONFIG. Install the client development headers, or pass --disable-cla-mysql.])])
  CPPFLAGS="$save_CPPFLAGS"
])
AC_SUBST([MYSQL_CFLAGS])
AC_SUBST([MYSQL_LIBS])

AM_CONDITIONAL([ENABLE_CLA_MYSQL], [test "x$enable_cla_mysql" = xyes])
AC_CONFIG_FILES([CLA/mysql/Makefile])
contrib_status="$contrib_status
    CLA/mysql ....... $enable_cla_mysql (${MYSQL_LIBS:-n/a})"
