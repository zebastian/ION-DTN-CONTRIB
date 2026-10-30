# -*- Autoconf -*- quota CLA configure fragment (m4_include'd by ./configure.ac).

AC_ARG_ENABLE([cla-quota],
  [AS_HELP_STRING([--enable-cla-quota], [build the quota shaping CLA (CLA/quota)])],
  [enable_cla_quota=$enableval], [enable_cla_quota=])
test -z "$enable_cla_quota" && enable_cla_quota=$contrib_default

# Nothing beyond ION and pthreads.
AS_IF([test "x$enable_cla_quota" = xyes], [contrib_selected=yes])

AM_CONDITIONAL([ENABLE_CLA_QUOTA], [test "x$enable_cla_quota" = xyes])
AC_CONFIG_FILES([CLA/quota/Makefile])
contrib_status="$contrib_status
    CLA/quota ....... $enable_cla_quota"
