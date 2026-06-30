#                                               -*- Autoconf -*-
# Process this file with autoreconf to produce a configure script.
#
# ION-DTN-CONTRIB builds against an *installed* ION-DTN (see --with-ion).
# Each contribution's own configure logic lives in its subfolder's
# configure.m4, m4_include'd below (one line per contribution).

AC_PREREQ([2.69])
AC_INIT([ion-dtn-contrib],[0.1.0],[https://github.com/nasa-jpl/ION-DTN/issues])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([CLA/mqtt/src/mqttclo.c])
AM_INIT_AUTOMAKE([subdir-objects foreign -Wall])

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MKDIR_P

# Nothing is built by default; opt in with --enable-<contrib> or --enable-all.
AC_ARG_ENABLE([all],
  [AS_HELP_STRING([--enable-all], [build every contribution])],
  [enable_all=$enableval], [enable_all=no])
AS_IF([test "x$enable_all" = xyes], [contrib_default=yes], [contrib_default=no])
contrib_selected=no
contrib_status=

#
# Locate the installed ION-DTN (headers + libraries).
#
AC_ARG_WITH([ion],
  [AS_HELP_STRING([--with-ion=PREFIX],
    [ION-DTN install prefix (default: /usr/local)])],
  [ion_prefix="$withval"],
  [ion_prefix="/usr/local"])

ION_CFLAGS="-I${ion_prefix}/include"
ION_LIBS="-L${ion_prefix}/lib -lbp -lici"
AC_SUBST([ION_CFLAGS])
AC_SUBST([ION_LIBS])

save_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="$CPPFLAGS $ION_CFLAGS"
AC_CHECK_HEADER([bp.h], [],
  [AC_MSG_ERROR([ION-DTN headers not found under ${ion_prefix}/include. Install ION-DTN or pass --with-ion=PREFIX.])])
CPPFLAGS="$save_CPPFLAGS"

save_LDFLAGS="$LDFLAGS"
save_LIBS="$LIBS"
LDFLAGS="$LDFLAGS -L${ion_prefix}/lib"
AC_CHECK_LIB([ici], [sdr_begin_xn], [],
  [AC_MSG_ERROR([libici not found under ${ion_prefix}/lib. Install ION-DTN or pass --with-ion=PREFIX.])])
AC_CHECK_LIB([bp], [bp_attach], [],
  [AC_MSG_ERROR([libbp not found under ${ion_prefix}/lib. Install ION-DTN or pass --with-ion=PREFIX.])],
  [-lici])
LDFLAGS="$save_LDFLAGS"
# AC_CHECK_LIB prepends -l flags to LIBS; the contrib targets set their own
# link lines, so clear them back out here.
LIBS="$save_LIBS"

# pthread is used by all of the daemons.
AC_CHECK_LIB([pthread], [pthread_create], [],
  [AC_MSG_ERROR([libpthread is required.])])

# Man pages are generated from POD only when pod2man is available.
AC_CHECK_PROG([POD2MAN], [pod2man], [pod2man])
AM_CONDITIONAL([HAVE_POD2MAN], [test "x$POD2MAN" != "x"])

# One include per contribution (the configure analogue of SUBDIRS).
m4_include([CLA/mqtt/configure.m4])
m4_include([CLA/mysql/configure.m4])
m4_include([CLA/quic/configure.m4])
m4_include([APP/bpsh/configure.m4])
m4_include([APP/bpcmd/configure.m4])

AS_IF([test "x$contrib_selected" = xno],
  [AC_MSG_WARN([no contributions selected; pass --enable-all or --enable-<contrib> (e.g. --enable-app-bpsh)])])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

echo
echo "  ION-DTN-CONTRIB configured"
echo "    ION prefix ...... ${ion_prefix}"
printf '%s\n' "$contrib_status"
echo
