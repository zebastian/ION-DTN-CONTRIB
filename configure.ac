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

AC_CANONICAL_HOST
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

# ION's platform.h shapes itself on the platform macros ION's own build
# passes - the OS name and SPACE_ORDER, log2 of the pointer size - and
# defaults to a 32-bit machine when told nothing.  What they change reaches
# the ABI: the vast/uvast printf field specifications, which libici's
# isprintf parses by the same macros, so a mismatch prints "u" for every
# node number.  Derive them the way ION's configure does.
AC_CHECK_SIZEOF([void *])
AS_CASE([$ac_cv_sizeof_void_p],
  [8], [ion_space_order=3],
  [4], [ion_space_order=2],
  [AC_MSG_ERROR([unsupported pointer size $ac_cv_sizeof_void_p])])
AS_CASE([$host_os],
  [linux*], [ion_platform_cflags="-Dunix -Dlinux"],
  [darwin*], [ion_platform_cflags="-Dunix -Ddarwin"],
  [freebsd*], [ion_platform_cflags="-D__BSD_VISIBLE -Dunix -Dfreebsd"],
  [AC_MSG_WARN([unrecognised host OS $host_os; ION's platform.h may misconfigure itself])
   ion_platform_cflags="-Dunix"])
ion_platform_cflags="$ion_platform_cflags -DSPACE_ORDER=$ion_space_order"

ION_CFLAGS="-I${ion_prefix}/include $ion_platform_cflags"
ION_LIBS="-L${ion_prefix}/lib -lbp -lici"
AC_SUBST([ION_CFLAGS])
AC_SUBST([ION_LIBS])

save_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="$CPPFLAGS $ION_CFLAGS"
AC_CHECK_HEADER([bp.h], [],
  [AC_MSG_ERROR([ION-DTN headers not found under ${ion_prefix}/include. Install ION-DTN or pass --with-ion=PREFIX.])])

# ION installs no version header.  From 4.1.4 its pkg-config file names the
# release; before that, the macros that include/bpP.h keys on tell the
# release group apart (see include/README).  Only informational: the
# contributions build against every release from 4.0.0 to 4.2.0 alike.
ion_version=unknown
AS_IF([test -r "${ion_prefix}/lib/pkgconfig/ion.pc"],
  [ion_version=`sed -n 's/^Version:[[ \t]]*//p' "${ion_prefix}/lib/pkgconfig/ion.pc"`
   test -n "$ion_version" || ion_version=unknown])
AS_IF([test "x$ion_version" = xunknown],
  [AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include "bp.h"
#ifndef BP_VERSION
#error pre-4.1.0
#endif]], [[]])],
     [ion_version="4.1.0 to 4.1.3s (no ion.pc)"],
     [AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include "bp.h"
#ifndef BP_BIBE_REQUESTED
#error pre-4.0.2
#endif]], [[]])],
        [ion_version="4.0.2 (no ion.pc)"],
        [ion_version="4.0.0 or 4.0.1 (no ion.pc)"])])])
AC_MSG_CHECKING([the installed ION-DTN version])
AC_MSG_RESULT([$ion_version])

# ION before 4.1.3s does not install cbor.h and crc.h, which its own bpP.h
# includes; include/compat carries the copies those releases would have
# installed.  ION before 4.1.4 has no ion_network.h; include/ioncompat.h
# stands in for it unless told the header is there.  Both are file tests on
# the ION prefix rather than compile tests, so that another ION on the
# compiler's default include path cannot answer for the one selected.
AC_MSG_CHECKING([whether ION installs cbor.h])
AS_IF([test -r "${ion_prefix}/include/cbor.h"],
  [AC_MSG_RESULT([yes])
   ion_compat_include=no],
  [AC_MSG_RESULT([no, using include/compat])
   ion_compat_include=yes
   ION_CFLAGS="$ION_CFLAGS -I\$(top_srcdir)/include/compat"])
AC_MSG_CHECKING([whether ION installs ion_network.h])
AS_IF([test -r "${ion_prefix}/include/ion_network.h"],
  [AC_MSG_RESULT([yes])
   ION_CFLAGS="$ION_CFLAGS -DION_CONTRIB_HAVE_ION_NETWORK_H"],
  [AC_MSG_RESULT([no, using include/ioncompat.h])])

# Recent ION deprecates the "Object" and "Address" aliases of SdrObject and
# SdrAddress, defining them only under ION_USE_LEGACY_ALIASES.  Every ION API
# these contributions call still speaks in Object - bpP.h itself is written in
# it - so ask for the aliases when the headers no longer offer them unasked.
AC_MSG_CHECKING([whether ION defines the legacy Object alias])
AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM([[#include "sdrxn.h"]], [[Object o = 0; (void) o;]])],
  [AC_MSG_RESULT([yes])],
  [CPPFLAGS="$CPPFLAGS -DION_USE_LEGACY_ALIASES"
   AC_COMPILE_IFELSE(
     [AC_LANG_PROGRAM([[#include "sdrxn.h"]], [[Object o = 0; (void) o;]])],
     [AC_MSG_RESULT([only under ION_USE_LEGACY_ALIASES])
      ION_CFLAGS="$ION_CFLAGS -DION_USE_LEGACY_ALIASES"],
     [AC_MSG_RESULT([no])
      AC_MSG_ERROR([ION under ${ion_prefix} defines neither Object nor ION_USE_LEGACY_ALIASES; its SDR headers are not the ones these contributions are written against.])])])
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
m4_include([CLA/mail/configure.m4])
m4_include([CLA/mqtt/configure.m4])
m4_include([CLA/mysql/configure.m4])
m4_include([CLA/quic/configure.m4])
m4_include([CLA/tcpv4/configure.m4])
m4_include([APP/bpsh/configure.m4])
m4_include([APP/bpcmd/configure.m4])

AS_IF([test "x$contrib_selected" = xno],
  [AC_MSG_WARN([no contributions selected; pass --enable-all or --enable-<contrib> (e.g. --enable-app-bpsh)])])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

echo
echo "  ION-DTN-CONTRIB configured"
echo "    ION prefix ...... ${ion_prefix}"
echo "    ION platform .... ${ion_platform_cflags}"
echo "    ION version ..... ${ion_version}"
AS_IF([test "x$ion_compat_include" = xyes],
  [echo "    ION headers ..... cbor.h/crc.h supplied from include/compat"])
printf '%s\n' "$contrib_status"
echo
