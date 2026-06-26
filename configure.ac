#                                               -*- Autoconf -*-
# Process this file with autoreconf to produce a configure script.
#
# ION-DTN-CONTRIB builds against an *installed* ION-DTN (see --with-ion).

AC_PREREQ([2.69])
AC_INIT([ion-dtn-contrib],[0.1.0],[https://github.com/nasa-jpl/ION-DTN/issues])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([CLA/mqtt/src/mqttclo.c])
AM_INIT_AUTOMAKE([subdir-objects foreign -Wall])

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MKDIR_P

#
# Per-contribution selection (mirrors the ALL / <KIND>_<NAME> tokens used by
# install-deps.sh and test.sh). Nothing is built by default: opt in to each
# contribution with --enable-<contrib>, or build everything with --enable-all.
# A contribution's own dependency checks below are skipped when it is not
# selected, so e.g. building only bpsh does not require the Paho MQTT library.
#
AC_ARG_ENABLE([all],
  [AS_HELP_STRING([--enable-all], [build every contribution])],
  [enable_all=$enableval], [enable_all=no])
AC_ARG_ENABLE([cla-mqtt],
  [AS_HELP_STRING([--enable-cla-mqtt], [build the MQTT CLA (CLA/mqtt)])],
  [enable_cla_mqtt=$enableval], [enable_cla_mqtt=])
AC_ARG_ENABLE([app-bpsh],
  [AS_HELP_STRING([--enable-app-bpsh], [build the bpsh app (APP/bpsh)])],
  [enable_app_bpsh=$enableval], [enable_app_bpsh=])

# --enable-all sets the default for any contribution not named explicitly, so
# --enable-all --disable-cla-mqtt still works.
AS_IF([test "x$enable_all" = xyes], [contrib_default=yes], [contrib_default=no])
test -z "$enable_cla_mqtt" && enable_cla_mqtt=$contrib_default
test -z "$enable_app_bpsh" && enable_app_bpsh=$contrib_default

AS_IF([test "x$enable_cla_mqtt$enable_app_bpsh" = xnono],
  [AC_MSG_WARN([no contributions selected; pass --enable-all or --enable-<contrib> (e.g. --enable-app-bpsh)])])

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

#
# pthread (used by the MQTT input daemon).
#
AC_CHECK_LIB([pthread], [pthread_create], [],
  [AC_MSG_ERROR([libpthread is required.])])

#
# Eclipse Paho MQTT C client (mirrors ION's own --with-paho-mqtt logic):
# prefer the TLS-capable libpaho-mqtt3cs, fall back to libpaho-mqtt3c.
# Only required when the MQTT CLA is enabled.
#
AS_IF([test "x$enable_cla_mqtt" = xyes], [
  save_LIBS="$LIBS"
  AC_CHECK_LIB([paho-mqtt3cs], [MQTTClient_create],
    [MQTT_LIBS="-lpaho-mqtt3cs"],
    [AC_CHECK_LIB([paho-mqtt3c], [MQTTClient_create],
      [MQTT_LIBS="-lpaho-mqtt3c"
       AC_MSG_WARN([Only libpaho-mqtt3c found (no TLS). MQTT TLS options will not work.])],
      [AC_MSG_ERROR([Neither libpaho-mqtt3cs nor libpaho-mqtt3c found. Install the Eclipse Paho MQTT C client library, or pass --disable-cla-mqtt.])])])
  LIBS="$save_LIBS"
  AC_CHECK_HEADER([MQTTClient.h], [],
    [AC_MSG_ERROR([MQTTClient.h not found. Install the Eclipse Paho MQTT C client development headers, or pass --disable-cla-mqtt.])])
])
AC_SUBST([MQTT_LIBS])

AM_CONDITIONAL([ENABLE_CLA_MQTT], [test "x$enable_cla_mqtt" = xyes])
AM_CONDITIONAL([ENABLE_APP_BPSH], [test "x$enable_app_bpsh" = xyes])

#
# Man pages are generated from POD only when pod2man is available.
#
AC_CHECK_PROG([POD2MAN], [pod2man], [pod2man])
AM_CONDITIONAL([HAVE_POD2MAN], [test "x$POD2MAN" != "x"])

AC_CONFIG_FILES([Makefile
                 CLA/mqtt/Makefile
                 APP/bpsh/Makefile])
AC_OUTPUT

echo
echo "  ION-DTN-CONTRIB configured"
echo "    ION prefix ...... ${ion_prefix}"
echo "    CLA/mqtt ........ ${enable_cla_mqtt} (${MQTT_LIBS:-n/a})"
echo "    APP/bpsh ........ ${enable_app_bpsh}"
echo
