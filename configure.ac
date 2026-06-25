#                                               -*- Autoconf -*-
# Process this file with autoreconf to produce a configure script.
#
# ION-DTN-CONTRIB builds against an *installed* ION-DTN (see --with-ion).

AC_PREREQ([2.69])
AC_INIT([ion-dtn-contrib],[0.1.0],[https://github.com/nasa-jpl/ION-DTN/issues])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([CLA/mqtt/bpv7/mqtt/mqttclo.c])
AM_INIT_AUTOMAKE([subdir-objects foreign -Wall])

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MKDIR_P

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
#
save_LIBS="$LIBS"
AC_CHECK_LIB([paho-mqtt3cs], [MQTTClient_create],
  [MQTT_LIBS="-lpaho-mqtt3cs"],
  [AC_CHECK_LIB([paho-mqtt3c], [MQTTClient_create],
    [MQTT_LIBS="-lpaho-mqtt3c"
     AC_MSG_WARN([Only libpaho-mqtt3c found (no TLS). MQTT TLS options will not work.])],
    [AC_MSG_ERROR([Neither libpaho-mqtt3cs nor libpaho-mqtt3c found. Install the Eclipse Paho MQTT C client library.])])])
LIBS="$save_LIBS"
AC_CHECK_HEADER([MQTTClient.h], [],
  [AC_MSG_ERROR([MQTTClient.h not found. Install the Eclipse Paho MQTT C client development headers.])])
AC_SUBST([MQTT_LIBS])

#
# Man pages are generated from POD only when pod2man is available.
#
AC_CHECK_PROG([POD2MAN], [pod2man], [pod2man])
AM_CONDITIONAL([HAVE_POD2MAN], [test "x$POD2MAN" != "x"])

AC_CONFIG_FILES([Makefile
                 CLA/mqtt/Makefile])
AC_OUTPUT

echo
echo "  ION-DTN-CONTRIB configured"
echo "    ION prefix ...... ${ion_prefix}"
echo "    MQTT libs ....... ${MQTT_LIBS}"
echo
