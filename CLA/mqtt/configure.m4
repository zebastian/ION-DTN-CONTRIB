# -*- Autoconf -*- MQTT CLA configure fragment (m4_include'd by ./configure.ac).

AC_ARG_ENABLE([cla-mqtt],
  [AS_HELP_STRING([--enable-cla-mqtt], [build the MQTT CLA (CLA/mqtt)])],
  [enable_cla_mqtt=$enableval], [enable_cla_mqtt=])
test -z "$enable_cla_mqtt" && enable_cla_mqtt=$contrib_default

AS_IF([test "x$enable_cla_mqtt" = xyes], [
  contrib_selected=yes
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
AC_CONFIG_FILES([CLA/mqtt/Makefile])
contrib_status="$contrib_status
    CLA/mqtt ........ $enable_cla_mqtt (${MQTT_LIBS:-n/a})"
