# MQTT convergence layer adapter for ION-DTN.
#
# Builds the mqttcli / mqttclo daemon pair against an installed ION-DTN.
# bpP.h is a private ION header that ION does not install; a copy is vendored
# under the top-level include/ (see include/README) so this builds without an
# ION source tree.

AM_CPPFLAGS = -I$(top_srcdir)/include $(ION_CFLAGS)

bin_PROGRAMS = mqttcli mqttclo

noinst_HEADERS = src/mqttcla.h

mqttcli_SOURCES = src/mqttcli.c
mqttcli_LDADD = $(ION_LIBS) $(MQTT_LIBS) -lpthread

mqttclo_SOURCES = src/mqttclo.c
mqttclo_LDADD = $(ION_LIBS) $(MQTT_LIBS) -lpthread

# --- man pages (generated from POD when pod2man is available) --- #

POD1 = doc/mqttcli.pod doc/mqttclo.pod

if HAVE_POD2MAN
man1_MANS = doc/mqttcli.1 doc/mqttclo.1
CLEANFILES = $(man1_MANS)

doc/%.1: doc/%.pod
	$(MKDIR_P) doc
	$(POD2MAN) -s 1 -c "ION-DTN-CONTRIB executables" $< $@
endif

EXTRA_DIST = \
	README.md \
	$(POD1) \
	tests
