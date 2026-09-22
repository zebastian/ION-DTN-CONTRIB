ACLOCAL_AMFLAGS = -I m4

# One subdirectory per contribution; each is included only when enabled at
# configure time (see --disable-cla-mqtt / --disable-app-bpsh).
SUBDIRS =
if ENABLE_CLA_MAIL
SUBDIRS += CLA/mail
endif
if ENABLE_CLA_MQTT
SUBDIRS += CLA/mqtt
endif
if ENABLE_CLA_MYSQL
SUBDIRS += CLA/mysql
endif
if ENABLE_CLA_QUIC
SUBDIRS += CLA/quic
endif
if ENABLE_CLA_TCPV4
SUBDIRS += CLA/tcpv4
endif
if ENABLE_APP_BPSH
SUBDIRS += APP/bpsh
endif
if ENABLE_APP_BPCMD
SUBDIRS += APP/bpcmd
endif

# Vendored ION-DTN private headers and the compatibility shims, shared by all
# contributions (see include/README).
EXTRA_DIST = README.md include/README include/bpP.h include/bpP-4.0.1.h \
	include/bpP-4.0.2.h include/bpP-4.1.3s.h include/bpP-4.1.4.h \
	include/bpP-4.2.0.h include/ioncompat.h include/compat/cbor.h \
	include/compat/crc.h
