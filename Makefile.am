ACLOCAL_AMFLAGS = -I m4

# One subdirectory per contribution; each is included only when enabled at
# configure time (see --disable-cla-mqtt / --disable-app-bpsh).
SUBDIRS =
if ENABLE_CLA_MQTT
SUBDIRS += CLA/mqtt
endif
if ENABLE_CLA_MYSQL
SUBDIRS += CLA/mysql
endif
if ENABLE_CLA_QUIC
SUBDIRS += CLA/quic
endif
if ENABLE_APP_BPSH
SUBDIRS += APP/bpsh
endif
if ENABLE_APP_BPCMD
SUBDIRS += APP/bpcmd
endif

# Vendored ION-DTN private headers, shared by all contributions (see
# include/README).
EXTRA_DIST = README.md include/bpP.h include/README
