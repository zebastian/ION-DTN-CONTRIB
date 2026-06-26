# bpsh / bpshd — SSH-like remote shell over Bundle Protocol, for ION-DTN.
#
# Builds the bpsh (client) / bpshd (daemon) pair against an installed ION-DTN.
# Only ION's public headers (bp.h, cbor.h) are used, so no private ION header
# needs to be vendored.

AM_CPPFLAGS = $(ION_CFLAGS)

bin_PROGRAMS = bpsh bpshd

noinst_HEADERS = src/bpsh_proto.h src/bpshd_session.h

bpsh_SOURCES = src/bpsh.c src/bpsh_proto.c
bpsh_LDADD = $(ION_LIBS) -lpthread

bpshd_SOURCES = src/bpshd.c src/bpshd_session.c src/bpsh_proto.c
bpshd_LDADD = $(ION_LIBS) -lpthread

# --- man pages (generated from POD when pod2man is available) --- #

POD1 = doc/bpsh.pod doc/bpshd.pod

if HAVE_POD2MAN
man1_MANS = doc/bpsh.1 doc/bpshd.1
CLEANFILES = $(man1_MANS)

doc/%.1: doc/%.pod
	$(MKDIR_P) doc
	$(POD2MAN) -s 1 -c "ION-DTN-CONTRIB executables" $< $@
endif

EXTRA_DIST = \
	README.md \
	$(POD1) \
	tests
