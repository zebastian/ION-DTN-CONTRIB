# bptun — IP over Bundle Protocol through a TUN interface, for ION-DTN.
#
# Every IP packet the kernel routes into the interface becomes one bundle
# to the bptun serving the packet's destination; every bundle delivered
# to bptun's endpoint becomes one packet.  Builds against an installed
# ION-DTN; only ION's public API is used.  Linux only (TUN/TAP).

AM_CPPFLAGS = $(ION_CFLAGS)

bin_PROGRAMS = bptun

noinst_HEADERS = src/bptun_route.h
bptun_SOURCES = src/bptun.c src/bptun_route.c
bptun_LDADD = $(ION_LIBS) -lpthread

# --- unit tests (make check) --- #
# The route table needs no ION, so its test builds with the source dir
# alone.

check_PROGRAMS = bptun_route_test
TESTS = bptun_route_test
bptun_route_test_SOURCES = tests/bptun_route_test.c src/bptun_route.c
bptun_route_test_CPPFLAGS = -I$(srcdir)/src

# --- man page (generated from POD when pod2man is available) --- #

POD1 = doc/bptun.pod

if HAVE_POD2MAN
man1_MANS = doc/bptun.1
CLEANFILES = $(man1_MANS)

doc/%.1: doc/%.pod
	$(MKDIR_P) doc
	$(POD2MAN) -s 1 -c "ION-DTN-CONTRIB executables" $< $@
endif

EXTRA_DIST = \
	README.md \
	install-deps.sh \
	tests/bptun-loopback/dotest \
	tests/bptun-loopback/cleanup \
	tests/bptun-loopback/config/host1.rc \
	$(POD1)
