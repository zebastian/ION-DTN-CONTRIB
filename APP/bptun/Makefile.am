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

# --- fuzzing --- #
# tests/fuzz/fuzz_route.c is a libFuzzer entry point over src/bptun_route.c.
# Under `make check` it is linked with a plain driver that replays its
# checked-in corpus, so the inputs the fuzzer once found interesting keep
# passing whatever the compiler.  `make fuzz` builds it with clang's
# libFuzzer and sanitizers and runs it for FUZZ_TIME seconds, starting from
# that corpus; anything it finds is left in fuzz-artifacts/.

FUZZ_DIR = $(srcdir)/tests/fuzz
check_PROGRAMS += fuzz_route_replay
TESTS += fuzz_route_replay
fuzz_route_replay_SOURCES = tests/fuzz/fuzz_replay.c \
	tests/fuzz/fuzz_route.c src/bptun_route.c
fuzz_route_replay_CPPFLAGS = -I$(srcdir)/src \
	-DFUZZ_CORPUS=\"$(FUZZ_DIR)/corpus/route\"

FUZZ_CC = clang
FUZZ_TIME = 60
FUZZ_JOBS = 4
FUZZ_CFLAGS = -g -O1 -fsanitize=fuzzer,address,undefined \
	-fno-sanitize-recover=undefined -I$(srcdir)/src

fuzz:
	$(MKDIR_P) fuzz-bin fuzz-corpus/route fuzz-artifacts
	$(FUZZ_CC) $(FUZZ_CFLAGS) $(FUZZ_DIR)/fuzz_route.c \
		$(srcdir)/src/bptun_route.c -o fuzz-bin/fuzz_route
	@echo "fuzzing route for $(FUZZ_TIME) s..."
	@fuzz-bin/fuzz_route fuzz-corpus/route $(FUZZ_DIR)/corpus/route \
		-max_total_time=$(FUZZ_TIME) -fork=$(FUZZ_JOBS) \
		-max_len=4096 -artifact_prefix=fuzz-artifacts/route- \
		> fuzz-route.log 2>&1; rc=$$?; tail -1 fuzz-route.log; \
	if ls fuzz-artifacts/* >/dev/null 2>&1; then \
		echo "fuzzing found inputs, see fuzz-artifacts/:"; \
		ls fuzz-artifacts; exit 1; \
	fi; \
	exit $$rc

clean-local:
	rm -rf fuzz-bin fuzz-corpus fuzz-artifacts fuzz-*.log

.PHONY: fuzz

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
	tests/fuzz \
	$(POD1)
