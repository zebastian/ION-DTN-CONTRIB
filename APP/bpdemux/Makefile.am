# bpdemux — data-label demux for ION-DTN.
#
# Builds bpdemuxd and bpdemuxadmin against an installed ION-DTN.
# bpdemuxd moves bundles between endpoint delivery queues and so uses
# ION's private bpP.h; a copy is vendored under the top-level include/
# (see include/README).

AM_CPPFLAGS = -I$(top_srcdir)/include $(ION_CFLAGS)

bin_PROGRAMS = bpdemuxd bpdemuxadmin

noinst_HEADERS = src/bpdemux.h src/dmxrules.h

bpdemuxd_SOURCES = src/bpdemuxd.c src/dmxrules.c
bpdemuxd_LDADD = $(ION_LIBS) -lpthread

bpdemuxadmin_SOURCES = src/bpdemuxadmin.c src/dmxrules.c
bpdemuxadmin_LDADD = $(ION_LIBS) -lpthread

# The integration test's receiver; not installed.
noinst_PROGRAMS = dmxrecv
dmxrecv_SOURCES = tests/dmxrecv.c
dmxrecv_LDADD = $(ION_LIBS) -lpthread

# --- unit tests (make check) --- #
# dmxrules needs nothing but libc, so the test overrides the ION
# include path with the source dir only.

check_PROGRAMS = dmxrules_test
TESTS = dmxrules_test
dmxrules_test_SOURCES = tests/dmxrules_test.c src/dmxrules.c
dmxrules_test_CPPFLAGS = -I$(srcdir)/src

# --- fuzzing --- #
# tests/fuzz/fuzz_rules.c is a libFuzzer entry point over what reaches
# dmxrules from outside: bpdemuxadmin's command words.  Under `make
# check` it is linked with a plain driver that replays its checked-in
# corpus; `make fuzz` builds it with clang's libFuzzer and sanitizers
# and runs it for FUZZ_TIME seconds, starting from that corpus;
# anything it finds is left in fuzz-artifacts/.

FUZZ_DIR = $(srcdir)/tests/fuzz
check_PROGRAMS += fuzz_rules_replay
TESTS += fuzz_rules_replay
fuzz_rules_replay_SOURCES = tests/fuzz/fuzz_replay.c \
	tests/fuzz/fuzz_rules.c src/dmxrules.c
fuzz_rules_replay_CPPFLAGS = -I$(srcdir)/src \
	-DFUZZ_CORPUS=\"$(FUZZ_DIR)/corpus/rules\"

FUZZ_CC = clang
FUZZ_TIME = 60
FUZZ_JOBS = 4
FUZZ_CFLAGS = -g -O1 -fsanitize=fuzzer,address,undefined \
	-fno-sanitize-recover=undefined -I$(srcdir)/src

fuzz:
	$(MKDIR_P) fuzz-bin fuzz-corpus/rules fuzz-artifacts
	$(FUZZ_CC) $(FUZZ_CFLAGS) $(FUZZ_DIR)/fuzz_rules.c \
		$(srcdir)/src/dmxrules.c -o fuzz-bin/fuzz_rules
	@echo "fuzzing rules for $(FUZZ_TIME) s..."
	@fuzz-bin/fuzz_rules fuzz-corpus/rules $(FUZZ_DIR)/corpus/rules \
		-max_total_time=$(FUZZ_TIME) -fork=$(FUZZ_JOBS) \
		-max_len=2048 -artifact_prefix=fuzz-artifacts/rules- \
		> fuzz-rules.log 2>&1; rc=$$?; tail -1 fuzz-rules.log; \
	if ls fuzz-artifacts/* >/dev/null 2>&1; then \
		echo "fuzzing found inputs, see fuzz-artifacts/:"; \
		ls fuzz-artifacts; exit 1; \
	fi; \
	exit $$rc

clean-local:
	rm -rf fuzz-bin fuzz-corpus fuzz-artifacts fuzz-*.log

.PHONY: fuzz

# --- man pages (generated from POD when pod2man is available) --- #

POD1 = doc/bpdemuxd.pod doc/bpdemuxadmin.pod

if HAVE_POD2MAN
man1_MANS = doc/bpdemuxd.1 doc/bpdemuxadmin.1
CLEANFILES = $(man1_MANS)

doc/%.1: doc/%.pod
	$(MKDIR_P) doc
	$(POD2MAN) -s 1 -c "ION-DTN-CONTRIB executables" $< $@
endif

EXTRA_DIST = \
	README.md \
	install-deps.sh \
	doc/design.md \
	$(POD1) \
	tests
