# quota: traffic shaping convergence layer adapter for ION-DTN.
#
# Builds quotaclo and quotaadmin against an installed ION-DTN.
# bpP.h is a private ION header that ION does not install; a copy is
# vendored under the top-level include/ (see include/README).

AM_CPPFLAGS = -I$(top_srcdir)/include $(ION_CFLAGS)

bin_PROGRAMS = quotaclo quotaadmin

noinst_HEADERS = src/quotacl.h src/quotarules.h

quotaclo_SOURCES = src/quotaclo.c src/quotarules.c
quotaclo_LDADD = $(ION_LIBS) -lpthread

quotaadmin_SOURCES = src/quotaadmin.c src/quotarules.c
quotaadmin_LDADD = $(ION_LIBS) -lpthread

# --- unit tests (make check) --- #
# quotarules needs nothing but libc, so the test overrides the ION
# include path with the source dir only.

check_PROGRAMS = quotarules_test
TESTS = quotarules_test
quotarules_test_SOURCES = tests/quotarules_test.c src/quotarules.c
quotarules_test_CPPFLAGS = -I$(srcdir)/src

# --- fuzzing --- #
# tests/fuzz/fuzz_rules.c is a libFuzzer entry point over what reaches
# quotarules from outside: EIDs from bundles, quotaadmin's arguments and
# the state file.  Under `make check` it is linked with a plain driver
# that replays its checked-in corpus; `make fuzz` builds it with clang's
# libFuzzer and sanitizers and runs it for FUZZ_TIME seconds, starting
# from that corpus; anything it finds is left in fuzz-artifacts/.

FUZZ_DIR = $(srcdir)/tests/fuzz
check_PROGRAMS += fuzz_rules_replay
TESTS += fuzz_rules_replay
fuzz_rules_replay_SOURCES = tests/fuzz/fuzz_replay.c \
	tests/fuzz/fuzz_rules.c src/quotarules.c
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
		$(srcdir)/src/quotarules.c -o fuzz-bin/fuzz_rules
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

POD1 = doc/quotaclo.pod doc/quotaadmin.pod

if HAVE_POD2MAN
man1_MANS = doc/quotaclo.1 doc/quotaadmin.1
CLEANFILES = $(man1_MANS)

doc/%.1: doc/%.pod
	$(MKDIR_P) doc
	$(POD2MAN) -s 1 -c "ION-DTN-CONTRIB executables" $< $@
endif

EXTRA_DIST = \
	README.md \
	doc/design.md \
	$(POD1) \
	tests
