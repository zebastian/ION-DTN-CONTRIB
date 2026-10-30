# zcl: zstd compressing tunnel convergence layer adapter for ION-DTN.
#
# Builds the zcli / zclo daemon pair against an installed ION-DTN.
# bpP.h is a private ION header that ION does not install; a copy is
# vendored under the top-level include/ (see include/README).

AM_CPPFLAGS = -I$(top_srcdir)/include $(ION_CFLAGS) $(ZSTD_CFLAGS)

bin_PROGRAMS = zcli zclo

noinst_HEADERS = src/zclcla.h src/zclcodec.h

zcli_SOURCES = src/zcli.c src/zclcodec.c
zcli_LDADD = $(ION_LIBS) $(ZSTD_LIBS) -lpthread

zclo_SOURCES = src/zclo.c src/zclcodec.c
zclo_LDADD = $(ION_LIBS) $(ZSTD_LIBS) -lpthread

# --- unit tests (make check) --- #
# zclcodec needs libzstd only (no ION), so the test overrides the ION
# include path with the source dir only.

check_PROGRAMS = zclcodec_test
TESTS = zclcodec_test
zclcodec_test_SOURCES = tests/zclcodec_test.c src/zclcodec.c
zclcodec_test_CPPFLAGS = -I$(srcdir)/src $(ZSTD_CFLAGS)
zclcodec_test_LDADD = $(ZSTD_LIBS)

# --- fuzzing --- #
# tests/fuzz/fuzz_zclrx.c is a libFuzzer entry point over the receive
# side of src/zclcodec.c, tests/fuzz/fuzz_zclinfo.c one over the bundle
# inspection zclo does on what other nodes built.  Under `make check`
# each is linked with a plain driver that replays its checked-in
# corpus, so the inputs the fuzzer once found interesting keep passing
# whatever the compiler.  `make fuzz` builds them with clang's
# libFuzzer and sanitizers and runs each for FUZZ_TIME seconds,
# starting from that corpus; anything found is left in fuzz-artifacts/.

FUZZ_DIR = $(srcdir)/tests/fuzz
check_PROGRAMS += fuzz_zclrx_replay
TESTS += fuzz_zclrx_replay
fuzz_zclrx_replay_SOURCES = tests/fuzz/fuzz_replay.c \
	tests/fuzz/fuzz_zclrx.c src/zclcodec.c
fuzz_zclrx_replay_CPPFLAGS = -I$(srcdir)/src $(ZSTD_CFLAGS) \
	-DFUZZ_CORPUS=\"$(FUZZ_DIR)/corpus/zclrx\"
fuzz_zclrx_replay_LDADD = $(ZSTD_LIBS)

check_PROGRAMS += fuzz_zclinfo_replay
TESTS += fuzz_zclinfo_replay
fuzz_zclinfo_replay_SOURCES = tests/fuzz/fuzz_replay.c \
	tests/fuzz/fuzz_zclinfo.c src/zclcodec.c
fuzz_zclinfo_replay_CPPFLAGS = -I$(srcdir)/src $(ZSTD_CFLAGS) \
	-DFUZZ_CORPUS=\"$(FUZZ_DIR)/corpus/zclinfo\"
fuzz_zclinfo_replay_LDADD = $(ZSTD_LIBS)

FUZZ_CC = clang
FUZZ_TIME = 60
FUZZ_JOBS = 4
FUZZ_CFLAGS = -g -O1 -fsanitize=fuzzer,address,undefined \
	-fno-sanitize-recover=undefined -I$(srcdir)/src $(ZSTD_CFLAGS)

FUZZ_TARGETS = zclrx zclinfo

fuzz:
	$(MKDIR_P) fuzz-bin fuzz-artifacts
	@rc=0; for t in $(FUZZ_TARGETS); do \
		$(MKDIR_P) fuzz-corpus/$$t; \
		$(FUZZ_CC) $(FUZZ_CFLAGS) $(FUZZ_DIR)/fuzz_$$t.c \
			$(srcdir)/src/zclcodec.c $(ZSTD_LIBS) \
			-o fuzz-bin/fuzz_$$t || exit 1; \
		echo "fuzzing $$t for $(FUZZ_TIME) s..."; \
		fuzz-bin/fuzz_$$t fuzz-corpus/$$t $(FUZZ_DIR)/corpus/$$t \
			-max_total_time=$(FUZZ_TIME) -fork=$(FUZZ_JOBS) \
			-max_len=16384 -artifact_prefix=fuzz-artifacts/$$t- \
			> fuzz-$$t.log 2>&1 || rc=1; tail -1 fuzz-$$t.log; \
	done; \
	if ls fuzz-artifacts/* >/dev/null 2>&1; then \
		echo "fuzzing found inputs, see fuzz-artifacts/:"; \
		ls fuzz-artifacts; exit 1; \
	fi; \
	exit $$rc

clean-local:
	rm -rf fuzz-bin fuzz-corpus fuzz-artifacts fuzz-*.log

.PHONY: fuzz

# --- man pages (generated from POD when pod2man is available) --- #

POD1 = doc/zcli.pod doc/zclo.pod

if HAVE_POD2MAN
man1_MANS = doc/zcli.1 doc/zclo.1
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
