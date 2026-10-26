# bpsh / bpshd — SSH-like remote shell over Bundle Protocol, for ION-DTN.
#
# Builds the bpsh (client) / bpshd (daemon) pair against an installed ION-DTN.
# Only ION's public headers (bp.h, cbor.h) are used, so no private ION header
# needs to be vendored; the top-level include/ supplies the CBOR signed-integer
# calls that ION before 4.1.4 lacks (see include/README).

AM_CPPFLAGS = -I$(top_srcdir)/include $(ION_CFLAGS)

bin_PROGRAMS = bpsh bpshd

noinst_HEADERS = src/bpsh_proto.h src/bpshd_session.h

bpsh_SOURCES = src/bpsh.c src/bpsh_proto.c
bpsh_LDADD = $(ION_LIBS) -lpthread

bpshd_SOURCES = src/bpshd.c src/bpshd_session.c src/bpsh_proto.c
bpshd_LDADD = $(ION_LIBS) -lpthread

# --- fuzzing --- #
# tests/fuzz/fuzz_proto.c is a libFuzzer entry point over src/bpsh_proto.c.
# Under `make check` it is linked with a plain driver that replays its
# checked-in corpus, so the inputs the fuzzer once found interesting keep
# passing whatever the compiler.  `make fuzz` builds it with clang's
# libFuzzer and sanitizers and runs it for FUZZ_TIME seconds, starting from
# that corpus; anything it finds is left in fuzz-artifacts/.

FUZZ_DIR = $(srcdir)/tests/fuzz
check_PROGRAMS = fuzz_proto_replay
TESTS = fuzz_proto_replay
fuzz_proto_replay_SOURCES = tests/fuzz/fuzz_replay.c \
	tests/fuzz/fuzz_proto.c src/bpsh_proto.c
fuzz_proto_replay_CPPFLAGS = $(AM_CPPFLAGS) -I$(srcdir)/src \
	-DFUZZ_CORPUS=\"$(FUZZ_DIR)/corpus/proto\"
fuzz_proto_replay_LDADD = $(ION_LIBS) -lpthread

FUZZ_CC = clang
FUZZ_TIME = 60
FUZZ_JOBS = 4
FUZZ_CFLAGS = -g -O1 -fsanitize=fuzzer,address,undefined \
	-fno-sanitize-recover=undefined -I$(top_srcdir)/include $(ION_CFLAGS) \
	-I$(srcdir)/src

fuzz:
	$(MKDIR_P) fuzz-bin fuzz-corpus/proto fuzz-artifacts
	$(FUZZ_CC) $(FUZZ_CFLAGS) $(FUZZ_DIR)/fuzz_proto.c \
		$(srcdir)/src/bpsh_proto.c -o fuzz-bin/fuzz_proto $(ION_LIBS) -lpthread
	@echo "fuzzing proto for $(FUZZ_TIME) s..."
	@fuzz-bin/fuzz_proto fuzz-corpus/proto $(FUZZ_DIR)/corpus/proto \
		-max_total_time=$(FUZZ_TIME) -fork=$(FUZZ_JOBS) \
		-max_len=4096 -artifact_prefix=fuzz-artifacts/proto- \
		> fuzz-proto.log 2>&1; rc=$$?; tail -1 fuzz-proto.log; \
	if ls fuzz-artifacts/* >/dev/null 2>&1; then \
		echo "fuzzing found inputs, see fuzz-artifacts/:"; \
		ls fuzz-artifacts; exit 1; \
	fi; \
	exit $$rc

clean-local:
	rm -rf fuzz-bin fuzz-corpus fuzz-artifacts fuzz-*.log

.PHONY: fuzz

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
	examples/dirsync.sh \
	tests
