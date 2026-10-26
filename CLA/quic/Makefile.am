# QUIC convergence layer adapter for ION-DTN (ngtcp2 + GnuTLS).
#
# Builds the quiccla daemon against an installed ION-DTN.  bpP.h is a private
# ION header that ION does not install; a copy is vendored under the top-level
# include/ (see include/README).

AM_CPPFLAGS = -I$(top_srcdir)/include $(ION_CFLAGS) $(QUIC_CFLAGS)

bin_PROGRAMS = quiccla

noinst_HEADERS = src/quiccla.h src/quicsession.h src/quictls.h \
	src/quicmsg.h src/quicudp.h

# TLS backend (GnuTLS is the only one apt-installable today; an OpenSSL or
# wolfSSL quictls_*.c can be swapped in here behind the same interface).
QUIC_TLS_SOURCES = src/quictls_gnutls.c

quiccla_SOURCES = src/quiccla.c src/quicsession.c src/quicmsg.c \
	src/quicudp.c $(QUIC_TLS_SOURCES)
quiccla_LDADD = $(ION_LIBS) $(QUIC_LIBS) -lpthread

# --- unit tests (make check) --- #
# quicmsg is dependency-free (no ION/ngtcp2), so the test overrides the
# ION include path with the source dir only.

check_PROGRAMS = quicmsg_test
TESTS = quicmsg_test
quicmsg_test_SOURCES = tests/quicmsg_test.c src/quicmsg.c
quicmsg_test_CPPFLAGS = -I$(srcdir)/src

# --- fuzzing --- #
# tests/fuzz/fuzz_quicmsg.c is a libFuzzer entry point over src/quicmsg.c.
# Under `make check` it is linked with a plain driver that replays its
# checked-in corpus, so the inputs the fuzzer once found interesting keep
# passing whatever the compiler.  `make fuzz` builds it with clang's
# libFuzzer and sanitizers and runs it for FUZZ_TIME seconds, starting from
# that corpus; anything it finds is left in fuzz-artifacts/.

FUZZ_DIR = $(srcdir)/tests/fuzz
check_PROGRAMS += fuzz_quicmsg_replay
TESTS += fuzz_quicmsg_replay
fuzz_quicmsg_replay_SOURCES = tests/fuzz/fuzz_replay.c \
	tests/fuzz/fuzz_quicmsg.c src/quicmsg.c
fuzz_quicmsg_replay_CPPFLAGS = -I$(srcdir)/src \
	-DFUZZ_CORPUS=\"$(FUZZ_DIR)/corpus/quicmsg\"

FUZZ_CC = clang
FUZZ_TIME = 60
FUZZ_JOBS = 4
FUZZ_CFLAGS = -g -O1 -fsanitize=fuzzer,address,undefined \
	-fno-sanitize-recover=undefined -I$(srcdir)/src

fuzz:
	$(MKDIR_P) fuzz-bin fuzz-corpus/quicmsg fuzz-artifacts
	$(FUZZ_CC) $(FUZZ_CFLAGS) $(FUZZ_DIR)/fuzz_quicmsg.c \
		$(srcdir)/src/quicmsg.c -o fuzz-bin/fuzz_quicmsg
	@echo "fuzzing quicmsg for $(FUZZ_TIME) s..."
	@fuzz-bin/fuzz_quicmsg fuzz-corpus/quicmsg $(FUZZ_DIR)/corpus/quicmsg \
		-max_total_time=$(FUZZ_TIME) -fork=$(FUZZ_JOBS) \
		-max_len=4096 -artifact_prefix=fuzz-artifacts/quicmsg- \
		> fuzz-quicmsg.log 2>&1; rc=$$?; tail -1 fuzz-quicmsg.log; \
	if ls fuzz-artifacts/* >/dev/null 2>&1; then \
		echo "fuzzing found inputs, see fuzz-artifacts/:"; \
		ls fuzz-artifacts; exit 1; \
	fi; \
	exit $$rc

clean-local:
	rm -rf fuzz-bin fuzz-corpus fuzz-artifacts fuzz-*.log

.PHONY: fuzz

# --- man pages (generated from POD when pod2man is available) --- #

POD1 = doc/quiccla.pod

if HAVE_POD2MAN
man1_MANS = doc/quiccla.1
CLEANFILES = $(man1_MANS)

doc/%.1: doc/%.pod
	$(MKDIR_P) doc
	$(POD2MAN) -s 1 -c "ION-DTN-CONTRIB executables" $< $@
endif

EXTRA_DIST = \
	README.md \
	$(POD1) \
	tests
