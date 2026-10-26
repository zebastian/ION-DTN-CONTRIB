# TCPCLv4 convergence layer adapter for ION-DTN (RFC 9174, TLS 1.3).
#
# Builds the tcpv4cla daemon against an installed ION-DTN.  bpP.h is a private
# ION header that ION does not install; a copy is vendored under the top-level
# include/ (see include/README).

AM_CPPFLAGS = -I$(top_srcdir)/include $(ION_CFLAGS) $(TCPV4_CFLAGS)

bin_PROGRAMS = tcpv4cla

noinst_HEADERS = src/tcpv4cla.h src/tcpv4session.h src/tcpv4sessint.h \
	src/tcpv4tls.h src/tcpv4x509.h src/tcpv4msg.h src/tcpv4nodeid.h

# TLS backend, chosen by configure (--with-tcpv4-tls).  RFC 9174 4.4.3
# mandates TLS 1.3; GnuTLS and Mbed TLS both ship here, and a further
# tcpv4tls_*.c can be swapped in behind the same interface.  The certificate
# decoding neither library does for us is shared rather than written twice.
if TCPV4_TLS_MBEDTLS
TCPV4_TLS_SOURCES = src/tcpv4tls_mbedtls.c src/tcpv4x509.c
else
TCPV4_TLS_SOURCES = src/tcpv4tls_gnutls.c src/tcpv4x509.c
endif

# The session engine is split by layer: message I/O, negotiation, the receive
# path, the send path, and the engine itself (session list and threads).
TCPV4_SESSION_SOURCES = src/tcpv4session.c src/tcpv4io.c \
	src/tcpv4negotiate.c src/tcpv4rx.c src/tcpv4tx.c

tcpv4cla_SOURCES = src/tcpv4cla.c src/tcpv4cfg.c $(TCPV4_SESSION_SOURCES) \
	src/tcpv4msg.c src/tcpv4nodeid.c $(TCPV4_TLS_SOURCES)
tcpv4cla_LDADD = $(ION_LIBS) $(TCPV4_LIBS) -lpthread

# --- unit tests (make check) --- #
# tcpv4msg, tcpv4nodeid and tcpv4x509 are dependency-free (no ION, no TLS
# library), so their tests override the ION include path with the source
# dir only.

check_PROGRAMS = tcpv4msg_test tcpv4nodeid_test tcpv4x509_test \
	fuzz_msg_replay fuzz_nodeid_replay fuzz_x509_replay
TESTS = tcpv4msg_test tcpv4nodeid_test tcpv4x509_test \
	fuzz_msg_replay fuzz_nodeid_replay fuzz_x509_replay
tcpv4msg_test_SOURCES = tests/tcpv4msg_test.c src/tcpv4msg.c
tcpv4msg_test_CPPFLAGS = -I$(srcdir)/src
tcpv4nodeid_test_SOURCES = tests/tcpv4nodeid_test.c src/tcpv4nodeid.c
tcpv4nodeid_test_CPPFLAGS = -I$(srcdir)/src
tcpv4x509_test_SOURCES = tests/tcpv4x509_test.c src/tcpv4x509.c
tcpv4x509_test_CPPFLAGS = -I$(srcdir)/src

# --- fuzzing --- #
# The fuzz targets in tests/fuzz are libFuzzer entry points over the same
# dependency-free units.  Under `make check` each is linked with a plain
# driver that replays its checked-in corpus, so the inputs the fuzzer once
# found interesting keep passing whatever the compiler.  `make fuzz` builds
# them with clang's libFuzzer and sanitizers and runs each for FUZZ_TIME
# seconds, starting from that corpus; anything it finds is left in
# fuzz-artifacts/.

FUZZ_DIR = $(srcdir)/tests/fuzz
fuzz_msg_replay_SOURCES = tests/fuzz/fuzz_replay.c tests/fuzz/fuzz_msg.c \
	src/tcpv4msg.c
fuzz_msg_replay_CPPFLAGS = -I$(srcdir)/src \
	-DFUZZ_CORPUS=\"$(FUZZ_DIR)/corpus/msg\"
fuzz_nodeid_replay_SOURCES = tests/fuzz/fuzz_replay.c \
	tests/fuzz/fuzz_nodeid.c src/tcpv4nodeid.c
fuzz_nodeid_replay_CPPFLAGS = -I$(srcdir)/src \
	-DFUZZ_CORPUS=\"$(FUZZ_DIR)/corpus/nodeid\"
fuzz_x509_replay_SOURCES = tests/fuzz/fuzz_replay.c tests/fuzz/fuzz_x509.c \
	src/tcpv4x509.c
fuzz_x509_replay_CPPFLAGS = -I$(srcdir)/src \
	-DFUZZ_CORPUS=\"$(FUZZ_DIR)/corpus/x509\"

FUZZ_CC = clang
FUZZ_TIME = 60
FUZZ_JOBS = 4
FUZZ_CFLAGS = -g -O1 -fsanitize=fuzzer,address,undefined \
	-fno-sanitize-recover=undefined -I$(srcdir)/src

fuzz:
	$(MKDIR_P) fuzz-bin fuzz-corpus fuzz-artifacts
	$(FUZZ_CC) $(FUZZ_CFLAGS) $(FUZZ_DIR)/fuzz_msg.c \
		$(srcdir)/src/tcpv4msg.c -o fuzz-bin/fuzz_msg
	$(FUZZ_CC) $(FUZZ_CFLAGS) $(FUZZ_DIR)/fuzz_nodeid.c \
		$(srcdir)/src/tcpv4nodeid.c -o fuzz-bin/fuzz_nodeid
	$(FUZZ_CC) $(FUZZ_CFLAGS) $(FUZZ_DIR)/fuzz_x509.c \
		$(srcdir)/src/tcpv4x509.c -o fuzz-bin/fuzz_x509
	@fail=0; for t in msg nodeid x509; do \
		$(MKDIR_P) fuzz-corpus/$$t; \
		echo "fuzzing $$t for $(FUZZ_TIME) s..."; \
		fuzz-bin/fuzz_$$t fuzz-corpus/$$t $(FUZZ_DIR)/corpus/$$t \
			-max_total_time=$(FUZZ_TIME) -fork=$(FUZZ_JOBS) \
			-max_len=4096 -artifact_prefix=fuzz-artifacts/$$t- \
			> fuzz-$$t.log 2>&1 || fail=1; \
		tail -1 fuzz-$$t.log; \
	done; \
	if ls fuzz-artifacts/* >/dev/null 2>&1; then \
		echo "fuzzing found inputs, see fuzz-artifacts/:"; \
		ls fuzz-artifacts; exit 1; \
	fi; \
	exit $$fail

clean-local:
	rm -rf fuzz-bin fuzz-corpus fuzz-artifacts fuzz-*.log

.PHONY: fuzz

# --- man pages (generated from POD when pod2man is available) --- #

POD1 = doc/tcpv4cla.pod

if HAVE_POD2MAN
man1_MANS = doc/tcpv4cla.1
CLEANFILES = $(man1_MANS)

doc/%.1: doc/%.pod
	$(MKDIR_P) doc
	$(POD2MAN) -s 1 -c "ION-DTN-CONTRIB executables" $< $@
endif

EXTRA_DIST = \
	README.md \
	$(POD1) \
	tests \
	bench
