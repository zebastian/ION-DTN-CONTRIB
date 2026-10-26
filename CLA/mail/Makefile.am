# Mail (SMTP/POP3) convergence layer adapter for ION-DTN (libcurl).
#
# Builds the mailcli / mailclo daemon pair against an installed ION-DTN.
# bpP.h is a private ION header that ION does not install; a copy is
# vendored under the top-level include/ (see include/README).

AM_CPPFLAGS = -I$(top_srcdir)/include $(ION_CFLAGS) $(CURL_CFLAGS)

bin_PROGRAMS = mailcli mailclo

noinst_HEADERS = src/mailcla.h src/mailmsg.h src/mailcurl.h

mailcli_SOURCES = src/mailcli.c src/mailcurl.c src/mailmsg.c
mailcli_LDADD = $(ION_LIBS) $(CURL_LIBS) -lpthread

mailclo_SOURCES = src/mailclo.c src/mailcurl.c src/mailmsg.c
mailclo_LDADD = $(ION_LIBS) $(CURL_LIBS) -lpthread

# --- unit tests (make check) --- #
# mailmsg is dependency-free (no ION/libcurl), so the test overrides the
# ION include path with the source dir only.

check_PROGRAMS = mailmsg_test
TESTS = mailmsg_test
mailmsg_test_SOURCES = tests/mailmsg_test.c src/mailmsg.c
mailmsg_test_CPPFLAGS = -I$(srcdir)/src

# --- fuzzing --- #
# tests/fuzz/fuzz_mailmsg.c is a libFuzzer entry point over src/mailmsg.c.
# Under `make check` it is linked with a plain driver that replays its
# checked-in corpus, so the inputs the fuzzer once found interesting keep
# passing whatever the compiler.  `make fuzz` builds it with clang's
# libFuzzer and sanitizers and runs it for FUZZ_TIME seconds, starting from
# that corpus; anything it finds is left in fuzz-artifacts/.

FUZZ_DIR = $(srcdir)/tests/fuzz
check_PROGRAMS += fuzz_mailmsg_replay
TESTS += fuzz_mailmsg_replay
fuzz_mailmsg_replay_SOURCES = tests/fuzz/fuzz_replay.c \
	tests/fuzz/fuzz_mailmsg.c src/mailmsg.c
fuzz_mailmsg_replay_CPPFLAGS = -I$(srcdir)/src \
	-DFUZZ_CORPUS=\"$(FUZZ_DIR)/corpus/mailmsg\"

FUZZ_CC = clang
FUZZ_TIME = 60
FUZZ_JOBS = 4
FUZZ_CFLAGS = -g -O1 -fsanitize=fuzzer,address,undefined \
	-fno-sanitize-recover=undefined -I$(srcdir)/src

fuzz:
	$(MKDIR_P) fuzz-bin fuzz-corpus/mailmsg fuzz-artifacts
	$(FUZZ_CC) $(FUZZ_CFLAGS) $(FUZZ_DIR)/fuzz_mailmsg.c \
		$(srcdir)/src/mailmsg.c -o fuzz-bin/fuzz_mailmsg
	@echo "fuzzing mailmsg for $(FUZZ_TIME) s..."
	@fuzz-bin/fuzz_mailmsg fuzz-corpus/mailmsg $(FUZZ_DIR)/corpus/mailmsg \
		-max_total_time=$(FUZZ_TIME) -fork=$(FUZZ_JOBS) \
		-max_len=4096 -artifact_prefix=fuzz-artifacts/mailmsg- \
		> fuzz-mailmsg.log 2>&1; rc=$$?; tail -1 fuzz-mailmsg.log; \
	if ls fuzz-artifacts/* >/dev/null 2>&1; then \
		echo "fuzzing found inputs, see fuzz-artifacts/:"; \
		ls fuzz-artifacts; exit 1; \
	fi; \
	exit $$rc

clean-local:
	rm -rf fuzz-bin fuzz-corpus fuzz-artifacts fuzz-*.log

.PHONY: fuzz

# --- man pages (generated from POD when pod2man is available) --- #

POD1 = doc/mailcli.pod doc/mailclo.pod

if HAVE_POD2MAN
man1_MANS = doc/mailcli.1 doc/mailclo.1
CLEANFILES = $(man1_MANS)

doc/%.1: doc/%.pod
	$(MKDIR_P) doc
	$(POD2MAN) -s 1 -c "ION-DTN-CONTRIB executables" $< $@
endif

EXTRA_DIST = \
	README.md \
	$(POD1) \
	tests
