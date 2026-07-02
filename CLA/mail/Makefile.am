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
