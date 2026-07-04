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
