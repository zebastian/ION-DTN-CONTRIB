# TCPCLv4 convergence layer adapter for ION-DTN (RFC 9174, GnuTLS).
#
# Builds the tcpv4cla daemon against an installed ION-DTN.  bpP.h is a private
# ION header that ION does not install; a copy is vendored under the top-level
# include/ (see include/README).

AM_CPPFLAGS = -I$(top_srcdir)/include $(ION_CFLAGS) $(TCPV4_CFLAGS)

bin_PROGRAMS = tcpv4cla

noinst_HEADERS = src/tcpv4cla.h src/tcpv4session.h src/tcpv4sessint.h \
	src/tcpv4tls.h src/tcpv4msg.h

# TLS backend.  RFC 9174 4.4.3 mandates TLS 1.3; GnuTLS is the backend that
# ships here, and an OpenSSL tcpv4tls_*.c can be swapped in behind the same
# interface.
TCPV4_TLS_SOURCES = src/tcpv4tls_gnutls.c

# The session engine is split by layer: message I/O, negotiation, the receive
# path, the send path, and the engine itself (session list and threads).
TCPV4_SESSION_SOURCES = src/tcpv4session.c src/tcpv4io.c \
	src/tcpv4negotiate.c src/tcpv4rx.c src/tcpv4tx.c

tcpv4cla_SOURCES = src/tcpv4cla.c $(TCPV4_SESSION_SOURCES) src/tcpv4msg.c \
	$(TCPV4_TLS_SOURCES)
tcpv4cla_LDADD = $(ION_LIBS) $(TCPV4_LIBS) -lpthread

# --- unit tests (make check) --- #
# tcpv4msg is dependency-free (no ION/GnuTLS), so the test overrides the
# ION include path with the source dir only.

check_PROGRAMS = tcpv4msg_test
TESTS = tcpv4msg_test
tcpv4msg_test_SOURCES = tests/tcpv4msg_test.c src/tcpv4msg.c
tcpv4msg_test_CPPFLAGS = -I$(srcdir)/src

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
