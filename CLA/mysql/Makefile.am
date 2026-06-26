# MySQL convergence layer adapter for ION-DTN.
#
# Builds the mysqlcli / mysqlclo daemon pair against an installed
# ION-DTN and a MySQL/MariaDB client library.  bpP.h is a private ION
# header that ION does not install; a copy is vendored under the
# top-level include/ (see include/README) so this builds without an
# ION source tree.

AM_CPPFLAGS = -I$(top_srcdir)/include $(ION_CFLAGS) $(MYSQL_CFLAGS)

bin_PROGRAMS = mysqlcli mysqlclo

noinst_HEADERS = src/mysqlcla.h

mysqlcli_SOURCES = src/mysqlcli.c
mysqlcli_LDADD = $(ION_LIBS) $(MYSQL_LIBS) -lpthread

mysqlclo_SOURCES = src/mysqlclo.c
mysqlclo_LDADD = $(ION_LIBS) $(MYSQL_LIBS) -lpthread

# --- man pages (generated from POD when pod2man is available) --- #

POD1 = doc/mysqlcli.pod doc/mysqlclo.pod

if HAVE_POD2MAN
man1_MANS = doc/mysqlcli.1 doc/mysqlclo.1
CLEANFILES = $(man1_MANS)

doc/%.1: doc/%.pod
	$(MKDIR_P) doc
	$(POD2MAN) -s 1 -c "ION-DTN-CONTRIB executables" $< $@
endif

EXTRA_DIST = \
	README.md \
	$(POD1) \
	tests
