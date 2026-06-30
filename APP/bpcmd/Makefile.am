# bpcmdd — Bundle Protocol command daemon, for ION-DTN.
#
# Listens on a BP endpoint and, for each delivered bundle, forks a
# user-supplied command, pipes the payload to its stdin, and returns its
# stdout to the source.  Builds against an installed ION-DTN; only ION's
# public header (bp.h) is used.

AM_CPPFLAGS = $(ION_CFLAGS)

bin_PROGRAMS = bpcmdd

bpcmdd_SOURCES = src/bpcmdd.c
bpcmdd_LDADD = $(ION_LIBS)

# --- man page (generated from POD when pod2man is available) --- #

POD1 = doc/bpcmdd.pod

if HAVE_POD2MAN
man1_MANS = doc/bpcmdd.1
CLEANFILES = $(man1_MANS)

doc/%.1: doc/%.pod
	$(MKDIR_P) doc
	$(POD2MAN) -s 1 -c "ION-DTN-CONTRIB executables" $< $@
endif

EXTRA_DIST = \
	README.md \
	$(POD1)
