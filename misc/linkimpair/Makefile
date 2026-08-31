# linkimpair is a benchmarking helper, not part of the contrib build: it needs
# libnetfilter_queue and root to run, neither of which the CLAs themselves do.
#
#   make            build linkimpair
#   make clean

CC      ?= cc
CFLAGS  ?= -O2 -g -Wall -Wextra
LDLIBS  := $(shell pkg-config --libs libnetfilter_queue 2>/dev/null || \
	echo -lnetfilter_queue -lnfnetlink)
CFLAGS  += $(shell pkg-config --cflags libnetfilter_queue 2>/dev/null)

all: linkimpair

linkimpair: linkimpair.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f linkimpair

.PHONY: all clean
