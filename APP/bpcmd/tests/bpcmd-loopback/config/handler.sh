#!/bin/sh
# bpcmdd loopback test handler.  In the new model the bundle payload IS the
# command line, so bpcmdd execs this script directly (empty stdin) with the
# payload's remaining tokens as our arguments.
#
# Proof of exec + env propagation: record "<source EID>|<args>" to
# $BPCMD_MARKER.  Reply path: echo the arguments back upper-cased on stdout.
printf '%s|%s\n' "$BP_SOURCE_EID" "$*" > "${BPCMD_MARKER:-/dev/null}"
printf '%s' "$*" | tr 'a-z' 'A-Z'
