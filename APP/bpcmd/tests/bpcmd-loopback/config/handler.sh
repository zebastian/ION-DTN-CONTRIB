#!/bin/sh
# bpcmdd test handler.  bpcmdd forks this per bundle, pipes the payload to
# stdin, and returns whatever we write to stdout.
#
# Side-effect (proof of exec + env propagation): record the source EID, the
# payload length, and the payload to $BPCMD_MARKER.
# Reply (proof of the reply path): the upper-cased payload on stdout.

payload=$(cat)

printf '%s|%s|%s\n' "$BP_SOURCE_EID" "$BP_PAYLOAD_LEN" "$payload" \
	> "${BPCMD_MARKER:-/dev/null}"

printf '%s' "$payload" | tr 'a-z' 'A-Z'
