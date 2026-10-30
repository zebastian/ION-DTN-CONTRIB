#!/bin/sh
# install-deps.sh — prerequisites for the quota CLA.
#   (default)  build deps: none beyond ION.
#   test       test deps:  none beyond ION's own udpcli/udpclo and bp
#              test tools, which the loopback test uses.

set -eu

case "${1:-build}" in
test | build) exit 0 ;;
*)
	echo "usage: $0 [test]" >&2
	exit 1
	;;
esac
