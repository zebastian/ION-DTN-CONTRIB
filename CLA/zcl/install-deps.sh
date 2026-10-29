#!/bin/sh
# install-deps.sh — prerequisites for the zcl CLA.
#   (default)  build deps: libzstd development headers.
#   test       test deps:  none beyond ION's own udpcli/udpclo, which
#              carry the compressed carriers in the loopback test.

set -eu

APT_GET=${APT_GET:-apt-get}
if [ -z "${SUDO+set}" ]; then
	if [ "$(id -u)" -eq 0 ]; then
		SUDO=
	else
		SUDO=sudo
	fi
fi

if ! command -v "$APT_GET" >/dev/null 2>&1; then
	echo "error: '$APT_GET' not found; this installer targets Debian/Ubuntu." >&2
	exit 1
fi

case "${1:-build}" in
test) exit 0 ;;
build) PKGS="libzstd-dev pkg-config" ;;
*)
	echo "usage: $0 [test]" >&2
	exit 1
	;;
esac

# shellcheck disable=SC2086
$SUDO "$APT_GET" install -y $PKGS
