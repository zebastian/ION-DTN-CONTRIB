#!/bin/sh
# install-deps.sh — prerequisites for the mail CLA.
#   (default)  build deps: libcurl development headers (SMTP + POP3).
#   test       test deps:  Python 3 (the loopback test uses a bundled
#              SMTP/POP3 mock server; no external mail server needed).

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
test) PKGS="python3" ;;
build) PKGS="libcurl4-openssl-dev" ;;
*)
	echo "usage: $0 [test]" >&2
	exit 1
	;;
esac

# shellcheck disable=SC2086
$SUDO "$APT_GET" install -y $PKGS
