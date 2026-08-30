#!/bin/sh
# install-deps.sh — prerequisites for the TCPCLv4 CLA (GnuTLS).
#   (default)  build deps: GnuTLS dev (TLS 1.3, RFC 9174 4.4.3).
#   test       test deps:  openssl, for the loopback test's certificate.

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
test) PKGS="openssl" ;;
build) PKGS="libgnutls28-dev" ;;
*)
	echo "usage: $0 [test]" >&2
	exit 1
	;;
esac

if [ -n "$PKGS" ]; then
	# shellcheck disable=SC2086
	$SUDO "$APT_GET" install -y $PKGS
fi
