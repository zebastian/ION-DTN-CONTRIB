#!/bin/sh
# install-deps.sh — prerequisites for the TCPCLv4 CLA.
#   (default)  build deps: GnuTLS dev (TLS 1.3, RFC 9174 4.4.3).
#   mbedtls    build deps: Mbed TLS dev, the alternative TLS backend
#              (--with-tcpv4-tls=mbedtls).  Note that the packaged Mbed TLS
#              is 3.6 or later only on recent distributions; the backend
#              needs 3.6 for TLS 1.3, and configure says so if it is older.
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
mbedtls) PKGS="libmbedtls-dev" ;;
*)
	echo "usage: $0 [mbedtls|test]" >&2
	exit 1
	;;
esac

if [ -n "$PKGS" ]; then
	# shellcheck disable=SC2086
	$SUDO "$APT_GET" install -y $PKGS
fi
