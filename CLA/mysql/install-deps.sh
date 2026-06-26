#!/bin/sh
# install-deps.sh — prerequisites for the MySQL CLA.
#   (default)  build deps: MariaDB client dev library (MySQL C API).
#   test       test deps:  a local MariaDB server + client for the loopback test.

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
test) PKGS="mariadb-server mariadb-client" ;;
build) PKGS="libmariadb-dev libmariadb3" ;;
*)
	echo "usage: $0 [test]" >&2
	exit 1
	;;
esac

# shellcheck disable=SC2086
$SUDO "$APT_GET" install -y $PKGS
