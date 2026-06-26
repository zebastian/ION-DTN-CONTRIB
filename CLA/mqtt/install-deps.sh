#!/bin/sh
# install-deps.sh — prerequisites for the MQTT CLA.
#   (default)  build deps: Eclipse Paho MQTT C client (TLS-capable) + headers.
#   test       test deps:  a local mosquitto broker + clients for the loopback test.

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
test) PKGS="mosquitto mosquitto-clients" ;;
build) PKGS="libpaho-mqtt-dev libpaho-mqtt1.3" ;;
*)
	echo "usage: $0 [test]" >&2
	exit 1
	;;
esac

# shellcheck disable=SC2086
$SUDO "$APT_GET" install -y $PKGS
