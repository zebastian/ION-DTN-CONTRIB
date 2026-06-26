#!/bin/sh
# install-deps.sh — install build prerequisites for the MQTT CLA.
#
# Pulls in the Eclipse Paho MQTT C client (TLS-capable) and its headers.
# Invoked by the top-level install-deps.sh, but may be run on its own.
#
# Honoured environment variables:
#   APT_GET   apt front-end to use      (default: apt-get)
#   SUDO      privilege-escalation cmd  (default: sudo, empty when run as root)

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

# libpaho-mqtt-dev provides the TLS-capable libpaho-mqtt3cs the CLA prefers
# (and the non-TLS libpaho-mqtt3c fallback); libpaho-mqtt1.3 is the runtime.
$SUDO "$APT_GET" install -y libpaho-mqtt-dev libpaho-mqtt1.3
