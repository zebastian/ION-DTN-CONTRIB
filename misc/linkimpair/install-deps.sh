#!/bin/sh
# install-deps.sh - prerequisites for linkimpair (libnetfilter_queue).

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

# shellcheck disable=SC2086
$SUDO "$APT_GET" install -y libnetfilter-queue-dev iptables
