#!/bin/sh
# install-deps.sh — install prerequisites for bpsh / bpshd.
#
# bpsh and bpshd build against an installed ION-DTN with only the general
# toolchain (no extra libraries). This installs rsync, which the loopback
# test's directory-sync case exercises over bpsh.
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

$SUDO "$APT_GET" install -y rsync
