#!/bin/sh
# install-deps.sh — install build prerequisites for the MySQL CLA.
#
# Pulls in the MariaDB client development library (which provides the
# MySQL C API and mariadb_config, and works against both MySQL and
# MariaDB servers), plus the command-line client used by the loopback
# test.  Invoked by the top-level install-deps.sh, but may be run on
# its own.
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

$SUDO "$APT_GET" install -y libmariadb-dev libmariadb3 mariadb-client
