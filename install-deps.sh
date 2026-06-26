#!/bin/sh
# install-deps.sh — install build prerequisites for ION-DTN-CONTRIB.
#
# Installs the general toolchain needed to build the contributions, then runs
# the per-CLA dependency installer (CLA/<name>/install-deps.sh) for each
# convergence-layer adapter you select.
#
# Usage:
#   ./install-deps.sh                  general build deps only
#   ./install-deps.sh ALL              general deps + every CLA under CLA/
#   ./install-deps.sh CLA_MQTT [...]   general deps + the named CLA(s)
#
# CLA tokens map to directories under CLA/: CLA_MQTT -> CLA/mqtt.
#
# Debian/Ubuntu (apt) only. ION-DTN itself must already be installed from
# source; it is not available as a package and is not installed here.
#
# Honoured environment variables (also passed to the per-CLA scripts):
#   APT_GET   apt front-end to use      (default: apt-get)
#   SUDO      privilege-escalation cmd  (default: sudo, empty when run as root)

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

APT_GET=${APT_GET:-apt-get}
if [ -z "${SUDO+set}" ]; then
	if [ "$(id -u)" -eq 0 ]; then
		SUDO=
	else
		SUDO=sudo
	fi
fi
export APT_GET SUDO

if ! command -v "$APT_GET" >/dev/null 2>&1; then
	echo "error: '$APT_GET' not found; this installer targets Debian/Ubuntu." >&2
	echo "       Install the equivalent packages with your package manager." >&2
	exit 1
fi

# General toolchain: autotools build + pod2man (perl) for the man pages.
GENERAL_PKGS="build-essential autoconf automake libtool pkg-config perl"

echo ">> Installing general build prerequisites"
$SUDO "$APT_GET" update
# shellcheck disable=SC2086
$SUDO "$APT_GET" install -y $GENERAL_PKGS

# Resolve the list of CLA install scripts to run.
clas=
for arg in "$@"; do
	case $arg in
	ALL)
		for d in "$ROOT"/CLA/*/; do
			[ -d "$d" ] || continue
			clas="$clas $d"
		done
		;;
	CLA_*)
		name=$(printf '%s' "${arg#CLA_}" | tr 'A-Z' 'a-z')
		dir="$ROOT/CLA/$name"
		if [ ! -d "$dir" ]; then
			echo "error: unknown CLA '$arg' (no $dir)" >&2
			exit 1
		fi
		clas="$clas $dir/"
		;;
	*)
		echo "error: unrecognised argument '$arg'" >&2
		echo "       expected ALL or CLA_<NAME> tokens." >&2
		exit 1
		;;
	esac
done

for dir in $clas; do
	script="$dir/install-deps.sh"
	if [ -x "$script" ]; then
		echo ">> Installing prerequisites for ${dir#"$ROOT"/}"
		"$script"
	elif [ -f "$script" ]; then
		echo ">> Installing prerequisites for ${dir#"$ROOT"/}"
		sh "$script"
	else
		echo ">> ${dir#"$ROOT"/} has no install-deps.sh, skipping"
	fi
done

echo ">> Done."
