#!/bin/sh
# install-deps.sh — install prerequisites for ION-DTN-CONTRIB.
#
# Build mode (default) installs the general toolchain plus each selected
# contribution's build dependencies.  Test mode (leading "test" argument)
# installs each selected contribution's runtime test dependencies instead.
#
# Usage:
#   ./install-deps.sh                     general build deps only
#   ./install-deps.sh ALL                 build deps for every contribution
#   ./install-deps.sh CLA_MQTT [...]      build deps for the named contribution(s)
#   ./install-deps.sh test                test deps for every contribution
#   ./install-deps.sh test CLA_MQTT [...] test deps for the named contribution(s)
#
# Tokens map <KIND>_<NAME> to <KIND>/<name>: CLA_MQTT -> CLA/mqtt.  Each
# contribution's install-deps.sh accepts the same "test" argument.
#
# Debian/Ubuntu (apt) only.  ION-DTN itself must already be installed from
# source; it is not available as a package and is not installed here.
#
# Honoured environment variables (also passed to the per-contribution scripts):
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

mode=build
if [ "${1:-}" = test ]; then
	mode=test
	shift
fi

$SUDO "$APT_GET" update

if [ "$mode" = build ]; then
	# General toolchain: autotools build + pod2man (perl) for the man pages.
	GENERAL_PKGS="build-essential autoconf automake libtool pkg-config perl"
	echo ">> Installing general build prerequisites"
	# shellcheck disable=SC2086
	$SUDO "$APT_GET" install -y $GENERAL_PKGS
fi

# Test mode with no tokens means every contribution.
if [ "$mode" = test ] && [ "$#" -eq 0 ]; then
	set -- ALL
fi

contribs=
for arg in "$@"; do
	case $arg in
	ALL)
		for d in "$ROOT"/CLA/*/ "$ROOT"/APP/*/; do
			[ -d "$d" ] || continue
			contribs="$contribs ${d%/}"
		done
		;;
	CLA_* | APP_*)
		kind=${arg%%_*}
		name=$(printf '%s' "${arg#*_}" | tr 'A-Z' 'a-z')
		dir="$ROOT/$kind/$name"
		if [ ! -d "$dir" ]; then
			echo "error: unknown contribution '$arg' (no $dir)" >&2
			exit 1
		fi
		contribs="$contribs $dir"
		;;
	*)
		echo "error: unrecognised argument '$arg'" >&2
		echo "       expected ALL or CLA_<NAME> / APP_<NAME> tokens." >&2
		exit 1
		;;
	esac
done

testarg=
[ "$mode" = test ] && testarg=test

for dir in $contribs; do
	script="$dir/install-deps.sh"
	name=${dir#"$ROOT"/}
	label="build prerequisites"
	[ "$mode" = test ] && label="test prerequisites"
	if [ -x "$script" ]; then
		echo ">> Installing $label for $name"
		"$script" $testarg
	elif [ -f "$script" ]; then
		echo ">> Installing $label for $name"
		sh "$script" $testarg
	else
		echo ">> $name has no install-deps.sh, skipping"
	fi
done

echo ">> Done."
