#!/bin/sh
# test.sh — run the test suites bundled with the ION-DTN-CONTRIB contributions.
#
# Exercises each selected convergence-layer adapter's tests/ folder, running
# every test directory's `dotest` (ION's test convention: exit 0 = pass) and
# its `cleanup` afterwards.
#
# Usage:
#   ./test.sh                  run every CLA's tests (same as ALL)
#   ./test.sh ALL              run every CLA's tests
#   ./test.sh CLA_MQTT [...]   run only the named CLA(s)
#
# CLA tokens map to directories under CLA/: CLA_MQTT -> CLA/mqtt.
#
# A test directory marked `.optional` (e.g. one needing an external broker)
# that fails is reported but does NOT fail the overall run; any non-optional
# failure makes test.sh exit non-zero. If a CLA provides its own
# tests/runtests script it is used instead of the built-in loop.

set -u

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

pass=0
fail=0
optfail=0
skip=0

# Run a single test directory: $1 = absolute path to the test dir.
run_one() {
	tdir=$1
	name=${tdir#"$ROOT"/}
	if [ ! -x "$tdir/dotest" ] && [ ! -f "$tdir/dotest" ]; then
		return
	fi
	echo "==== TEST: $name ===="
	(
		cd "$tdir" || exit 99
		if [ -x ./dotest ]; then
			./dotest
		else
			sh ./dotest
		fi
	)
	rc=$?
	# Best-effort cleanup, regardless of result.
	if [ -x "$tdir/cleanup" ]; then
		(cd "$tdir" && ./cleanup) >/dev/null 2>&1 || true
	elif [ -f "$tdir/cleanup" ]; then
		(cd "$tdir" && sh ./cleanup) >/dev/null 2>&1 || true
	fi
	if [ "$rc" -eq 0 ]; then
		echo "---- PASS: $name"
		pass=$((pass + 1))
	elif [ -f "$tdir/.optional" ]; then
		echo "---- OPTIONAL FAIL ($rc): $name"
		optfail=$((optfail + 1))
	else
		echo "---- FAIL ($rc): $name"
		fail=$((fail + 1))
	fi
}

# Run all tests for one CLA: $1 = absolute path to the CLA dir.
run_cla() {
	cdir=$1
	cname=${cdir#"$ROOT"/}
	if [ -x "$cdir/tests/runtests" ]; then
		echo ">> $cname: using its own tests/runtests"
		(cd "$cdir/tests" && ./runtests) || fail=$((fail + 1))
		return
	fi
	if [ ! -d "$cdir/tests" ]; then
		echo ">> $cname has no tests/, skipping"
		skip=$((skip + 1))
		return
	fi
	echo ">> $cname: running tests"
	for t in "$cdir"/tests/*/; do
		[ -d "$t" ] || continue
		run_one "${t%/}"
	done
}

# Resolve the list of CLA directories from the arguments (default: ALL).
clas=
if [ "$#" -eq 0 ]; then
	set -- ALL
fi
for arg in "$@"; do
	case $arg in
	ALL)
		for d in "$ROOT"/CLA/*/; do
			[ -d "$d" ] || continue
			clas="$clas ${d%/}"
		done
		;;
	CLA_*)
		name=$(printf '%s' "${arg#CLA_}" | tr 'A-Z' 'a-z')
		dir="$ROOT/CLA/$name"
		if [ ! -d "$dir" ]; then
			echo "error: unknown CLA '$arg' (no $dir)" >&2
			exit 1
		fi
		clas="$clas $dir"
		;;
	*)
		echo "error: unrecognised argument '$arg'" >&2
		echo "       expected ALL or CLA_<NAME> tokens." >&2
		exit 1
		;;
	esac
done

for dir in $clas; do
	run_cla "$dir"
done

echo
echo "======== SUMMARY ========"
echo "  passed:        $pass"
echo "  failed:        $fail"
echo "  optional-fail: $optfail"
echo "  skipped:       $skip"

[ "$fail" -eq 0 ]
