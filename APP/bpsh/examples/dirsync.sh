#!/usr/bin/env bash
# bpsh example: two-roundtrip directory sync over the Bundle Protocol.
#
# Mirrors the top-level files of a local directory onto a remote bpshd node
# in EXACTLY TWO request/response exchanges, regardless of file count.
# 
#   1. Pull the remote dir's per-file SHA-256 manifest; diff it locally.
#   2. Ship only the missing/changed files as one gzipped tar stream, which
#      the remote side extracts in bulk.
#
# Usage:
#   dirsync.sh -h <remoteEID> -l <localEID> [-k <secretfile>] \
#              <localdir> <remotedir>
#
# -k (or env BPSH_SECRET) authenticates to a secret-gated bpshd.

set -euo pipefail

usage() {
    echo "Usage: $0 -h <remoteEID> -l <localEID> [-k <secretfile>]" \
         "<localdir> <remotedir>" >&2
    exit 1
}

REMOTE= LOCAL= SECRET=
while getopts "h:l:k:" opt; do
    case "$opt" in
    h) REMOTE=$OPTARG ;;
    l) LOCAL=$OPTARG ;;
    k) SECRET=$OPTARG ;;
    *) usage ;;
    esac
done
shift $((OPTIND - 1))

LDIR=${1:-}
RDIR=${2:-}
[ -n "$REMOTE" ] && [ -n "$LOCAL" ] && [ -n "$LDIR" ] && [ -n "$RDIR" ] || usage
[ -d "$LDIR" ] || { echo "$0: '$LDIR' is not a directory" >&2; exit 1; }

BPSH=(bpsh -h "$REMOTE" -l "$LOCAL")
[ -n "$SECRET" ] && BPSH+=(-k "$SECRET")

# --- Roundtrip 1: pull the remote per-file SHA-256 manifest. ---
# Missing remote dir is fine (first sync) -- an empty manifest sends all.
manifest=$("${BPSH[@]}" -c \
    "cd '$RDIR' 2>/dev/null && for f in *; do [ -f \"\$f\" ] && \
     echo \"\$f \$(sha256sum \"\$f\" | cut -c1-64)\"; done" 2>/dev/null || true)

# Diff locally: a file missing remotely or with a different hash is sent.
to_send=()
shopt -s nullglob
for path in "$LDIR"/*; do
    [ -f "$path" ] || continue
    f=$(basename "$path")
    lsha=$(sha256sum "$path" | cut -c1-64)
    rsha=$(awk -v n="$f" '$1==n{print $2}' <<< "$manifest")
    [ "$lsha" != "$rsha" ] && to_send+=("$f")
done
shopt -u nullglob

if [ ${#to_send[@]} -eq 0 ]; then
    echo "up to date; nothing to send"
    exit 0
fi

# --- Roundtrip 2: ship needed files as one gzipped tar; remote extracts. ---
echo "sending ${#to_send[@]} file(s): ${to_send[*]}"
tar -C "$LDIR" -czf - "${to_send[@]}" | \
    "${BPSH[@]}" -c "mkdir -p '$RDIR' && tar -xzf - -C '$RDIR'"

echo "done"
