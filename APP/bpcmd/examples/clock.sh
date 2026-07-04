#!/bin/sh
# bpcmdd example handler: spacecraft-style UTC time reference, wired to ION.
#
# ION tracks UTC as a correction to the free-running onboard clock:
# utcdelta (IonDB.deltaFromUTC, seconds: local clock minus correct UTC) and
# utcerror (IonDB.maxClockError, seconds, 0-60).  ION's corrected time is
# getCtime() = systemtime - utcdelta.  This handler NEVER sets the system
# clock; it only reads and writes ION's corrections, via ionadmin:
#
#   clock.sh get                 report sys time, utcdelta, utcerror, and
#                                ION's corrected UTC (from "ionadmin i clock")
#   clock.sh set <delta> <err>   set utcdelta and utcerror
#                                ("ionadmin m utcdelta" / "m clockerr")
#
# Suggested whitelist rules:
#   exact clock.sh get
#   regex clock.sh set -?[0-9]+ [0-9]+

IONADMIN="${IONADMIN:-ionadmin}"

# fmt <epoch>: ISO 8601 UTC.
fmt() {
    date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ
}

case "$1" in
get)
    line=$(printf 'i clock\n' | "$IONADMIN" 2>/dev/null)
    delta=$(echo "$line" | sed -n 's/.*utcdelta \(-\{0,1\}[0-9]\{1,\}\).*/\1/p')
    error=$(echo "$line" | sed -n 's/.*clockerr \([0-9]\{1,\}\).*/\1/p')
    ct=$(echo "$line" | sed -n 's/.*ctime \([0-9]\{1,\}\).*/\1/p')
    st=$(echo "$line" | sed -n 's/.*systime \([0-9]\{1,\}\).*/\1/p')
    if [ -z "$ct" ]; then
        echo "clock.sh: can't read ION clock (is the node running?)" >&2
        exit 1
    fi
    printf 'sys=%s\nutcdelta=%ss\nutcerror=%ss\nutc=%s\n' \
        "$(fmt "$st")" "$delta" "$error" "$(fmt "$ct")"
    ;;
set)
    case "$2" in -[0-9]* | [0-9]*) ;; *)
        echo "clock.sh: delta must be an integer" >&2; exit 1 ;;
    esac
    case "$3" in [0-9]*) ;; *)
        echo "clock.sh: error must be a non-negative integer" >&2; exit 1 ;;
    esac
    if [ "$3" -gt 60 ]; then
        echo "clock.sh: error must be 0-60 seconds (ION limit)" >&2; exit 1
    fi
    printf 'm utcdelta %s\nm clockerr %s\n' "$2" "$3" | "$IONADMIN" >/dev/null 2>&1
    printf 'utcdelta=%ss\nutcerror=%ss\n' "$2" "$3"
    ;;
*)
    echo "usage: clock.sh get | set <delta> <error>" >&2
    exit 1 ;;
esac
