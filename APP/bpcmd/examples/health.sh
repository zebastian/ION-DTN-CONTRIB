#!/bin/sh
# bpcmdd example handler: onboard computer health snapshot.
#
#   health.sh        one-line status: uptime, load, memory, CPU temp
#
# Read-only: reads /proc and /sys only, takes no arguments, no side effects.
# Suggested whitelist rule:  exact health.sh

# Uptime, in whole days.
up=$(cut -d. -f1 /proc/uptime)
days=$((up / 86400))

# 1-minute load average.
load=$(cut -d' ' -f1 /proc/loadavg)

# Memory in MiB: used = total - available.
total_kb=$(sed -n 's/^MemTotal:[ \t]*\([0-9]*\).*/\1/p' /proc/meminfo)
avail_kb=$(sed -n 's/^MemAvailable:[ \t]*\([0-9]*\).*/\1/p' /proc/meminfo)
[ -n "$avail_kb" ] || avail_kb=$(sed -n 's/^MemFree:[ \t]*\([0-9]*\).*/\1/p' \
    /proc/meminfo)
used_mb=$(((total_kb - avail_kb) / 1024))
total_mb=$((total_kb / 1024))

# CPU temperature from the first readable thermal zone, if any.
temp=NA
for z in /sys/class/thermal/thermal_zone*/temp; do
    [ -r "$z" ] || continue
    temp="$(($(cat "$z") / 1000))C"
    break
done

printf 'up %dd load %s mem %dM/%dM temp %s\n' \
    "$days" "$load" "$used_mb" "$total_mb" "$temp"
