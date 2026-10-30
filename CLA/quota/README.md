# quota - Traffic Shaping CLA (quotaclo / quotaadmin)

A convergence layer adapter that shapes the bundles ION queues for a
neighbor by operator rules - matched on source, destination or previous
hop - and moves those within quota, unchanged, onto the real link.  Its
main use is rate limiting one data producer; the same rules express
daily or monthly byte and bundle budgets.  Nothing changes on the wire
and the neighbor needs nothing.

- `quotaclo` - output daemon: matches, charges quotas, hands bundles on
- `quotaadmin` - rules: added, changed and inspected while ION runs

The design - where it plugs in, why there, and what that costs - is in
[doc/design.md](doc/design.md).

## Features

- Rules per quota duct, matching `src`, `dst` and `prev` EID patterns
  (`ipn:7.*`, `ipn:100-199.*`, `dtn://host/*`, ...); a bundle passes only
  if every matching rule has room
- Quotas as token buckets: `bytes 1M/1s`, `bundles 50000/1d`, several
  per rule; the timeframe sets the burst
- Over quota a bundle waits in ION's own storage: it expires normally
  and survives a restart; held bundles of one producer never block
  another's
- Optional hold bound per rule, beyond which bundles are dropped (with a
  "traffic pared" status report), stall the duct, or are re-forwarded
- Changes take effect at once: held bundles are looked at again
- Quota levels and counters survive a restart (state file in ION's
  working directory)
- Refuses a setup that would let bundles past it

## Layout

```
src/quotarules.{h,c}  patterns, units, token buckets, state file; no ION
src/quotacl.h         shared definitions of the daemons
src/quotaclo.c        output daemon
src/quotaadmin.c      rules administration
doc/design.md         design
doc/*.pod             man page sources (quotaclo, quotaadmin)
tests/quotarules_test.c   unit tests: units, patterns, rules, buckets, state
tests/fuzz/               libFuzzer target for quotarules, and its corpus
tests/loopback-quota/     one ION node sending to itself through quota
                          onto UDP
```

## Build

Needs nothing beyond ION.

```bash
./configure --enable-cla-quota
make && sudo make install
```

## Configuration

Node 10 limits producer `ipn:7.1` to 1 MB/s towards node 20, over LTP:

```
# bprc on node 10
a protocol quota 26                      # class "any": every bundle takes it
a outduct ltp 20 ltpclo                  # the real link: in no plan
a outduct quota 20 'quotaclo ltp/20'     # the shaper, handing off to it
a plan ipn:20.0
a planduct ipn:20.0 quota 20
r 'quotaadmin node10.quotarc'

# node10.quotarc
1
a rule cam quota/20 src ipn:7.1
a quota cam bytes 1M/1s
```

The target duct must be in no plan - don't use the `a plan ipn:20.0
ltp/20` shorthand for it - or bpclm could hand bundles to it directly;
quotaclo refuses to start on such a target.  The quota duct takes the
target's max payload length by itself.

More rules:

```
a rule cam quota/20 src ipn:7.* hold 10M drop   # hold at most 10 MB, then drop
a quota cam bundles 50000/1d                    # a second quota on the rule
a rule gw quota/20 prev ipn:30.0 dst ipn:20-29.*
a quota gw bytes 10G/1d
c quota cam bytes 2M/1s                         # level carries over
i rule cam                                      # levels and counters
l rule                                          # rules, as commands
r rule cam                                      # quotas back to full
```

Counts take k, M, G (powers of ten), timeframes s, m, h, d.  See
`quotaadmin(1)` for every command and `quotaclo(1)` for the daemon.

ionconfig's `pathName` - where the state file goes - defaults to `/tmp`;
set it to a persistent directory where long budgets matter.

## Testing

```bash
make check                       # unit tests + fuzz corpus replay
make fuzz FUZZ_TIME=300          # libFuzzer + ASan/UBSan (clang)
./test.sh CLA_QUOTA              # loopback through ION (from the top dir)
```

The loopback test checks pass-through of unmatched bundles, the rate, a
backlog not blocking other traffic, a quota change freeing a backlog,
dropping at the hold bound, reset, the state file and its reload after a
restart, stalling, and the refusal of a target in a plan.  It uses the
daemons built in this tree when they are there.

## Limitations

- A rule belongs to one quota duct: one limit across several neighbors
  is not expressible.
- Held bundles are invisible to CGR's backlog forecast for the plan.
- A bundle that fails on the link and is re-forwarded is charged again.
- `reforward` loops when routing has no other way: the bundle comes
  straight back.
- quotaclo reads and writes ION's `Bundle` structure, which the other
  contributions never touch.  Its layout matches the vendored `bpP.h`
  copies only for 4.0.1, 4.0.2, 4.1.3s, 4.1.4 and 4.2.0; 4.0.0 and 4.1.0
  to 4.1.2 share a copy whose `Bundle` differs from theirs (see
  `include/README`), so do not run quotaclo on those releases.  Tested on
  4.2.0.
- Each wake-up walks every bundle held on the duct; very long backlogs
  cost CPU in proportion.
