# bpdemux - Data-Label Demux (bpdemuxd / bpdemuxadmin)

Late binding of the destination service: remote senders know one
endpoint of a node, say `ipn:1.1`, and pick the service that gets their
bundle with an ION data label.  On the node, `bpdemuxd` owns `ipn:1.1`
and moves each bundle on to the endpoint its label names - `ipn:1.705`
for label 42, say - by rules that can change at any time without the
senders knowing.  The node's service numbers stay its own business.

- `bpdemuxd` - daemon: owns the demux endpoint, moves bundles by label
- `bpdemuxadmin` - rules: added, changed and inspected while ION runs

Nothing runs on the sender.  The data label is a standard part of ION's
class of service and travels in ION's QoS extension block, so stock
tools set it: `bpsendfile ipn:2.1 ipn:1.1 file 0.1.0.0.0.42`.

The design - where it plugs in, why there, and what that costs - is in
[doc/design.md](doc/design.md).

## Features

- The bundle is moved, not re-sent: the target application sees the
  real source, and the bundle keeps its ID, creation time, lifetime and
  status-report requests
- Labels 1 to 4294967295 map to services; a rule may have a display
  name (`a label 42 705 cherry`) or not (`a label 43 706`)
- Bundles without a label or a rule go to a default service, or are
  abandoned (with a "deleted" status report if one was asked for)
- Changes apply to the next bundle; the rules live in ION's SDR
- The target endpoint's own rule applies: queue or discard while no
  application has it open, reanimation script included
- The move is one SDR transaction: a crash leaves the bundle in exactly
  one queue

## Layout

```
src/dmxrules.{h,c}    labels, services, names, rule table; no ION
src/bpdemux.h         shared definitions of the daemon and admin
src/bpdemuxd.c        daemon
src/bpdemuxadmin.c    rules administration
doc/design.md         design
doc/*.pod             man page sources (bpdemuxd, bpdemuxadmin)
tests/dmxrules_test.c     unit tests: parsing, table checks, resolution
tests/fuzz/               libFuzzer target for dmxrules, and its corpus
tests/dmxrecv.c           test receiver (not installed)
tests/bpdemux-2node/      node 2 sends to node 1's demux endpoint over UDP
```

## Build

Needs ION 4.1.4 or later (bpdemuxd reads ION's Bundle record).

```bash
./configure --enable-app-bpdemux
make && sudo make install
```

## Configuration

Node 1 offers `ipn:1.1` to the world and runs its services on 705, 706
and, for everything else, 799:

```
# bprc on node 1
a endpoint ipn:1.1 q        # the demux endpoint: 'q' holds bundles
a endpoint ipn:1.705 q      #   while bpdemuxd is not running
a endpoint ipn:1.706 q
a endpoint ipn:1.799 q
r 'bpdemuxadmin node1.demuxrc'
r 'bpdemuxd ipn:1.1'

# node1.demuxrc
1 ipn:1.1 799
a label 42 705 cherry
a label 43 706
```

On a sender, any ION application that sets `dataLabel` in its
`BpAncillaryData`, or any tool taking a class of service string
`custody.priority.ordinal.unreliable.critical.label`:

```
bpsendfile ipn:2.1 ipn:1.1 report.txt 0.1.0.0.0.42    # -> ipn:1.705
```

At run time:

```
c label cherry 706          # label 42 now goes to 706
d label 43
s default 0                 # no default: unmatched bundles are abandoned
i                           # demux endpoint and default: open? queued?
i label cherry              # the rule and its target endpoint
l                           # everything, as commands
```

See `bpdemuxadmin(1)` for every command and `bpdemuxd(1)` for the
daemon.

## Testing

```bash
make check                       # unit tests + fuzz corpus replay
make fuzz FUZZ_TIME=300          # libFuzzer + ASan/UBSan (clang)
./test.sh APP_BPDEMUX            # two ION nodes over UDP (from the top dir)
```

The two-node test sends with stock `bpsendfile` and checks delivery by
rule with the sender's source kept, by default for an unknown label and
for none, a rule changed while running, abandonment without a default,
the daemon's counters, and the admin's listing.  It uses the programs
built in this tree when they are there.

## Limitations

- The demux endpoint belongs to `bpdemuxd`: an application that used it
  moves to the default service.
- Only `ipn` endpoints; one demux endpoint per node.
- The label is not authenticated: any sender may pick any whitelisted
  label.  It cannot name a service that has no rule.
- ION's routing overrides (`ipnrc a rtovrd <label> ...`) also key on
  the data label: a label used for demux steers routing on the way if
  some node has an override for it.  Use label numbers apart.
- Senders other than ION must emit ION's QoS extension block to carry a
  label.
- Endpoint statistics count the bundle as queued twice: at the demux
  endpoint and at its target.
