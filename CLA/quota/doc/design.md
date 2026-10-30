# quota - design

quota is a traffic shaper for ION-DTN.  It sits between an egress plan
and a real convergence layer, matches each bundle queued for one
neighbor against operator rules - by source, destination or previous
hop - and lets it through only while every matching rule has quota
left.  A bundle over quota waits in ION's own storage until it fits,
unless the rule says to drop it.  The main use is rate limiting one
data producer; the same rules express daily or monthly byte and bundle
budgets.

```
node A                                                      node B
app/ipnfw -> plan B --bpclm--> quota/B xmitBuffer
                                 |  quotaclo: match rules, charge quotas
                                 |  over quota: stays here (held)
                                 |  passes: moved, unchanged
                                 v
                               ltp/B xmitBuffer   (in no plan)
                                 |
                               ltpclo ---------- wire: the bundle ---> B
```

Nothing changes on the wire and the neighbor needs nothing: the bundle
that leaves is the bundle ION queued.  The names are `quota` (ION
protocol, duct `quota/<n>`), `quotaclo` (outduct daemon) and
`quotaadmin` (rules).  There is no `quotacli`; quota acts on egress
only.

## Where it plugs in, and why there

quota is a convergence-layer protocol in ION's sense (`a protocol
quota`), and its duct is the only duct of the plan it shapes.  bpclm,
which moves bundles from a plan's queues onto a duct, puts every bundle
for that neighbor into the quota duct's `xmitBuffer`.

A CLO normally takes bundles with `bpDequeue`, which pops the head of
that list and serializes the bundle.  After that there is no API to
pass the bundle on to another duct.  The alternatives considered, and
why they lost:

* *Tunnel* (as zcl does): wrap passing bundles in carrier bundles to a
  peer that unwraps them.  Needs `quotacli` on every neighbor - odd for
  a purely local policy - and costs a carrier header per bundle.
* *Label and reforward*: stamp a data label on passing bundles and send
  them back through routing, where a route override for the label picks
  the real duct.  Dead for three reasons found in ION 4.2.1:
  critical, anonymous and duplicate-ID bundles cannot be found again
  after `bpDequeue` (stewardship is refused for them,
  `libbpP.c:12880-12930`); `bpReforwardBundle` sets `returnToSender`
  and double-counts plan statistics; and the label leaves the node in
  the QoS extension block (`ext/bpq/bpq.c:44`), where the receiver
  adopts it (`bpq.c:117`) - so any upstream node could set the label
  and bypass the shaper through A's own override.
* *An induct-side shaper* would have to own the transport (ION cannot
  chain inducts), cannot hold bundles that are not yet acquired, and
  never sees locally produced bundles.

### Duct handoff

quotaclo does not call `bpDequeue` on its own duct.  It walks its
`xmitBuffer` and reads each `Bundle` directly: source and destination
are decoded already, and the previous hop is in `clDossier.senderEid`,
filled by the receiving CLA or from the Previous Node block
(`libbpP.c:10209-10230`).  For a bundle that passes, quotaclo does in
one transaction what bpclm does for any duct (`bpclm.c:778-781`):

```
sdr_list_delete(own ductXmitElt)
bundle.ductXmitElt = sdr_list_insert_last(target.xmitBuffer, bundleObj)
sdr_write(bundle)
sm_SemGive(target vduct semaphore)            after the transaction
```

The target's CLO then dequeues it as usual.  `bpDequeue` finds the
neighbor's plan through the bundle's `proxNodeEid`, not through the duct
(`libbpP.c:12609-12620`), so the target belongs to no plan; `bpStart`
starts every outduct's CLO whether planned or not (`libbpP.c:2085`);
and ltpclo takes its engine number from the duct name alone
(`ltpclo.c:107`).

What this gives:

* *No head-of-line blocking.*  The list is walked, not popped: a held
  bundle of one rule does not stop the bundles behind it.  Order within
  the list - bpclm's priority order - is kept.
* *Held bundles are ION's.*  They stay in the SDR, survive a quotaclo
  restart, and expire normally: `bpDestroyBundle` unlinks
  `ductXmitElt` (`libbpP.c:3065`).
* *Every bundle works*, critical and anonymous ones included, and no
  routing or statistics run twice.

What it costs:

* quotaclo writes ION's duct lists directly, as bpclm does.  The fields
  it relies on, `Outduct.xmitBuffer` and `Bundle.ductXmitElt`, exist in
  every `include/bpP-*.h` from 4.0.1 on; the source behaviour was
  checked in 4.2.1 only.  It reads and writes back whole `Bundle`
  structures, so it is right only on releases whose layout a vendored
  copy has: 4.0.1, 4.0.2, 4.1.3s, 4.1.4, 4.2.0 - not 4.0.0 or 4.1.0 to
  4.1.2 (see `include/README`).
* bpclm has counted a held bundle as dequeued, so CGR's backlog for the
  plan does not see it.  Holding does not push back into routing.
* A bundle that fails on the link is re-forwarded by ION, comes back
  through the plan and quotaclo, and is charged again.  Accepted: it
  does use the link again.

### Configuration

```
# bprc on node 10
a protocol quota 26
a outduct ltp 20 ltpclo                  # the real link: in no plan
a outduct quota 20 'quotaclo ltp/20'     # the shaper, handing off to it
a plan ipn:20.0
a planduct ipn:20.0 quota 20
r 'quotaadmin node10.quotarc'
```

Protocol class 26 ("any") matters: bpclm picks a duct whose class suits
the bundle's requested reliability and falls back only between best
effort and reliable, so a quota duct of a narrower class could be
passed over.

Avoid the shorthand `a plan ipn:20.0 ltp/20`: it attaches the target to
the plan, and bpclm could then hand bundles to it directly.

### Start-up checks

quotaclo refuses to run, with a memo, when:

* the target duct is missing or is attached to a plan (bypass);
* the target duct is another quota duct (handoff loop).

bpclm fragments against the quota duct's `maxPayloadLen`, not the
target's.  When the quota duct has none or a larger one, quotaclo gives
it the target's (`updateOutduct`, passing its own CLO command back, as
that call replaces it too) - a UDP target has 65000 by default, and
nobody should have to copy that by hand.

## Rules (quotaadmin)

Rules live in the SDR under the catalogue name `quotacl`, and are
managed with quotaadmin in the manner of ION's other admin programs:
single-letter commands, read from an rc file or typed interactively.

```
# node10.quotarc
1                                                 # initialize
a rule cam quota/20 src ipn:7.* hold 10M drop
a quota cam bytes   1M/1s
a quota cam bundles 50000/1d
a rule gw  quota/20 prev ipn:30.0 dst ipn:20-29.*
a quota gw  bytes 10G/1d
```

### Rules

```
a rule <name> quota/<duct> [src P] [dst P] [prev P] [hold <bytes> [drop|stall|reforward]]
c rule <name> ...            same arguments; quotas and their levels are kept
d rule <name>
i rule <name>                counters and quota levels, from quotaclo
l rule [quota/<duct>]        the rules, as the commands that recreate them
r rule <name>                reset: every quota of the rule back to full
```

Each rule carries a serial, set from the change count when it is added
or reset.  quotaclo keeps a rule's bucket levels across a reload only
while its serial is unchanged, so a reset - or a delete and re-add in
one breath, before quotaclo has looked - starts the buckets full.
Counters are kept by rule name.

`i rule` cannot read quotaclo's memory.  It bumps `infoRequest` in the
rules root and wakes the duct; quotaclo answers by writing its state
file at once with the request number in the header, which quotaadmin
waits for (3 s at most) and prints.  If quotaclo is not running it
prints the last file, with its age.

* A rule belongs to one quota duct, which fixes the next hop; there is
  no `next` field.  A limit across several neighbors is not
  expressible.  Rule names are unique per node.
* The fields of a rule are ANDed.  A rule with no field matches every
  bundle on its duct.
* A bundle may match several rules; it passes only if every quota of
  every matching rule has room, and is then charged to all of them.
  Rule order does not matter.
* A bundle that matches no rule passes, uncharged.
* `prev` never matches a bundle produced on this node: it has no
  sender.  The previous hop is not authenticated unless the CLA that
  received the bundle authenticates it.

### Patterns

| pattern | matches |
|---------|---------|
| `ipn:7.1` | that endpoint |
| `ipn:7.*` | any service on node 7 |
| `ipn:7-9.*`, `ipn:7-9.1` | nodes 7 to 9 inclusive |
| `ipn:*.*` | any ipn endpoint |
| `dtn://host/app` | that endpoint |
| `dtn://host/*` | any EID starting `dtn://host/` |
| `*` | any EID |

### Quotas

```
a quota <rule> bytes|bundles <count>/<timeframe>
c quota <rule> bytes|bundles <count>/<timeframe>
d quota <rule> bytes|bundles <timeframe>
```

Counts take decimal suffixes k, M, G (1M = 1 000 000); timeframes s, m,
h, d.  A quota is identified by its rule, kind and timeframe, so a rule
may hold `bytes 1M/1s` and `bytes 10G/1d` at once; `c quota` changes
the count of the quota with that timeframe.  Changing a timeframe is a
delete and an add.

Bytes are the bundle's payload length, as ION's own statistics count
them.

### Overflow

Without a `hold` clause a rule holds over-quota bundles without bound:
they wait until they fit or expire.  With `hold <bytes>` the rule holds
at most that many bytes; a bundle beyond that gets the action named
after it (default `drop`):

| action | effect |
|--------|--------|
| `drop` | the bundle is destroyed; a deletion status report with reason *traffic pared* (`SrTrafficPared`, RFC 9171 code 9) is sent if requested |
| `stall` | quotaclo moves nothing from this duct until the rule has room again - every rule on the duct waits |
| `reforward` | the bundle goes back to routing (`bpReforwardBundle`) for another route |

## Token buckets

Each quota is a token bucket.  `count/timeframe` gives a capacity of
`count` and a refill of `count` per `timeframe`, continuous, so
`1M/1s` and `60M/60s` have the same average rate and differ only in
burst: the timeframe is the burst control.  A bucket starts full.

Arithmetic is integer, in fixed point, and refill is computed lazily
from the monotonic clock when a bucket is looked at - there is no
refill tick.

A bundle larger than a bucket's capacity could never pass a plain
token bucket.  Here it passes once the bucket is full, and the bucket
goes negative: the producer then waits until the debt is refilled.
The long-run average stays exact and nothing is stuck for good.

## quotaclo

* *Wake-ups.*  quotaclo sleeps on its duct semaphore, which is given by
  bpclm (bundle added), by quotaadmin (rules changed) and by quotaclo's
  own timer thread at the earliest time a held bundle could pass.
* *Pass.*  It walks the `xmitBuffer` front to back.  For each bundle it
  collects the matching rules; if all have room it charges them and
  hands the bundle off, otherwise the bundle stays and is attributed to
  the first rule that blocked it.
* *Rule changes.*  quotaadmin bumps a change counter in the `quotacl`
  root and gives the semaphore of every quota duct it touched.
  quotaclo reloads its rules before the next decision and re-evaluates
  every held bundle: a bundle no rule blocks any more leaves at once.
  `c rule` and `c quota` keep bucket levels, clipped to a new capacity;
  a reset or re-added rule starts full (see the serial above).
* *Overflow.*  `drop` unlinks the bundle and hands it to `bpAbandon`
  with `BP_REASON_TRAFFIC_PARED`, which sends the deletion report if
  one was requested.  `reforward` calls `bpReforwardBundle`.  `stall`
  ends the walk: nothing behind the bundle is looked at.
* *Counters* per rule, shown by `i rule`: bundles and bytes passed,
  held now, dropped, reforwarded; time spent stalled; tokens left per
  quota.

## State snapshot

Bucket levels must survive a restart, or restart cycling would grant
a fresh burst and reset long budgets.  Every 10 s, at clean exit and
when `i rule` asks, quotaclo writes `<pathName>/quota-<duct>.state`,
where `<pathName>` is ION's working directory
(`getIonWorkingDirectory()`, ionconfig `pathName`) and a `/` in the
duct name becomes `_`.  The file is written to a temporary name and
renamed.

```
quota-state 1 <duct> <unix time> <info request served>
b <rule> bytes|bundles <timeframe s> <level> <fraction>
c <rule> <passed> <bytes> <held> <bytes> <dropped> <bytes> <reforwarded> <stalled ms>
```

A bucket is keyed by duct (the file), rule, kind and timeframe.  On
start quotaclo loads the file, refills each bucket for the time it was
down (capped at capacity), takes the counters back, and ignores keys
that no longer exist; unknown lines are skipped, so the format can
grow.  A crash loses at most 10 s of charges.

ionconfig's `pathName` defaults to `/tmp`, which many systems clear at
boot; set it to a persistent directory where long budgets matter.

## Not done (yet)

* Limits across several neighbors: every rule is bound to one duct, and
  buckets are per quotaclo process.
* Held bundles are invisible to CGR's backlog forecast.
* `reforward` can loop when routing has no other way to the
  destination: the bundle comes straight back and is held or
  reforwarded again.
* One target duct per quotaclo; per-rule targets (e.g. bulk over UDP,
  urgent over LTP) are not offered.
* Re-forwarded bundles are charged again.
* ipn EIDs are matched in their two-element form; the three-element
  form with an allocator is not covered by the patterns.
* Each wake-up walks every bundle held on the duct, and bpclm wakes it
  for every bundle it adds: a backlog of n bundles costs O(n) per
  arrival.
* Checked against the ION 4.2.1 BPv7 source only, and run on 4.2.0;
  4.0.1 to 4.1.4 are covered by their headers but not yet by reading
  their sources.
