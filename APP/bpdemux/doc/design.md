# bpdemux - design

bpdemux delivers bundles to local services by their ION data label.  A
node publishes one endpoint, the demux endpoint (say `ipn:1.1`);
senders address it and set a data label; `bpdemuxd` owns the endpoint
and moves each bundle delivered there on to the endpoint the label's
rule names.

```
node B                                   node A
app/bpsendfile                           ltpcli/udpcli/... (stock)
  bp_send(ipn:1.1, label 42)               |
  QoS block carries the label  --- wire -->  acquire, deliverable
                                             |
                                    ipn:1.1 delivery queue
                                             |  bpdemuxd: label 42 -> 705
                                             |  same bundle, destination
                                             v  service rewritten
                                    ipn:1.705 delivery queue
                                             |
                                    app: bp_receive, source ipn:2.1
```

This is late binding of the destination (RFC 4838, 3.3): with DTN
delays a node cannot quickly tell its peers that it renumbered,
relocated or versioned a service; with a demux endpoint it never has
to.  `dtn://A/cherry` offers string demux statically, but cannot be
remapped at run time and moves the applications off `ipn`.

## Where it plugs in, and why there

A bundle for a local endpoint is *delivered*, not forwarded: ION's
dispatch puts it into the endpoint's delivery queue and gives the
endpoint's semaphore (libbpP.c, `enqueueForDelivery`).  No egress plan
and no outduct ever sees it, so quota's trick of moving bundles between
duct queues does not apply; and an induct-side component would have to
own a transport, since ION cannot chain inducts.  What remains is the
same move one stage later - between delivery queues:

* `bpdemuxd` opens the demux endpoint with `bp_open`, which makes it
  the endpoint's application: bundles are queued for it, and every
  delivery gives the semaphore it waits on.  It never calls
  `bp_receive`.
* For each queued bundle it reads the Bundle record, takes the label
  from `ancillaryData.dataLabel` (where ION's QoS block parser put it on
  acquisition, `ext/bpq/bpq.c`), unlinks the bundle from the queue,
  rewrites `destination.ssp.ipn.serviceNbr` and appends it to the
  target endpoint's queue - all in one SDR transaction.
* The append repeats ION's `enqueueForDelivery`: the target's
  reanimation script and discard rule apply when no application has it
  open, the queue element is recorded in the bundle, the target's
  semaphore is given and the endpoint tallied.  ION exports
  `deliverBundle` in 4.1.4 but not in 4.2.x, so bpdemuxd carries its
  own copy of these few lines.  Fragment reassembly, the other half of
  `deliverBundle`, is not needed: ION reassembled the bundle before it
  reached the demux endpoint.
* Afterwards, as ION's dispatch does, `bpDestroyBundle(bundle, 0)`
  frees the bundle only if the target's discard rule left it in no
  queue.

Nothing is re-serialized, so primary-block CRCs and BPSec blocks are
not touched; they were checked on acquisition.  The "delivered" status
report, which ION sends from `bp_receive`, comes when the target's
application takes the bundle.

The alternatives considered:

* *Relay*: receive on the demux endpoint and `bp_send` a new bundle to
  the target.  Public API only, but the target sees `ipn:1.1` as the
  source, the lifetime restarts, and status reports end at the node.
* *Ingress rewrite in a CLA*: rewrite the destination in the raw bytes
  before `bpBeginAcq`.  Needs a CBOR re-encode and a CRC recompute,
  breaks a BIB over the primary block, and covers only the bundles that
  arrive over that one induct.
* *A new extension block for the tag*: ION's extension table is compiled
  in, so the sender's ION could not emit it without a patch.  The data
  label is already carried by every ION bundle.

## The rules

`bpdemuxadmin` keeps one record in the SDR, cataloged as `bpdemux`:
the demux endpoint, the default service and a list of rules (label,
service, optional name).  `bpdemuxd` reads it for every batch of up to
64 bundles, so a change applies to the next bundle; there is nothing to
signal.

A bundle's service is picked in this order: its label's rule; the
default if it has no label (0), no rule, or a rule whose endpoint the
node lacks; otherwise it is abandoned with `bpAbandon` (reason "no
known route"), which sends the "deleted" status report if one was
requested.  A rule may not name the demux endpoint itself, nor may the
default, so a bundle can never come back to it.

The parsing, the table checks and the resolution are in `dmxrules.c`,
which needs no ION; its unit test and fuzz target build with the source
dir alone.

## Version dependence

bpdemuxd reads and writes ION's Bundle, Endpoint and VEndpoint records
and so needs the `bpP.h` copy of the installed release: it is built on
4.1.4 and later only (configure, and an `#error` without
`BPP_BUNDLE_LAYOUT_EXACT`).  `bpEndpointTally`, exported by libbp but
declared in no header, is declared in bpdemuxd.c.  ION keeps an ipn
service number in an `unsigned long`; on targets where that is 32 bits,
bpdemuxadmin refuses larger services.

## Costs and limits

* The demux endpoint is bpdemuxd's: no other application can open it.
* Endpoint statistics count a moved bundle as queued at the demux
  endpoint and again at its target.
* The label is the sender's choice and not authenticated; only labels
  with a rule reach a named service, the rest go to the default.
* ION's routing overrides also key on the data label (`ipnrc a rtovrd`),
  so a demux label can steer routing on the way if a node has an
  override for that number.
* Senders other than ION carry a label only if they emit ION's QoS
  extension block.
