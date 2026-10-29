# zcl - design

zcl is a compressing tunnel for ION-DTN.  It sits between bundle
forwarding and a real convergence layer, gathers the bundles queued for
one neighbor over a short window, compresses them with zstd and ships the
result as the payload of an ordinary *carrier bundle* to a peer endpoint.
The peer decompresses the carriers and hands the inner bundles back to
ION as if a convergence layer had received them.

```
node A                                                      node B
app -> bp_send -> ipnfw --(plan B: zcl/ipn:B.7)--> zclo
                                                     | window / byte cap
                                                     | zstd stream
                                                     v
                                    bp_send(ipn:B.7, label L) carrier
                                                     |
                     (rtovrd L -> ltp/B)  ltpclo --- any CLA(s), any hops ---
                                                                   |
                                                    ipn:B.7 <- bp_receive
                                                       zcli
                                                        | reorder, zstd
                                                        v
                                         bpBeginAcq/ContinueAcq/EndAcq
                                                        |
                                                   ION forwarding
```

## Where it plugs in, and why there

zcl is a convergence-layer *protocol* in ION's sense (`a protocol zcl`),
so it is selected exactly like any other outduct: by egress plan, plan
duct or routing override.  Compression therefore applies per neighbor
(or per data label / source / destination through ION's overrides) and
needs no change to applications or to ION.

The compressed output leaves as a bundle, not as bytes on a socket, so
it rides whatever BP would use to reach the peer - LTP, TCPCL, QUIC,
several hops - and nodes on the way need not know about zcl at all.
This is the pattern ION's own BIBE CLA follows (`bibeclo` dequeues from
an outduct and re-sends encapsulated; the receiver re-acquires).

Seeing many bundles at once is the point: zstd gains little on one
small bundle, but a window of bundles to the same neighbor repeats
primary blocks, EIDs and similar payloads, which a shared compression
history catches.

### Keeping carriers out of the tunnel

The carrier's destination (`ipn:B.7`) is on node B, whose egress plan is
the zcl duct itself; plain routing would feed carriers back into zclo.
Carriers therefore carry a data label (default `8020844`, ASCII "zcl"),
and a routing override sends that label over the real duct:

```
# ipnrc on A
a plan B zcl/ipn:B.7                    # everything to B is compressed
a rtovrd 8020844 B 0 B ltp/B            # except the carriers themselves
# bprc on A: make ltp/B a duct of plan B as well
a planduct ipn:B.0 ltp B
```

The duct named in an override is honored by `bpclm` from ION 4.1.4
on.  zclo refuses (and drops, with a memo) a carrier that reaches its own
outduct, so a configuration mistake ends in a log line, not in a loop.

## Wire format

Every carrier bundle payload is one *carrier*: a fixed 36-byte header
followed by a slice of a zstd stream.  All integers are big-endian.

| offset | size | field     | meaning |
|-------:|-----:|-----------|---------|
|      0 |    4 | magic     | `5A 43 4C 01` ("ZCL", format version 1) |
|      4 |    1 | flags     | bit 0 `END`: last carrier of its chunk; other bits 0 |
|      5 |    3 | reserved  | 0 |
|      8 |    8 | stream_id | random, chosen when zclo starts |
|     16 |    8 | chunk_id  | 0, 1, 2, ... within the stream |
|     24 |    4 | seq       | carrier index within the chunk; 0 starts a chunk |
|     28 |    4 | length    | bytes of zstd data after the header |
|     32 |    4 | crc32c    | CRC-32C of bytes 0..31 and the zstd data |

A receiver rejects a carrier whose magic, reserved bits, length or CRC
is wrong.  The CRC is checked per carrier, so inner bundles can be
delivered as soon as their carrier decodes; the zstd frame checksum at
the end of a chunk would come too late for that.

### Chunks

A *chunk* is one zstd frame.  The compressor's history - its "dynamic
dictionary" - is built up inside the frame from the data already sent
and is discarded when the frame ends; the next chunk starts empty.  No
trained or pre-shared dictionary is involved.

A chunk is cut into carriers at flush points (`ZSTD_e_flush`): each
carrier ends on a zstd block boundary, so everything sent so far is
decodable without waiting for the rest of the frame.  The last carrier
of a chunk ends the frame (`ZSTD_e_end`) and carries `END`.

The decompressed content of a chunk is a sequence of records:

```
record = length (4 bytes, big-endian, 1..max) || serialized bundle
```

A record may span carriers; the sender happens to flush only between
records, but the receiver does not rely on it.

### Two knobs

| knob | zclo option | decides |
|------|-------------|---------|
| flush window | `-w ms`, `-b bytes` | when a carrier leaves, i.e. the latency zcl adds |
| chunk length | `-c bytes`, `-C ms` | when the history resets, i.e. ratio vs. how much one loss costs |

A carrier leaves when its oldest pending bundle is `-w` ms old or when
`-b` bytes of bundles are pending.  A chunk ends at the first flush after
it has taken in `-c` bytes or has been open `-C` ms.

## Sender (zclo)

* The main thread dequeues bundles (`bpDequeue`), copies each out of its
  ZCO and appends it as a record to the open chunk
  (`ZSTD_compressStream2(ZSTD_e_continue)`).
* A flusher thread applies the window: it cuts a carrier, sends it with
  `bp_send` (anonymous source, label L, configured lifetime and priority),
  and then reports every bundle in that carrier to ION with
  `bpHandleXmitSuccess`.  From that point the carrier is BP's
  responsibility, as with BIBE without custody.
* If `bp_send` fails, the receiver can no longer decode the rest of the
  chunk.  zclo abandons it: the bundles in that carrier and all bundles
  already compressed into the chunk but not yet sent are handed back
  with `bpHandleXmitFailure` (ION re-forwards them, usually straight
  back into zclo) and the next carrier starts a new chunk.
* On shutdown pending data is flushed and the chunk ended.

stream_id is random per zclo run, so a restarted zclo is a new stream to
the receiver and chunk numbering may begin at 0 again.

## Receiver (zcli)

zcli opens the endpoint named as its induct (`bp_open`), receives
carriers with `bp_receive`, and keeps state per stream_id (at most `-S`
streams, least recently used evicted).

### Reordering

LTP delivers blocks reliably but not in order: several export sessions
run concurrently and a retransmitted block completes after later ones.
Routing can reorder too.  Each stream therefore keeps a reorder buffer
of carriers sorted by (chunk_id, seq), bounded by count and bytes.

### State machine

```
            START (seq 0) of chunk done+1     next (cur, seq) present
 UNSYNCED --------------------------------> SYNCED ----------------+
    ^      or, after the reorder timeout,     | decode, seq++  <---+
    |      the lowest START buffered          |
    |                                         | END decoded: chunk complete
    +-----------------------------------------+ timeout/overflow: chunk lost
                                              | decode error: chunk corrupt
```

* *Stale and duplicates.*  A carrier of a chunk at or below `done` (the
  last chunk finished or given up), of the current chunk below the next
  expected seq, or already buffered, is dropped.
* *Sync.*  Unsynced, the receiver starts on a buffered `seq 0` of chunk
  `done + 1` at once.  A fresh stream has no `done` and starts on the
  first `seq 0` it gets.
* *Decode.*  Synced on chunk `cur`, the carrier `(cur, next)` is fed to
  `ZSTD_decompressStream`; every record completed is injected into ION
  right away (`bpBeginAcq` / `bpContinueAcq` / `bpEndAcq`).
* *Gap.*  What is missing at a gap was sent before the carrier at the
  head of the buffer, right behind the gap.  When that carrier has
  waited the reorder timeout `-r` since it arrived, or the buffer is
  full, the gap is declared permanent: the current chunk is given up
  (its decoded bundles stay delivered, the partial record and the rest
  are discarded), the receiver resyncs on the lowest buffered `seq 0`,
  and carriers left without a chunk start are dropped once they are
  themselves older than the timeout.  Timing each gap from the carrier
  behind it, rather than from when the receiver began to wait, lets
  gaps that queued up behind one another be given up together.

A lost carrier thus costs the rest of its chunk, never more; bundles
decoded before the gap were verified by the carrier CRCs and are valid.

### Limits

Everything a peer controls is bounded:

* zstd window: `ZSTD_d_windowLogMax` (`-W`, default 23, 8 MiB), matching
  the sender's `ZSTD_c_windowLog`.
* record length: `-B` (default 64 MiB); a larger length marks the chunk
  corrupt.
* decompressed bytes per chunk: `-X` (default 1 GiB).
* reorder buffer: 4096 carriers and 64 MiB per stream; carrier payload
  size: 64 MiB.
* streams: `-S` (default 16).

A frame that ends before `END`, data after the end of a frame, or an
`END` carrier that leaves the frame or a record unfinished, makes the
chunk corrupt.

## With LTP underneath

LTP red parts retransmit lost segments, so carriers are not lost to
segment loss.  A chunk is lost only when LTP cancels a session
(retransmission limit, contact ending) or a carrier expires or is
dropped on the way.  Then the rule above applies: the rest of that chunk
is gone and the stream continues with the next chunk.  Keep `-c` / `-C`
moderate (hundreds of kB, a few seconds) so one cancelled session costs
little.

The flush window adds up to `-w` ms of queuing delay before LTP sees the
data; account for it in LTP's timers if it is large.

## Not done (yet)

* The carrier lifetime is a fixed `-l`; it is not derived from the inner
  bundles' remaining lifetimes.
* Bundle priority is not visible to a CLO through `bpDequeue`, so
  expedited bundles wait for the window like any other.
* No custody on carriers; run it over a reliable CL, or use BP custody
  on the path, when loss matters.
* Compression happens after BPSec: encrypted payloads do not compress.
