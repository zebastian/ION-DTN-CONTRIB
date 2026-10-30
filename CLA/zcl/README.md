# zcl - zstd Compressing Tunnel CLA (zcli / zclo)

A convergence layer adapter pair that compresses the bundles ION queues for
a neighbor and carries them, as a zstd stream cut into ordinary *carrier
bundles*, to a peer endpoint, where they are decompressed and handed back to
ION.  Because the carriers are bundles, they travel over any convergence
layer (LTP, TCPCL, QUIC, ...) and across nodes that know nothing about zcl.

- `zclo` - output daemon: windowed zstd compression, sends carriers
- `zcli` - input daemon: reorders, decompresses, re-injects bundles

The design - where it plugs in, the carrier format, the receive state
machine - is in [doc/design.md](doc/design.md).

## Features

- Many bundles share one compression history: a flush window (`-w` ms /
  `-b` bytes) decides when a carrier leaves, the chunk length (`-c` bytes /
  `-C` ms) when the history resets
- No pre-shared dictionary: each chunk is one zstd frame that builds its
  history from the data it carries
- Carriers decode as they arrive; every carrier is CRC-32C checked
- Reorder buffer per sender: carriers may arrive out of order (LTP sessions
  complete out of order); a carrier still missing when the one behind it
  has waited `-r` ms costs the rest of its chunk, never more
- Bounded against hostile input: zstd window, record length, decompressed
  bytes per chunk, reorder buffer, number of senders
- Selected like any outduct - per plan, plan duct or routing override - so
  only the traffic you choose is compressed
- Carriers live as long as the bundles inside need (capped by `-L`) and
  travel at their priority; an expedited bundle skips the window
- Carriers are handed to the real link directly (`zclo -T`): no data
  label, no routing override

## Layout

```
src/zclcodec.{h,c}  carrier format, compressor, receive state machine; libzstd only
src/zclcla.h        shared definitions of the daemons
src/zclo.c          output daemon
src/zcli.c          input daemon
doc/design.md       design and wire format
doc/*.pod           man page sources (zcli, zclo)
tests/zclcodec_test.c   unit tests: round trip, reorder, loss, corruption,
                        limits, bundle inspection
tests/fuzz/             libFuzzer targets for the receiver and the bundle
                        inspection, and their corpora
tests/loopback-zcl/     one ION node sending to itself through zcl over UDP:
                        expedited bypass, carrier lifetimes, handoff, and
                        a loss phase through misc/linkimpair
```

## Build

Needs ION 4.1.4 or later - zclo reads ION's `Bundle` record, whose layout
is known exactly only from there on (`include/README`); configure leaves
zcl out of `--enable-all` on older releases - and libzstd >= 1.4.0
(`libzstd-dev`; `./install-deps.sh CLA_ZCL`).

```bash
./configure --enable-cla-zcl
make && sudo make install
```

## Configuration

Node 10 compresses everything for node 20; the carriers go over LTP.
The carriers are addressed to node 20 like everything else in plan 20, so
they come back into the zcl duct; zclo moves them, unchanged, onto the
duct named by `-T`, which is in no plan:

```
# bprc on node 10
a protocol zcl
a outduct ltp 20 ltpclo                         # the real link: in no plan
a outduct zcl ipn:20.7 'zclo -w 20 -c 262144 -T ltp/20'
r 'ipnadmin node10.ipnrc'

# node10.ipnrc
a plan 20 zcl/ipn:20.7              # bundles for node 20, carriers included
```

zclo refuses to start if the target is in a plan - bpclm could then send
bundles to it directly; don't use the `a plan 20 ltp/20` shorthand for
it - and gives the zcl duct the target's max payload length, which bpclm
fragments to.  The last carrier cut when zclo stops waits in the zcl duct
for the next zclo.

On node 20:

```
# bprc on node 20
a protocol zcl
a endpoint ipn:20.7 q
a induct zcl ipn:20.7 'zcli -r 5000'
```

The outduct's name is the peer's zcl endpoint and the induct's name is the
node's own one.

Main knobs (see `zclo(1)` / `zcli(1)`):

| option | default | effect |
|--------|---------|--------|
| `zclo -w` | 20 ms | longest a bundle waits for its carrier |
| `zclo -b` | 64 KiB | cut a carrier when this much is pending |
| `zclo -c` / `-C` | 512 KiB / 5 s | chunk length: compression vs. loss cost |
| `zclo -l` | 3 | zstd level |
| `zclo -L` | 86400 s | longest carrier lifetime; used for bundles without one |
| `zclo -p` | std | carrier priority for bundles without ION's QoS block |
| `zclo -T` | (required) | the outduct the carriers go out on |
| `zcli -r` | 10 s | how long a gap may stay open before giving up |

Carriers must fit the transport underneath: over UDP, keep `-b` well below
64 KiB.

## Testing

```bash
make check                       # unit tests + fuzz corpus replay
make fuzz FUZZ_TIME=300          # libFuzzer + ASan/UBSan (clang)
./test.sh CLA_ZCL                # loopback through ION (from the top dir)
```

The loopback test's loss phase drops 25% of the carrier datagrams with
`misc/linkimpair` and checks that only the chunks hit are given up and
that the stream carries on.  It needs `iptables` (as root or through
`sudo -n`) and CAP_NET_ADMIN on linkimpair
(`sudo setcap cap_net_admin+ep misc/linkimpair/linkimpair`); without them
the phase is skipped and the rest of the test still runs.  It uses the
daemons built in this tree when they are there.

## Limitations

- All carriers of a chunk share one priority and one expiry, as the
  later ones depend on the earlier: a bundle of another priority, or one
  that must outlive carriers already sent, starts a new chunk.  Traffic
  that changes priority often compresses less.
- Priority comes from ION's QoS extension block; bundles from other
  implementations travel at `-p`.
- No custody on carriers: losses below are handled by the reliability of
  the convergence layer the carriers ride on.
- Encrypted (BCB) payloads do not compress; only their headers do.
