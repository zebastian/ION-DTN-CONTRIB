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
- A carrier routed back into its own tunnel is dropped and logged, not
  wrapped again

## Layout

```
src/zclcodec.{h,c}  carrier format, compressor, receive state machine; libzstd only
src/zclcla.h        shared definitions of the daemons
src/zclo.c          output daemon
src/zcli.c          input daemon
doc/design.md       design and wire format
doc/*.pod           man page sources (zcli, zclo)
tests/zclcodec_test.c   unit tests: round trip, reorder, loss, corruption, limits
tests/fuzz/             libFuzzer target for the receiver, and its corpus
tests/loopback-zcl/     one ION node sending to itself through zcl over UDP,
                        with a loss phase through misc/linkimpair
```

## Build

Needs libzstd >= 1.4.0 (`libzstd-dev`; `./install-deps.sh CLA_ZCL`).

```bash
./configure --enable-cla-zcl
make && sudo make install
```

## Configuration

Node 10 compresses everything for node 20; the carriers go over LTP.

```
# bprc on node 10
a protocol zcl
a outduct zcl ipn:20.7 'zclo -w 20 -c 262144'
r 'ipnadmin node10.ipnrc'
a planduct ipn:20.0 ltp 20          # LTP as a second duct of plan 20

# node10.ipnrc
a plan 20 zcl/ipn:20.7              # bundles for node 20: compressed ...
a rtovrd 8020844 20 0 20 ltp/20     # ... but the carriers (label 8020844) over LTP

# bprc on node 20
a protocol zcl
a endpoint ipn:20.7 q
a induct zcl ipn:20.7 'zcli -r 5000'
```

The outduct's name is the peer's zcl endpoint and the induct's name is the
node's own one.  The route override is what keeps carriers - addressed to
node 20 like everything else in plan 20 - out of the tunnel; its duct
expression is honored from ION 4.1.4 on.  The data label is set with
`zclo -D`.

Main knobs (see `zclo(1)` / `zcli(1)`):

| option | default | effect |
|--------|---------|--------|
| `zclo -w` | 20 ms | longest a bundle waits for its carrier |
| `zclo -b` | 64 KiB | cut a carrier when this much is pending |
| `zclo -c` / `-C` | 512 KiB / 5 s | chunk length: compression vs. loss cost |
| `zclo -l` | 3 | zstd level |
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
the phase is skipped and the rest of the test still runs.

## Limitations

- Carrier lifetime is fixed (`zclo -L`), not derived from the bundles inside.
- A CLO does not see bundle priority, so expedited bundles wait for the
  window like any other.
- No custody on carriers: losses below are handled by the reliability of
  the convergence layer the carriers ride on.
- Encrypted (BCB) payloads do not compress; only their headers do.
