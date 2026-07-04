# QUIC Convergence Layer Adapter (quiccla)

A Bundle Protocol v7 convergence layer adapter that carries bundles over
QUIC, implementing the **QUICCL** protocol of
[draft-caini-dtn-quiccl](https://datatracker.ietf.org/doc/draft-caini-dtn-quiccl/)
(QUICCLv1). Built on [ngtcp2](https://github.com/ngtcp2/ngtcp2) with the
**GnuTLS** crypto backend.

QUICCL sessions are **peer-symmetric**: once established, either peer may send
bundles over the connection regardless of which peer opened it.

`quiccla` is the convergence-layer daemon. It binds a UDP socket, accepts
connections (demultiplexed by connection ID) and injects the bundles they
carry into ION; it also opens connections for the egress plans that cite
`quic` outducts and drains those outducts, transmitting over the session to
that node. An established session to a node is reused for both directions,
whether `quiccla` accepted it or opened it.

## Protocol

- **ALPN** `quicclav1`, default **UDP port 4560**. TLS 1.3 is mandatory and is
  part of the QUIC handshake (no separate contact header).
- **Stream 0** carries all signalling: `SESS_INIT`, `KEEPALIVE`, `SESS_TERM`,
  `MSG_REJECT` (raw big-endian fields, no CBOR).
- **Reliable service (default):** bundles are sent as `XFER_SEGMENT` messages
  on the client-initiated data streams. Each bundle is segmented to the peer's
  negotiated Segment MRU, carries a per-direction Transfer ID and START/END
  flags, and is acknowledged with a cumulative `XFER_ACK`. Bundles are mapped
  to one of four priority streams (4 = expedited, 8 = normal, 12 = bulk,
  16 = no priority) by the bundle's ECOS ordinal.
- **Unreliable service (`quiccla -u`):** bundles are segmented and sent as QUIC
  DATAGRAM frames (RFC 9221), without acknowledgement; a lost segment leaves
  the transfer incomplete (dropped), as befits a best-effort service.
- **Keepalive / termination:** an idle session emits `KEEPALIVE` at the
  negotiated interval; shutdown performs a `SESS_TERM` exchange.

## Conformance to draft-caini-dtn-quiccl

| Area | Status |
|------|--------|
| ALPN `quicclav1`, port 4560, TLS 1.3 | implemented |
| SESS_INIT exchange + parameter negotiation | implemented |
| KEEPALIVE, SESS_TERM, MSG_REJECT | implemented |
| Reliable XFER_SEGMENT / XFER_ACK / XFER_REFUSE | implemented (REFUSE decoded) |
| Four-stream priority mapping (4/8/12/16) | implemented (by ECOS ordinal) |
| Unreliable service (QUIC DATAGRAM) | implemented (`-u`) |
| Notified service (datagram + per-segment ACK) | **not implemented** |
| Cross-bundle pipelining (multiple transfers in flight) | **not implemented** (draft *MAY*; one transfer in flight) |
| Session / transfer extension items | accepted and skipped (none emitted) |

## TLS

`quiccla` requires a certificate (`-c`) and key (`-k`), used when it accepts a
connection. When it opens a connection it verifies the peer against the system
trust store or a CA file (`-C`); `-n` disables verification (e.g. self-signed
certificates).

GnuTLS is the only ngtcp2 crypto backend currently packaged on common distros.
The TLS code is isolated behind `quictls.h`, so an OpenSSL or wolfSSL backend
can be added as a sibling `quictls_*.c` without touching the engine.

## Configuration

Duct name is `host[:port]` (default port 4560, UDP). Declare a `quic` induct
(its command starts the daemon) and a `quic` outduct per reachable peer; the
daemon drains the outducts, so their command is empty:

```
a protocol quic
a induct  quic '0.0.0.0:4560' 'quiccla -c server.pem -k server.key -C ca.pem'
a outduct quic 'peer.example:4560' ''
```

Flags (on the `quiccla` induct command): `-c`/`-k` cert/key, `-C` CA file,
`-n` no-verify, `-A` ALPN, `-t` idle timeout (s), `-u` unreliable (datagram)
service, `-r`/`-w` UDP socket receive/send buffer sizes in bytes
(`SO_RCVBUF`/`SO_SNDBUF`; 0 = OS default).

On Linux the datapath uses UDP GSO (segmentation offload) on transmit and GRO
on receive when the kernel supports them, coalescing many QUIC packets into a
single `sendmsg`/`recvmsg` to cut per-packet syscall overhead; it falls back to
one datagram per packet otherwise.

## Layout

```
src/quiccla.h          constants, config, duct/arg parsing
src/quicmsg.{c,h}      QUICCL wire-message codec (dependency-free)
src/quictls.{h}        TLS backend interface
src/quictls_gnutls.c   GnuTLS backend
src/quicsession.{c,h}  ngtcp2 engine: accepts and opens connections, one I/O
                       thread, session state machine, streams, datagrams
src/quiccla.c          daemon (accepts + opens sessions, drains outducts)
doc/*.pod              man page sources
tests/loopback-quic/         single-node reliable loopback (.optional)
tests/loopback-quic-dgram/   single-node unreliable loopback (.optional)
tests/interop-unibo-bp/      ION <-> Unibo-BP cross-project interop (.optional)
bench/bench-quic             throughput benchmark
```

## Testing

- `make check` — codec round-trip unit tests for every message type.
- `tests/loopback-quic` — reliable service: single- and multi-segment
  transfers, multiple streamed bundles, priority-to-stream routing
  (a high-ordinal bundle must use stream 4), and graceful SESS_TERM.
- `tests/loopback-quic-dgram` — unreliable service over multiple datagrams.
- `tests/interop-unibo-bp` — live cross-project interop against a Unibo-BP
  node (picoquic/OpenSSL). Two phases, each using a single QUIC connection to
  prove the session is bidirectional: phase 1 with ION as the active peer
  (ION opens the connection), phase 2 with Unibo-BP as the active peer; each
  phase carries a bundle both ways over that one connection. SKIPs unless the
  `unibo-bp*` tools are on `PATH` (or `UNIBO_BP_BIN_DIR`).
- `tests/dissect-quic` — captures a loopback session, decrypts it with the
  `SSLKEYLOGFILE` key log, and checks that the `quiccl-wireshark` dissector
  decodes the QUICCL messages. SKIPs without `tshark`, capture privilege, or
  the dissector plugin (see below).

## Observing traffic in Wireshark

The [`quiccl-wireshark`](https://gitlab.com/mattiamoffa/quiccl-wireshark)
dissector decodes the QUICCL messages carried on the QUIC streams (and hands
the reassembled bundles to Wireshark's BPv7 dissector), a convenient way to
document a successful (interop) run. It is a compiled Wireshark plugin: build
it against the `wireshark-dev` headers and drop `quiccl.so` into your
version-specific personal plugin dir, e.g.
`~/.local/lib/wireshark/plugins/<major.minor>/epan/` (see Wireshark's *Help >
About > Folders*). It targets recent Wireshark (4.4+); on older releases it
needs a few source tweaks. It needs Wireshark to decrypt the QUIC layer first.

`quiccla` uses GnuTLS, which writes a TLS key log to the file named by the
`SSLKEYLOGFILE` environment variable, so the CLA itself needs no change. To
capture a decryptable session, export the variable before starting ION (so the
spawned `quiccla` inherits it) and capture UDP on the quic port:

```
export SSLKEYLOGFILE=/tmp/quic.keys
# start the node / run a test, then capture, e.g.:
dumpcap -i lo -f 'udp port 4560' -w /tmp/quic.pcap
```

Point Wireshark at the key log (*Edit > Preferences > Protocols > TLS >
(Pre)-Master-Secret log filename*), or use
`tshark -o tls.keylog_file:/tmp/quic.keys -r /tmp/quic.pcap`; the QUIC frames
then decrypt and the dissector labels the SESS_INIT / XFER_SEGMENT / XFER_ACK
messages.

## Verified by inspection

Some behaviours are verified by inspection rather than by the automated
suite, as they are awkward to drive with the standard BP tools:
cumulative `XFER_ACK` transmission (the sender does not block on it),
`KEEPALIVE` emission on a long-idle session, and `MSG_REJECT` generation.
`XFER_REFUSE` is decoded but never originated by this implementation.

## License

See the repository root for details.
