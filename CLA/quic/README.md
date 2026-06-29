# QUIC Convergence Layer Adapter (quiccli / quicclo)

A Bundle Protocol v7 convergence layer adapter pair that carries bundles over
QUIC, implementing the **QUICCL** protocol of
[draft-caini-dtn-quiccl](https://datatracker.ietf.org/doc/draft-caini-dtn-quiccl/)
(QUICCLv1). Built on [ngtcp2](https://github.com/ngtcp2/ngtcp2) with the
**GnuTLS** crypto backend.

- `quicclo` — output daemon: the QUICCL **active** entity (QUIC client). It
  connects to a peer, performs the SESS_INIT exchange, and transmits bundles.
- `quiccli` — input daemon: the QUICCL **passive** entity (QUIC server). It
  accepts connections, replies to SESS_INIT, reassembles bundles and injects
  them into ION. The server demultiplexes connections by connection ID.

ION carries each direction over its own duct, so a QUICCL session here is used
unidirectionally (clo → cli); this is a conformant use of the protocol.

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
- **Unreliable service (`quicclo -u`):** bundles are segmented and sent as QUIC
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

The server (`quiccli`) requires a certificate (`-c`) and key (`-k`). The
client (`quicclo`) verifies the server against the system trust store or a CA
file (`-C`); `-n` disables verification (e.g. self-signed certificates).

GnuTLS is the only ngtcp2 crypto backend currently packaged on common distros.
The TLS code is isolated behind `quictls.h`, so an OpenSSL or wolfSSL backend
can be added as a sibling `quictls_*.c` without touching the engine.

## Configuration

Duct name is `host[:port]` (default port 4560, UDP):

```
a protocol quic
a induct  quic '0.0.0.0:4560' 'quiccli -c server.pem -k server.key'
a outduct quic 'peer.example:4560' 'quicclo -C ca.pem'
```

Flags: `-c`/`-k` cert/key, `-C` CA file, `-A` ALPN, `-n` no-verify, `-t` idle
timeout (s), `-u` unreliable (datagram) service.

## Layout

```
src/quiccla.h          constants, config, duct/arg parsing
src/quicmsg.{c,h}      QUICCL wire-message codec (dependency-free)
src/quictls.{h}        TLS backend interface
src/quictls_gnutls.c   GnuTLS backend
src/quicsession.{c,h}  ngtcp2 engine: session state machine, streams, datagrams
src/quicclo.c          output daemon (active entity / client)
src/quiccli.c          input daemon  (passive entity / server)
doc/*.pod              man page sources
tests/loopback-quic/         single-node reliable loopback (.optional)
tests/loopback-quic-dgram/   single-node unreliable loopback (.optional)
bench/bench-quic             throughput benchmark
```

## Testing

- `make check` — codec round-trip unit tests for every message type.
- `tests/loopback-quic` — reliable service: single- and multi-segment
  transfers, multiple streamed bundles, priority-to-stream routing
  (a high-ordinal bundle must use stream 4), and graceful SESS_TERM.
- `tests/loopback-quic-dgram` — unreliable service over multiple datagrams.

Some behaviours are verified by inspection rather than by the automated
suite, as they are awkward to drive with the standard BP tools:
cumulative `XFER_ACK` transmission (the sender does not block on it),
`KEEPALIVE` emission on a long-idle session, and `MSG_REJECT` generation.
`XFER_REFUSE` is decoded but never originated by this implementation.

## License

See the repository root for details.
