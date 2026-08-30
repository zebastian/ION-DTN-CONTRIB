# TCPCLv4 Convergence Layer Adapter (tcpv4cla)

A Bundle Protocol v7 convergence layer adapter implementing **TCPCL version
4**, [RFC 9174](https://www.rfc-editor.org/rfc/rfc9174.html), over TLS 1.3
(**GnuTLS**).

ION ships a TCPCL **version 3** adapter (`tcpcli`, RFC 7242). TCPCLv4 is a
different protocol on the wire — different contact header, different message
type codes, mandatory-to-implement TLS, 64-bit lengths, extension items — so
this is a separate CLA under its own `tcpv4` protocol name rather than a patch
to `tcpcli`. The two can coexist on a node (on different ports).

TCPCLv4 sessions are **bidirectional**: once established, either entity may
transfer bundles over the session regardless of which one opened the TCP
connection.

`tcpv4cla` is the convergence-layer daemon. It listens on a TCP socket, accepts
sessions and injects the bundles they carry into ION; it also opens sessions
for the egress plans that cite `tcpv4` outducts and drains those outducts,
transmitting over the session to that node. An established session to a node is
reused for both directions, whether `tcpv4cla` accepted it or opened it.

## Protocol

- **TCP port 4556** (RFC 9174 §8.1), contact header magic `dtn!`, version 4.
- **Session establishment** (§4): the active entity sends its contact header
  first and the passive entity answers; Enable TLS is the logical AND of the
  two `CAN_TLS` flags, then local policy is applied; the TLS handshake (active
  entity = TLS client, passive entity = TLS server, both presenting
  certificates) runs before any TCPCL message; then both entities send
  `SESS_INIT` and the session parameters are negotiated (keepalive = min of
  the two proposals, Segment/Transfer MTU = the peer's MRUs).
- **Transfers** (§5.2): each bundle is one transfer with its own 64-bit
  Transfer ID, segmented to the peer's Segment MTU and sent as `XFER_SEGMENT`
  messages with START/END flags. Segments are pipelined, not stop-and-wait; the
  receiver acknowledges each with a cumulative `XFER_ACK`, and the sender
  reports transmission success to BP only once the whole transfer is acked.
- **Refusal** (§5.2.4): an inbound transfer that would exceed the advertised
  Transfer MRU, that carries an unknown CRITICAL transfer extension item, or
  that starts while the session is Ending is answered with `XFER_REFUSE` and
  drained.
- **Upkeep** (§5.1): `KEEPALIVE` at the negotiated interval, `MSG_REJECT` for
  unknown / unexpected messages, and session failure when nothing has been
  received for twice the keepalive interval.
- **Termination** (§6): `SESS_TERM` with the REPLY flag exchanged on shutdown,
  and optional idle session termination (`-t`).

## Conformance to RFC 9174

| Area | Status |
|------|--------|
| Contact header, version negotiation, `CAN_TLS` (§4.2, §4.3) | implemented |
| TLS 1.3 handshake, mutual certificates, SNI (§4.4) | implemented (GnuTLS) |
| `SESS_INIT` exchange + parameter negotiation (§4.6, §4.7) | implemented |
| Session extension items (§4.8) | parsed; unknown CRITICAL ends the session |
| `KEEPALIVE`, `MSG_REJECT` (§5.1) | implemented |
| `XFER_SEGMENT` / `XFER_ACK`, segment pipelining (§5.2.2, §5.2.3) | implemented |
| `XFER_REFUSE` (§5.2.4) | originated and decoded |
| Transfer extension items (§5.2.5) | parsed; unknown CRITICAL refuses the transfer |
| `SESS_TERM`, REPLY flag, Ending state (§6.1) | implemented |
| Idle session termination (§6.2) | implemented (`-t`) |
| Reconnection backoff, contact timeout (§4.1) | implemented (binary backoff, capped at 60 s) |
| Node ID authentication for routing (§4.4.4, §7.9) | peer node ID is used for session reuse only; the authenticated flag is logged, not enforced |
| TCPCLv3 fallback after "Version mismatch" (§4.3) | **not implemented** (an implementation matter; use `tcpcli` for v3 peers) |
| Emitting session / transfer extension items | **not implemented** (none defined) |

## TLS

`tcpv4cla` requires a certificate (`-c`) and key (`-k`), used in both roles:
RFC 9174 §4.4.3 has the passive entity supply a certificate *and* request one
from the active entity. Peers are verified against the system trust store or a
CA file (`-C`); `-n` disables verification (e.g. self-signed certificates)
while still using TLS, and the session is then reported as unauthenticated.

`-T` sets the policy applied to the negotiated Enable TLS value: `require`
(default), `prefer` (opportunistic security, RFC 7435), or `none` (plaintext).
Only TLS 1.3 is offered, per §4.4.3.

The TLS code is isolated behind `tcpv4tls.h`, so an OpenSSL or wolfSSL backend
can be added as a sibling `tcpv4tls_*.c` without touching the engine.

## Configuration

Duct name is `host[:port]` (default port 4556, TCP). Declare a `tcpv4` induct
(its command starts the daemon) and a `tcpv4` outduct per reachable peer; the
daemon drains the outducts, so their command is empty:

```
a protocol tcpv4
a induct  tcpv4 '0.0.0.0:4556' 'tcpv4cla -c node.pem -k node.key -C ca.pem'
a outduct tcpv4 'peer.example:4556' ''
```

Flags (on the `tcpv4cla` induct command): `-c`/`-k` cert/key, `-C` CA file,
`-n` no-verify, `-T` TLS policy (`require`/`prefer`/`none`), `-K` keepalive
interval to propose, `-t` idle session timeout, `-S`/`-M` advertised Segment
and Transfer MRUs, `-r`/`-w` socket receive/send buffer sizes in bytes
(`SO_RCVBUF`/`SO_SNDBUF`; 0 = OS default).

Note that ION's own `tcp` protocol (TCPCLv3, `tcpcli`) also defaults to port
4556; give one of them a different port if both run on the same node.

## Layout

```
src/tcpv4cla.h          constants, config, duct/arg parsing
src/tcpv4msg.{c,h}      RFC 9174 wire-message codec (dependency-free)
src/tcpv4tls.h          TLS backend interface
src/tcpv4tls_gnutls.c   GnuTLS backend (TLS 1.3)
src/tcpv4session.{c,h}  session engine: accept and connect, per-session
                        receiver thread, state machine, transfers, clock
src/tcpv4cla.c          daemon (accepts + opens sessions, drains outducts)
doc/*.pod               man page sources
tests/loopback-tcpv4/       single-node loopback over TLS (.optional)
tests/loopback-tcpv4-notls/ single-node plaintext loopback (.optional)
bench/bench-tcpv4           throughput benchmark (TLS / plaintext / TCPCLv3)
```

## Threading

One accept thread; one receiver thread per session, which runs the
establishment sequence and then the message loop; one clock thread driving
keepalives, timeouts and idle termination for every session; and one sender
thread per `tcpv4` outduct, drained by `bpDequeue`. Every socket write is
serialised per session, since RFC 9174 §5.2.4 forbids interleaving a message
with another. Each session has its own acquisition work area and attendant, so
one session blocking on ZCO space does not disturb another.

## Testing

- `make check` — codec round-trip unit tests for the contact header, every
  message type, and the extension-item TLV walker.
- `tests/loopback-tcpv4` — over TLS: session establishment, a single-segment
  transfer, a multi-segment transfer (Segment MRU forced to 2000 with `-S`),
  50 streamed bundles, an idle period survived on KEEPALIVEs, and a graceful
  `SESS_TERM` on shutdown.
- `tests/loopback-tcpv4-notls` — `-T none`: Enable TLS negotiated to false,
  bundle transfer, idle session termination (`-t 8`), and re-establishment of
  the session afterwards.

Both loopback tests are marked `.optional`; the TLS one needs `openssl` to
generate a throwaway certificate.

## Benchmarking

`bench/bench-tcpv4` drives a single-node loopback with `bpdriver` ->
[CL] -> `bpcounter` over a sweep of bundle sizes, and sweeps three modes
through the identical measurement path so the differences are the
protocol's and not the harness's: `tls`, `plaintext` (`-T none`), and
`tcpv3` — ION's stock `tcpcli` (RFC 7242) as a baseline.

Like ION's own `demos/bench-tcp`, the sweep holds the total bytes per size
constant (`TOTALBYTES`, default 32 MB) and derives the bundle count from
it, rather than sending a fixed number of bundles at every size. A fixed
count quadruples the queued payload from one size to the next and runs the
SDR heap out at the large end, which stalls the run instead of measuring
it — a trap ION's own benchmark README warns about, and one that takes
`tcpcli` down just as it does this CLA.

Measured on one x86-64 Linux host, loopback, 32 MB per size, every size
delivering 100% (Mbps as reported by `bpcounter`):

| payload | bundles | tcpv4 TLS | tcpv4 plaintext | TCPCLv3 (`tcpcli`) |
|--------:|--------:|----------:|----------------:|-------------------:|
|   1 KiB |  10000  |     19.6  |           19.0  |              19.6  |
|   2 KiB |  10000  |     31.1  |           31.1  |              32.9  |
|   4 KiB |   7812  |     60.8  |           59.2  |              60.0  |
|   8 KiB |   3906  |    110.6  |          108.4  |             111.4  |
|  16 KiB |   1953  |    199.7  |          205.0  |             224.8  |
|  32 KiB |    976  |    331.6  |          340.7  |             375.4  |
|  64 KiB |    488  |    494.8  |          530.0  |             551.6  |

Reading it: TCPCLv4 is at parity with ION's TCPCLv3 up to 8 KiB and about
10% behind it from 16 KiB up, where `tcpcli`'s transmission pipeline (it
keeps up to 100 bundles awaiting acknowledgment) starts to pay off against
this implementation's one-transfer-at-a-time sender, which RFC 9174 5.2.2
requires within a single session but which a v4 implementation may overlap
across several sessions. TLS costs nothing measurable below 16 KiB and
about 5-7% at 64 KiB, where the AEAD work scales with the payload.

Throughput at small sizes is dominated by ION's per-bundle cost, not by
the convergence layer: all three modes land within 3% of each other at
1 KiB.

> A note on where these numbers came from: the first version of this CLA
> benchmarked at 0.2 Mbps, some 30x slower than `tcpcli`, because it wrote
> each XFER_SEGMENT's header and payload as two separate writes with no
> `TCP_NODELAY` — so every header waited on the previous write's
> acknowledgment, a ~40 ms stall per bundle. The segment now goes out as a
> single `writev` (or a single corked TLS record), and every socket sets
> `TCP_NODELAY`.

## Observing traffic in Wireshark

Wireshark dissects TCPCLv4 natively (`tcpcl` dissector, "TCP Convergence
Layer"); point it at the port in use with *Decode As...* if it is not 4556. A
plaintext run (`-T none`) is therefore readable with no extra setup. For a TLS
run, GnuTLS writes a TLS key log to the file named by the `SSLKEYLOGFILE`
environment variable, so exporting it before starting ION (the spawned
`tcpv4cla` inherits it) lets Wireshark decrypt the session:

```
export SSLKEYLOGFILE=/tmp/tcpv4.keys
# start the node / run a test, then capture, e.g.:
dumpcap -i lo -f 'tcp port 4556' -w /tmp/tcpv4.pcap
tshark -o tls.keylog_file:/tmp/tcpv4.keys -r /tmp/tcpv4.pcap
```

## Verified by inspection

Some behaviours are verified by inspection rather than by the automated suite,
as they are awkward to drive with the standard BP tools: `MSG_REJECT`
generation, `XFER_REFUSE` on an oversized transfer or an unknown CRITICAL
extension item, the "Version mismatch" and "Contact Failure" termination paths,
and the reconnection backoff.

## License

See the repository root for details.
