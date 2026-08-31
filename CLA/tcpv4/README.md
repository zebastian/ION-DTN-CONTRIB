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
  *Transfers* are pipelined too: §5.2.2 forbids interleaving the segments of
  two transfers, but not beginning one before the previous is acknowledged, so
  up to 100 transfers (or 4 MB) may be outstanding on a session at once. Each
  START segment carries a Transfer Length extension item (§5.2.5.1).
- **Refusal** (§5.2.4): an inbound transfer that would exceed the advertised
  Transfer MRU, that carries an unknown CRITICAL transfer extension item, or
  that starts while the session is Ending is answered with `XFER_REFUSE` and
  drained.
- **Upkeep** (§5.1): `KEEPALIVE` at the negotiated interval, `MSG_REJECT` for
  unknown / unexpected messages, and session failure when nothing has been
  received for twice the keepalive interval.  An inbound `MSG_REJECT` is
  reported and never answered with another, which §5.1.2 forbids; one that
  names the transfer machinery ends the session, since the two ends no longer
  agree about its state.
- **Termination** (§6): `SESS_TERM` with the REPLY flag exchanged on shutdown,
  no new transfer begun once one has been sent, and optional idle session
  termination (`-t`).  A connection arriving past the session limit (`-L`) is
  told `SESS_TERM` "Busy" rather than simply dropped.

## Conformance to RFC 9174

| Area | Status |
|------|--------|
| Contact header, version negotiation, `CAN_TLS` (§4.2, §4.3) | implemented |
| TLS 1.3 handshake, mutual certificates, SNI (§4.4) | implemented (GnuTLS) |
| `SESS_INIT` exchange + parameter negotiation (§4.6, §4.7) | implemented |
| Session extension items (§4.8) | parsed; unknown CRITICAL ends the session |
| `KEEPALIVE`, `MSG_REJECT` (§5.1) | implemented |
| `XFER_SEGMENT` / `XFER_ACK`, segment pipelining (§5.2.2, §5.2.3) | implemented |
| `XFER_REFUSE` (§5.2.4) | originated and honoured; "Completed" counts the transfer as sent |
| `MSG_REJECT` (§5.1.2) | originated and honoured; never sent in answer to one |
| Transfer extension items (§5.2.5) | parsed; unknown CRITICAL refuses the transfer |
| Transfer Length extension item (§5.2.5.1) | emitted and honoured |
| `SESS_TERM`, REPLY flag, Ending state (§6.1) | implemented |
| Idle session termination (§6.2) | implemented (`-t`) |
| Reconnection backoff, contact timeout (§4.1) | implemented (randomized binary backoff, capped at 60 s, reset only by an established session) |
| Session limit and "Busy" refusal (§6.1, §7.10) | implemented (`-L`, plus a per-address cap on concurrent negotiations) |
| Peer node ID (§4.6) | any EID scheme; sessions are keyed on the node ID, not on an ipn node number |
| NODE-ID authentication (§4.4.1, §4.4.4.3, §7.9) | implemented (`-E`); an unauthenticated node ID never attracts egress |
| Network-level (DNS-ID / IPADDR-ID) authentication (§4.4.4.2) | implemented via the TLS hostname check; not separately configurable |
| Certificate profile, extended key usage (§4.4.2) | implemented; a certificate restricted to other purposes is refused |
| Path validation and revocation (§4.4.4.1) | implemented; revocation lists via `-R` (RFC 5280 §6.3). OCSP **not implemented** |
| TCPCLv3 fallback after "Version mismatch" (§4.3) | **not implemented** (an implementation matter; use `tcpcli` for v3 peers) |
| Emitting session extension items | **not implemented** (none defined) |

## TLS

`tcpv4cla` requires a certificate (`-c`) and key (`-k`), used in both roles:
RFC 9174 §4.4.3 has the passive entity supply a certificate *and* request one
from the active entity. Peers are verified against the system trust store or a
CA file (`-C`); `-n` disables verification (e.g. self-signed certificates)
while still using TLS, and the session is then reported as unauthenticated.

`-T` sets the policy applied to the negotiated Enable TLS value: `require`
(default), `prefer` (opportunistic security, RFC 7435), or `none` (plaintext).
Only TLS 1.3 is offered, per §4.4.3: `-P` chooses the cipher policy (a GnuTLS
priority string, `SECURE128` by default) but not the protocol version, which
is appended to whatever it names.

### Node ID authentication

A peer's `SESS_INIT` node ID is only a claim. RFC 9174 §4.4.1 defines a
**NODE-ID** as a `subjectAltName` `otherName` of form `id-on-bundleEID`
(OID `1.3.6.1.5.5.7.8.11`) whose value is that node ID, and §4.4.4.3 requires
validating it against the claim. §7.9 explains why: without it, any peer that
can complete a session — in a shared-CA deployment, *any* certificate holder —
can name itself as some other node and collect that node's traffic.

`-E` sets the policy: `require` (default, and what §4.4.5 recommends),
`prefer`, or `none`. Independently of the policy, **a node ID that was not
authenticated is never used to route bundles to the peer**: a session this
node accepted is marked *inbound only* and will not be selected to carry
bundles outward. A session this node opened keeps the node ID from its
egress plan, which came from configuration rather than from the wire, so
egress works even in plaintext — but if such a peer answers claiming a
*different* node ID that cannot be authenticated, that session is dropped from
egress selection too.

Because `-n` is a decision not to authenticate the peer at all, it implies
`-E none` unless `-E` is given explicitly — a NODE-ID in an unvalidated
certificate proves nothing.

### Revocation

RFC 9174 §4.4.4.1 has the entity "perform the certification path validation
described in [RFC5280] up to one of the entity's trusted CA certificates", and
checking whether the issuer has withdrawn the certificate is part of that
validation (RFC 5280 §6.3). The RFC names **OCSP** as the way to ask — "if
enabled by local policy, the entity SHALL perform an OCSP check of each
certificate providing OCSP authority information" — and §4.4.5 recommends
enabling it. It says nothing about OCSP stapling, and it puts the
"deploying or accessing [of] certificate revocation lists (CRLs)" explicitly
out of its own scope (§1.1).

`-R <crlfile>` loads revocation lists (PEM) and turns the check on. It is
revocation lists rather than OCSP because a list is a file: it can be given to
a node in advance, or carried to one over the DTN itself, where an OCSP
responder is something a disconnected node may have no way to reach — and
making session establishment wait on a live query to an internet responder,
inside the contact timeout of §4.1, is the wrong shape for this protocol. A
deployment that *can* reach a responder is exactly the one that should follow
§4.4.5 and enable OCSP, which this CLA does not yet do.

A file named by `-R` that cannot be read, or that holds no list, **stops the
daemon**. An operator who asked for revocation checking has to be told when it
is not happening; carrying on would leave the node believing it checks
revocation when it does not, which is worse than never having asked. `-R` with
`-n` is rejected for the same reason: revocation is a question about a
certificate one is checking at all.

### Certificate profile

RFC 9174 §4.4.2 asks that a certificate be valid for the role its holder
plays: `id-kp-serverAuth` for the passive entity, `id-kp-clientAuth` for the
active one. Every `tcpv4cla` is both — it accepts sessions and opens them —
so its certificate needs **both** purposes.

A peer certificate whose Extended Key Usage leaves out the purpose this
handshake needs is refused: it was issued for something else, and RFC 5280
§4.2.1.12 forbids using it here. Refusing it matters because everything
downstream rests on that certificate, the NODE-ID above all — without the
check, a mail certificate from a shared CA authenticates a TCPCL peer. A
certificate carrying *no* Extended Key Usage extension is unrestricted, so it
is accepted, with a memo noting the deviation from the profile.

Generating a certificate that carries a NODE-ID and both purposes, with
OpenSSL 1.1.1+:

```
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout node.key -out node.pem -days 365 -nodes -subj "/CN=node1.example" \
    -addext "subjectAltName=DNS:node1.example,\
otherName:1.3.6.1.5.5.7.8.11;IA5:ipn:1.0" \
    -addext "extendedKeyUsage=serverAuth,clientAuth"
```

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
`-R` CRL file, `-n` no-verify, `-T` TLS policy (`require`/`prefer`/`none`), `-E` NODE-ID
policy (`require`/`prefer`/`none`), `-K` keepalive
interval to propose, `-t` idle session timeout, `-S`/`-M` advertised Segment
and Transfer MRUs, `-r`/`-w` socket receive/send buffer sizes in bytes
(`SO_RCVBUF`/`SO_SNDBUF`; 0 = OS default), `-L` concurrent session limit,
`-P` GnuTLS priority string.

A peer is named by the neighbour EID of its egress plan, in whatever scheme
that EID uses. RFC 9174 §4.6 identifies a peer by a node ID rather than by a
node number, and that node ID is what the peer's `SESS_INIT` claim is matched
against and what its certificate has to authenticate, so a `dtn:` neighbour is
as reachable as an `ipn:` one. Two spellings of the same `ipn` node ID
(`ipn:5`, `ipn:5.0`, `ipn:0.5.0`) name the same node; anything else is
compared literally.

Note that ION's own `tcp` protocol (TCPCLv3, `tcpcli`) also defaults to port
4556; give one of them a different port if both run on the same node.

### Tuning

**Set `m heapmax` in your `bprc`.** This is by far the largest throughput
lever, and it is not in this CLA at all. ION acquires a received bundle into
the SDR heap only while it fits `maxAcqInHeap`, and otherwise spools it
through a file — one `open`/`write`/`close`/`unlink` per bundle. The default
is **560 bytes**, so a node that has not raised it writes very nearly every
bundle to disk on reception. Raising it to the largest bundle you expect
(here, the Transfer MRU) is worth 40–80% of throughput on its own, and helps
`tcpcli` exactly as much. `tcpv4cla` logs a warning at start-up when
`maxAcqInHeap` is below its advertised Transfer MRU:

```
m heapmax 262144
```

The SDR heap has to be sized for it (`heapWords` in the `.ionconfig`).

`-r`/`-w` set `SO_RCVBUF`/`SO_SNDBUF`. Leave them at 0 unless you have
measured a reason not to: setting either one **disables Linux's socket buffer
autotuning**, so a hand-set value is usually worse than the default, and on a
high bandwidth-delay path it is the autotuned maximum (`net.ipv4.tcp_rmem`)
you want to raise instead.

**Two ION limits constrain the induct command**, and both fail in ways that do
not name themselves. ION stores the command as an SDR string capped at
`MAX_SDRSTRING` (255) characters and truncates past that, so a long
certificate path can leave the daemon opening half a filename ("Error while
reading file"). Its spawn helper accepts at most **11 arguments**, the duct
name ION appends included, and rejects the command outright ("More than 11
args in command") — `-c X -k Y -C Z -T t -E e -K k` is already 13. Keep
credentials on short paths and lean on the defaults; both loopback tests check
these limits before starting ION so the failure is legible.

## Layout

```
src/tcpv4cla.h          constants and configuration struct
src/tcpv4cfg.c          duct-name and command-line argument parsing
src/tcpv4nodeid.{c,h}   node ID comparison (dependency-free)
src/tcpv4msg.{c,h}      RFC 9174 wire-message codec (dependency-free)
src/tcpv4tls.h          TLS backend interface
src/tcpv4tls_gnutls.c   GnuTLS backend (TLS 1.3)
src/tcpv4session.h      session engine interface (engine start/send/stop)
src/tcpv4sessint.h      session engine internals, shared by the units below
src/tcpv4session.c      engine: listening socket, session list, reconnection
                        backoff, accept and clock threads
src/tcpv4io.c           message-level session I/O (framing, socket options)
src/tcpv4negotiate.c    contact header, TLS handshake, SESS_INIT exchange
src/tcpv4rx.c           receive path: reassembly, message loop, delivery
src/tcpv4tx.c           send path: transmission window and transmit thread
src/tcpv4cla.c          daemon (accepts + opens sessions, drains outducts)
doc/*.pod               man page sources
tests/loopback-tcpv4/       single-node loopback over TLS (.optional)
tests/loopback-tcpv4-notls/ single-node plaintext loopback (.optional)
tests/nodeid-tcpv4/         NODE-ID authentication policy (.optional)
tests/certprofile-tcpv4/    certificate profile / key usage (.optional)
tests/revocation-tcpv4/     path validation against a CRL (.optional)
tests/protocol-tcpv4/       error paths, against a synthetic peer (.optional)
bench/bench-tcpv4           throughput benchmark (TLS / plaintext / TCPCLv3)
bench/bench-tcpv4-impaired  the same sweep over a delayed / lossy link
```

## Threading

One accept thread; one clock thread driving keepalives, timeouts and idle
termination for every session; one sender thread per `tcpv4` outduct, drained
by `bpDequeue`; and three threads per established session:

- the **receiver** thread, which runs the establishment sequence, then the
  message loop, and owns the other two;
- the **transmit** thread, the only writer of `XFER_SEGMENT`s — which is what
  keeps transfers from interleaving now that several may be outstanding. It
  streams each bundle out of its ZCO a bufferful at a time rather than copying
  it whole, so a large bundle neither costs a long SDR transaction nor has to
  fit a fixed buffer;
- the **delivery** thread, which hands a reassembled transfer to BP and then
  acknowledges it, so that acquisition overlaps with reading the next transfer
  off the wire.

Every socket write is serialised per session, since RFC 9174 §5.2.4 forbids
interleaving a message with another. Each session has its own acquisition work
area and attendant, so one session blocking on ZCO space does not disturb
another.

The hand-off to the delivery thread holds exactly one transfer. That bound is
deliberate: `bpContinueAcq` is given the attendant so that it *blocks* when ZCO
reception space is exhausted rather than dropping the bundle, and that
backpressure is meant to reach the peer by way of a closing TCP window. A
deeper queue here would absorb it instead, and the CLA would grow without
limit while BP was congested.

## Testing

- `make check` — codec round-trip unit tests for the contact header, every
  message type, and the extension-item TLV walker; and node ID comparison,
  which decides which session may carry a node's traffic.
- `tests/protocol-tcpv4` — the error paths, driven by a synthetic RFC 9174
  peer (`peer.py`) that speaks the protocol on a plaintext socket. The bp
  test tools can drive the happy path and no more: they cannot send a
  `MSG_REJECT`, refuse a transfer, stall part way through negotiation or
  leave a connection unanswered. Six phases, each asserting both what went
  over the wire and what `tcpv4cla` wrote to `ion.log`: an inbound
  `MSG_REJECT` is reported and never reflected (§5.1.2) while one naming
  `XFER_SEGMENT` ends the session; a transfer refused as "Completed" counts
  as sent while one refused otherwise comes back (§5.2.4); a peer that names
  itself `dtn://peer-b/` is routable (§4.6); connections left half-negotiated
  are rationed per address (§7.10); a session past `-L` is refused with
  `SESS_TERM` "Busy" (§6.1); and the reconnection delay grows after a peer
  that accepts the connection but never establishes a session (§4.1).
- `tests/loopback-tcpv4` — over TLS: session establishment, a single-segment
  transfer, a multi-segment transfer (Segment MRU forced to 2000 with `-S`),
  50 streamed bundles, an idle period survived on KEEPALIVEs, and a graceful
  `SESS_TERM` on shutdown.
- `tests/loopback-tcpv4-notls` — `-T none`: Enable TLS negotiated to false,
  bundle transfer, idle session termination (`-t 8`), and re-establishment of
  the session afterwards.
- `bench/bench-tcpv4-impaired` — the same measurement path over a delayed
  link (`misc/linkimpair` behind an NFQUEUE), sweeping round-trip time at a
  fixed bundle size. This is what shows the transmission window working:
  loopback has no round-trip time, so `bench-tcpv4` cannot distinguish a CL
  that keeps one bundle in flight from one that keeps a hundred. At 200 ms
  RTT with 4 KiB bundles, over 16 MB, this CLA sustains about 300 bundles/s
  against `tcpcli`'s 57. Note that ION sets `TCP_NODELAY` nowhere, and
  `tcpcli` writes each segment's header and payload separately, so part of
  that gap is Nagle rather than pipelining.

  `BENCH_MSS=1460` clamps the MSS both ends advertise, giving realistically
  sized segments without touching loopback's 64 KiB MTU. That multiplies the
  packet count by about forty, which is more than `linkimpair` can carry: as
  a userspace NFQUEUE handler it sustains roughly 6500 packets/s at a 5 ms
  delay but only 150/s at 25 ms, and past that point it is the impairer
  being measured rather than the convergence layer. Use
  `BENCH_IMPAIRER=netem` for clamped runs at any real delay — it impairs in
  the kernel, at the cost of applying to the whole loopback device rather
  than to one port, and it needs `NOPASSWD: /usr/sbin/tc`.

  Two traps in this measurement, both of which the script now guards
  against. `--queue-bypass` means a *full* nfnetlink queue does not drop but
  **bypasses**, so the excess arrives undelayed and an overloaded run looks
  *faster* than it is; the script compares the rule's packet counter against
  what `linkimpair` reports handling and warns when they disagree. And the
  impairment must be installed *before* the node starts: `tcpcli` connects
  as its daemon comes up, so a clamp added afterwards would never reach its
  SYN, and it would keep using 64 KiB segments while `tcpv4cla` used
  1460-byte ones.
- `tests/certprofile-tcpv4` — RFC 9174 §4.4.2, three certificates alike in
  everything but their Extended Key Usage: `serverAuth,clientAuth` (the
  profile the RFC asks for, and what a `tcpv4cla` needs, since it is both
  entities) establishes a session and carries a bundle; `emailProtection`
  alone is refused, and nothing gets through; no extension at all is
  accepted, since RFC 5280 §4.2.1.12 makes that unrestricted, with the
  deviation logged.
- `tests/revocation-tcpv4` — RFC 9174 §4.4.4.1, against a real CA, since a
  self-signed certificate has no issuer to withdraw it: a certificate the CRL
  does not name carries a bundle; the same certificate, once the CA has
  revoked it and reissued the CRL, establishes no session and the log says
  why; and a `-R` file that is not a CRL stops the daemon instead of leaving
  it to believe it is checking.
- `tests/nodeid-tcpv4` — RFC 9174 §4.4.4.3: with a certificate carrying no
  NODE-ID, `-E require` refuses the session with "Contact Failure" and no
  bundle gets through, while `-E prefer` keeps the session but marks the
  accepted side inbound only, so a merely claimed node ID cannot attract
  egress.

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
10% behind it from 16 KiB up. TLS costs nothing measurable below 16 KiB and
about 5-7% at 64 KiB, where the AEAD work scales with the payload.

These figures predate the transmission window, and loopback cannot show
what the window is for: with no round-trip time to hide, a sender that
keeps one transfer in flight and one that keeps a hundred measure the
same. The impaired-link sweep below is the measurement that separates
them.

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

## Diagnostics

ION has no log levels, so the daemon says what happened in `ion.log` memos —
`[i]` for the ordinary course of a session, `[?]` for anything an operator
would want to look into. These are also what the tests assert on, so the
wording is deliberately stable:

| Memo | Means |
|------|-------|
| `session established with '...'` | with the peer's node ID, whether TLS and the NODE-ID authenticated, and whether the session is `bidirectional` or `inbound only` |
| `got MSG_REJECT from '...'` | the peer rejected a message of ours, with the reason and the message type |
| `ending a session whose transfers were rejected by` | that rejection named the transfer machinery, so the session is being ended (§5.1.2) |
| `transfer refused by '...'` | with the reason, and whether the bundle counts as sent (`already completed`) or goes back to BP |
| `refusing a connection, too many sessions being negotiated with` | the per-address cap on concurrent negotiations (§7.10) |
| `refusing a session, too many sessions open` | past `-L`; the peer is being told `SESS_TERM` "Busy" (§6.1) |
| `refusing a connection, session limit reached` | past `-L` plus the slack, so not even that far |
| `has more than one session to node` | two nodes dialled each other; senders settle on one and the other falls idle |
| `no session took the bundle, will retry` | said once per run of refusals, not once per attempt |
| `peer claims an unauthenticated node ID that is not the one dialled` | the session will not be used for egress (§7.9) |
| `peer's certificate is not valid for this role` | its extended key usage leaves out the purpose this handshake needs (§4.4.2); the session is refused |
| `peer's certificate carries no extended key usage` | unrestricted, so usable, but not the profile §4.4.2 asks for |
| `peer's certificate has been revoked by its issuer` | it appears on a list loaded by `-R` (§4.4.4.1, RFC 5280 §6.3) |
| `can't load CRL file` | `-R` named something unusable; the daemon stops rather than run without the check |

## Verified by inspection

Some behaviours are still verified by inspection rather than by the automated
suite: `XFER_REFUSE` on an oversized transfer or an unknown CRITICAL extension
item, and the "Version mismatch" termination path.  A NODE-ID that is present
but names a *different* node (the `Failure` case of RFC 9174 §4.4.4, as
against the `Absent` case the test covers) is likewise verified by
inspection.

## License

See the repository root for details.
