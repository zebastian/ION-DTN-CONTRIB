# TCPCLv4 Convergence Layer Adapter (tcpv4cla)

A Bundle Protocol v7 convergence layer adapter implementing **TCPCL version
4**, [RFC 9174](https://www.rfc-editor.org/rfc/rfc9174.html), over TLS 1.3
(**GnuTLS** or **Mbed TLS**).

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
| TLS 1.3 handshake, mutual certificates, SNI (§4.4) | implemented (GnuTLS or Mbed TLS) |
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
| Certificate profile, key usage and EKU (§4.4.2, §4.4.4.1) | implemented; a certificate restricted to other purposes is refused, `-B` applies the §4.4.5 policy |
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
Only TLS 1.3 is offered, per §4.4.3: `-P` chooses the cipher policy — in the
syntax of whichever backend this build uses (see below) — but not the protocol
version, which is imposed on top of whatever it names.

### TLS backends

The TLS 1.3 §4.4.3 requires can come from either of two libraries, chosen when
the tree is configured:

```
./configure --enable-cla-tcpv4                          # auto: GnuTLS if present
./configure --enable-cla-tcpv4 --with-tcpv4-tls=mbedtls # Mbed TLS >= 3.6
```

GnuTLS needs 3.6.5 or later (TLS 1.3). Mbed TLS needs 3.6 or later, built with
`MBEDTLS_SSL_PROTO_TLS1_3` — TLS 1.3 arrived in 3.x and can still be compiled
out — and with `MBEDTLS_THREADING_C`, since the CLA shares one TLS
configuration between the handshakes of concurrent sessions and that is what
the library's threading layer makes safe. `configure` asks the headers for all
three rather than trusting a version number. Note that only recent
distributions package Mbed TLS 3.6 (Debian and Ubuntu shipped 2.28 for a long
while); where the packaged one is older, build 3.6 and name it with
`MBEDTLS_CFLAGS` / `MBEDTLS_LIBS` or through `PKG_CONFIG_PATH`. `tcpv4cla`
names the backend it is running with in its start-up line in `ion.log`.

All of the CLA's use of a TLS library is confined behind `src/tcpv4tls.h` and
implemented in one `src/tcpv4tls_<backend>.c`, so the session engine, the
protocol and the wire are the same either way. Three things an operator can
see are not:

- **`-P` syntax.** GnuTLS takes a priority string (`SECURE128` by default);
  Mbed TLS takes a colon-separated list of ciphersuite names, such as
  `TLS1-3-AES-256-GCM-SHA384:TLS1-3-CHACHA20-POLY1305-SHA256`. Without `-P`
  each library's own list is used, less `TLS_AES_128_CCM_8_SHA256` — the one
  TLS 1.3 suite with a truncated (64-bit) authentication tag, which BCP 195
  (RFC 9325 §4.2) asks not be negotiated and which Mbed TLS would otherwise
  offer.
- **The system trust store**, used when `-C` is absent. GnuTLS finds the
  platform's; the Mbed TLS backend, which has no such notion to draw on, looks
  in the usual files (`/etc/ssl/certs/ca-certificates.crt` and its
  equivalents) and then in `/etc/ssl/certs`. A system that keeps its anchors
  elsewhere wants `-C`.
- **This node's own certificate.** Mbed TLS will not offer a server
  certificate that omits `id-kp-serverAuth`, which §4.4.2 does not require of
  one, so under that backend `-c` has to name a certificate carrying
  `id-kp-serverAuth` and `id-kp-clientAuth` — as the example below does — or
  carrying no extended key usage at all. A certificate carrying
  `id-kp-bundleSecurity` alone, which is what §4.4.5 recommends issuing, is
  accepted from a *peer* under both backends but cannot be used as this node's
  own under Mbed TLS.

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

RFC 9174 §4.4.2 asks for less than one might assume. A TCPCL certificate
**SHOULD** carry `id-kp-bundleSecurity` (`1.3.6.1.5.5.7.3.35`), **MAY** carry
`id-kp-clientAuth` and `id-kp-serverAuth`, and need carry no Extended Key
Usage extension at all. §4.4.4.1 then requires that security policy be applied
to the key usage and extended key usage extensions *if present*, per RFC 5280
§§4.2.1.3 and 4.2.1.12.

So a peer certificate is usable here when its EKU names the TLS purpose this
role needs (`id-kp-serverAuth` from the passive entity, `id-kp-clientAuth`
from the active one), or names `id-kp-bundleSecurity`, or names
`anyExtendedKeyUsage`, or carries no EKU at all. It is refused when it carries
an EKU naming none of those: it was issued for something else, and RFC 5280
forbids using it here. That refusal matters because everything downstream
rests on this certificate, the NODE-ID above all — without the check, a mail
certificate from a shared CA authenticates a TCPCL peer.

`-B` sets the policy §4.4.5 recommends, that a certificate carrying an EKU at
all name `id-kp-bundleSecurity` in it: `require` refuses one that does not,
`prefer` (default) accepts it and says so, `none` asks only what RFC 5280
asks. None of the three refuses a certificate with no EKU, since §4.4.2 does
not require one. The default is `prefer` rather than `require` because
requiring it would refuse certificates that work today; a deployment issuing
its own certificates should use `require`.

A key usage extension that withholds `digitalSignature` is refused outright:
every TLS 1.3 cipher suite authenticates the peer by a signature, so such a
certificate cannot have authenticated the handshake it just completed. Both
TLS libraries generally decline these during the handshake anyway; the check
here is the backstop.

Every `tcpv4cla` is both entities — it accepts sessions and opens them — so
its own certificate wants both TLS purposes. Generating one that carries a
NODE-ID and the full profile, with OpenSSL 1.1.1+:

```
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout node.key -out node.pem -days 365 -nodes -subj "/CN=node1.example" \
    -addext "subjectAltName=DNS:node1.example,\
otherName:1.3.6.1.5.5.7.8.11;IA5:ipn:1.0" \
    -addext "extendedKeyUsage=serverAuth,clientAuth,1.3.6.1.5.5.7.3.35" \
    -addext "keyUsage=digitalSignature"
```

The TLS code is isolated behind `tcpv4tls.h` — the GnuTLS and Mbed TLS
backends are two implementations of it — so an OpenSSL or wolfSSL backend can
be added as a sibling `tcpv4tls_*.c` without touching the engine. The
certificate decoding that neither library does for us (the NODE-ID
`otherName`, the extension walk) lives once in `tcpv4x509.c` rather than in
each backend.

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
`-R` CRL file, `-B` certificate profile policy, `-n` no-verify, `-T` TLS policy (`require`/`prefer`/`none`), `-E` NODE-ID
policy (`require`/`prefer`/`none`), `-K` keepalive
interval to propose, `-t` idle session timeout, `-S`/`-M` advertised Segment
and Transfer MRUs, `-r`/`-w` socket receive/send buffer sizes in bytes
(`SO_RCVBUF`/`SO_SNDBUF`; 0 = OS default), `-L` concurrent session limit,
`-W` transmission window as `count[:bytes]`, `-P` cipher policy in the TLS
backend's own syntax.

The transmission window is what bounds throughput on a link with a long
round-trip time: several transfers may await their `XFER_ACK` at once, so a
session carries about one window per round trip rather than one bundle. It
defaults to `100:4194304` - 100 transfers or 4 MB of them, whichever binds
first - which is about 500 bundles per second at a 200 ms round-trip time.
Raise it for a long link; the octet bound is the outbound ZCO space a session
may pin, since an unacknowledged transfer holds its bundle until the
acknowledgment retires it.

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
src/tcpv4tls_mbedtls.c  Mbed TLS backend (TLS 1.3)
src/tcpv4x509.{c,h}     certificate decoding shared by the backends
                        (dependency-free)
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
  message type, and the extension-item TLV walker; node ID comparison, which
  decides which session may carry a node's traffic; and the certificate
  decoding both TLS backends share, which decides who a peer is allowed to
  be.
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

  `BENCH_WINDOW` passes `-W` through to `tcpv4cla`, and `BENCH_RCVBUF` /
  `BENCH_SNDBUF` pass `-r` / `-w`, which is how to find out what a run is
  actually measuring. At this size and delay it is not the window: 4 KiB
  bundles at 300/s hold the impairer at about 100 packets/s, which is all it
  carries at a 100 ms delay, and neither a larger window nor larger socket
  buffers moves the figure. Smaller bundles are where the default window
  binds - see "What the transmission window is worth" below.

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
  deviation logged. Two further phases cover `-B require` and a key usage
  that forbids signing. The phase that offers `id-kp-bundleSecurity` alone
  is skipped under the Mbed TLS backend, which will not offer such a
  certificate as its own (see "TLS backends"); everything the test asks of a
  *peer's* certificate holds under both.
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

### What the transmission window is worth

`bench/bench-tcpv4-impaired` with `BENCH_WINDOW` sweeping `-W`, TLS mode,
same host, `linkimpair` supplying the delay:

| link | bundle | `-W` | bundles/s | Mbps |
|------|-------:|------|----------:|-----:|
| 200 ms RTT | 1 KiB | `10:33554432`  |  40 |  0.33 |
| 200 ms RTT | 1 KiB | default (`100:4194304`) | 402 |  3.30 |
| 200 ms RTT | 1 KiB | `1000:33554432` | 931 |  7.63 |
| 200 ms RTT | 1 KiB | `1000:32768` | 111 |  0.91 |
|  10 ms RTT | 4 KiB | `10:33554432`  | 733 | 24.0  |
|  10 ms RTT | 4 KiB | default | 3561 | 116.7 |

The window is the bound, and it is close to arithmetic: a session carries
about one window per round trip, so 100 transfers per 200 ms is a ceiling of
500 bundles/s and 402 is what that measures out at. Ten times the window is
2.3 times the throughput here, not ten, because something else takes over
before the new ceiling is reached - which is the point of measuring rather
than assuming. The fourth row holds the count at 1000 and shrinks the octet
bound to 32 KiB instead: 32 KiB of 1 KiB bundles is 32 in flight, and the
throughput lands where a window of 32 would. Either half of `-W` can be the
one that binds.

The default does not bind everywhere. At 10 ms RTT it admits 10,000
bundles/s, ten times what ION itself will pass at 4 KiB, so the last row is
measuring ION and not the window. And at 200 ms RTT with 4 KiB bundles this
testbed tops out around 10 Mbps whatever the window is (303 bundles/s at the
default, 247 with `-W 1000:33554432` and 8 MB socket buffers): every such run
sits at 94-115 packets/s, which is `linkimpair`'s own capacity at a 100 ms
delay, so it is the impairer being measured. Raise the window when a link's
round-trip time is long and its bundles are small; measure before assuming it
was the window.

One practical limit when tuning: ION allows an induct's command at most 11
arguments including the duct name, and `-c cert -k key -n -W ... -r ... -w
...` overruns it - the daemon then fails to start. That is why `-W` carries
both bounds in one argument.

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
run **built against GnuTLS**, the library writes a TLS key log to the file
named by the `SSLKEYLOGFILE` environment variable, so exporting it before
starting ION (the spawned `tcpv4cla` inherits it) lets Wireshark decrypt the
session; Mbed TLS has no equivalent, so under that backend a plaintext run is
the way to read the exchange:

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
| `peer's certificate carries no id-kp-bundleSecurity` | usable, but does not say it is for TCPCL (§4.4.5); refused under `-B require` |
| `peer's certificate key usage does not allow the signature` | its key usage withholds `digitalSignature` (§4.4.4.1, RFC 5280 §4.2.1.3) |
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
