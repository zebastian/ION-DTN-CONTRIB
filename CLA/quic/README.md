# QUIC Convergence Layer Adapter (quiccli / quicclo)

A Bundle Protocol v7 convergence layer adapter pair that carries bundles over
QUIC (RFC 9000), using [ngtcp2](https://github.com/ngtcp2/ngtcp2) with the
**GnuTLS** crypto backend.

- `quicclo` — output daemon (QUIC **client**): connects to a peer and writes
  each bundle, length-prefixed, on one bidirectional stream.
- `quiccli` — input daemon (QUIC **server**): accepts connections and
  reassembles the bundles, injecting them into ION.

## Framing

Each bundle is sent as a 4-byte big-endian length prefix followed by the raw
bundle bytes, concatenated on a single QUIC bidirectional stream per
connection (the same length-delimited approach the TCP CL uses over its
stream). The server demultiplexes multiple client connections by connection
ID.

## TLS

QUIC mandates TLS 1.3. The server (`quiccli`) requires a certificate (`-c`)
and key (`-k`). The client (`quicclo`) verifies the server against the system
trust store or a CA file (`-C`); `-n` disables verification for self-signed
certificates. The ALPN id defaults to `dtn` and must match on both ends.

## Configuration

Duct name is `host[:port]` (default port 4556, UDP):

```
a protocol quic
a induct  quic '0.0.0.0:4556' 'quiccli -c server.pem -k server.key'
a outduct quic 'peer.example:4556' 'quicclo -C ca.pem'
```

## Layout

```
src/quiccla.h        constants, config, duct/arg parse, framing
src/quicsession.h    QUIC engine API
src/quicsession.c    ngtcp2 + GnuTLS engine (UDP pump, TLS, stream I/O)
src/quicclo.c        output daemon (client)
src/quiccli.c        input daemon  (server)
doc/*.pod            man page sources
tests/loopback-quic/ single-node loopback (.optional)
```

## License

See the repository root for details.
