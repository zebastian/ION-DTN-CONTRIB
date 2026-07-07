# bpsh / bpshd — remote shell over Bundle Protocol

An SSH-like remote shell that runs commands on a remote node over BPv7, in the
spirit of `ssh` but built for store-and-forward DTN links. Implements ION-DTN
issue #83.

- `bpshd` — daemon: runs a persistent `/bin/sh` per client and returns stdout,
  stderr, and the exit code in separate bundles
- `bpsh` — client: interactive REPL or one-shot (`-c`) command execution

## Features

- CBOR-framed protocol carried in bundle payloads (INIT, REQ, STDIN, STDOUT,
  STDERR, CWD, EXIT, ERROR, …) with per-session ids and ordered sequencing
- One persistent `/bin/sh` per client (keyed by source EID), so `cd`, exports,
  and shell functions persist across commands
- Separate stdout/stderr delivery and out-of-band exit-code propagation
- stdin forwarding with ReqAttendant-based flow control so large output blocks
  for ZCO space instead of being dropped
- Per-command wall-clock timeout and output cap with process-group teardown
- Client REPL with in-line editing, command history, and a working-directory
  prompt; `-c` one-shot mode exits with the remote command's exit code
- see also the `bpsh` / `bpshd` man pages

## Layout

```
src/bpsh.c                 client (REPL + one-shot)
src/bpshd.c                daemon entry point + manager loop
src/bpshd_session.c/.h     per-session shell, pipes, command execution
src/bpsh_proto.c/.h        shared CBOR protocol, send/receive/attach helpers
doc/*.pod                  man page sources (bpsh, bpshd)
tests/bpsh-loopback/       single-node loopback regression (.optional)
```

## Security

`bpshd` executes shell commands for remote clients, so deploy it with care:

- `-k secretfile` — require a shared secret in each client's INIT. It is
  checked only at INIT and travels in band, so it is access control, not
  authentication.
- `-a eidlist` — serve only source EIDs matching the comma-separated globs
  (e.g. `ipn:1.*,ipn:2.3`). A source EID is spoofable unless the bundles are
  authenticated by BPSec, so `-a` is only meaningful over BPSec-protected
  links — run `bpshd` under BPSec for both authenticity and confidentiality.
- `-u user` — the preferred containment: drop each shell to a dedicated
  unprivileged identity, then bound its reach with the target machine's own
  permission mechanics (file ownership and modes, sudoers, and the like)
  rather than relying on `bpshd` itself.

See the `bpshd` man page for details.

## License

See the repository root for details.
