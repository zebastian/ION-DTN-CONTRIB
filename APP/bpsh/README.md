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

## License

See the repository root for details.
