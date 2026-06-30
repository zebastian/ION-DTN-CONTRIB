# bpcmdd — Bundle Protocol command daemon

`bpcmdd` listens on a BP endpoint and, for **each** delivered bundle,
forks a user-supplied command, pipes the bundle payload to that command's
standard input, and (by default) returns whatever the command writes to
its standard output back to the bundle's source EID as a reply bundle.

It is the BP analogue of `inetd`/`xinetd` "wait" services: plug in any
script or program and it processes one bundle per invocation.

## Build

Built as part of ION-DTN-CONTRIB against an installed ION:

```sh
./configure --enable-app-bpcmd      # or --enable-all
make
sudo make install
```

## Usage

```
bpcmdd [-n] [-t ttl] <own endpoint ID> <command> [arg ...]
```

- `-n` — do not send the command's stdout back to the source.
- `-t ttl` — reply bundle lifetime in seconds (default 86400).

For every bundle, `bpcmdd` spawns a fresh `<command>` process
(fork-per-bundle, processed serially). The command receives the bundle
payload on **stdin** and these environment variables:

| Variable          | Meaning                              |
|-------------------|--------------------------------------|
| `BP_SOURCE_EID`   | source EID of the received bundle    |
| `BP_DEST_EID`     | own endpoint ID (`<own endpoint ID>`)|
| `BP_PAYLOAD_LEN`  | payload length in bytes              |

Anything the command writes to **stdout** is returned as a reply bundle
to `BP_SOURCE_EID` (unless `-n`, the source is anonymous `dtn:none`, or
the output is empty). The command's **stderr** is inherited and appears
on `bpcmdd`'s own stderr.

## Example

Echo service — reply with the upper-cased payload:

```sh
bpcmdd ipn:1.5 tr a-z A-Z
```

From another node:

```sh
echo "hello dtn" | bpsource ipn:1.5      # send a request
bpsink ipn:2.5                           # receive the reply
```

Run an arbitrary handler script:

```sh
bpcmdd ipn:1.5 /opt/handlers/process-telemetry.sh
```

where `process-telemetry.sh` reads the payload on stdin, uses
`$BP_SOURCE_EID` to know who asked, and writes its response to stdout.

## Notes

- There is **no command whitelisting** at the protocol level — the
  command is fixed at launch and applies to every bundle. Restrict the
  endpoint and use OS-level controls as needed.
- Long-running commands block subsequent bundles (serial processing).
  Wrap with your own dispatcher if you need concurrency.
