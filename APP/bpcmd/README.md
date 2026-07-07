# bpcmdd — Bundle Protocol command daemon

`bpcmdd` listens on a BP endpoint and treats **each delivered bundle's
payload as a command line**. It tokenises the payload on whitespace,
checks the result against a whitelist, and — if permitted — execs the
command directly (no shell), returning whatever the command writes to its
standard output back to the bundle's source EID as a reply bundle.

It is the BP analogue of `inetd`/`xinetd`: remote nodes invoke commands
by name, and a whitelist decides what may run.

Because the command is exec'd directly from the tokenised payload, shell
metacharacters (`;`, `|`, `$(…)`, backticks) are inert — they become
literal arguments and can do nothing unless a whitelist rule explicitly
permits a shell.

## Build

Built as part of ION-DTN-CONTRIB against an installed ION:

```sh
./configure --enable-app-bpcmd      # or --enable-all
make
sudo make install
```

## Usage

```
bpcmdd [-n] [-t ttl] [-a eidlist] [-u user] <own endpoint ID> <whitelist file>
```

- `-n` — do not send the command's stdout back to the source.
- `-t ttl` — reply bundle lifetime in seconds (default 86400).
- `-a eidlist` — comma-separated source-EID glob patterns (e.g.
  `ipn:1.*,ipn:2.3`); only matching sources are served. Omitted: any source.
- `-u user` — run every command as this unprivileged user (the daemon must
  start with privilege). Omitted: commands run as the daemon's own user.

For every bundle, `bpcmdd` splits the payload into an argument vector,
matches it against the whitelist, and — if allowed — spawns a fresh
process (fork-per-bundle, processed serially) with an **empty stdin**. The
command sees these environment variables:

| Variable        | Meaning                               |
|-----------------|---------------------------------------|
| `BP_SOURCE_EID` | source EID of the received bundle     |
| `BP_DEST_EID`   | own endpoint ID (`<own endpoint ID>`) |

Anything the command writes to **stdout** is returned as a reply bundle
to `BP_SOURCE_EID` (unless `-n`, the source is anonymous `dtn:none`, or
the output is empty). A refused command is not run; instead a
`command not permitted` reply is returned (unless `-n`). The command's
**stderr** is inherited and appears on `bpcmdd`'s own stderr.

## Whitelist file

One rule per line; `#` comments and blank lines are ignored. Each rule
is `[mode] <pattern>`, where `mode` is one of:

| Mode    | Matches                                          |
|---------|--------------------------------------------------|
| `exact` | a literal string, matched whole                  |
| `glob`  | shell wildcards `*` and `?`                      |
| `regex` | a POSIX extended regular expression              |

The mode keyword is optional; a bare rule is treated as `regex`. Every
rule is **anchored** — it must match the *entire* normalised command line
(the argv tokens rejoined with single spaces), so a rule for `gpio` can
never authorise `gpionuke`. A command runs if it matches **any** rule. An
empty or unreadable whitelist denies everything (fail-closed).

```
# examples
exact gpio info
glob  gpio get *
glob  gpio set * [01]
regex (echo|printf) .+
```

## Example

GPIO control service. Whitelist (`gpio.acl`):

```
glob gpio.py get *
glob gpio.py set * [01]
exact gpio.py info
```

Run it:

```sh
bpcmdd ipn:1.5 gpio.acl
```

From another node, the payload *is* the command:

```sh
printf 'gpio.py set 17 1' | bpsource ipn:1.5   # run: gpio.py set 17 1
bpsink ipn:2.5                                  # receive "17=1"
```

A runnable `gpio.py` is provided under `examples/`. Because the command
is looked up via `execvp`, it must be on `PATH` (or named with a path,
e.g. `/opt/handlers/gpio.py`, matched textually by the whitelist).

## More examples

`examples/` holds a few small handlers illustrating typical spacecraft
ground→onboard operations:

| Script      | Commands                                  | Purpose                                                     |
|-------------|-------------------------------------------|-------------------------------------------------------------|
| `gpio.py`   | `gpio.py get\|set\|info ...`              | Read/set GPIO pins via `/sys/class/gpio`.                   |
| `health.sh` | `health.sh`                               | One-line OBC health snapshot (uptime, load, memory, temp).  |
| `clock.sh`  | `clock.sh get` / `clock.sh set <d> <e>`   | Read/set ION's UTC correction (`utcdelta`, `utcerror`) via `ionadmin`. |

Each script's header lists suggested whitelist rules.

## Notes

- The whitelist fixes *what* may run; it is the primary defence, so keep
  rules as tight as possible (`glob *` or `regex .*` authorise everything).
  Use `-a` to also restrict *who* may ask, but a source EID is spoofable
  unless the bundles are authenticated by BPSec, so `-a` is only meaningful
  over BPSec-protected links. Use `-u` to run commands under a dedicated
  unprivileged identity and bound its reach with OS-level controls (file
  ownership and modes, sudoers, and the like) rather than relying on the
  daemon alone.
- Long-running commands block subsequent bundles (serial processing).
  Wrap with your own dispatcher if you need concurrency.
