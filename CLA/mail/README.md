# Mail Convergence Layer Adapter (mailcli / mailclo)

A Bundle Protocol v7 convergence layer adapter pair that carries bundles as
electronic mail: bundles are sent with SMTP and received by polling a POP3
mailbox. This enables store-and-forward delivery over ordinary mail
infrastructure, including intermittently-connected mailboxes. The design
follows IBR-DTN's e-mail convergence layer, adapted to ION and BPv7.

- `mailclo` — output daemon (SMTP sender)
- `mailcli` — input daemon (POP3 poller)

## Features

- libcurl for both SMTP and POP3 (implicit TLS or STARTTLS/STLS, SASL auth)
- Duct name is the peer mailbox address (`mailclo`) / a local induct label
  (`mailcli`)
- Selectable payload encoding (`-e`), the same choice on both daemons:
  - `attach` (default) — one bundle per base64 MIME attachment
  - `b64` — base64 bundle in the message body
  - `raw` — raw serialized bundle bytes in the message body
- Multiple bundles per message: several attachments, or body chunks delimited
  by `--ION-BUNDLE-MAIL-SEPARATOR--`
- Optional send digest (`-d secs`, with `-m` / `-M` caps): batch several
  bundles into one message; off by default
- Advisory `X-ION-Bundle-Encoding` / `X-ION-Bundle-Count` headers are set by
  the sender but are **not** required for reception

## Layout

```
src/mailmsg.{h,c}   encoding/framing core (base64, MIME, separators); no deps
src/mailcurl.{h,c}  libcurl SMTP send + POP3 poll transport
src/mailcla.h       shared config structs and constants
src/mailclo.c       output daemon (SMTP)
src/mailcli.c       input daemon (POP3)
doc/*.pod           man page sources (mailcli, mailclo)
tests/mailmsg_test.c    unit test for the encoding core (make check)
tests/loopback-mail/    loopback send/receive via a bundled mock server (.optional)
```

## Encoding notes

`raw` body mode places unencoded bundle bytes into the message body, delimited
by the separator line when more than one bundle is present. This is the most
compact option but is only safe on 8-bit-clean paths, and (as with any
separator-framed binary) a bundle whose bytes happen to contain the exact
separator string would be mis-split; use `attach` or `b64` when in doubt.

## Build

Requires libcurl (`libcurl4-openssl-dev`).

```
./install-deps.sh            # build prerequisites
./configure --enable-cla-mail --with-ion=/usr/local
make
make check                   # runs the encoding unit test
```

## Configuration

Add the `mail` protocol and a duct pair with `bpadmin` / a `.bprc` file:

```
a protocol mail
a induct  mail node1@example.org 'mailcli -S pop.example.org:995 -s -u node1 -p secret'
a outduct mail node2@example.org 'mailclo -S smtp.example.org:587 -t -f node1@example.org -u node1 -p secret'
```

ION appends the duct name (the peer mailbox / induct label) to each command
automatically, so it is not repeated in the command text.

See `mailclo(1)` and `mailcli(1)` for the full option list.
