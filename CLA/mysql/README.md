# MySQL Convergence Layer Adapter (mysqlcli / mysqlclo)

A Bundle Protocol v7 convergence layer adapter pair that uses a
MySQL/MariaDB server as a shared bundle mailbox. Several ION nodes can
point at one server; each node picks up only the bundles addressed to
it, so a single pair of tables multiplexes many links.

- `mysqlclo` — output daemon (ION _outduct_): takes bundles from ION and
  stores them, with metadata, into its table (default `inbound`).
- `mysqlcli` — input daemon (ION _induct_): reads bundles whose source is
  the local node from its table (default `outbound`), injects them into
  ION, and deletes the consumed rows.

## How it works

```
                 MySQL server (db `ion`)
   ION node ──bpDequeue──> [mysqlclo] ──INSERT──> `inbound`  table
                                                  (metadata: src/dst eid)

   `outbound` table ──SELECT WHERE src_eid = me──> [mysqlcli] ──bpEndAcq──> ION
                     <──DELETE consumed rows──────
```

The `mysqlcli` filter is derived automatically from the local node's own
EID (`getOwnFqnn()`), so no per-node configuration is needed; `-e` can
override it with a SQL `LIKE` pattern.

## Features

- MySQL C API client (works with MySQL or MariaDB servers)
- Tables auto-created if absent: `id, payload, length, src_eid, dst_eid,
  created_at`
- `mysqlclo` always stores; batched inserts (size + flush-window) in one
  transaction
- `mysqlcli` bulk-reads up to N rows at a time (default 100) and deletes
  them transactionally
- Optional username/password auth (`-u` / `-p`), Unix socket (`-S`)
- Optional TLS (`-t` / `-c` / `-k` / `-K`)
- see also the `mysqlcli` / `mysqlclo` man pages

## Configuration

Duct name is `host[:port]` (default port 3306). Database and table are
flags so one server can host several:

```
a protocol mysql
a outduct mysql 'db1:3306' 'mysqlclo -d ion -T inbound  -u ion -p secret'
a induct  mysql 'db1:3306' 'mysqlcli -d ion -T outbound -u ion -p secret'
```

## Layout

```
src/mysqlcla.h             shared constants, parsers, connect/DDL, EID extractor
src/mysqlclo.c             output daemon (ION -> table)
src/mysqlcli.c             input daemon  (table -> ION)
doc/*.pod                  man page sources (mysqlcli, mysqlclo)
tests/loopback-mysql/      single-node loopback (.optional, needs a server)
```

## License

See the repository root for details.
