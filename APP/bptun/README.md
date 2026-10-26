# bptun — IP over Bundle Protocol through a TUN interface

`bptun` gives a node an ordinary IP interface whose packets travel as
bundles. It creates a TUN device and opens a BP endpoint; every packet the
kernel routes into the device becomes one bundle to the `bptun` serving the
packet's destination, and every bundle delivered to the endpoint becomes
one packet. Applications on either side see a normal — slow, lossy — IP
link that keeps working across disruptions for as long as the bundles'
lifetime allows, and nothing needs a DTN API: `ping`, `ssh`, `rsync`,
`curl` all just run.

Status: a first, working version. One packet is one bundle; see
*Roadmap* for what is not there yet.

## Build

Built as part of ION-DTN-CONTRIB against an installed ION (Linux only —
it needs TUN/TAP):

```sh
./configure --enable-app-bptun      # or --enable-all
make
sudo make install
```

## Usage

```
bptun [-i interface] [-a address/prefixlen ...] [-m MTU] [-l lifetime]
      [-p bulk|std|expedited] [-c] [-u user] <own endpoint ID> <route> ...
```

A route is `<address>[/<prefix length>]=<EID>`: an IPv4 or IPv6 prefix (a
bare address is a host route) and the endpoint of the `bptun` that serves
it. Longest prefix wins; `default=<EID>` catches everything else. A packet
no route covers is dropped and counted. Packets for the local link only —
IPv4 `224.0.0.0/24` and `255.255.255.255`, IPv6 multicast of interface or
link scope (`ff02::/16` and the like) — are dropped before the route table
is consulted and counted as `link-local`: the kernel sends router
solicitations and MLD/IGMP reports into the interface on its own, and
these must not be carried to the far end, not even by a default route.

| Option | Meaning |
|---|---|
| `-i name` | TUN interface name (default: kernel-chosen `bptunN`, reported in the log) |
| `-a addr/len` | configure the interface with this IPv4 or IPv6 address and bring it up; once for IPv4, repeatedly for IPv6 (`-a 10.42.0.1/24 -a fd00:42::1/64` for dual stack); otherwise configure it yourself with `ip` |
| `-m MTU` | interface MTU — one packet is one bundle, so this bounds the bundle size; 1400 suits most CLAs. IPv6 needs at least 1280: below that the kernel disables IPv6 on the interface, so `-m` under 1280 with an IPv6 `-a` is refused, and without one it is noted in `ion.log` |
| `-l secs` | bundle lifetime (default 300) |
| `-p prio` | bundle priority: `bulk`, `std` (default), `expedited` |
| `-c` | request custody transfer |
| `-u user` | drop to this user once the interface is open (creating it needs `CAP_NET_ADMIN`, i.e. root or a user namespace of one's own) |

`SIGUSR1` logs the packet/bundle counters to `ion.log`; `SIGINT`/`SIGTERM`
stop the daemon, which logs them once more on the way out.

### Point-to-point

Two nodes, ipn:1 and ipn:2, already exchanging bundles over any CLA. Add
`a endpoint ipn:1.7 q` / `a endpoint ipn:2.7 q` to the respective
`bpadmin` configs, then on node 1:

```
# bptun -i dtn0 -a 10.42.0.1/24 -m 1400 ipn:1.7 10.42.0.2=ipn:2.7
```

and on node 2:

```
# bptun -i dtn0 -a 10.42.0.2/24 -m 1400 ipn:2.7 10.42.0.1=ipn:1.7
```

Then `ping 10.42.0.2` from node 1 goes: kernel → `dtn0` → `bptun` →
bundle to `ipn:2.7` → node 2's `bptun` → its `dtn0` → kernel, and the
reply comes back the same way.

### Gateway pair

Each node fronts a subnet; prefix routes and IP forwarding do the rest:

```
node1# bptun -i dtn0 -a 10.42.1.1/24 ipn:1.7 10.42.2.0/24=ipn:2.7
node1# sysctl -w net.ipv4.ip_forward=1
node2# bptun -i dtn0 -a 10.42.2.1/24 ipn:2.7 10.42.1.0/24=ipn:1.7
node2# sysctl -w net.ipv4.ip_forward=1
```

with the hosts behind each node routing the other subnet via their node.

## Payload format

The first byte of every bundle payload names its format, so the format
can grow without a flag day:

| Byte 0 | Meaning |
|---|---|
| `0x01` | one IP packet follows (all of it; the packet is not framed further) |

A payload whose first byte names no format this `bptun` knows — from a
newer `bptun` using a format this one lacks, or from something else
sending to the endpoint — is dropped and counted (`unknown format` in
the counters), never written to the interface. A batching format is the
intended next value; see *Roadmap*.

## What to expect

TCP over a link with real DTN delay or long disruptions is a poor fit —
its timers assume milliseconds to seconds. Over a merely lossy or
intermittently connected link it works (the loopback test moves a TCP
stream), and UDP, ICMP and anything built for delay is fine. The bundle
lifetime (`-l`) is the tunnel's memory: packets wait in ION for that long
for a contact.

Every packet costs a bundle's overhead (tens of bytes plus the CLA's), so
small-packet traffic is expensive; see *Roadmap*.

## Testing

```sh
./test.sh APP_BPTUN            # or: cd APP/bptun/tests/bptun-loopback && ./dotest
```

`tests/bptun-loopback` runs two `bptun` instances on one ION node, each
in its own network namespace (two addresses of one subnet on one host
would otherwise meet inside the kernel and never enter the tunnel), and
checks ping both ways, a 256 KiB TCP transfer, that an unroutable
destination is dropped and noted, and that the `SIGUSR1` counters add up;
then ping and a TCP transfer over IPv6, with both families configured by
`-a`, and that `-a`/`-m` refuse what cannot work.

The namespaces are unprivileged user+network namespaces (`unshare -Urn`),
in which the caller is root and may create TUN devices, so the test needs
no real root; `bptun` attaches to ION from inside them as usual. It needs
`unshare`, `nsenter`, `ip`, `ping` and `python3`, and reports SKIP
otherwise; it is marked `.optional` for `test.sh`.

Ubuntu 23.10 and later restrict unprivileged user namespaces through
AppArmor by default, and the test then SKIPs. Either lift the restriction
system-wide,

```sh
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
echo 'kernel.apparmor_restrict_unprivileged_userns = 0' | \
    sudo tee /etc/sysctl.d/60-apparmor-userns.conf
```

or, narrower, give `unshare` the AppArmor profile Ubuntu uses for such
tools (`/etc/apparmor.d/unshare`, then `sudo apparmor_parser -r` it):

```
abi <abi/4.0>,
include <tunables/global>
profile unshare /usr/bin/unshare flags=(unconfined) {
  userns,
  include if exists <local/unshare>
}
```

`make check` runs the route table's unit test, which needs neither
namespaces nor ION, and replays the route table's fuzz corpus. The fuzz
target adds route specs, as an operator would, then looks up a packet,
which a remote host can shape: lookup and the link-local check must read
no further than the packet, and a lookup must give back one of the table's
own EIDs or none.

`make fuzz` builds the fuzz target in `tests/fuzz` with clang's libFuzzer,
AddressSanitizer and UBSan and runs it for `FUZZ_TIME` seconds (default 60,
with `FUZZ_JOBS` workers), starting from the checked-in corpus; `make check`
replays that corpus without libFuzzer. A failing input is left in
`fuzz-artifacts/` and fails the target; one worth keeping belongs in
`tests/fuzz/corpus/`.

## Roadmap

- **Batching**: several small packets per bundle, flushed by size or a
  few-millisecond timer — the big win for DTN overhead. A second payload
  format byte; the receiver slices packets by their own IP total length.
- **TCP proxy mode**: terminate TCP locally and carry the stream in
  bundles, for interactive use over real delay (the way the ISS e-mail
  gateways worked), next to the raw packet mode.
- Packet-level statistics per route.

## Files

```
src/bptun.c           the daemon
src/bptun_route.[ch]  the route table (no ION dependency; unit-tested)
tests/bptun_route_test.c
tests/fuzz/           libFuzzer target for the route table, and its corpus
tests/bptun-loopback/ end-to-end test (unprivileged namespaces)
doc/bptun.pod         man page source
```
