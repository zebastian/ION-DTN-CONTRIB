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
bptun [-i interface] [-a address/prefixlen] [-m MTU] [-l lifetime]
      [-p bulk|std|expedited] [-c] [-u user] <own endpoint ID> <route> ...
```

A route is `<address>[/<prefix length>]=<EID>`: an IPv4 or IPv6 prefix (a
bare address is a host route) and the endpoint of the `bptun` that serves
it. Longest prefix wins; `default=<EID>` catches everything else. A packet
no route covers is dropped and counted.

| Option | Meaning |
|---|---|
| `-i name` | TUN interface name (default: kernel-chosen `bptunN`, reported in the log) |
| `-a addr/len` | configure the interface with this IPv4 address and bring it up; otherwise configure it yourself with `ip` |
| `-m MTU` | interface MTU — one packet is one bundle, so this bounds the bundle size; 1400 suits most CLAs |
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
destination is dropped and noted, and that the `SIGUSR1` counters add up.

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
namespaces nor ION.

## Roadmap

- **Batching**: several small packets per bundle, flushed by size or a
  few-millisecond timer — the big win for DTN overhead. A second payload
  format byte; the receiver slices packets by their own IP total length.
- **TCP proxy mode**: terminate TCP locally and carry the stream in
  bundles, for interactive use over real delay (the way the ISS e-mail
  gateways worked), next to the raw packet mode.
- IPv6 address configuration (`-a` is IPv4; use `ip` for IPv6 today).
- Packet-level statistics per route.

## Files

```
src/bptun.c           the daemon
src/bptun_route.[ch]  the route table (no ION dependency; unit-tested)
tests/bptun_route_test.c
tests/bptun-loopback/ end-to-end test (unprivileged namespaces)
doc/bptun.pod         man page source
```
