# linkimpair - NFQUEUE link impairment for ION-DTN benchmarks

A benchmark run over loopback measures a link with no delay and no loss, which
is the one case a convergence layer never has to cope with: nothing is ever
retransmitted, congestion control never engages, and an unreliable service
looks exactly as good as a reliable one.  `linkimpair` puts the delay and the
loss back.

It takes packets that iptables has handed to an NFQUEUE, holds each one for a
one-way delay, and drops a configurable share of them:

```
linkimpair [-q queue] [-d delay_ms] [-j jitter_ms] [-l loss_pct] [-s seed] [-v]
```

The delay is **one-way**.  The usual rule pair queues both directions of a
link, so a `-d 25` gives a round-trip time of 50 ms.  Packets are released in
arrival order, so `-j` spreads arrival times without reordering them.

It is modelled on `owlt_delay.c` from the ION-DTN simulator, which delays per
destination to model one-way light time.  This one impairs whatever the queue
is fed and adds loss, for benchmarking rather than simulation.

## Building

```
./install-deps.sh     # libnetfilter-queue-dev (Debian/Ubuntu)
make
```

## Using it

Root is needed for both the iptables rules and the queue itself:

```
sudo ./impair-link start 4656       # queue UDP port 4656 (both directions)
sudo ./linkimpair -d 25 -l 2 -v     # 50 ms RTT, 2% loss, until Ctrl-C
sudo ./impair-link stop 4656
```

While the rules are installed, that port's traffic goes nowhere unless
`linkimpair` is bound to the queue.  That is deliberate: a benchmark that lost
its daemon should stall visibly rather than quietly report unimpaired numbers.
`impair-link stop` always removes the rules.

`bench-tcpv4-impaired` (in `CLA/tcpv4/bench`) drives all of this for you: it
installs its own rules - for a TCP port, where `impair-link` handles UDP -
runs the daemon, sweeps `BENCH_DELAYS`, and tears everything down on every
exit path.

## Caveats

- Delay is applied per packet, in arrival order; head-of-line blocking of a
  jittered packet is therefore possible by design.
- The kernel's queue is finite (65535 packets).  A delay-bandwidth product
  larger than that overflows it, and the kernel drops the excess - which adds
  loss you did not ask for.  Watch for `ENOBUFS` on stderr.
- Only what the iptables rule matches is impaired; everything else on the host
  is untouched.
