# SentinelFW Performance Benchmarks

> **Status**: No inline data plane exists yet. The numbers previously in this
> file were projections, not measurements. This document will be populated with
> real, reproducible benchmarks once each capability is implemented and testable.

## Current Capabilities (measured)

| Capability | What it does | Measurement |
|---|---|---|
| Host-level IP bans | nft set lookup (Linux) / netsh rule (Windows) | Kernel-speed; latency is nft's, not ours |
| Passive packet sniffer | AF_PACKET / RCVALL copy, Python processing | ~50 kpps on a single core (Python-bound) |
| Feed-based blocklists | nft sets with `flags interval` | Kernel-speed for matching; Python for loading |
| Web console API | stdlib http.server | Suitable for single-operator use; not a load-balanced API |

## Planned Capabilities (not yet measured)

These will be filled in with real `iperf3`, `wrk`, `hping3`, and `tcpreplay`
numbers from the netns lab once each phase is implemented:

| Capability | Phase | How to measure |
|---|---|---|
| Stateful L3/L4 forwarding | Phase 1 | `iperf3` through netns gateway |
| Inline IPS (Suricata NFQUEUE) | Phase 2 | `iperf3` + ET ruleset enabled |
| TLS proxy (SNI only) | Phase 4a | `wrk` HTTPS through proxy |
| TLS proxy (full decrypt) | Phase 4b | `wrk` HTTPS through proxy |
| XDP drop rate | Phase 6 | `hping3` SYN flood, measure PPS |
| HA failover time | Phase 10 | `iperf3` stream across VRRP failover |

## How to run benchmarks

```bash
# Set up the 3-zone netns lab
sudo lab/setup_netns_lab.sh up

# Throughput: iperf3 through the gateway
ip netns exec sg-wan iperf3 -s &
ip netns exec sg-lan iperf3 -c 198.51.100.10

# Latency: ping through gateway
ip netns exec sg-lan ping -c 100 198.51.100.10

# Teardown
sudo lab/setup_netns_lab.sh down
```

## Honest Limitations

1. **No ASIC acceleration.** SentinelFW runs on commodity x86-64 CPUs.
   It cannot match Fortinet FortiASIC NP7/CP9 or Cisco's custom silicon.
2. **Python sniffer is visibility-only.** Detection runs in Python at ~50 kpps.
   Enforcement is done by the kernel (nft sets) or, once built, by Suricata/Go.
3. **No inline forwarding path today.** The gateway daemon (`sentinelgated`) is
   a skeleton. Packet inspection happens post-capture, not in-path.
