# SentinelFW 3.0: System Architecture

## 1. What This Is

SentinelFW is a **host firewall and security agent** for Ubuntu 22.04+ and
Windows 10/11/Server 2019+. It is not an inline gateway, NGFW appliance, or
network forwarding device.

It provides:
- Passive packet inspection with heuristic detection (scan, flood, brute force, payload signatures)
- IP bans enforced via the kernel firewall (nftables on Linux, Windows Defender Firewall on Windows)
- Process monitoring with exec-time response (kill, quarantine)
- Honeypot and deception services
- Feed-based blocklists with automatic updates
- Web management console with REST API
- Suricata alert ingest (passive, not inline)
- ClamAV antivirus integration
- DNS-layer domain blocking

It does **not** provide (yet):
- Inline packet inspection (traffic forwarding / NFQUEUE / TPROXY)
- NAT, routing, or zone-based policies
- TLS interception
- Application-layer identification (nDPI)
- VPN termination
- High availability / failover
- Traffic shaping (tc/CAKE/HTB)

---

## 2. Architecture

```
                        +-------------------- sentinelfw/ --------------------+
 kernel exec events --> | monitors.ExecWatcher --+                            |
 (netlink proc conn.,   |                        v                            |
  Win snapshots)        |                  monitors.Responder  <-- ProcessMonitor <-- procinfo (socket->pid->exe)
 raw packets ---------> | detector.Sniffer -> Detector (scan/flood/brute/signature/DNS)
 (AF_PACKET/RCVALL)     |                        |                            |
                        |                        v                            |
 feeds + drop-in lists->| lists.Lists -------> engine.Engine --> backends.NftBackend / WinBackend  --> OS firewall
                        |                        |                            |
                        |   config.Store (config.json, state.json bans)       |
                        |   Housekeeper: ban expiry, feed updates, quarantine |
                        +-----------------------------------------------------+
                                                 |
                +--------------------------------+--------------------------------+
                |                                |                                |
    honeypot.py (SSH, HTTP,            webui.py (console,          mgmt.py (auth, audit,
    FTP, Telnet, MySQL,                REST API, SSE)              TOTP, Sigma, syslog,
    SMB, RDP, SMTP tarpits)                                        Prometheus, STIX)
```

### Key modules

| Module | Role | Status |
|---|---|---|
| `backends.py` | nft ban sets (Linux) / netsh rules (Windows) | **Working** |
| `detector.py` | AF_PACKET/RCVALL sniffer, heuristic IDS | **Working** (visibility only, not inline) |
| `monitors.py` | Exec-time hook, socket monitor, response engine | **Working** |
| `policies.py` | Ordered firewall policies compiled to nft/netsh | **Working** (no zones, no NAT, no ct state) |
| `honeypot.py` | Service emulators, session recording | **Working** |
| `mgmt.py` | Auth, audit, TOTP, Sigma, syslog, Prometheus | **Working** |
| `forensics.py` | PCAP ring, JA3, persistence watcher | **Working** |
| `ops.py` | DNS forwarder, fleet relay, log vault | **Working** |
| `webui.py` | Console + REST API | **Working** |

### Go components

| Component | Status |
|---|---|
| `cmd/sentinelgated/` | **Skeleton** — parses flags, waits for signal, exits |
| `pkg/tlsproxy/` | **Partial** — mints certs but has no listener or stream copy |
| `pkg/nftables/` | **Exists** — not wired to anything |
| `pkg/ha/` | **Config generators only** — does not run keepalived/conntrackd |
| `pkg/vpn/` | **Config generators only** — does not run WireGuard/strongSwan |
| `pkg/sdwan/` | **Config generators only** |
| `bpf/xdp_prefilter.c` | **Placeholder** — map lookup commented out, only drops 0.0.0.0 |

---

## 3. What the sniffer actually does

The Python sniffer in `detector.py`:
1. Opens a raw socket (AF_PACKET on Linux, RCVALL on Windows)
2. **Copies** packets — it does not sit in the forwarding path
3. Parses headers and payloads in Python
4. If an attack is detected, adds the source IP to an nft ban set

**The first packets of every attack get through.** This is inherent to
copy-on-capture detection. Inline inspection (Phase 2 in the roadmap)
would require Suricata in NFQUEUE mode or a Go proxy in the forwarding path.

---

## 4. Policy engine limitations

The current policy engine (`policies.py`):
- Compiles ordered first-match rules to nft chains / netsh rules
- Supports src/dst IP, services, direction, enable/disable
- **Does not** support: zones, interfaces, ct state, NAT/masquerade/DNAT,
  security profiles (display-only), traffic shaping, application identification

The nft chains use `policy accept` (fail-open). FortiGate uses implicit deny.

---

## 5. Security considerations

- The web console defaults to binding on `127.0.0.1:443`. Network exposure
  requires explicit `webui.listen` override.
- First-run generates a random password printed once to stdout.
- The Python sniffer parses attacker-controlled packets as root. This is a
  risk surface. Moving hot-path parsing to Go/Suricata is planned.
- Honeypot services accept attacker connections. They run as threads in the
  main process (not isolated namespaces). Resource limits are enforced via
  connection counts and timeouts but not OS-level isolation.
