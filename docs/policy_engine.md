# Canonical Unified Policy Engine & Dataplane Architecture

SentinelFW enforces network policies through a single canonical policy model defined in `pkg/config/model.go` and `sentinelfw/policies.py`.

## 1. Rule Processing Pipeline

```
Packet Ingress (XDP / NIC)
       │
       ▼
[eBPF/XDP Pre-filter] ──(Drop)──► Bogon / Flood / Known Banned IP
       │
       ▼
[Stateful Flow Conntrack] ──(Match)──► Bypass DPI for Established Flow
       │ (New Flow)
       ▼
[Zone & Interface Resolution] ──► Tenant VDOM Lookup
       │
       ▼
[App-ID & TLS SNI Inspection]
       │
       ▼
[Security Policy Evaluation] ──(First Match Wins)
       │
       ├─► Verdict: DROP / REJECT / QUARANTINE
       │
       └─► Verdict: ALLOW / INSPECT
                 │
                 ▼
       [Inline IPS / DLP / Antivirus Scanners]
```

## 2. Policy Syntax & Match Criteria

Rules are evaluated strictly in ascending `priority` order (first-match wins). A policy definition includes:

- `action`: `allow`, `drop`, `reject`, `inspect`
- `src_zone` & `dst_zone`: Security zone names (e.g., `trust`, `untrust`, `dmz`)
- `src_ip` & `dst_ip`: IPv4/IPv6 address or CIDR
- `app_id`: Deep application protocol (e.g., `ssl`, `ssh`, `dns`, `http`, `wireguard`)
- `service`: Transport protocol and port specifier (e.g., `tcp/443`, `udp/53`)
- `ips_profile`: Inline IPS rule pack ID
- `tenant_id`: Virtual Domain isolation tag (`root`, `tenant-a`)

## 3. Shadowed & Unused Rule Analysis

SentinelFW continuously analyzes the active ruleset:
- **Shadowed Rules:** Detected when a higher-priority rule subsumes the 5-tuple match criteria of a lower-priority rule with an identical or conflicting action.
- **Unused Rules:** Flagged when zero hit counters have incremented over a configurable observation window (default: 30 days).
