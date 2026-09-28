# SentinelGate & SentinelFW 3.0: System Architecture Specification

## 1. System Overview

SentinelGate is an open-architecture Next-Generation Firewall (NGFW) platform engineered for enterprise edge, branch, and datacenter deployments on modern Linux kernels (Ubuntu 22.04/24.04 LTS, x86-64 and ARM64). It orchestrates proven, industry-standard networking and security primitives under a unified, declarative FortiOS-style policy engine and high-concurrency Go control plane.

Together with SentinelGate, **SentinelFW 3.0** provides continuous endpoint visibility and enforcement across Windows (10, 11, Server) and Linux endpoints. It operates either autonomously as a standalone host firewall/IPS or federated with SentinelGate via mutual TLS (mTLS).

---

## 2. High-Level Architectural Planes

The platform is cleanly separated into four operational planes:

```
+-------------------------------------------------------------------------------+
|                             MANAGEMENT PLANE (Go)                             |
|  - sentinelgated (gRPC / OpenAPI REST / Unix Socket / mTLS :8443)             |
|  - Unified CLI / TUI: sfw (top, sessions, flows, alerts, policy, commit)      |
|  - Declarative Config Engine: Candidate -> Validate -> Diff -> Commit-Confirm |
|  - RBAC, Audit Trail, PKI / Internal CA Manager, Fleet Orchestrator           |
+-------------------------------------------------------------------------------+
                                      |
       +------------------------------+-------------------------------+
       |                                                              |
+------v----------------------------------+   +-----------------------v---------+
|        CONTROL PLANE (Go / Daemons)     |   |       INSPECTION PLANE (L7)     |
| - Dynamic Routing: FRR (BGP, OSPF, BFD) |   | - Suricata 7.x (IPS / NFQUEUE)  |
| - High Availability: keepalived + Raft  |   | - nDPI Protocol & App Classifier|
| - Session Sync: conntrackd              |   | - Go TLS Interception Proxy     |
| - VPN Orchestrator: WireGuard + strong- |   | - Content: Unbound DNS (RPZ) +  |
|   Swan IPsec (VTI route-based)          |   |   ClamAV / YARA + Detonation SB |
| - SD-WAN: SLA Probes & Path Steering    |   | - DLP & Anti-Beaconing Engine   |
+-----------------------------------------+   +---------------------------------+
       |                                                              ^
       +------------------------------+-------------------------------+
                                      |
+-------------------------------------v-----------------------------------------+
|                                DATA PLANE (Fast Path)                         |
|  - Ingress eBPF / XDP Pre-filter: Bogons, Spoofing (uRPF), SYN Cookie DDoS    |
|  - Kernel Flowtable Offload: Fast-path bypass for established L4 sessions     |
|  - Stateful nftables: Zones, NAT44/NAT64, Mangle, Security Rulesets           |
|  - Traffic Control: tc / CAKE / HTB for active queue management & shaping     |
|  - Optional AF_XDP / DPDK fast path for Tier 3 SmartNIC offload               |
+-------------------------------------------------------------------------------+
```

---

## 3. Data Plane Throughput Tiers

| Tier | Throughput Target | Hardware Profile | Pipeline Mechanics |
|---|---|---|---|
| **Tier 1 (T1)** | 1 Gbps line-rate with full inspection | 4 vCPU / 8 GB RAM | Stateful nftables + Suricata NFQUEUE + TLS Proxy + AppID |
| **Tier 2 (T2)** | 10 Gbps firewall + IPS | 16 vCPU / 32 GB RAM | XDP Pre-filter + nftables flowtable bypass + AF_PACKET Suricata |
| **Tier 3 (T3)** | 25–40 Gbps stateless / L4 filter | SmartNIC (ConnectX-6) | AF_XDP zero-copy / DPDK driver bypass |

*Engineering Honesty*: Proprietary ASIC offload (NP7/SPU) and commercial proprietary threat-intel cloud feeds are explicitly outside scope. Throughput figures are benchmarked on standard x86-64 server silicon.

---

## 4. Policy Model & Configuration Lifecycle

### 4.1 Declarative Model Hierarchy
- **Zones**: Logical groupings of network interfaces (`wan`, `lan`, `dmz`, `guest`, `vpn`).
- **Objects**: Address groups (CIDR, FQDN, GeoIP, ASN), Services (L4 port/proto specs), Schedules, Users/User Groups.
- **Firewall Policies**: Zone-pair indexed rules containing source/dest matches, applications, inspection profiles (IPS, AV, Web, TLS, DLP), NAT mappings, and shaping classes.

### 4.2 Configuration State Machine
```
[Candidate Config] ──(sfw validate)──> [Validated AST]
        │
    (sfw diff)
        │
        v
 [Dry-Run Diff] ──(sfw commit --confirm=10m)──> [Active Ruleset (nftables/FRR/XDP)]
                                                       │
                                      ┌────────────────┴────────────────┐
                           (sfw confirm within 10m)          (Timeout / Unreachable)
                                      │                                 │
                                      v                                 v
                             [Committed State]              [Automated Rollback]
```

---

## 5. Security & Isolation Boundaries

1. **Privilege Separation**:
   - `sentinelgated` drops Linux capabilities to `CAP_NET_ADMIN`, `CAP_NET_RAW`, and `CAP_BPF` where strictly necessary; non-privileged web/API endpoints run unprivileged.
   - Decoy and honeypot services execute in isolated network namespaces (`ip netns`) with zero egress capability.
2. **Memory Safety**:
   - Control plane, APIs, config parser, and proxy written in Go (memory-safe).
   - Ingress packet filtering and socket tracing written in eBPF / Rust.
   - High-risk protocol parsing (e.g. DNS, SMB, TLS) undergoes continuous automated fuzzing (`go-fuzz` / `AFL++`).
3. **Endpoint Agent Isolation (SentinelFW 3.0)**:
   - Daemon runs as system service (`root` / `LocalSystem`).
   - Unprivileged CLI communicates strictly via authenticated local Unix socket / Windows Named Pipe.
   - Failsafe kernel rules ensure administrative SSH/RDP and localhost traffic can never be blocked by heuristic false positives.
