# SentinelGate & SentinelFW 3.0: Threat Model & Security Posture

## 1. Scope & Methodology

This document analyzes the threat landscape for SentinelGate (the Linux-based Next-Generation Firewall gateway) and SentinelFW 3.0 (the endpoint host agent) using the **STRIDE** methodology (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege).

---

## 2. System Assets & Trust Boundaries

### 2.1 Critical Assets
1. **Firewall Rule Engine & Kernel State**: Active `nftables` rulesets, eBPF maps, and conntrack connection tables.
2. **Cryptographic Material**: TLS Inspection Internal Root CA private keys, WireGuard private keys, strongSwan IPsec pre-shared keys and private keys, mTLS fleet certificates.
3. **Audit Trails & Security Event Streams**: System audit logs, tamper-evident telemetry logs, threat intelligence feeds.
4. **Endpoint Host Process Integrity**: The running SentinelFW daemon, local quarantine store, and process execution monitors.

### 2.2 Primary Trust Boundaries
- **TB-1: WAN to Gateway (Untrusted to Perimeter)**: Untrusted external packets entering physical/virtual NIC interfaces.
- **TB-2: Protected LAN / DMZ to Gateway (Semi-trusted to Perimeter)**: Internal network hosts, guest networks, and servers attempting outbound or cross-zone connections.
- **TB-3: Management Interface (Internal/Admin to Control Plane)**: Operators accessing gRPC, REST, or the `sfw` CLI over Unix socket or TLS port 8443.
- **TB-4: Endpoint Agent to Gateway (Endpoint to Fleet Controller)**: Distributed SentinelFW agents reporting posture and retrieving policy over mTLS.
- **TB-5: Host to Decoy Sandbox (Host to Isolated Deception)**: Attacker sessions redirected into honeypot environments.

---

## 3. STRIDE Threat Analysis & Defensive Mitigations

| Threat Category | Threat Scenario | Impact | Mitigation Mechanism |
|---|---|---|---|
| **Spoofing (S)** | Attacker spoofs source IP to bypass ACLs or cause auto-banning of legitimate infrastructure (e.g. gateway, DNS). | Legitimate traffic dropped; denial of service on legitimate hosts. | 1. Strict **uRPF** (unicast Reverse Path Forwarding) in XDP pre-filter.<br>2. Hardcoded safety whitelist: RFC1918, default gateway, local DNS, and appliance own IPs can **never** be auto-banned.<br>3. Anti-spoofing scoring algorithm requires multi-packet TCP handshake validation before IP ban. |
| **Spoofing (S)** | Rogue node attempts to register as a SentinelFW endpoint or push fake telemetry. | False security alarms or unauthorized policy requests. | 1. Mutual TLS (mTLS) with appliance-signed client certificates.<br>2. Endpoint hardware fingerprinting and cryptographic challenge-response during enrollment. |
| **Tampering (T)** | Attacker tampers with local configuration files (`config.json` / `rules.nft`) or state tables. | Security policy weakened; unauthorized traffic permitted. | 1. Declarative config engine with cryptographic SHA-256 state hashing.<br>2. Non-writable configuration directory for non-root users (`chmod 700`, owned by `root`).<br>3. Commit-confirm watchdog automatically restores active state if candidate breaks management access. |
| **Tampering (T)** | Malware attempts to disable or terminate SentinelFW 3.0 endpoint service. | Endpoint left unprotected. | 1. System watchdog daemon monitoring parent process PID and thread state.<br>2. Kernel-level protection: WFP driver callout protection on Windows; cgroup freeze resistance on Linux.<br>3. Self-protection rails: SentinelFW binary directory integrity checksummed continuously. |
| **Repudiation (R)** | Malicious administrator modifies firewall policy and deletes system logs to hide activity. | Inability to attribute configuration changes or policy breaches. | 1. Append-only, tamper-evident audit logging with HMAC cryptographic chain.<br>2. Remote syslog / CEF / ClickHouse forwarding immediately upon transaction commit.<br>3. Granular RBAC ensuring `Auditor` role cannot be modified by `NetworkAdmin`. |
| **Information Disclosure (I)** | Intercepted cleartext data from TLS forward proxy leaks to unauthorized users. | Sensitive credentials or confidential user traffic exposed. | 1. TLS proxy operates purely in memory; zero session payload caching to disk.<br>2. Decrypted buffers scrubbed and overwritten (`memzero`) upon socket close.<br>3. Mandatory SNI bypass list for banking, healthcare, and governmental domains enforced by default. |
| **Information Disclosure (I)** | Decoy honeypot reveals internal gateway host architecture or allows lateral traversal. | Attacker fingerprints real platform or pivots into corporate network. | 1. Honeypots run in completely unprivileged, isolated network namespaces (`ip netns`) or Firecracker microVMs.<br>2. Strict nftables `DROP` on all outbound egress traffic originating from decoy namespaces. |
| **Denial of Service (D)** | Volumetric SYN flood, UDP flood, or ICMP flood targeting gateway WAN interface. | Conntrack table exhaustion, CPU overload, gateway unresponsiveness. | 1. Line-rate **eBPF/XDP** pre-filter drops floods before conntrack entry allocation.<br>2. eBPF syncookies / SYNPROXY offload for TCP SYN floods.<br>3. Multi-queue NIC tuning with RSS, IRQ affinity balancing across CPU cores. |
| **Denial of Service (D)** | Threat actor exhausts conntrack states through rapid short-lived connections. | Firewall drops legitimate new connections. | 1. Conntrack aggressive timeout tuning (`tcp_timeout_syn_recv`, `tcp_timeout_fin_wait`).<br>2. Early-drop algorithm when table reaches 90% threshold, terminating oldest unestablished sessions. |
| **Elevation of Privilege (E)** | Attacker exploits parser vulnerability in L7 inspection (DNS, SMB, HTTP, Suricata) to gain remote code execution. | Root compromise of the firewall gateway. | 1. All untrusted packet parsing implemented in memory-safe Go or fuzzed C/Rust.<br>2. Sandboxed execution with systemd hardening: `ProtectSystem=strict`, `NoNewPrivileges=true`, `CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_BPF`.<br>3. Continuous automated fuzz testing (`go-fuzz`, `AFL++`) integrated into CI. |

---

## 4. Operational Safety Rails

The platform strictly enforces the following non-negotiable safety guardrails:
1. **Administrative Exemption**: Management ports (default TCP 8443, SSH on defined management interfaces, and local Unix sockets) are protected by implicit priority-0 rules that cannot be shadowed or blocked by declarative user policies.
2. **Commit-Confirm Watchdog**: Any policy change applied via `sfw commit` triggers a confirmation countdown timer (default 10 minutes). If `sfw confirm` is not received before timeout, the system executes an atomic transaction rollback to the previous known good configuration.
3. **Emergency Console Access**: A local physical/virtual TTY console provides recovery utilities (`sfw recover`, `sfw factory-reset`) operating independently of the IP network stack.
