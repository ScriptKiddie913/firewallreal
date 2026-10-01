# SentinelFW / SentinelGate Architecture Audit

**Status Date:** October 2026  
**Audited Subsystems:** Dataplane, Policy Engine, eBPF/XDP, nftables, Userspace Daemons, WAF, TLS Inspection, IPS/Suricata, Identity, NAC/Posture, VPN/SD-WAN, High Availability, Threat Intelligence, Sandboxing, Deception, WebUI/API, Logging/SOC, Security Controls, and Deployment.

---

## 1. Executive Summary & Plane Separation Status

| Architectural Plane | Current State | Maturity Rating | Key Deficiencies |
|---|---|---|---|
| **Management Plane** | Partially Implemented | Medium | WebUI (Python basic/session auth) and `sentinelgated` (Go HTTP `:8443`) use divergent configuration schemas; unified RBAC across Go and Python is incomplete. |
| **Control Plane** | Partially Implemented | Medium | SD-WAN SLA probes and VRRP HA failover managers exist; routing operates via static/FRR configuration generation rather than dynamic programmatic FIB manipulation. |
| **Dataplane** | Partially Implemented | Medium-High | Linux nftables compiler generates atomic rules; userspace AF_PACKET/RCVALL detector runs alongside. Fastpath flowtable bypass is implemented; packet-level conntrack state machine needs deeper session context. |
| **Security Inspection Plane** | Implemented (Hybrid) | High | WAF reverse proxy, DLP, TCP stream reassembly, HTTP normalization, QUIC JA4Q, Suricata EVE ingestion, and streaming anomaly trees exist and execute in runtime. Inline proxy/NFQUEUE bridge requires unified session metadata. |
| **Analytics & SOC Plane** | Implemented | High | Flow rollups (SQLite), OTLP export, forensic PCAP incident bundler, MITRE ATT&CK mapper, and Mermaid kill-chain exporter are live. |

---

## 2. Granular Subsystem Classification

Each component is audited and classified into one of the following strict categories:
- **Implemented:** Full functional code running in production daemon paths with test coverage.
- **Partially Implemented:** Functional in core paths, but missing advanced edge cases, OS parity, or deeper integration.
- **Stubbed:** Interface or skeleton exists with minimal or no operative execution.
- **Mocked:** Simulated or synthetic responses returned instead of real operational handling.
- **Broken:** Contains syntax errors, compilation bugs, or fatal runtime mismatches.
- **Duplicated:** Multiple overlapping implementations for the same function.
- **Unused:** Functional code with no production importer or runtime invocation.
- **Insecure:** Contains cryptographic, authentication, or isolation vulnerabilities.
- **Missing:** Required capability completely absent from the codebase.

---

### A. Dataplane & Packet Processing

1. **Linux nftables Ruleset Compilation (`pkg/nftables/compiler.go`)**
   - **Status:** *Implemented*
   - **Analysis:** Generates atomic nftables syntax for zones, address objects, services, policy rules, and NAT.
   - **Gaps:** Flowtable bypass is placed before zone inspection; IPv6 objects are compiled with `ipv4_addr` types in legacy paths.

2. **Windows Defender Firewall Backend (`sentinelfw/backends.py`)**
   - **Status:** *Implemented*
   - **Analysis:** Uses `netsh advfirewall` rules prefixed with `SentinelFW-*` and process-level WFP hooks.
   - **Gaps:** Windows raw socket (`SIO_RCVALL`) only captures IPv4 on the primary interface.

3. **eBPF Ingress Prefilter (`bpf/xdp_prefilter.c`)**
   - **Status:** *Partially Implemented*
   - **Analysis:** Performs early drop for bad IP hashes (XDP BPF map), null scans, and broadcast packets.
   - **Gaps:** IPv4-only; lacks SYN-cookie generation (SYNPROXY offload) and multi-queue RSS load distribution.

4. **eBPF Cgroup Socket Filter (`bpf/sock_filter.c`)**
   - **Status:** *Implemented*
   - **Analysis:** Queries `bpf_get_current_cgroup_id()` against `endpoint_sock_policy` BPF hash map to return `BPF_OK` (1) or `BPF_DROP` (0).
   - **Gaps:** Needs integration with dynamic user-space cgroup tagging upon process startup.

5. **TCP Stream Reassembler (`sentinelfw/protocols/tcp_reassembly.py`)**
   - **Status:** *Implemented*
   - **Analysis:** Implements sliding sequence windows, duplicate packet dropping, overlapping segment trimming, and per-flow byte memory limits.
   - **Gaps:** Operates in userspace sniffer/proxy path; requires kernel NFQUEUE interception for full inline modification.

---

### B. Policy & Configuration Engine

1. **Canonical Policy Configuration Model**
   - **Status:** *Partially Implemented / Duplicated*
   - **Analysis:** Python uses `config.json` (`firewall_policies`, `objects`, `zones`) while Go uses `config.GatewayConfig` (`Policies`, `Services`, `Addresses`).
   - **Deficiency:** Two distinct configuration schemas exist; policies configured via WebUI must be synchronized to Go gateway configuration via `gateway_sync.py`.

2. **Policy Simulation & Shadow Analysis (`sentinelfw/policies.py`)**
   - **Status:** *Implemented*
   - **Analysis:** Evaluates first-match policy contracts with default-deny, provides dry-run simulation, and detects shadowed/unused rules.

3. **Config Migration Subsystem (`sentinelfw/config.py`)**
   - **Status:** *Implemented*
   - **Analysis:** Migrates policy versions from v1 (pre-2.0), v7/8 (2.9), v9 (3.0) up to v10 (4.0) with atomic disk commit.

---

### C. Inspection, Detection & Protocols

1. **HTTP Normalization & Decoders (`sentinelfw/protocols/http.py`)**
   - **Status:** *Implemented*
   - **Analysis:** Handles recursive percent-decoding loops, unicode NFKC normalization, chunked transfer decoding, gzip bomb limits, and HTTP/2 preface / gRPC awareness.

2. **QUIC & TLS JA4Q Fingerprinting (`sentinelfw/protocols/tls.py`)**
   - **Status:** *Implemented*
   - **Analysis:** Parses QUIC Initial packets, extracts DCID/SCID and SNI, generates JA4Q fingerprints, and enforces fallback policies.

3. **Go TLS Inspection Proxy (`pkg/tlsproxy/proxy.go`)**
   - **Status:** *Partially Implemented*
   - **Analysis:** Accepts connections, terminates TLS with internal CA leaf minting, and dials upstream with cert verification.
   - **Gaps:** Uses forward proxy listener (`net.Listen`) rather than transparent `TPROXY` / `SO_ORIGINAL_DST`. ClientHello parsing on single socket read can fragment across TCP segments.

4. **WAF Engine (`sentinelfw/waf/`)**
   - **Status:** *Implemented*
   - **Analysis:** Reverse proxy listener, virtual host router, bot challenges, upload scanning to sandbox, LLM prompt injection / API key protection, and rate limiting.

5. **DLP Subsystem (`sentinelfw/dlp.py`)**
   - **Status:** *Implemented*
   - **Analysis:** Real-time regex pattern and Shannon entropy analysis for credit cards, SSNs, API tokens, and private keys across uploads and streams.

6. **DDoS Amplification & L2 Detection (`sentinelfw/detector.py`)**
   - **Status:** *Implemented*
   - **Analysis:** Detects DNS, NTP monlist, SSDP, Memcached, and CLDAP amplification with Tier 1-3 escalation; detects ARP cache poisoning, rogue DHCP, and LLMNR/NBT-NS poisoning.

7. **Online Anomaly Model (`sentinelfw/anomaly.py`)**
   - **Status:** *Implemented*
   - **Analysis:** Pure stdlib online Half-Space Tree (HSTree) ensemble with labelled precision gating and plain-language alert explanations.

---

### D. Identity, Posture & Access

1. **Identity & Directory Integration (`sentinelfw/identity.py`)**
   - **Status:** *Implemented*
   - **Analysis:** Multi-source identity supporting local accounts, verified TLS LDAP/AD, RADIUS, and strictly verified OIDC/JWT.
   - **Gaps:** Stale IP-to-user mappings require continuous active heartbeat or 802.1X accounting feeds.

2. **Device Posture & ZTNA Evaluation (`sentinelfw/identity.py`)**
   - **Status:** *Implemented*
   - **Analysis:** Assesses host compliance (encryption, firewall, patch level) and evaluates ZTNA reverse-proxy access with short-lived tokens and JIT auto-expiring rules.

3. **Micro-segmentation (`sentinelfw/identity.py`)**
   - **Status:** *Implemented*
   - **Analysis:** Learning mode records inter-workload flows, generates least-privilege policies, and promotes to enforcement.

---

### E. Deception, Honeypots & Sandboxing

1. **Deception Services (`sentinelfw/decoy_advanced.py`, `sentinelfw/honeypot.py`)**
   - **Status:** *Implemented*
   - **Analysis:** Emulates OpenSSH, IIS/nginx HTTP, MySQL, Telnet, Elasticsearch, RDP, Ollama/OpenAI banners, clusters attackers across IPs, and isolates processes with Windows Job Objects / Linux rlimits.
   - **Gaps:** In-process honeypot sockets share main daemon PID namespace when run without container/netns wrapper.

2. **Honeytokens (`sentinelfw/canary_tokens.py`)**
   - **Status:** *Implemented*
   - **Analysis:** Deploys and monitors fake AWS keys, GCP Service Accounts, Azure connection strings, database canary rows, and local canary files.

3. **Malware Sandbox (`sentinelfw/sandbox.py`)**
   - **Status:** *Partially Implemented*
   - **Analysis:** Static analysis with PE/ELF/archive inspection is robust; dynamic detonation uses Docker (`sentinelgate/sandbox-worker:latest`).
   - **Gaps:** Firecracker / KVM microVM backend is missing; falls back to static analysis when Docker is absent.

---

### F. Control Plane: Routing, SD-WAN, VPN & HA

1. **SD-WAN Subsystem (`pkg/sdwan/`)**
   - **Status:** *Partially Implemented*
   - **Analysis:** `NewSDWANManager` probes latency, jitter, and packet loss across WAN links.
   - **Gaps:** Generates FRR BGP/routing configurations, but does not yet reprogram kernel multipath routing tables (PBR / `ip route`) dynamically based on SLA breaches.

2. **High Availability (`pkg/ha/`)**
   - **Status:** *Partially Implemented*
   - **Analysis:** Failover manager tracks VRRP states and generates Keepalived and conntrackd configurations.
   - **Gaps:** Lacks direct kernel-to-kernel state sync socket for real-time conntrack and NAT session replication without external conntrackd. Split-brain fencing relies on witness ping.

3. **VPN Subsystem (`pkg/vpn/`, `sentinelfw/identity.py`)**
   - **Status:** *Implemented*
   - **Analysis:** Generates WireGuard keypairs, manages dynamic peer configurations and allowed IPs, and generates strongSwan IPsec configs (`swanctl.conf`).
   - **Gaps:** Direct kernel Netlink WireGuard device configuration is orchestrated through CLI/OS helpers rather than pure in-process Netlink Go code.

---

### G. Management, API, Telemetry & Security

1. **Encrypted Secrets Vault (`sentinelfw/vault.py`)**
   - **Status:** *Implemented*
   - **Analysis:** AES-256-GCM sealed via Windows DPAPI (`CryptProtectData`) on Windows and a `0600` root-owned keyfile on Linux.

2. **Management Plane Authentication (`sentinelfw/webui.py`, `sentinelfw/mgmt.py`)**
   - **Status:** *Implemented*
   - **Analysis:** Salted scrypt password hashing, session tokens, CSRF validation, TOTP 2FA, `must_change_password` write-gate, and zero hardcoded credentials.

3. **API & CLI (`sentinelfw/cli.py`, `pkg/api/`)**
   - **Status:** *Implemented*
   - **Analysis:** Rich CLI (`sfwctl`) and versioned REST endpoints (`/api/v1/`). Go daemon provides `/healthz` and `/api/v1/status`.

4. **Telemetry & SOC Export (`sentinelfw/elastic.py`, `sentinelfw/forensics.py`)**
   - **Status:** *Implemented*
   - **Analysis:** Prometheus `/metrics`, OpenTelemetry OTLP JSON log shipper, SQLite flow rollups (`flows.db`), and one-click incident `.tar.gz` bundle generator.
