# SentinelFW — Enterprise NGFW & Security Fabric Implementation Plan

## Executive Summary & Target Architecture

The goal of this initiative is to evolve SentinelFW from a hybrid host-defense agent into a carrier-grade Next-Generation Firewall (NGFW) and Unified Security Fabric. The architecture strictly decouples into four coordinated planes with a single canonical policy and session model:

```
                           SENTINELGATE OS / SECURITY FABRIC
                                          │
       ┌──────────────────────────────────┼──────────────────────────────────┐
       │                                  │                                  │
       ▼                                  ▼                                  ▼
 MANAGEMENT PLANE                  CONTROL PLANE                      ANALYTICS PLANE
 - SentinelManager CLI/API/UI      - Dynamic Routing (BGP/OSPF/FRR)   - SentinelAnalyzer Event Lake
 - RBAC / Audit / Credentials      - Application-Aware SD-WAN         - Multi-stage Correlation
 - Tenant / Object Isolation       - IPsec / WireGuard VPN            - MITRE ATT&CK Incident Graph
 - Policy Compiler & Simulation    - Active/Passive HA State Sync     - Compliance & Security Rating
 - Fleet Orchestration (mTLS)      - Multi-source Identity Engine     - AI Analyst (Advisory Layer)
       │                                  │                                  │
       └──────────────────────────────────┼──────────────────────────────────┘
                                          │
                                          ▼
                                   DATAPLANE CORE
                                          │
              ┌───────────────────────────┴───────────────────────────┐
              ▼                                                       ▼
        FAST PATH (Offload)                                    SLOW PATH (NGFW DPI)
   - eBPF / XDP Ingress Filter                            - TCP Stream Reassembly
   - Flowtable / Session Conntrack Cache                  - HTTP/2 & HTTP Normalization
   - Hardware / Kernel Forwarding                         - Transparent TLS Interception Proxy
   - L3/L4 Stateless & Established Packet Path            - Unified Policy & Verdict Engine
                                                                      │
                                     ┌────────────────────────────────┼────────────────────────────────┐
                                     ▼                                ▼                                ▼
                              L7 APPLICATION ID                 INLINE IPS ENGINE                 WAF & DLP
                              - Protocol Decoders               - Suricata NFQUEUE / EVE          - Reverse Proxy
                              - SNI / TLS / JA4 Fingerprints    - Signature Matching              - CRS Basic Rules
                              - Behavior Classifier             - Virtual Patching & CVE          - Content Redaction
                                     │                                │                                │
                                     └────────────────────────────────┼────────────────────────────────┘
                                                                      │
                                                                      ▼
                                                              VERDICT AGGREGATOR
                                                              (Drop / Accept / Reject / Quarantine)
```

---

## Detailed Phase Breakdown (Phases 0 — 37)

### Phase 0 — Full Repository Audit & Baseline Gap Analysis
- **Goal:** Conduct a comprehensive, unvarnished audit of all Go, Python, C/eBPF, and documentation assets in the repository.
- **Deliverables:**
  - `docs/ARCHITECTURE_AUDIT.md`: Categorizes every existing module as *Implemented*, *Partially Implemented*, *Stubbed*, *Mocked*, *Broken*, *Duplicated*, *Unused*, *Insecure*, or *Missing*.
  - `docs/FEATURE_MATRIX.md`: Complete matrix containing *Feature*, *Current State*, *Implementation Location*, *Dependencies*, *Missing Pieces*, *Risk*, *Priority* (P0/P1/P2/P3), and *Test Status*.

### Phase 1 — Unified Canonical Policy Engine
- **Goal:** Unify Python and Go configuration schemas into a single canonical policy model consumed by all enforcement backends.
- **Components:**
  - Multi-dimensional criteria: Source/Dest IPs, subnets, ports, protocols, interfaces, zones, users, groups, devices, posture states, applications, categories, domains, URL categories, countries, ASNs, threat scores, schedules, bandwidth classes.
  - Policy Actions: `ACCEPT`, `DROP`, `REJECT`, `LOG`, `RATE_LIMIT`, `QUARANTINE`, `REDIRECT`, `INSPECT`, `CHALLENGE`, `TARPIT`.
  - Compiler Pipeline: Validation -> Normalization -> Conflict/Shadow Detection -> Backend Compilation (nftables, XDP, WAF, DNS, TLS Proxy) -> Atomic Deployment -> Verification.

### Phase 2 — Stateful Dataplane & Session Conntrack Engine
- **Goal:** Replace polling socket snapshots with an inline packet-driven conntrack session table.
- **Components:**
  - Full TCP State Machine: `NEW`, `SYN_SENT`, `SYN_RECV`, `ESTABLISHED`, `FIN_WAIT`, `CLOSE_WAIT`, `LAST_ACK`, `TIME_WAIT`, `INVALID`.
  - UDP pseudo-state tracking with aging timers; ICMP request/reply state matching.
  - Complete IPv4 and IPv6 state tracking parity.
  - Stateful NAT Subsystem: SNAT, DNAT, PAT, NAT64, and Hairpin NAT tied directly to session tuples (original tuple <-> translated tuple).
  - TCP flag validation, sequence tracking, window checks, and SYN flood protection.

### Phase 3 — Deep Application Identification (App-ID)
- **Goal:** Build an enterprise application identification database beyond port and heuristic heuristics.
- **Components:**
  - Inspection pipeline: Packet -> Flow -> Protocol Decoder -> TLS ClientHello/SNI/JA4 -> DNS correlation -> HTTP Host/User-Agent -> Application Classifier -> Policy Verdict.
  - Protocol support: HTTP/HTTPS, HTTP/2, QUIC/HTTP/3, DNS (DoH/DoT), SSH, FTP, SMTP, IMAP, POP3, WebSocket, WireGuard, OpenVPN, Tor, BitTorrent.
  - Application Catalog: Structured signatures with Risk Level (1–5), Category (Cloud, Messaging, Streaming, P2P, Dev, Social), and Confidence score.
  - Explicit `UNKNOWN` state preserved for unclassified traffic with configurable fallback policies.

### Phase 4 — Identity-Aware Networking & Multi-Source Engine
- **Goal:** Propagate identity directly into firewall policies and session states.
- **Components:**
  - Authentication sources: Local user store, LDAP / Active Directory (with strict TLS validation and certificate verification), RADIUS, OIDC/SAML, and OAuth2 JWT (with mandatory cryptographic signature verification).
  - Dynamic Identity Mapping: IP/MAC <-> Device <-> User <-> Group <-> Session with strict TTLs and auto-expiry.
  - Session revocation and group membership caching with active polling.

### Phase 5 — Passive Network Access Control (NAC) & Device Discovery
- **Goal:** Passively identify, profile, and classify every network device without active disruption.
- **Components:**
  - Telemetry ingestion: DHCP Option 55 fingerprints, TCP SYN packet fingerprints (window size, options, TTL), HTTP User-Agents, mDNS/SSDP broadcasts, and MAC OUI vendor lookups.
  - Device Classification: Workstation, Server, Mobile, Printer, IP Camera, IoT Device, Network Infrastructure, Unknown.
  - Risk categorization (Low, Medium, High, Critical) and automatic policy binding (e.g., isolate unknown devices or camera VLANs).

### Phase 6 — Endpoint Posture Assessment
- **Goal:** Verify host compliance before allowing access to sensitive segments or corporate applications.
- **Components:**
  - Lightweight SentinelFW agent daemon reporting OS build, host identity, running processes, disk encryption state (BitLocker/LUKS), OS patch level, firewall status, and AV/EDR agent status.
  - Mutual TLS (mTLS) agent-to-gateway telemetry channel.
  - Posture evaluation states: `COMPLIANT`, `NON_COMPLIANT`, `UNKNOWN`, `COMPROMISED`.

### Phase 7 — Zero Trust Network Access (ZTNA)
- **Goal:** Application-level micro-perimeters replacing legacy broad network VPNs.
- **Components:**
  - ZTNA reverse proxy evaluating: User Identity + Group + Device ID + Posture State + Continuous Risk Score.
  - Application connectors with short-lived session tokens and mutual TLS.
  - Dynamic session revocation on posture downgrade or behavioral anomaly.

### Phase 8 — Transparent TLS Inspection Engine
- **Goal:** High-throughput transparent TLS decryption and re-encryption for inline security inspection.
- **Components:**
  - Internal Root & Subordinate CA management; on-the-fly leaf certificate minting with caching.
  - Upstream certificate validation: Full chain trust verification, revocation check (CRL/OCSP), and expired/self-signed handling.
  - Certificate pinning detection and automatic or explicit bypass lists for sensitive categories (Banking, Healthcare).
  - Handling of TLS 1.2, TLS 1.3, ALPN negotiation, and QUIC/HTTP/3 policy enforcement.

### Phase 9 — Production Inline IPS Architecture
- **Goal:** Enterprise-grade signature-based attack prevention with deterministic verdicts.
- **Components:**
  - Bi-directional NFQUEUE (Linux) / userspace proxy integration with Suricata EVE socket.
  - Explicit per-profile failure mode: `fail-open` vs `fail-closed`.
  - Actions: `PASS`, `ALERT`, `DROP`, `RESET`, `QUARANTINE`.
  - Versioned rule packs with CVE cross-references, MITRE ATT&CK techniques, atomic hot-reload, and rollback.

### Phase 10 — Multi-Engine Antivirus & Malware Defense
- **Goal:** Inline file reconstruction and multi-stage malware analysis.
- **Components:**
  - Protocol stream extraction across HTTP/HTTPS, FTP, SMTP, SMB.
  - Hash reputation caching (SHA-256), MIME/magic-byte verification (ignoring extensions).
  - Decompression bomb protection, archive recursion depth limits (max 5 levels), and file size thresholds.
  - ClamAV, YARA pattern matching, and heuristics engine integration.

### Phase 11 — Hardened Disposable Sandbox
- **Goal:** Safe, fully isolated dynamic execution of untrusted files.
- **Components:**
  - Disposable container or microVM (Firecracker/KVM) execution with zero host network access, isolated virtual filesystem, no host socket mount, and strict CPU/memory limits.
  - Behavioral telemetry recorder: Process tree, registry/filesystem mutations, DNS simulation, mutexes, dropped payloads.
  - Verdict feedback pipeline returning `CLEAN`, `SUSPICIOUS`, or `MALICIOUS` to trigger automated firewall quarantine.

### Phase 12 — Content-Aware Data Loss Prevention (DLP)
- **Goal:** Bidirectional inspection of payloads and files to prevent sensitive data exfiltration.
- **Components:**
  - High-speed pattern matching: Credit cards (Luhn validated), Social Security Numbers, private keys, API keys, source code credentials, and custom proprietary expressions.
  - Shannon entropy scanning to detect encrypted/obfuscated secrets.
  - Actions: `ALLOW`, `LOG`, `BLOCK`, `QUARANTINE`, `REDACT` across upload and download streams.

### Phase 13 — Secure Web Gateway (SWG) & URL Filtering
- **Goal:** Comprehensive web security and policy-based categorization.
- **Components:**
  - Category database: Malware, Phishing, Gambling, Adult, Social Media, Streaming, Cloud Storage, Developer Tools, Unknown.
  - Reputation engine: Newly registered domains (NRDs), suspicious top-level domains (TLDs), and typosquatting heuristics.
  - Deep HTTP request/header inspection and policy enforcement.

### Phase 14 — Advanced DNS Security & Sinkholing
- **Goal:** DNS-layer threat containment and protocol abuse defense.
- **Components:**
  - Caching recursive forwarder with Response Policy Zones (RPZ).
  - Malicious domain sinkhole routing to controlled internal sinkhole IP with original query context preserved.
  - Real-time detection of Domain Generation Algorithms (DGA), DNS tunneling (hex/base32 encoding), and unauthorized DoH/DoT bypass.

### Phase 15 — Threat Intelligence Subsystem (TIP)
- **Goal:** High-volume feed ingestion, deduplication, and automated IOC scoring.
- **Components:**
  - Ingestion connectors: STIX 2.1 / TAXII, MISP, URLhaus, Abuse.ch, Spamhaus DROP, and custom HTTP feeds.
  - Canonical IOC schema: IP, domain, URL, file hash, ASN, JA3/JA4, confidence score, first/last seen, expiration TTL.
  - Feed health checks, poisoned-feed protection (anti-private/gateway IP guards), and atomic IOC database updates.

### Phase 16 — Advanced C2 & Botnet Detection
- **Goal:** Detection of command-and-control communication channels in encrypted or stealthy traffic.
- **Components:**
  - Statistical beaconing analysis: Inter-arrival time variance and metronomic periodicity detection.
  - TLS fingerprint anomaly detection and rare destination scoring.
  - Dynamic `C2_SCORE` (0–100) combining statistical, reputation, and protocol signals.

### Phase 17 — Cloud Access Security Broker (CASB)
- **Goal:** Visibility and control over SaaS applications and corporate tenants.
- **Components:**
  - Tenant restriction headers (e.g., Microsoft 365, Google Workspace).
  - Unsanctioned SaaS ("Shadow IT") discovery and bandwidth accounting.
  - File upload/download interception with DLP policy routing.

### Phase 18 — Application-Aware SD-WAN Engine
- **Goal:** Dynamic multi-path routing based on real-time link performance and application SLA requirements.
- **Components:**
  - Continuous SLA link probes: Latency, jitter, packet loss, availability across WAN1, WAN2, LTE, VPN links.
  - Application-aware path selection matrix with configurable cost and quality thresholds.
  - Route flapping hysteresis and graceful link failover.

### Phase 19 — Enterprise VPN Subsystem
- **Goal:** Operational management and data-plane control for IPsec and WireGuard.
- **Components:**
  - WireGuard interface orchestration, dynamic peer lifecycle, endpoint IP routing, and per-peer policy binding.
  - IPsec site-to-site and remote-access orchestration with strongSwan (`swanctl.conf`).
  - Zero private key exposure across all management APIs; MFA enforcement for client tunnels.

### Phase 20 — Active/Passive High Availability (HA)
- **Goal:** Zero-loss stateful failover across redundant gateway appliances.
- **Components:**
  - Virtual Router Redundancy (VRRP/Keepalived) with virtual IP (VIP) migration.
  - Real-time state synchronization link: TCP/UDP conntrack session tables, NAT translation states, and active bans.
  - Split-brain prevention with external witness pinging, quorum validation, and node fencing.

### Phase 21 — Centralized Fleet Management (SentinelManager)
- **Goal:** Single-pane-of-glass management for distributed firewall clusters and endpoint agents.
- **Components:**
  - Mutual TLS (mTLS) device enrollment, unique agent certificates, and inventory tracking.
  - Group policy distribution, staged template rollout, and automated rollback upon health check failure.
  - Bi-directional threat ban propagation with confidence-weighted TTLs.

### Phase 22 — Security Analytics Lake & SOC Engine (SentinelAnalyzer)
- **Goal:** Centralized event streaming, storage, search, and visualization.
- **Components:**
  - Canonical event schema across all subsystems (firewall, DNS, IPS, WAF, DLP, identity, endpoint).
  - SQLite/Elasticsearch flow time-series rollups (1m, 5m, 1h, 24h).
  - Forensic incident bundling: One-click export of relevant PCAP, event logs, verdicts, and host context.

### Phase 23 — SOAR & Automated Threat Response
- **Goal:** Deterministic, policy-controlled automated response to verified incidents.
- **Components:**
  - Playbook trigger engine reacting to IPS alerts, malware verdicts, C2 detections, and honeypot hits.
  - Autonomous actions: IP ban, domain sinkhole, endpoint network quarantine, session termination, admin notification.
  - Hard safety rails: Mandatory TTLs for auto-blocks, loop protection, and hard exclusions for trusted/management subnets.

### Phase 24 — AI Security Analyst (Advisory Layer)
- **Goal:** Agentic threat synthesis without giving AI unchecked execution authority.
- **Components:**
  - LLM integration analyzing normalized incidents, event timelines, and MITRE mappings.
  - Output: Plain-language executive summaries, root-cause hypothesis, investigation steps, and suggested policy rules.
  - Strict guardrails: Prompt sanitization against injection, policy simulation before any suggested change, and mandatory human confirmation.

### Phase 25 — MITRE ATT&CK Mapping & Incident Graphs
- **Goal:** Graph-based correlation of disparate security alerts into coherent intrusion campaigns.
- **Components:**
  - Mapping all detection rules and signatures to MITRE ATT&CK tactics (TA0001–TA0040) and techniques.
  - Real-time incident graph correlation linking hosts, users, IOCs, and alert sequences.
  - Mermaid diagram generation and STIX 2.1 bundle export.

### Phase 26 — Hardened Deception & Honeypot Ecosystem
- **Goal:** Low-interaction decoy services that capture attacker reconnaissance without becoming pivot points.
- **Components:**
  - Emulated banner profiles: OpenSSH, IIS/nginx HTTP, MySQL, Telnet, Elasticsearch, RDP, Ollama/OpenAI API.
  - Honeytokens: AWS keys, GCP Service Account JSON, Azure connection strings, and canary database rows.
  - Process containment: Windows Job Objects and Linux rlimits with egress traffic strictly blocked and logged.

### Phase 27 — Defense-in-Depth System Hardening
- **Goal:** Enforce strict OS-level least privilege and isolation across all running daemons.
- **Components:**
  - Linux capabilities restriction (`CAP_NET_ADMIN`, `CAP_NET_RAW` only where necessary; non-root user for proxies).
  - Systemd sandboxing directives (`ProtectSystem=strict`, `PrivateTmp=yes`, `NoNewPrivileges=yes`).
  - Web UI API protection: Mandatory token authentication, strict RBAC, CSRF token validation, rate limiting, and secure headers.

### Phase 28 — Cryptographic Secrets Management & Vault
- **Goal:** Zero hardcoded secrets, sealed credential storage, and continuous secret auditing.
- **Components:**
  - AES-256-GCM vault sealed with Windows DPAPI or Linux 0600 root-owned keyfile.
  - Automated migration of API keys (VT, Sarvam, Telegram, Fleet) into sealed storage with environment variable precedence.
  - Pre-commit and CI secret scanning tools preventing accidental commits.

### Phase 29 — Multi-Tenancy & Virtual Domains (VDOMs)
- **Goal:** Logical isolation of network policies, interfaces, routing, and logs across separate organizations.
- **Components:**
  - Ubiquitous `tenant_id` tagging across all objects, policies, routing tables, and logs.
  - Strict storage-level and API-level authorization boundaries preventing cross-tenant leakage.

### Phase 30 — Versioned REST API & OpenAPI Documentation
- **Goal:** Complete, documented programmatic control for automation and orchestration.
- **Components:**
  - Versioned `/api/v1/` endpoints for all resources: policies, objects, identity, threat intel, incidents, VPN, HA, system status.
  - Strict JSON request/response schema validation and consistent error response structures.
  - Auto-generated OpenAPI 3.0 specification available directly from the management console.

### Phase 31 — Enterprise Security Management Console (Web UI)
- **Goal:** Dense, operational web console built for security engineers and SOC operators.
- **Components:**
  - Core views: Live Dashboard, Policy Editor, Object Catalog, Identity & Posture, Threat Intelligence, Network Flow Inspector, Geo Threat Map, Application Wall, Forensics, and System Administration.
  - Real-time event streaming via WebSockets/SSE with search, filtering, and deep packet inspection dialogs.

### Phase 32 — Telemetry & Prometheus Observability
- **Goal:** High-resolution metrics export for capacity planning and external monitoring.
- **Components:**
  - Prometheus-compatible `/metrics` endpoint exposing packet rates, connection counters, drops, policy lookup latency, proxy latency, and CPU/memory utilization.
  - OpenTelemetry (OTLP) log export over HTTP/JSON to external SIEM/data lakes.

### Phase 33 — Performance Optimization & Fast-Path Offload
- **Goal:** Maximizing packet processing throughput and minimizing per-packet latency.
- **Components:**
  - eBPF/XDP early packet drop for known banned IPs, malformed packets, and flood patterns.
  - Linux kernel flowtable offload for established L4 sessions bypasses userspace once inspected.
  - Multi-queue NIC affinity and lock-free per-CPU ring buffers in packet capture routines.

### Phase 34 — Multi-Tiered Verification & Automated Testing Suite
- **Goal:** Exhaustive automated verification proving correctness under benign, adversarial, and edge conditions.
- **Components:**
  - Unit tests for all parsers, state machines, and compilers.
  - Network namespace (netns) integration tests for routed, NATed, and bridged traffic.
  - Adversarial negative tests: Malformed packets, TCP flag anomalies, HTTP request smuggling, decompression bombs, archive loops, and policy race conditions.

### Phase 35 — Supply Chain Security & Release Hygiene
- **Goal:** Verifiable, reproducible release pipeline free of vulnerabilities and unintended artifacts.
- **Components:**
  - Automated hygiene verifier (`scripts/check_release_hygiene.py`) failing on any private keys, certificates, or cache directories.
  - Software Bill of Materials (SBOM) generation and automated vulnerability scanning for dependencies.

### Phase 36 — Packaging & Deployment Orchestration
- **Goal:** Standardized, reproducible installation across physical, virtual, and containerized targets.
- **Components:**
  - Native systemd service units for Linux and PowerShell installation scripts for Windows Server.
  - Docker Compose definitions for distributed control/management/analytics deployment.
  - Offline deployment bundle packager (`scripts/package_release.py`).

### Phase 37 — Production Documentation & Operational Runbooks
- **Goal:** Comprehensive, production-grade documentation across all operational disciplines.
- **Components:**
  - Complete documentation suite across 18 standalone documents in `docs/` covering architecture, installation, configuration, threat model, API, policy engine, TLS inspection, IPS, DLP, ZTNA, SD-WAN, HA, threat intelligence, operations, troubleshooting, and development.

---

## Phased Implementation Sequence & Milestones

To maintain stability, each phase must follow the strict compile -> test -> negative test -> verify cycle before proceeding to downstream dependencies:

```
[Phase 0: Audit & Matrix]
       │
       ▼
[Phase 1: Unified Policy Engine] ───► [Phase 2: Stateful Dataplane & NAT]
                                                    │
       ┌────────────────────────────────────────────┴────────────────────────────────────────────┐
       ▼                                            ▼                                            ▼
[Phase 3: App-ID]                           [Phase 4: Identity Engine]                   [Phase 5: NAC & Posture]
       │                                            │                                            │
       └────────────────────────────────────────────┼────────────────────────────────────────────┘
                                                    │
                                                    ▼
                                            [Phase 7: ZTNA Engine]
                                                    │
       ┌────────────────────────────────────────────┴────────────────────────────────────────────┐
       ▼                                            ▼                                            ▼
[Phase 8: TLS Inspection]                   [Phase 9: Inline IPS]                        [Phase 10: AV / Malware]
       │                                            │                                            │
       ├────────────────────────────────────────────┼────────────────────────────────────────────┤
       ▼                                            ▼                                            ▼
[Phase 11: Sandbox Engine]                  [Phase 12: Content DLP]                      [Phase 13: SWG & Web Security]
       │                                            │                                            │
       └────────────────────────────────────────────┼────────────────────────────────────────────┘
                                                    │
                                                    ▼
                                            [Phase 14: DNS Security]
                                                    │
       ┌────────────────────────────────────────────┴────────────────────────────────────────────┐
       ▼                                            ▼                                            ▼
[Phase 15: Threat Intel Platform]           [Phase 16: C2 Detection]                     [Phase 17: CASB]
       │                                            │                                            │
       └────────────────────────────────────────────┼────────────────────────────────────────────┘
                                                    │
                                                    ▼
                                            [Phase 18: SD-WAN & Phase 19: VPN]
                                                    │
                                                    ▼
                                            [Phase 20: High Availability]
                                                    │
       ┌────────────────────────────────────────────┴────────────────────────────────────────────┐
       ▼                                            ▼                                            ▼
[Phase 21: SentinelManager]                 [Phase 22: SentinelAnalyzer]                 [Phase 23: SOAR Response]
       │                                            │                                            │
       └────────────────────────────────────────────┼────────────────────────────────────────────┘
                                                    │
                                                    ▼
                                            [Phase 24: AI Security Analyst]
                                                    │
                                                    ▼
                                            [Phase 25: MITRE Graph & Phase 26: Deception]
                                                    │
                                                    ▼
                                            [Phase 27: Hardening & Phase 28: Secrets Vault]
                                                    │
                                                    ▼
                                            [Phase 29: Multi-Tenancy & Phase 30: REST API]
                                                    │
                                                    ▼
                                            [Phase 31: Web UI & Phase 32: Telemetry]
                                                    │
                                                    ▼
                                            [Phase 33: Performance & Phase 34: Testing]
                                                    │
                                                    ▼
                                            [Phase 35: Supply Chain & Phase 36: Packaging]
                                                    │
                                                    ▼
                                            [Phase 37: Complete Docs & Final Gap Analysis]
```

---

## Verification & Quality Gates

At the completion of each milestone:
1. **Compilation & Build:** Go and C/eBPF code compiles without warnings or errors. No `|| true` in CI or makefiles.
2. **Automated Pytest Suite:** All tests execute with zero failures. Every new security feature includes corresponding negative/bypass test cases.
3. **Hygiene Verification:** The release hygiene auditor confirms zero embedded private keys, certificates, or hardcoded secrets.
4. **Documentation Sync:** `FEATURE_MATRIX.md` and `docs/ROADMAP.md` are updated with verified evidence.
