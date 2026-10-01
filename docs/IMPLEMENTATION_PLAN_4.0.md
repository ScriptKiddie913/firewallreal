# SentinelFW / SentinelGate 4.0.0 — Comprehensive Implementation Plan

## 1. Executive Summary & Architectural Realignment

### 1.1 Unification of SentinelFW and SentinelGate
Historically, the repository maintained two diverging paradigms:
1. **SentinelFW**: Python-based host firewall, security agent, and management controller.
2. **SentinelGate**: Go-based network gateway, data-plane compiler, and transparent proxy services.

In 4.0.0, both are unified under a single **SentinelGate Next-Generation Firewall OS** architecture structured into four distinct planes:

```
                            SENTINELGATE OS 4.0
                                     │
    ┌────────────────────────────────┼────────────────────────────────┐
    │                                │                                │
    ▼                                ▼                                ▼
MANAGEMENT PLANE              CONTROL PLANE                    SECURITY PLANE
- Web UI & Console (HTTPS)    - Routing & BGP/OSPF             - Suricata IPS (NFQUEUE)
- sfwctl CLI                  - SD-WAN SLA Monitoring          - App-ID Engine (L7)
- REST & Management API       - WireGuard & IPsec VPN          - ClamAV & Sandbox
- Role-Based Access (RBAC)    - VRRP / High Availability       - TLS Forward Proxy
- Encrypted Secrets Vault     - Zone & Identity Manager        - WAF & DLP Engine
    │                                │                                │
    └────────────────────────────────┼────────────────────────────────┘
                                     │
                                     ▼
                            SESSION & POLICY IR
                        - Unified Canonical Config
                        - Stateful Conntrack & NAT
                        - Policy Compiler (nftables/XDP)
                        - Verdict Aggregator
                                     │
                    ┌────────────────┴────────────────┐
                    │                                 │
                    ▼                                 ▼
             FAST PATH (Offload)              SLOW PATH (Inspection)
             - XDP Pre-filter                 - User-space Proxies
             - Flowtable HW/Kernel            - Deep Packet Inspection
             - SYN Flood Protection           - Stream Reassembly
```

### 1.2 Core Constraints & Standards
- **Cross-Platform**: Support Ubuntu 22.04+ LTS and Windows 10/11/Server 2019+ with identical CLI, config schema, and UI capabilities.
- **Agent Dependencies**: Python 3.8+ Standard Library ONLY. No new third-party Python package dependencies (`pip`) in the core agent.
- **Go Components**: Go 1.22+ stdlib + `golang.org/x/*`, strictly no cgo, compiled for `linux/amd64` and `windows/amd64`.
- **Zero Credentials in Code**: Complete elimination of hardcoded credentials, test keys, and plaintext password references.

---

## 2. Phase P0: Critical Security Bugs & Secret Hygiene

### P0.1 & P0.2: Credential Reset Bug & Password Initialization
- **Problem**: `sentinelfw/engine.py` (lines 194-205) hardcodes `sotanikai` and scrypt hash for `Hotmeha21@`, resetting any user-configured password on daemon startup.
- **Implementation**:
  1. Delete hardcoded hash and comments from `sentinelfw/engine.py`.
  2. Implement first-run random OTP generator using `secrets.token_urlsafe(16)` when no `password_hash` exists.
  3. Emit generated one-time credentials to console once during initialization, and write them to an admin-only file (`auth.initial` with 0600 permissions on Linux, SYSTEM/Admin ACL on Windows).
  4. Store salted scrypt hash (`scrypt$16384$8$1$<salt>$<hash>`) in config, set `must_change_password: True`.
  5. Never overwrite an existing operator password hash under any username.
  6. Update `sentinelfw/webui.py`: replace loose initialization checks with an explicit `must_change_password` gate. Until `/api/v1/auth/password` is called with valid old and new credentials, all operational endpoints return `403 Password Change Required`.
  7. Scan repository and documentation to purge leftover plaintext credential references (`sotanikai`, `Hotmeha21@`).
  8. Add regression test `tests/test_p0_credentials.py` asserting password persistence across engine restarts and rejection of default credentials.

### P0.3: Repository Hygiene & Release Packaging
- **Problem**: `_test_data/` ships in the repository containing live private keys (`console.key`), certificates (`console.crt`), and mock logs.
- **Implementation**:
  1. Remove `_test_data/`, `__pycache__`, `.pytest_cache`, and any lingering `*.key`/`*.crt`.
  2. Refactor `tests/test_gateway_phases.py` to use isolated temporary directories via `tempfile.TemporaryDirectory` rather than `_test_data/`.
  3. Create `scripts/check_release_hygiene.py` to assert absence of private keys, certificates, caches, and test artifacts before release builds.
  4. Create `scripts/package_release.py` to create clean, production-ready release archives.

### P0.4: Fix Broken Regression Tests
- **Problem 1**: `tests/test_phase4_5.py::TestSandbox::test_sandbox_file_detonation` fails because host execution was disabled in 4.0 for security.
  - *Fix*: Update test to assert static analysis results (entropy, PE/ELF markers, strings) when no container runtime exists. Add separate Docker-gated execution test.
- **Problem 2**: `tests/test_policy_identity.py::TestPoliciesBlock5::test_packet_simulation` fails because it expects default-accept while the engine enforces implicit-deny.
  - *Fix*: Update test to verify implicit-deny (`drop`) contract and add test coverage for configurable default fallback actions.

### P0.5: Self-Signed TLS Generation & Stock Windows Support
- **Problem**: `generate_self_signed` in `sentinelfw/integrations.py` relies exclusively on the `openssl` CLI, which is absent on stock Windows.
- **Implementation**:
  1. Update `sentinelfw/integrations.py` to invoke the bundled `sfw-certgen` Go helper executable first.
  2. Fallback to `openssl` CLI if `sfw-certgen` is unavailable.
  3. Automatically generate a console certificate and key on first launch when `webui.tls.enabled` is `True`.

### P0.6: Cross-Platform Encrypted Secrets Vault
- **Problem**: API keys (VirusTotal, Sarvam AI, Telegram, SIEM, Fleet tokens) are stored in plaintext in `config.json`.
- **Implementation**:
  1. Create `sentinelfw/vault.py` with standard `Vault` interface.
  2. Windows backend: DPAPI via `ctypes.windll.crypt32.CryptProtectData` and `CryptUnprotectData`.
  3. Linux backend: AES-256-GCM sealed with a master key stored in a root-only (0600) keyfile at `/etc/sentinelfw/vault.key` or `~/.sentinelfw/vault.key`.
  4. Automatic migration: on engine startup, scan config for plaintext secret keys, encrypt them into `vault_store`, erase plaintext fields, while honoring environment variable overrides.
  5. Add test `tests/test_vault.py` validating encryption, decryption, migration, and env overrides.

---

## 3. Phase P1: Wire Unwired 4.0 Modules into Live Daemon Runtime

### P1.1 Runtime Wiring Inventory & Daemon Integration
A static scan revealed 18 modules present in `sentinelfw/` but not instantiated by `Engine.__init__`. Each module will be wired into the live runtime:

| Module | Purpose | Live Start Path | Integration Test |
|---|---|---|---|
| `sentinelfw/waf` | Reverse proxy & L7 WAF engine | `Engine.start_waf()` | `test_runtime_wiring.py::test_waf_runtime` |
| `sentinelfw/identity.py` | LDAP, RADIUS, JWT & Identity sets | `Engine.identity` | `test_runtime_wiring.py::test_identity_runtime` |
| `sentinelfw/nat.py` | Stateful NAT rules & kernel table compiler | `Engine.nat_mgr` | `test_runtime_wiring.py::test_nat_runtime` |
| `sentinelfw/objects.py` | Network Address, Service & Schedule Objects | `Engine.objects` | `test_runtime_wiring.py::test_objects_runtime` |
| `sentinelfw/zones.py` | Zone boundary management & pair chains | `Engine.zones` | `test_runtime_wiring.py::test_zones_runtime` |
| `sentinelfw/appid.py` | Application-ID classification & signatures | `Engine.appid` | `test_runtime_wiring.py::test_appid_runtime` |
| `sentinelfw/dlp.py` | Data Loss Prevention pattern & file inspection | `Engine.dlp` | `test_runtime_wiring.py::test_dlp_runtime` |
| `sentinelfw/playbook.py` | Security incident response automation | `Engine.playbooks` | `test_runtime_wiring.py::test_playbook_runtime` |
| `sentinelfw/compliance.py` | CIS Benchmarks & Security Rating auditing | `Engine.compliance` | `test_runtime_wiring.py::test_compliance_runtime` |
| `sentinelfw/correlation.py` | Real-time multi-stage incident correlation | `Engine.correlation` | `test_runtime_wiring.py::test_correlation_runtime` |
| `sentinelfw/assetmap.py` | Network asset discovery & MAC/OS fingerprinting | `Engine.assetmap` | `test_runtime_wiring.py::test_assetmap_runtime` |
| `sentinelfw/feeds.py` | Automated threat intelligence feed ingestion | `Engine.feed_mgr` | `test_runtime_wiring.py::test_feeds_runtime` |
| `sentinelfw/decoy_advanced.py` | High-interaction multi-service decoy profiles | `Engine.advanced_decoys` | `test_runtime_wiring.py::test_decoy_advanced_runtime` |
| `sentinelfw/tarpit.py` | Low-rate TCP tarpit for offensive scanners | `Engine.tarpit` | `test_runtime_wiring.py::test_tarpit_runtime` |
| `sentinelfw/watchdog.py` | Process health, binary hash & memory watchdog | `Engine.watchdog` | `test_runtime_wiring.py::test_watchdog_runtime` |
| `sentinelfw/fleet.py` | Unified Fleet Manager with mTLS agent sync | `Engine.fleet_mgr` | `test_runtime_wiring.py::test_fleet_runtime` |
| `sentinelfw/gateway_sync.py` | Active-Passive state & session synchronization | `Engine.gateway_sync` | `test_runtime_wiring.py::test_gateway_sync_runtime` |
| `sentinelfw/killchain.py` | MITRE ATT&CK killchain reconstruction | `Engine.killchain` | `test_runtime_wiring.py::test_killchain_runtime` |
| `sentinelfw/protocols/*` | L7 protocol decoders (DNS, HTTP, TLS, SSH) | `Engine.protocols` | `test_runtime_wiring.py::test_protocols_runtime` |

### P1.2 Specific Subsystem Wiring Fixes
1. **WAF**:
   - Start an async reverse proxy listener (`sentinelfw/waf/proxy.py`) bound to configured ports.
   - Front upstream HTTP services with virtual hosts, Core Rule Set (CRS) evaluation, bot challenge headers, API protection, credential shield, and file upload sandbox detonation.
   - Expose live WAF statistics, rule hit counters, and inspection mode (Block/Monitor) in `/api/v1/waf/stats` and `sfwctl waf status`.
2. **Policy Objects, Zones, NAT & App-ID**:
   - Bind `ObjectCatalog`, `ZoneManager`, `NatManager`, and `AppIdEngine` into `FirewallPolicies`.
   - Update `simulate_packet` to resolve named objects (`@DMZ_SERVERS`, `@FINANCE_NET`), zone memberships, NAT translations, and App-ID tags.
   - Add rule hit counters and shadowed/unused rule analysis in the WebUI and API.
3. **Playbooks & Correlation**:
   - Attach `PlaybookEngine` and `CorrelationEngine` directly to the `events` bus subscriber queue.
   - Implement dry-run mode, execution rate limits, loop detection (maximum recursion depth 3), and audit trails.
4. **Go Daemon & Supervisor**:
   - In `sentinelfw/integrations.py`: remove `-version` flag from `GoServiceSupervisor.start()`.
   - In `cmd/sentinelgated/main.go`: fix `sdwan.NewSDWANManager` call by adding required types in `pkg/sdwan/monitor.go`.
   - Implement real HTTP/gRPC management listener in `sentinelgated` on `-listen` and `-socket`.
   - Create `go.sum` with verified checksums. Remove `|| true` from Makefile and CI workflows.
5. **TLS Inspection + DLP End-to-End**:
   - Internal CA generation with dynamic per-host leaf minting.
   - Privacy bypass lists (banking, healthcare) and certificate pinning detection with auto-bypass.
   - Intercepted payload streaming into `DLPManager` with real-time audit logging of inspected domains.

---

## 4. Phase P2: Missing Capabilities & Deep FortiGate Parity

### P2.1 Inspection Plane
- **TCP Stream Reassembly**: Implement sliding window reassembly in `sentinelfw/protocols/tcp_reassembly.py` with per-flow memory budget (default 64KB/flow, max 10,000 active flows) to eliminate evasion via TCP fragmentation.
- **HTTP Normalization**: Implement multi-pass percent-decoding loops, unicode normalization, chunked transfer de-chunking, and gzip decompression.
- **QUIC / HTTP/3 Visibility**: Extract UDP/443 QUIC Initial Connection IDs, SNI, and JA4/QUIC fingerprints. Provide policy action to allow, log, or block to force TCP/TLS fallback.
- **Versioned Signed IPS Packs**: Support versioned IPS rule archives with digital signatures (HMAC-SHA256/Ed25519), CVE mappings, and virtual patch rules.

### P2.2 Detection Plane
- **DDoS Amplification Taxonomy**: Add specialized amplification signatures (DNS ANY, NTP monlist, SSDP M-SEARCH, memcached, CLDAP) with tier-based thresholds.
- **L2/L3 Spoofing Detection**: ARP spoofing detection (gratuitous ARP discrepancies), rogue DHCP/DNS offer detection, and LLMNR/NBT-NS poisoning warnings.
- **Anomaly Detection**: Stdlib-based streaming Half-Space Tree / Online Isolation Forest algorithm in `sentinelfw/anomaly.py` that stays in alert-only mode until a labeled precision gate is met.
- **LLM-API Protection**: Add WAF rules against prompt injection, model extraction/scraping, and API key stuffing.

### P2.3 Identity & Zero Trust Network Access (ZTNA)
- **Identity Provider Hardening**:
  - Enforce strict TLS certificate verification with trusted CA in `sentinelfw/identity.py` (remove `ssl.CERT_NONE`).
  - Reject unverified JWT tokens when signature verification secret is omitted.
- **ZTNA Application Gateway**:
  - Authenticated reverse-proxy access requiring device posture check (OS version, firewall status, disk encryption).
  - Just-in-Time (JIT) temporary access rules that auto-expire after a specified TTL.
- **WireGuard Peer Management**:
  - Expose interactive peer creation, QR codes, and per-peer policy binding (no hardcoded interface names).

### P2.4 Deception & Honeypot Hardening
- **Process & Socket Isolation**:
  - Isolate decoy socket handlers using Job Objects (Windows) and `rlimit` / unprivileged execution (Linux).
  - Ensure egress from decoy sockets is blocked and logged.
- **Kernel Redirect Cleanup**:
  - Fix `sentinelfw/scanner_redirect.py` to use named nftables sets with timeouts (`flags timeout`) on Linux and netsh cleanup on Windows to prevent rule leaks.
- **Attacker Clustering**: Cross-correlate attacker IPs by JA3/JA4 fingerprints, SSH client banners, and authentication usernames.

### P2.5 Visibility, Telemetry & SOC
- **Flow Time-Series**: SQLite-backed rollups (1m, 5m, 1h) for network flow metrics.
- **Incident Bundle Export**: Single-click export bundling PCAP slice, event logs, verdicts, and timeline into a `.tar.gz`/`.zip`.
- **OTLP Exporter**: OpenTelemetry Protocol (OTLP/gRPC or OTLP/HTTP) export for metrics and traces.
- **CIS Security Rating & Mermaid Kill-Chain**: Interactive CIS control rating and Mermaid-formatted attack kill-chain visualizer.

---

## 5. Phase P3: Quality, Packaging, Documentation & Testing

### P3.1 Testing & CI Hardening
- **Single Test Runner**: `pytest` covering 100% of unit, integration, and security tests.
- **PCAP Regression Corpus**: Labelled benign and attack PCAP replay testing with zero false-positive tolerance.
- **CI Strict Mode**: Remove `|| true` from all test steps in GitHub Actions and Makefile.

### P3.2 Documentation & Versioning
- **ROADMAP.md**: Complete rewrite categorizing all capabilities as SHIPPED, PARTIAL, or PLANNED with explicit test file references.
- **README.md**: Complete 4.0.0 section detailing unified architecture, API endpoints, ZTNA, WAF, and administration without default credentials.
- **Version Bump**: Align version string `4.0.0` across `sentinelfw/__init__.py`, `sentinelfw/config.py`, `cmd/sentinelgated/main.go`, and documentation.

### P3.3 Packaging & Installation
- **Cross-Platform Scripts**: Idempotent installation and uninstallation scripts for both Ubuntu (`install.sh`, `uninstall.sh`) and Windows (`install.ps1`, `uninstall.ps1`).
- **Offline Bundle**: Packaging script that creates a self-contained offline deployment bundle.

---

## 6. Execution Order & Milestone Roadmap

```
Step 1: P0 Security Bugs
  ├── P0.1 & P0.2: Credentials & Explicit must_change Gate (engine.py, webui.py, config.py)
  ├── P0.3: Repository Hygiene (_test_data purge, package & hygiene scripts)
  ├── P0.4: Fix 2 Failing Tests (test_phase4_5.py, test_policy_identity.py)
  ├── P0.5: sfw-certgen First for TLS (integrations.py)
  └── P0.6: Encrypted Secrets Vault (vault.py, config migration)
  └── Validation: Run pytest to confirm P0 regression tests pass 100%

Step 2: P1 Wire Unwired Modules
  ├── P1.1: Engine Wiring of all 18 Modules (engine.py, config.py, cli.py, webui.py)
  ├── P1.2: Go Daemon & Supervisor Fixes (sentinelgated, sdwan, gosvc, go.sum)
  ├── P1.3: Reverse Proxy WAF, Policy Simulation & DLP Pipeline
  └── Validation: Add & run tests/test_runtime_wiring.py

Step 3: P2 Missing Capabilities
  ├── P2.1: TCP Reassembly & HTTP Normalization (protocols/)
  ├── P2.2: Hardened Identity (Strict LDAP TLS, Verified JWT) & ZTNA Gateway
  ├── P2.3: Anomaly Detection, DDoS Amplification & LLM Abuse Rules
  ├── P2.4: Deception Isolation & Scanner Redirect Cleanup
  └── P2.5: Telemetry, Flow Rollups & Mermaid Killchain
  └── Validation: Run pytest across all extended capabilities

Step 4: P3 Quality, Packaging & Documentation
  ├── P3.1: Clean Packaging & CI Verification Scripts
  ├── P3.2: Update docs/ROADMAP.md & README.md (Version 4.0.0)
  ├── P3.3: Idempotent Installers (install.sh, install.ps1)
  └── Validation: Full pytest suite run & Final Verified Status Table
```
