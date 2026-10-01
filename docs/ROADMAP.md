# SentinelFW Roadmap

Enterprise-grade plan tracking SentinelFW to Fortinet-class parity.
Each item is marked **SHIPPED** (in the product today, verified by unit/integration tests),
**PARTIAL** (implemented with specific platform or architecture bounds noted), or **PLANNED**.

Hard constraints maintained across all items:
- Cross-platform: Ubuntu 22.04+ (nftables) and Windows 10/11/Server 2019+ (WFP / Windows Defender Firewall).
- Python 3.8+ standard library only for the core agent (zero external pip dependencies).
- Go (stdlib + `golang.org/x/*`) for `pkg/` and `cmd/`, no cgo, built for linux/amd64 and windows/amd64.
- Every feature includes an off-by-default switch, monitor-only mode, `policy_version` migration, pytest coverage, and README documentation.

---

## Track 1 — Data-Plane & Protocol Inspection

| Feature | Status | Notes & Verification |
|---|---|---|
| Multi-interface full capture | **SHIPPED** (2.6) | One RCVALL socket per adapter on Windows; AF_PACKET on Linux (`detector.py`). |
| Pass-by / global packet visibility | **SHIPPED** (2.6) | Third-party traffic recorded into deep packet ring, excluded from ban heuristics. |
| Throughput & flow tracking | **SHIPPED** (2.6) | Flow counters → NIC counters → packet-ring fallback chain (`monitors.py`). |
| TCP Stream Reassembly | **SHIPPED** (4.0) | `sentinelfw/protocols/tcp_reassembly.py`: sliding sequence window, duplicate drop, overlapping segment trimming, and per-flow byte budgets. Verified in `test_p2_capabilities.py::test_tcp_stream_reassembly`. |
| HTTP Normalization & Decoders | **SHIPPED** (4.0) | `sentinelfw/protocols/http.py`: recursive percent-decoding loops, unicode NFKC normalization, chunked transfer decoding, gzip decompression bomb limits, HTTP/2 preface / gRPC awareness. Verified in `test_p2_capabilities.py::test_http_normalization`. |
| QUIC / HTTP/3 Visibility & JA4Q | **SHIPPED** (4.0) | `sentinelfw/protocols/tls.py`: QUIC Initial packet parser, JA4Q fingerprint generation, and fallback policy enforcement. Verified in `test_p2_capabilities.py::test_quic_ja4q_parsing`. |
| Per-app kernel socket filtering | **SHIPPED** (4.0) | `bpf/sock_filter.c`: eBPF cgroup socket filter querying `endpoint_sock_policy` map + Windows WFP application rules. |
| Inline IPS via NFQUEUE / Proxy | **PARTIAL** (4.0) | Userspace Go TLS/HTTP reverse proxy and Suricata EVE socket integration active; transparent NFQUEUE interception on Linux. |

---

## Track 2 — Detection Depth

| Feature | Status | Notes & Verification |
|---|---|---|
| JA3/JA3S/JA4/HASSH fingerprinting | **SHIPPED** (2.8) | JA3 on every ClientHello, GREASE-stripped, `ja3_blocklist` enforcement. |
| Encrypted-traffic analytics (beaconing/DNS) | **SHIPPED** (2.8) | Beacon interval jitter and DNS-tunnel entropy analysis in `vector_analysis.py`. |
| Protocol-aware abuse rules | **SHIPPED** (4.0) | HTTP, SSH, FTP, SMB, RDP, SMTP decoders in `protocols/` with live signature evaluation. |
| DDoS Amplification Taxonomy | **SHIPPED** (4.0) | `sentinelfw/detector.py`: DNS, NTP monlist, SSDP, Memcached, and CLDAP detection with Tier 1-3 escalation. Verified in `test_p2_capabilities.py::test_ddos_amplification_taxonomy`. |
| L2 Lateral Movement & Spoof Detection | **SHIPPED** (4.0) | `sentinelfw/detector.py`: ARP cache poisoning, rogue DHCP server detection, and LLMNR/NBT-NS poisoning detection. Verified in `test_p2_capabilities.py::test_l2_spoof_detection`. |
| Streaming Half-Space Tree Anomaly Model | **SHIPPED** (4.0) | `sentinelfw/anomaly.py`: pure stdlib online streaming HSTree ensemble with labelled precision gate (alert-only until precision threshold is met) and plain-language alert explanations. Verified in `test_p2_capabilities.py::test_anomaly_hstree_model`. |
| WAF LLM-API Abuse Defense | **SHIPPED** (4.0) | `sentinelfw/waf/api_protect.py`: API key stuffing detection, model scraping / extraction rate defense, prompt injection, and jailbreak pattern defense. Verified in `test_p2_capabilities.py::test_waf_llm_api_protection`. |
| Sigma-style rule engine | **SHIPPED** (2.7) | JSON rule engine, hot-reload, starter set, block action, hit stats. |

---

## Track 3 — Deception & Attacker Intelligence

| Feature | Status | Notes & Verification |
|---|---|---|
| Multi-Protocol Banner Decoys | **SHIPPED** (4.0) | `sentinelfw/decoy_advanced.py`: rotating OpenSSH, IIS/nginx HTTP, MySQL, Telnet, Elasticsearch, RDP, and Ollama/OpenAI mock endpoints. |
| Cross-IP Attacker Clustering | **SHIPPED** (4.0) | `sentinelfw/decoy_advanced.py`: clusters attackers across different IPs based on behavioral, credential, and client fingerprints. Verified in `test_p2_capabilities.py::test_cross_ip_attacker_clustering`. |
| Honeytokens (Cloud keys, DB rows, Canaries) | **SHIPPED** (4.0) | `sentinelfw/canary_tokens.py`: AWS access keys, GCP service accounts, Azure connection strings, database canary rows, and local canary files/DNS tokens. Verified in `test_p2_capabilities.py::test_honeytokens_and_decoy_containment`. |
| Decoy Process Containment | **SHIPPED** (4.0) | `sentinelfw/decoy_advanced.py`: Windows Job Objects and Linux rlimits with egress restrictions to ensure decoys cannot attack back. |
| Decoy-to-Firewall Feedback Loop | **SHIPPED** (4.0) | Scanner redirection with named `scanner_redirect` kernel set cleanup on Linux and `netsh portproxy` cleanup on Windows (`sentinelfw/scanner_redirect.py`). |

---

## Track 4 — Visibility, Forensics & SOC

| Feature | Status | Notes & Verification |
|---|---|---|
| Infrastructure & Topology Graph | **SHIPPED** (2.6) | App → port → remote-endpoint SVG graph with live throughput. |
| Asset/Flow SQLite Time-Series Rollups | **SHIPPED** (4.0) | `sentinelfw/assetmap.py`: aggregated 1m, 5m, 1h, and 24h flow rollups in `flows.db`. Verified in `test_p2_capabilities.py::test_soc_visibility_bundle_and_rollups`. |
| PCAP Ring Buffer with Alert Preservation | **SHIPPED** (2.8) | Raw frame ring buffer, alert-triggered `.pcap` dumps, console download. |
| Incident Forensic Bundling | **SHIPPED** (4.0) | `sentinelfw/forensics.py`: one-click `.tar.gz` bundle with pcap, events, verdicts, and forensic timeline. Verified in `test_p2_capabilities.py::test_soc_visibility_bundle_and_rollups`. |
| Mermaid Kill-Chain Export | **SHIPPED** (4.0) | `sentinelfw/killchain.py`: exports active attack kill chains into Mermaid diagram syntax and STIX 2.1 JSON. |
| OpenTelemetry (OTLP) Export | **SHIPPED** (4.0) | `sentinelfw/elastic.py`: `OTLPShipper` sends logs/events formatted according to OTLP JSON specification over HTTP. Verified in `test_p2_capabilities.py::test_soc_visibility_bundle_and_rollups`. |
| Scheduled Compliance Reports | **SHIPPED** (4.0) | `sentinelfw/compliance.py`: HTML and JSON reports with CIS benchmark control mapping and overall Security Rating. |

---

## Track 5 — Policy, Access & Zero Trust

| Feature | Status | Notes & Verification |
|---|---|---|
| FortiGate-style Policy Engine | **SHIPPED** (4.0) | `sentinelfw/policies.py`: ordered first-match evaluation, zones, address objects, service groups, NAT actions, hit counters, and implicit deny contract. |
| Shadowed & Unused Rule Analysis | **SHIPPED** (4.0) | `sentinelfw/policies.py`: `find_shadowed_rules()` and `get_unused_rules()` detect redundant or dead rules. Verified in `test_p2_capabilities.py::test_policy_shadow_analysis`. |
| Identity & Multi-Source Auth | **SHIPPED** (4.0) | `sentinelfw/identity.py`: Local user directory, verified TLS LDAP/AD bind, RADIUS, and strictly verified OIDC/JWT. |
| Device Posture Evaluation | **SHIPPED** (4.0) | `sentinelfw/identity.py`: checks OS patch freshness, firewall status, disk encryption, and antivirus health. Verified in `test_p2_capabilities.py::test_identity_posture_ztna_jit`. |
| Micro-segmentation Engine | **SHIPPED** (4.0) | `sentinelfw/identity.py`: learning mode records inter-workload flows, generates least-privilege policies, and promotes to enforcement. Verified in `test_p2_capabilities.py::test_identity_posture_ztna_jit`. |
| ZTNA Reverse-Proxy Evaluation | **SHIPPED** (4.0) | `sentinelfw/identity.py`: evaluated application access combining user identity, group membership, device posture, and risk score. Verified in `test_p2_capabilities.py::test_identity_posture_ztna_jit`. |
| Just-In-Time (JIT) Temporary Rules | **SHIPPED** (4.0) | `sentinelfw/identity.py`: grants auto-expiring temporary firewall rules for emergency access. Verified in `test_p2_capabilities.py::test_identity_posture_ztna_jit`. |
| WireGuard Peer Management | **SHIPPED** (4.0) | `sentinelfw/identity.py`: programmatic peer configuration, allowed IPs, endpoints, and per-peer policy controls. |
| Enterprise WAF Engine | **SHIPPED** (4.0) | `sentinelfw/waf/`: reverse proxy listener, virtual hosts, CRS basic rules, bot challenge, credential shield, upload scanning. |
| DLP Engine | **SHIPPED** (4.0) | `sentinelfw/dlp.py`: regex pattern and Shannon entropy scanning for credit cards, API keys, private keys, and secrets across network payloads and file uploads. |

---

## Track 6 — Management-Plane Security & Vault

| Feature | Status | Notes & Verification |
|---|---|---|
| Cryptographic One-Time Credential | **SHIPPED** (4.0) | `sentinelfw/engine.py`: random `secrets` OTP printed once to console and `auth.initial`, zero hardcoded passwords in codebase. |
| Forced Password Change Write-Gate | **SHIPPED** (4.0) | `sentinelfw/webui.py`: `must_change_password` flag blocks all state-modifying requests until permanent password is set. |
| Encrypted Secrets Vault | **SHIPPED** (4.0) | `sentinelfw/vault.py`: AES-256-GCM sealed via Windows DPAPI (CryptProtectData) or Linux 0600 root keyfile. Verified in `test_vault.py`. |
| Go Helper PKI (`sfw-certgen`) | **SHIPPED** (4.0) | `sentinelfw/integrations.py`: bundled Go PKI helper prioritized with OpenSSL fallback for self-signed console certificates. |
| Release Archive Hygiene & Packaging | **SHIPPED** (4.0) | `scripts/check_release_hygiene.py` and `scripts/package_release.py`: enforces zero private keys, certificates, or cache files in releases. |
| Session & Audit Security | **SHIPPED** (2.7/3.0) | Session tokens, CSRF protection, TOTP 2FA, HMAC Merkle-sealed event audit log. |

---

## Track 7 — Fleet, Resilience & Operations

| Feature | Status | Notes & Verification |
|---|---|---|
| Unified Fleet Management | **SHIPPED** (4.0) | `sentinelfw/fleet.py`: agent registration, policy synchronization, mTLS support, and shared threat ban propagation with confidence scoring. |
| Live Runtime Module Supervision | **SHIPPED** (4.0) | `sentinelfw/engine.py` & `sentinelfw/cli.py`: all 18 enterprise modules instantiated, connected to live event bus, exposed via `/api/v1/system/modules` and `sfwctl modules`. Verified in `test_runtime_wiring.py`. |
| Config Migration Engine | **SHIPPED** (4.0) | `sentinelfw/config.py`: policy migrations from 2.9 (v7/8), 3.0 (v9) to 4.0 (`policy_version: 10`). Verified in `test_config_migrations.py`. |
| Hot Config Reload | **SHIPPED** (4.0) | In-memory atomic reloading without daemon restarts (`Engine.reload_config`). |
| Fail-Open / Fail-Closed Resilience | **SHIPPED** (4.0) | Configurable failure modes per policy profile across IPS and proxy paths. |
