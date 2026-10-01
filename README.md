# SentinelFW 4.0.0

Enterprise Next-Generation Host Firewall & Autonomous Threat Defense Platform for **Ubuntu 22.04+ (nftables)** and **Windows 10/11/Server 2019+ (Windows Defender Firewall / WFP)**.

Python 3.8+ standard library only for the core agent: zero third-party pip dependencies, runs natively as root / Administrator. Go (stdlib + `golang.org/x/*`) for high-performance proxying, PKI, and helper daemons.

---

## What's New in SentinelFW 4.0.0

### Security Fixes (P0)
1. **Master Credential Elimination**: Removed all hardcoded credentials and static password hashes. On first launch, SentinelFW generates a cryptographic one-time password (OTP) via `secrets`, prints it once to stdout and to root/admin-only `auth.initial`, stores a salted scrypt hash, and locks write APIs with `must_change_password` until the operator sets a permanent credential.
2. **Encrypted Secrets Vault**: Integrated AES-256-GCM vault (`sentinelfw/vault.py`) sealed via Windows DPAPI (`CryptProtectData`) or Linux 0600 root-only keyfile. Automatically protects VirusTotal, Sarvam AI, Telegram, Fleet, and SIEM credentials with environment-variable overrides.
3. **PKI & TLS Bootstrap**: Bundled `sfw-certgen` Go helper prioritized over OpenSSL for cross-platform zero-dependency TLS console certificate generation on stock Windows and Ubuntu.
4. **Release Archive Hygiene**: Enforced automated CI check (`scripts/check_release_hygiene.py`) and release packager (`scripts/package_release.py`) that strictly prohibits private keys, certificates, or cache directories from entering release artifacts.
5. **Implicit Deny Policy Contract**: Standardized firewall policy simulation to the implicit-deny contract with configurable default actions.

### Live Runtime Architecture & Wired Modules (P1)
All 18 enterprise modules are instantiated, supervised, and connected to the live event bus in the running daemon:
- **WAF Engine** (`sentinelfw/waf/`): Reverse proxy listener, virtual hosts, CRS basic rules, bot challenge, API protection, credential shield, upload scanning.
- **Identity & Posture** (`sentinelfw/identity.py`): Local directory, verified TLS LDAP/AD, RADIUS, strictly verified OIDC/JWT, and device posture assessment.
- **Micro-segmentation & ZTNA**: Inter-workload flow learning, least-privilege policy generation, promotion to enforcement, and ZTNA reverse-proxy access evaluation.
- **DLP Engine** (`sentinelfw/dlp.py`): Real-time regex pattern and Shannon entropy analysis for credit cards, private keys, and secrets.
- **Decoys & Tarpits** (`sentinelfw/decoy_advanced.py`): Multi-protocol decoys (SSH, HTTP, MySQL, Telnet, Elasticsearch, RDP, Ollama/OpenAI) with Windows Job Object and Linux rlimit isolation.
- **Fleet Manager** (`sentinelfw/fleet.py`): Unified relay and manager with mTLS support, agent enrollment, group policy distribution, and ban federation.
- **Watchdog, Correlation & Playbooks**: Continuous file/process integrity monitoring, multi-stage event correlation, and automated playbook execution with rate limits and loop protection.
- Check live module status anytime: `python sfwctl.py modules` or `GET /api/v1/system/modules`.

### Deep Inspection, Detection & SOC Capabilities (P2)
- **TCP Stream Reassembly**: Sliding sequence window, packet deduplication, overlapping segment trimming, and per-flow memory budgets (`protocols/tcp_reassembly.py`).
- **HTTP Normalization**: Recursive percent-decoding loops, unicode NFKC normalization, chunked transfer decoding, gzip decompression bomb protection, HTTP/2 preface / gRPC awareness (`protocols/http.py`).
- **QUIC & JA4Q Visibility**: QUIC Initial parser, JA4Q fingerprinting, and fallback policy enforcement (`protocols/tls.py`).
- **DDoS Amplification Taxonomy**: DNS, NTP monlist, SSDP, Memcached, and CLDAP amplification vector detection with Tier 1-3 escalation (`detector.py`).
- **L2 Spoofing & Poisoning Detection**: ARP cache poisoning, rogue DHCP servers, and LLMNR/NBT-NS poisoning detection (`detector.py`).
- **Streaming Anomaly Model**: Pure stdlib online Half-Space Tree (HSTree) ensemble with labelled precision gating and plain-language alert explanations (`anomaly.py`).
- **WAF LLM-API Abuse Defense**: API key stuffing, model scraping / extraction rate limiter, prompt injection, and jailbreak defense (`waf/api_protect.py`).
- **Cross-IP Attacker Clustering**: Multi-vector behavioral and credential fingerprinting clustering malicious actors across distinct IP addresses (`decoy_advanced.py`).
- **Honeytokens**: AWS, GCP Service Account, Azure Connection String, and DB-row canary tokens (`canary_tokens.py`).
- **SOC Forensics & Export**: SQLite flow time-series rollups (`flows.db`), one-click incident `.tar.gz` bundle generation, Mermaid kill-chain export, and OpenTelemetry (OTLP) log export.

---

## Install
Ubuntu:  `sudo ./install.sh`      Windows (elevated PowerShell, Python installed for all users): `.\install.ps1`
No install: `sudo python3 sfwctl.py run`

## Architecture
```
                        +-------------------- sentinelfw/ --------------------+
 kernel exec events --> | monitors.ExecWatcher --+                            |
 (netlink proc conn.,   |                        v                            |
  Win snapshots)        |                  monitors.Responder  <-- ProcessMonitor <-- procinfo (socket->pid->exe)
 raw packets ---------> | detector.Sniffer -> Detector (scan/flood/brute/signature/DNS/amplification/L2)
 (AF_PACKET/RCVALL)     |                        |                            |
                        |                        v                            |
 feeds + drop-in lists->| lists.Lists ------> engine.Engine --> backends.NftBackend / WinBackend  --> OS firewall
                        |                        |                            |
                        |   config.Store (config.json, state.json bans)       |
                        |   Event Bus Dispatcher -> Correlation & Playbooks   |
                        |   WAF, DLP, Identity, ZTNA, Anomaly, Decoys, Fleet  |
                        +-----------------------------------------------------+
```
| Module | Role |
|---|---|
| `backends.py` | Real enforcement: nft table `inet sentinelfw` (drop sets, priority -10) / `netsh advfirewall` rules `SentinelFW-*` |
| `detector.py` | Packet capture + IDS/IPS logic |
| `monitors.py` | Exec-time hook, socket monitor, response engine (kill / quarantine / delete), housekeeping |
| `procinfo.py` | Socket-to-process-to-executable mapping, kill, hash, quarantine/delete |
| `lists.py` | IP/domain/hash/program lists, feed updater |
| `engine.py` | Ban logic with escalation, safety guard, hosts-file sinkhole |
| `config.py`, `common.py`, `packets.py`, `cli.py` | Config/state, helpers/logging, parsers, commands |

## What it enforces automatically (profile `aggressive`, the default)
| Trigger | Response |
|---|---|
| Program launched matching `program_*.txt` path/glob, or SHA-256 in `hash_*.txt` | Killed at exec, file quarantined (or deleted) |
| Executable in temp dir (`/tmp`, `/dev/shm`, `%TEMP%`...) using the network | Killed, file quarantined |
| Running binary deleted from disk / memfd (fileless) | Killed |
| Process connected to a blocklisted IP | Killed (traffic is already dropped by the firewall) |
| Scan / flood / brute force / bad flags / attack payload from a public IP | IP banned in the kernel firewall, doubling on repeats up to 30 days |
| Query or answer for a blocked domain | Hosts sinkhole; answer IPs banned for 1h |

Quarantined files are removed from their path immediately and hard-deleted after `quarantine_retention_days` (7). For instant permanent deletion set `"malicious_file_action": "delete"`.

## Commands (`python3 sfwctl.py ...`)
`run` `status` `block-ip IP|CIDR [--duration 6h] [--force]` `unblock-ip` `block-domain` `unblock-domain` `block-program PATH|GLOB` `unblock-program` `block-hash SHA256` `list bans|quarantine|domains|programs` `update-lists` `quarantine-restore ID` `quarantine-purge ID` `harden --allow-ports 22,443` `unharden` `mode aggressive|monitor` `install-service` `uninstall-service` `cleanup`

Extend lists any time by dropping files into the data dir `lists/` (`/var/lib/sentinelfw` or `C:\ProgramData\SentinelFW`):
`ip_*.txt`, `domain_*.txt`, `hash_*.txt`, `program_*.txt`. They are hot-reloaded. Feeds are set in `config.json` (`feeds`).

## Hard safety rails (deliberately not configurable off)
* Private, loopback, link-local, CGNAT, this host's own IPs, default gateway and DNS servers are never auto-banned (spoofed traffic cannot make it cut you off).
* Feeds can never inject private/reserved or huge (< /8) ranges.
* Heuristic triggers never kill or touch OS-owned paths (`/usr`, `/bin`, `/etc`, `/snap`, `C:\Windows`). Only your explicit path/hash rules may kill there; even then files there are never deleted.
* SentinelFW never deletes its own package or the Python interpreter.
* `mode monitor` switches every action to log-only if you need to investigate a false positive.

## Honest limits
* It is a host firewall, not a Fortinet appliance: no TLS inspection, VPN, full L7 app-ID, or line-rate DPI (the sniffer is Python).
* Linux per-app *network* blocking is enforced by kill-on-exec + kill-on-connect + file removal, not by a per-executable kernel rule (nftables has none). Windows gets real per-program firewall rules for exact paths.
* The Windows sniffer sees IPv4 on the primary interface. IPS bans follow the attack pattern, so the first packets get through.
* Windows exec-blocking polls every 0.4 s; Linux uses the kernel process connector (instant; needs root and host PID namespace, i.e. not inside a container).
* Feed URLs are public lists and may change; edit them in `config.json`.

## Tests
```bash
pytest tests/ -v
# Note: pytest is required to run all 235 tests (including pytest-style
# test_mgmt, test_ops, test_forensics, and test_integrations).
# Running `python3 -m unittest discover` only executes unittest.TestCase classes (~61 tests).
```

---

## SentinelFW 2.1 — Defense Console Upgrade

**Bug fixes**
- `GET /api/v1/appwall` crashed (`get_policies`/`get_violations` were missing) — implemented in `appwall.py`.
- `POST /api/v1/sandbox/submit` called a non-existent `Sandbox.detonate()` — now uses `analyze_file()`.
- Traffic stats endpoint returned hardcoded fake numbers — now computed from real flow counters (with packet-buffer fallback).
- Ban records read the wrong timestamp key (`created` vs `added`).
- `ScannerRedirector.redirect_scanner()` failed whenever the kernel DNAT rule could not be applied — kernel rules are now best-effort with the redirect window still tracked (all 61 unit tests pass).

**Network Monitor (new)** — Wireshark-grade deep packet inspection page:
- Every inbound/outbound packet captured by the engine sniffer (run as root/admin) is deep-parsed (Ethernet/VLAN, IPv4/IPv6, TCP, UDP, ICMP, DNS, HTTP, TLS ClientHello/SNI) into an 8000-packet ring buffer.
- Live table with Wireshark-style Info column, per-packet protocol/severity/verdict colouring, protocol chips and counters.
- Filters: protocol, severity, direction, verdict, time window (1m/5m/15m/1h) and free-text search.
- Click any packet for the full protocol tree (every header field) plus a hex + ASCII dump of the raw frame.

**Geo Threat Map (new)** — all connected IPs on a world map (MapLibre GL + free OpenFreeMap tiles, with CARTO dark raster fallback — no Leaflet, no API keys):
- Endpoint markers coloured by threat (malicious/banned, suspicious, normal) sized by traffic.
- Heatmap layer toggle weighting traffic volume and threat level.
- Country distribution bars, searchable endpoint list, click-to-fly, popup with per-IP stats and one-click ban.
- Offline GeoIP country database (290k IPv4 ranges) auto-downloaded and refreshed; private/local ranges labelled.

**Applications (new)** — full inventory of every application on the system:
- Cards with icons, process count, CPU %, memory, live connections, per-app bandwidth and remote IP count.
- Click an app for full detail: identity, SHA-256, command line, every live socket, remote endpoints with GeoIP.
- Actions per application: block network access, unblock, kill process, quarantine binary (all enforced through the engine).

**Honeypot Deception (rebuilt)** — services now spawn/stop properly from the UI:
- New emulators: MySQL, SMB, RDP, SMTP open-relay bait (plus the existing HTTP, SSH, FTP, Telnet).
- Per-service cards with status, hits, uptime, live port re-binding, SPAWN/STOP buttons, and a "spawn configured" bulk action; state persists to config.

**Dashboard (FortiGate-grade)** — system health gauges (CPU/memory/disk), host/engine info strip, real throughput + PPS KPIs, DPI protocol distribution, top talkers, service status chips (capture, honeypots, Telegram, Suricata), unique-IP and threat KPIs.

**Settings** — restructured: Telegram dispatcher with connection + alert-content columns, inline status, and a step-by-step BotFather setup guide; engine parameters; capture buffer controls.

**Dev/testing** — `SENTINELFW_SIM=1 python3 test_webui_server.py` runs the console with a deterministic synthetic packet source for offline demos.

---

## SentinelFW 2.2 — Console Round 2

- **Honeypot port fallback** — if a decoy port cannot be bound (WinError 10013: Windows reserved/excluded ranges, port in use, missing elevation), SentinelFW now automatically tries nearby ports, reports the actually-bound port (and what it fell back from), and persists it so restarts are stable.
- **Unified Network Monitor** — the deep packet inspector and the Geo threat map are one section: packets on top, live world map with malicious-IP heatmap below.
- **Country mapping fixed** — IPs seen while the GeoIP database was still downloading are no longer stuck as "XX"; the resolver cache is invalidated when the database finishes loading, unallocated ranges get an honest "Unallocated / reserved" label, IPv4-mapped IPv6 is resolved to its real IPv4 country, and the country database is bundled with the package (works offline; auto-refreshed from the network when possible).
- **VirusTotal threat intelligence** — configure a free API key in Settings. Every new remote IP is scanned once; detections are cached permanently (never rescanned), clean results re-validate after 7 days. Verdicts appear on the map, in the endpoint lists, and in per-app remote endpoints. Optional auto-ban of confirmed-malicious IPs. Background scanning respects the free-tier rate limit.
- **Applications upgraded** — real vector icons for known software categories, sort (traffic/memory/CPU/connections/name), filter chips (All / Network active / Blocked / System), and a right-click context menu on every application (view details, block/unblock network, kill, quarantine, copy path, ban remote IPs, VirusTotal scan remote IPs). Remote IPs in the detail view have their own right-click menu and inline VT buttons.
- **FortiGate-style Firewall Policies** — a new Policies page: ordered first-match policies with Create New / Edit / Delete, sequence reordering (▲▼), enable/disable toggles, source/destination CIDR lists, a 27-object service catalog (ANY, HTTPS, DNS, SSH, RDP, MySQL…), action ACCEPT/DENY, NAT and security-profile columns, search, and live kernel hit counters on Linux. Policies are enforced by nftables (Linux) or Windows Defender Firewall (Windows) directly from the console. The compiled chain defaults to ACCEPT, so you can never lock yourself out of the server.

---

## SentinelFW 3.0 — Security Hardening Release

Every finding from the 2.9 security review, fixed and live-verified:

- **Forced first-run password set.** At first initialization, SentinelFW generates a random one-time password and displays it once in the console/log, with no shipped default hash or plaintext literal. All administrative operations require setting an operator password with a 10-character minimum and salted-scrypt hashing.
- **Console TLS, built in.** `webui_tls: {enabled, cert_file, key_file}` wraps the listener with stdlib TLS; `sfwctl tls-gencert` generates a self-signed pair for lab use. Verified live with HTTPS requests end-to-end. For production, front with your PKI cert or a TLS proxy as before.
- **API keys out of config.json.** `SFW_VT_KEY`, `SFW_TELEGRAM_TOKEN`, `SFW_SARVAM_KEY`, `SFW_FLEET_KEY` override the matching config values in memory — and the persist path is env-safe, so injected secrets are never written back to disk. Verified live (fleet enrollment with an env-only key).
- **gateway_sync.py de-stubbed.** Real HTTPS check-in with optional mTLS client certs; no fake `edr_active`, no mock policy cache, honest posture from injected providers. Unit-tested against a live mock gateway.
- **Log Vault off-box anchoring.** Every sealed block now ships a `vault_anchor` event (block index + head hash + Merkle root) through the syslog channel, so re-sealing or truncation is detectable against any off-box collector. Verified live.
- **Suricata / ClamAV managed integrations.** Integrations require explicit opt-in (`integrations.auto_install: false` by default) to prevent unexpected package installations on production systems. Retry button + live status in Settings → Integrations.
- **Go services supervisor.** `go_services.enabled` builds sentinelgated via the local Go toolchain, runs it supervised with crash events and restart-with-backoff, and reports an honest state machine (`go_not_installed` / `build_failed` / `running` / `crashed`). Straight talk: sentinelgated's `main.go` is still a skeleton — the supervisor makes it manageable, it does not conjure TLS inspection out of libraries that no code path calls yet.
- **Version alignment** — `VERSION = 3.0.1` everywhere.

Full verification: 109 unit tests, 16 new live checks (TLS handshake, forced-password gating, env-key fleet enrollment, anchor events), 14 regression checks, 6 DOM checks.

---

## SentinelFW 2.9 — DNS Security, Fleet & the Log Vault

### Filtering DNS forwarder (new Settings → DNS Security section)

`dns_server.enabled` starts a local filtering resolver (UDP): every query is checked against your domain blocklists (suffix-aware), blocked domains get the sinkhole answer, everything else is forwarded to your chosen upstreams with a 60 s cache. Point the host — or a whole segment via DHCP — at it for DNS-layer blocking that works even when the hosts file isn't writable. Live-verified: blocked → `0.0.0.0`, clean → forwarded, stats tracked.

### Fleet mode v1 (new Settings → Fleet section)

Enable this console as a relay (with a regenerate-able shared key), then run `python sfwctl.py fleet-agent --relay https://central:443 --key KEY` on every other SentinelFW host. Agents enroll and heartbeat every 30 s — hostname, version, bans, threats, recent events, top offenders — and pull the relay's shared IP blocklist into their own `lists/fleet_shared.txt`. The Fleet section shows every agent (online/offline) and its top attackers. Relay endpoints are key-authed (constant-time compare), never console-session-authed, and the relay accepts only heartbeats — it cannot command agents. Verified end-to-end against a live relay including a real `FleetAgent.beat()`.

### Log Vault — blockchain-grade sealing + the FLUSH button (new Settings → Log Vault section)

Every interval (or on demand), the new events since the last block are hashed into a **Merkle tree**; its root, the previous block's hash and a running counter form a new block appended to `vault/chain.json` — a blockchain over your event log, each block signed with **HMAC-SHA256** under your seal key. The chain verifier catches edited records, forged blocks, removed blocks and wrong keys (all unit-tested with deliberate tampering). For at-rest *confidentiality*, use LUKS/BitLocker — see the new **docs/DEPLOYMENT.md**; the vault gives you integrity + authenticity, and says so honestly.

**FLUSH** (typed confirmation, audited) deletes every stored log artifact at once — `events.jsonl` (+rotations), the audit chain, the vault chain, the VirusTotal intel cache and all forensic PCAPs — then re-opens logging on a fresh file and seals a fresh genesis block, with a `log_flush_executed` tombstone proving a wipe happened.

### Fixed from your production logs

- `housekeeper_error TypeError: event() got multiple values for keyword argument 'bans'` — `event()` now defensively drops reserved kwargs.
- Repeated hosts-file `Permission denied` on Windows when running non-elevated — now a single clear message with the DNS-layer fallback spelled out, no more log spam.
- **Real bug found by the new fleet tests:** the audit-log body masker mutated the live request dict, so any API field named `*key*`/`*token*`/`*password*` was silently saved as `***` (fleet keys, Telegram tokens, VT API keys). Now it copies first.

Full verification: 98 unit tests, 25 new live checks, 14 regression checks across the 2.7/2.8 feature set, 6 DOM checks. Enterprise rollout guide in `docs/DEPLOYMENT.md` (systemd/NSSM services, TLS fronting, hardening checklist, fleet topology, runbook).

---

## SentinelFW 2.8 — Operations Safety & Forensics

### Commit-confirm with automatic rollback

Stage a config change, and if you do not press **CONFIRM** within the TTL (default 5 minutes) it reverts itself — the networking equivalent of `reload in 5` / FortiGate's commit-confirm. Available in Settings → Operations Safety (`STAGE / CONFIRM / ROLLBACK NOW`) and from the CLI: `python sfwctl.py commit-confirm` → `commit-confirmed` / `commit-rollback`. The CLI-staged sessions are picked up by the running daemon's watchdog too. Rollback restores the snapshot, rewrites `config.json`, re-syncs the firewall backend and logs the whole sequence.

### PCAP forensic ring buffer

With `pcap_ring.enabled`, raw frames are kept in a bounded in-memory ring (default 20 s / 64 MB, no disk cost at idle). On any alert-worthy event — ban, IDS signature hit, honeypot touch, Sigma match, canary/quarantine — the ring is dumped to `<data-dir>/pcaps/<timestamp>_<ip>.pcap`, a standard Wireshark-openable file (correct link-type header for both Ethernet and raw-IP capture paths). Dumps are listed and downloadable from the console, with path-traversal protection on the download endpoint.

### Persistence-mechanism watch

`persistence_watch.enabled` baselines and then polls the OS persistence locations — Linux: cron (`/etc/cron.*`, `/var/spool/cron`), systemd units, `/etc/rc.local`, init.d, autostart dirs, `~/.bashrc`, `authorized_keys`, plus UID-0 account tracking; Windows: Run/RunOnce registry keys (HKCU + HKLM), Startup folders. Any addition, modification or removal raises a `persistence_change` event — the classic ransomware/persistence-implant tell. Re-baseline from the console or `sfwctl persistence-baseline` after intentional changes.

### JA3 TLS client fingerprinting

Every sniffed TLS ClientHello now yields a **JA3 MD5 fingerprint** (RFC 8701 GREASE values stripped, correct ClientHello version) alongside SNI — visible in the packet monitor Info column and its layers. Put known-bad hashes in `ja3_blocklist` to auto-ban matching clients. Bonus fix: the pre-existing SNI decoder had a latent bug (Python's `idna` codec rejects `errors="replace"`), so SNI extraction silently failed before this release.

All features are off by default (`policy_version` 6 migration adds them safely), each has unit + live-integration coverage (89 unit tests, 24 live checks, 12 regression checks).

---

## SentinelFW 2.7 — Management-Plane Security & SOC Layer

### Console authentication, rebuilt (Block 1 of the roadmap)

- **Salted scrypt credentials** (`hashlib.scrypt`, constant-time compare) with automatic verification of legacy SHA-256 hashes on upgrade. Generate a new hash with `python3 -c "from sentinelfw.mgmt import hash_password; print(hash_password('YOUR-PW'))"` and put it in `webui.password_hash`.
- **Session-cookie login** for browsers: a styled sign-in page, `HttpOnly` + `SameSite=Strict` cookies, and **CSRF tokens** on every state-changing request. Basic auth remains available for scripts and Prometheus scrapers.
- **Login throttling**: 8 failed attempts per IP+user inside 10 minutes → 10-minute lockout.
- **TOTP two-factor (RFC 6238)** — Settings → Console Security → ENABLE 2FA gives you the secret + otpauth URI + **8 single-use recovery codes**. Pure stdlib (hmac/hashlib).
- The console warns in red while the shipped default password is still in use.

### Tamper-evident audit log

Every management action (logins, API calls with masked bodies, 2FA changes, learning-mode switches) is appended to `audit.log` as a **hash-chained record** — each entry embeds the SHA-256 of the previous one, and the chain checks both content hashes and linkage. `sfwctl audit-verify` (exit code 1 on any tampering) and `GET /api/v1/audit/log` report integrity. A rooted host cannot silently rewrite history.

### SOC integrations

- **Prometheus**: `GET /metrics` (same auth) exports bans, blocklists, traffic rates, sessions, indexed apps, per-severity event counters and uptime.
- **Syslog forwarding**: config `syslog` → `{enabled, host, port, proto: udp|tcp, format: rfc5424|cef}` — every engine event is shipped off-box in RFC 5424 or ArcSight CEF format.
- **STIX 2.1 export**: `GET /api/v1/stix/export` bundles all active bans + VirusTotal-malicious IPs as STIX indicators for your SIEM/TIP.

### Sigma-style rule engine

JSON rules in `<data-dir>/lists/sigma/*.json` (Sigma-inspired selections: exact / glob / list values) are **hot-reloaded** and evaluated against every engine event. Matching raises a `sigma_rule_match` event with per-rule hit statistics (`GET /api/v1/sigma/rules`); rules with `action: "block"` also ban the event's source IP. A starter ruleset ships bundled and seeds on first run.

### Detection allow-list & learning mode

`detections.allowlist` (by IP or reason substring) suppresses specific enforcement, and **learning mode** (Settings toggle) records every detection while suppressing all bans — ideal for burn-in on new hosts. Both log exactly what they suppressed.

---

## SentinelFW 2.6 — Full-Packet Capture, Tarpit, ClamAV & Infrastructure Graph

### Packet capture — every packet, every interface, global included

- **Windows: the sniffer now opens one RCVALL socket per active IPv4 interface** (previously it bound a single adapter — usually a VMware/Hyper-V virtual NIC — and missed the real traffic entirely).
- **Pass-by (global) traffic is now shown.** Packets on the wire that involve neither of your own IPs (visible in promiscuous mode) are recorded in the packet monitor tagged as third-party — but never run through ban heuristics or flow accounting, so foreign LAN chatter can't get anyone banned.
- On Linux nothing changed: AF_PACKET already captures every interface, all ports, in and out.
- Optional `sniffer.bind_ips` config override for pinned captures.

### Throughput tracking fixed

Live rates now come from three layers: per-flow sniffer counters first, then **real NIC counters (psutil) — which work even when the raw sniffer can't run (no admin) — and finally packet-recorder totals.** The dashboard and connections page show real bytes/s at all times.

### Live connections — FortiGate-style

- A **session summary strip** (SESSIONS / ESTABLISHED / LISTENING / UDP / APPS / REMOTE IPs / LIVE THROUGHPUT) above the table, like a FortiGate dashboard.
- The table itself is compact: tight rows, small monospace cells, live per-connection rates.
- **New FLOW MAP: a node-by-node infrastructure graph** — application nodes → live port spine → remote endpoint nodes, drawn as SVG. Node/edge size follows live throughput, edges colored per application, remote nodes flagged red when they have detected threat vectors. The RATES chart and world-map APP MAP views remain.

### Application control

The appwall policy editor now offers **autocomplete over every indexed application** (type to search; full paths with app names).

### ClamAV antivirus backend

- System malware scanning through the local ClamAV engine (`clamscan`/`clamdscan`), Ubuntu and Windows.
- **Definitions auto-update daily** via a scheduled freshclam run (~03:30 local).
- Settings → Antivirus: status (engine, DB age/staleness, last update/scan) + **SCAN SYSTEM NOW**, **SCAN + QUARANTINE** (findings moved into the SentinelFW quarantine store) and **UPDATE DEFINITIONS**. Everything degrades gracefully (clear status + install instructions) when ClamAV is absent.

### SSH tarpit — seeker-bot trap (port 22222)

- A new honeypot service that presents a **realistic, rotating OpenSSH banner**, records the client's fingerprint, then **holds the connection open at glacial speed** (endlessh-style) to waste bot time.
- Every visitor lands in the **Seeker Bot Registry** (Honeypot tab): IP, hit count, client fingerprint, first/last seen.
- **Auto-block is on by default**: each visitor is banned for 7 days (protected management IPs are never banned). A manual **BLOCK ALL VISITOR IPS** button and an on/off toggle are on the same panel.

### Ops fixes

- The `hosts_error ... Permission denied` seen when running the engine **without elevation** on Windows is now handled gracefully: one clear INFO event explaining that hosts-file sinkholing needs Administrator (everything else keeps working) instead of a repeating error.
- Management-plane hardening note: the console's default password hash ships for first-boot usability — change it via `webui.password_hash` on any internet-exposed install.

---

## SentinelFW 2.5 — Dashboard Auth, IP Intelligence & Sarvam AI Analyst

- **The console now serves on 0.0.0.0:443 with login credentials** — browser basic-auth and session auth. On first boot, SentinelFW generates a secure random one-time password (OTP) and prints it once to console and to `auth.initial`. Operators must authenticate and set a permanent password (`must_change_password` write-gate enforced). All endpoints, static files and the API require authentication; an empty password hash disables auth. If the engine lacks permission to bind 443 (non-root Linux), it falls back to port 9443 and logs `webui_bind_fallback`. Upgraded installs are migrated automatically (`policy_version: 3`). Note: basic auth sends credentials as base64 — for exposure beyond a trusted LAN, put SentinelFW behind an HTTPS reverse proxy.
- **Network page formatting fixed** — the right-hand panels are wider (340→440px) with larger, non-clipped country names, byte totals and taller country-distribution bars; the side column scrolls instead of clipping.
- **Suricata status is no longer a red herring** — the overview chip now shows four honest states: RUNNING (green), INSTALLED/idle (amber), NOT INSTALLED (neutral, with install instructions on hover) and DISABLED. The Windows binary search covers choco/scoop installs; with Suricata installed, alerts flow from its EVE JSON into the engine as before.
- **Click any flagged IP to see exactly why** — a new IP Intelligence modal consolidates every reason: the exact ban reason and time remaining, each threat-vector hit with its evidence line ("47 ports in 60s", "ET exploit signature matched 4x"…), the VirusTotal verdict, the engine event history and the traffic profile. Left-clicking an IP in the map list opens it; every right-click menu gains "View details".
- **Full VirusTotal reports, stored in a local SQLite database** — every VT query now persists the complete response (per-engine detection results, reputation, AS owner) in `intel.db`. Right-click any scanned IP → "VT report" renders the whole thing: verdict, engine counts, a per-engine detections table and a direct link to VirusTotal.
- **Sarvam-105B AI threat analyst** — Settings → AI Threat Analyst takes your Sarvam API key. Right-click any IP → "AI threat analysis" sends the consolidated evidence to Sarvam's flagship `sarvam-105b` model and gets back a structured verdict, confidence, threat type, plain-language assessment, reasoning trace and recommended actions (cached in `intel.db`). With auto-analysis enabled, high-risk IPs above the risk threshold are assessed automatically (rate-limited, default 4/hour) and novel-pattern findings raise `ai_threat_assessment` events — this is the agentic layer for catching new threat shapes the signature engine can't name yet.
- **Connections APP MAP** — a third view on the connections page: a graphical world map from the server to every remote endpoint, arcs colored by application, arc width following live throughput, an app legend with click-to-toggle filters, and popups with live rates + a jump to IP intelligence. (The RATES chart and FLOW MAP views remain available.)

---

## SentinelFW 2.4 — False-Positive Overhaul, FortiGrade App Console & Split-Screen Connections

### Critical fixes (why apps and SSH were being blocked)

- **The `cmd_injection_pipes` signature no longer fires on encrypted traffic.** It used to scan the raw payload of every inbound TCP packet — TLS/SSH-encrypted bytes occasionally look like `;cat` or `|sh` by pure chance, so after a few hundred packets any HTTPS server (Google, AWS, your laptop over SSH…) got banned. Signatures now only match plaintext-looking payloads and skip the encrypted ports (443, 8443, 22, 3389, 993, 995).
- **Applications are no longer killed for talking to a banned IP.** Traffic to banned IPs was already dropped by the kernel, but the old default *also* killed the connecting process — which took down every application that happened to reach a banned CDN (this is what killed Antigravity IDE). Both `blocklisted_ip_connection` and `blocked_port_connection` now default to alert-only. Existing configs are migrated automatically on first start (`policy_version: 2`).
- **Protected Management IPs.** New `trusted_ips` setting (Settings → Protected Management IPs): IPs/CIDRs that are never banned, killed or redirected — your laptop, jump hosts and admin ranges. Private LAN ranges (10/8, 172.16/12, 192.168/16) are protected by default, so SSH from your LAN cannot be blocked; add your public management IPs manually if you connect from outside.
- Fixed the recurring `housekeeper_error ... got multiple values for keyword argument 'bans'` crash in the housekeeper heartbeat.

### VirusTotal consistency & controls

- Map popups are now **live**: an open popup refreshes with every 5-second data cycle, so the country, byte counts and VT verdict no longer disagree with the lists. A popup that was opened before a VT verdict existed back-fills it automatically; clean verdicts older than the 7-day revalidation window are marked "revalidate pending" instead of silently showing "not scanned".
- Operator-triggered VT scans get priority over the background scanner (short 4s spacing, shared hourly budget), so clicking VT SCAN rarely hits the free-tier limiter.
- Popups also show *why* an IP is banned (the exact signature/reason and the offense count).

### Connections page — split screen

- **Top half:** the live socket list, now with per-connection total and **live ↓/↑ rates**, auto-sorted by current throughput. Click a row to select it; right-click for actions (ban remote, VT scan, copy, kill process).
- **Bottom left:** a **connection details** panel for the selected socket — process, geo, live rates, detected threat vectors, and one-click Ban / VT / Kill.
- **Bottom right:** a **Live Traffic Visualizer** with two views — RATES (multi-series throughput chart of the top 6 flows) and PROCESS → IP MAP (a graph linking every application to the remote IPs it talks to, with traffic rates). The connections tab polls every 2 seconds while open.

### Application console — FortiGate-style

- The application popup now has a full **Resource Monitor**: live CPU / memory / network-rate / connection-count sparkline charts (10-minute rolling window, sampled every 5s by the new backend sampler), with current, peak values.
- **Resource alert thresholds** per application (CPU %, memory MB, connection count) — breaches raise `app_resource_alert` events (deduplicated to one per 10 minutes).
- New actions in the popup: **CREATE FIREWALL POLICY** (jumps to the policy editor prefilled for the app) and **APP NETWORK POLICY** (jumps to the application-firewall editor prefilled with the executable path), alongside block network / kill / quarantine.
- **Application firewall policies are now managed from the console** — a Create/Edit/Delete UI on the Appwall page (target executable path or glob, allowed outbound/inbound ports, denied destination CIDRs, action on violation). No more hand-editing config.json.

### Bans page

- The ban table now shows the reason, source, **offense count**, when it was added, when it expires, remaining time, and the VirusTotal verdict, with quick actions (UNBAN, +24H, ∞).
- **Right-click any ban** for the full menu: unban, extend 1h / 24h / 7d, make permanent, VT scan, locate on the threat map, copy IP.
- Entries in the protected management list are badged PROTECTED and never re-enforced.

### Network page

- Bigger layout: the packet inspector and the threat map both grew substantially (56vh / 62vh) for easier reading.

---

## SentinelFW 2.3 — Live Traffic Pipelines & Threat-Vector Analysis

- **Live connection pipelines on the map** — every remote IP is now linked to the server by an animated arc on the Geo Threat Map (Network Monitor tab). Pipeline thickness follows live throughput, color follows threat (red = high risk, amber = suspicious, blue = normal), and the flow direction data updates every 5 seconds. A pulsing "THIS SERVER" marker marks the origin (auto-located from the server's public IP). Toggle pipelines on/off from the map legend.
- **Hover any pipeline** to see exactly what is being transmitted: live ↓/↑ rates, total volume, packet/connection counts, protocol mix, the ports in use, the local applications talking to that IP, and the actual data in flight — DNS queries, TLS server names (SNI) and HTTP request lines captured from the packet inspector.
- **In-depth threat-vector analysis** — a new "Threat Vector Analysis" panel classifies every remote IP by attack profile across 14 vectors: PORT SCAN, SYN SCAN, BRUTE FORCE, CREDENTIAL STUFFING, DDoS/FLOOD, C2/BEACONING, CRYPTOMINING, EXPLOIT ATTEMPT, MALWARE (VirusTotal), HONEYPOT RECON, DNS TUNNELING, CANARY TRIGGER, NETWORK SWEEP and SUSPICIOUS traffic. Evidence comes from the deep packet recorder (port spread, bare-SYN ratios, tiny-packet floods, mining-pool ports, metronomic beacon intervals), honeypot sessions with captured credentials, IDS events, active bans and the VirusTotal cache — and every vector badge carries its human-readable evidence ("47 ports in 60s", "beacon every 60s ± 2.1s"). Each IP gets a 0–100 risk score, shown on the map list, popups, pipelines and the analysis panel.
