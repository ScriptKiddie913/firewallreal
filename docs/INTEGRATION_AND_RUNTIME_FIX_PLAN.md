# SentinelFW 4.0: Production Runtime Fix & Deep Integration Plan

## Executive Summary
SentinelFW has achieved broad architectural coverage across 37 planned enterprise phases. However, operational evaluation reveals two distinct categories of required work:
1. **Immediate Runtime & Web UI Defects:** Non-functional maps (CSP blocking CDN/tiles), 0% CPU consumption reporting across all processes, flow/app map UI stalls, and console log spam (Telegram 404, WAF socket `WinError 10013`).
2. **Deep Architectural Production Integration:** Unifying disparate modules (`policies.py`, `stateful_engine.py`, `appid.py`, `identity.py`, `ips.py`, `dlp.py`, `casb.py`, `swg.py`, `tlsproxy`) into a **single canonical decision and enforcement pipeline**, making identity authoritative against IP drift, tying endpoint posture to automated firewall quarantine enclaves, distinguishing granular SaaS actions in CASB, and exposing a live **Security Services Matrix** (`ACTIVE`, `STANDBY`, `CONFIGURED`, `UNWIRED`) in the Web UI.

---

## Phase 1: Immediate Runtime & Web UI Fixes

### 1.1 Content-Security-Policy (CSP) & MapLibre Rendering
- **Problem:** The Web UI sets a strict `default-src 'self'` CSP that blocks MapLibre GL JS from `unpkg.com`, Google Fonts, web worker blobs (`worker-src blob:`), and OpenFreeMap vector tile servers (`https://tiles.openfreemap.org`, OSM). As a result, `window.maplibregl` is undefined and maps fail silently.
- **Solution:**
  - Update `SentinelRequestHandler.end_headers()` in `sentinelfw/webui.py` to allow:
    - `script-src 'self' 'unsafe-inline' https://unpkg.com`
    - `style-src 'self' 'unsafe-inline' https://unpkg.com https://fonts.googleapis.com`
    - `font-src 'self' https://fonts.gstatic.com data:`
    - `connect-src 'self' https://tiles.openfreemap.org https://demotiles.maplibre.org https://*.tile.openstreetmap.org https://api.telegram.org`
    - `img-src 'self' data: blob: https://*`
    - `worker-src 'self' blob:`
    - `child-src 'self' blob:`
  - In `sentinelfw/webui_static/app.js`: Ensure both the Network Map and App Map initialize MapLibre GL safely, with fallback to an embedded SVG world projection if external tile networks are unavailable.
  - In `sentinelfw/webui_static/app.js`: Ensure the Flow Map has an autonomous 3-second live connection polling loop.

### 1.2 Multi-Platform Process Resource Sampler (Fixing "0% CPU")
- **Problem:** `sentinelfw/webui.py` calculates CPU usage via `/proc/{pid}/stat`, which does not exist on Windows. Its fallback to `psutil.Process(pid).cpu_percent(None)` creates an ephemeral instance with zero observation interval, always returning `0.0`. If `psutil` is absent, it returns hardcoded `0.0`. Furthermore, the UI only refreshed once on tab mount.
- **Solution:**
  - Implement a persistent `ProcessResourceSampler` in `sentinelfw/procinfo.py` and `sentinelfw/webui.py`:
    - On Windows: Use pure standard library `ctypes.windll.kernel32.GetProcessTimes` (providing `KernelTime` + `UserTime` in 100ns units) and `ctypes.windll.psapi.GetProcessMemoryInfo` for `WorkingSetSize` (RAM).
    - On Linux: Parse `/proc/{pid}/stat` and `/proc/{pid}/status`.
    - Maintain historical `(timestamp, total_proc_time)` per PID.
    - Compute CPU% = $(\Delta \text{proc\_time} / \Delta t) \times 100 / \text{num\_cores}$.
  - Run a lightweight background thread every 3 seconds to pre-calculate and cache process metrics.
  - Expose `/api/v1/applications` serving the cached snapshot instantly without request-time blocking.
  - In `sentinelfw/webui_static/app.js`: Set up periodic polling (every 3 seconds) for the Applications tab.

### 1.3 Console Noise: Telegram 404 & WAF Socket Permission Error
- **Problem:**
  - Telegram notifier spams `Failed to send Telegram alert: HTTP Error 404: Not Found` on every event loop because an invalid/dummy token was migrated into vault.
  - WAF proxy fails with `[WinError 10013] An attempt was made to access a socket in a way forbidden by its access permissions` when binding port 80/443 without administrator elevation or on port collision.
- **Solution:**
  - In `sentinelfw/telegram_bot.py`: Catch HTTP 404 / 401. Detect invalid bot token, log a single warning with exponential backoff (1h pause), and disable dispatching rather than printing exceptions on every event.
  - In `sentinelfw/waf/proxy.py`: Catch `WinError 10013` / `EACCES` and fall back to alternative unprivileged ports (8080/8443) or log a clean status message.

### 1.4 Web UI "Security Services" Matrix
- **Problem:** Operational visibility is blurred when modules exist on disk but their runtime wiring status is unknown.
- **Solution:**
  - Add backend endpoint `GET /api/v1/services/status` returning real runtime states (`ACTIVE`, `STANDBY`, `CONFIGURED`, `UNWIRED`) and metrics for all 18 security subsystems.
  - Add a dedicated "Security Services" navigation view in `sentinelfw/webui_static/index.html` and `app.js` with live service cards, badges, and diagnostic metrics.

---

## Phase 2: Deep Architectural Production Integration

### 2.1 Unified Enforcement Pipeline (`ONE POLICY -> VERDICT -> ALL BACKENDS`)
- **Architecture:**
  ```
  Packet / Flow Ingress
          │
          ▼
  Stage 0: Hardware / XDP Pre-filter (Bogon, Flood, Banned IP)
          │
          ▼
  Stage 1: Stateful Conntrack Lookup (Established flow fast-path)
          │
          ▼
  Stage 2: Zone & VDOM Resolution (Interface -> Tenant -> Zone)
          │
          ▼
  Stage 3: Authoritative Identity & Posture Check (Compromised -> Quarantine Enclave)
          │
          ▼
  Stage 4: App-ID Deep Protocol Inspection (Strict: unknown != safe)
          │
          ▼
  Stage 5: Unified Policy Match (5-tuple + App-ID + User + Device Posture)
          │
          ▼
  Stage 6: Inline L7 Services (IPS -> DLP -> AV -> CASB -> SWG)
          │
          ▼
  Stage 7: Canonical Verdict (ALLOW, DROP, REJECT, QUARANTINE)
  ```
- **Implementation:** Wire `StatefulDataplane.process_packet()` in `sentinelfw/stateful_engine.py` and `sentinelfw/engine.py` to route all flows through this sequential evaluation chain.

### 2.2 Deep Application Identification & Unknown Traffic Semantics
- Traverse protocol decoders: TCP/UDP $\rightarrow$ TLS Handshake $\rightarrow$ SNI $\rightarrow$ ALPN $\rightarrow$ JA4 Fingerprint $\rightarrow$ HTTP $\rightarrow$ App-ID.
- Traffic on port 443 with unrecognized SNI or non-standard payload must remain classified as `unknown-ssl` or `unknown-tcp`.
- Enforce explicit policy rule: `unknown-ssl` to untrusted zones is dropped by default; it is never assumed to be safe HTTPS.

### 2.3 Authoritative Identity & Anti-IP Drift Protection
- Bind identity mappings across 4 keys: `(IP, MAC, Device_ID, Session_Token)`.
- If a packet arrives from an IP with mismatched MAC or missing valid JWT, the mapping is invalidated immediately.
- Enforce 60-second telemetry heartbeats; DHCP lease events trigger instant session eviction.

### 2.4 Endpoint Posture $\rightarrow$ Firewall Quarantine Enclave
- When Endpoint Agent reports `edr_active: false` or active malware telemetry, state transitions to `COMPROMISED`.
- Identity engine triggers `engine.quarantine_host(ip, device_id)`:
  - Injects top-priority dataplane rule allowing access ONLY to the designated remediation server (`10.0.0.5/32:remediation-portal`).
  - Blocks all other internal lateral and external traffic.
  - Immediately terminates active sessions with TCP RST.

### 2.5 ZTNA Contextual Microsegmentation
- Replace broad subnet routing with per-application reverse proxy connectors.
- Validate user identity, device enrollment, compliant posture (<15 min), and RBAC role per request before splicing connections.

### 2.6 Threat Intelligence Lifecycle & Anti-Poisoning
- Complete lifecycle: Ingest $\rightarrow$ Anti-Poisoning Validation (reject RFC 1918 / loopback / gateway IPs) $\rightarrow$ Normalize $\rightarrow$ Dedup $\rightarrow$ Score $\rightarrow$ Activate $\rightarrow$ TTL Decay $\rightarrow$ Rollback.
- Enforce strict confidence threshold: confidence $< 70$ is `ALERT` only; confidence $\ge 85$ with multi-source corroboration triggers automated dataplane `DROP`.

### 2.7 SaaS-Granular CASB & SWG Action Inspection
- In `sentinelfw/casb.py`, discriminate SaaS actions beyond domain allowlists:
  - `GET /repos/...` $\rightarrow$ `ALLOW`
  - `POST /upload/...` or `POST /git-receive-pack` $\rightarrow$ Divert through DLP engine for credential/PII inspection.
  - Inject tenant restriction headers (`X-Goog-Allowed-Domains`, `Restrict-Access-To-Tenants`).

### 2.8 TLS Inspection Fail-Open vs Fail-Closed Semantics
- Support policy-level `"inspection_failure_mode": "fail-closed"` or `"fail-open"`.
- Upstream untrusted CA / expired certificate $\rightarrow$ strict `DROP` with `bad_certificate` alert.
- Certificate pinning failure threshold (3 consecutive handshake resets) $\rightarrow$ 24-hour auto-bypass with high-severity audit logging.

### 2.9 High Availability (HA) Conntrack State Synchronization
- Active node replicates TCP 5-tuple states, sequence numbers, NAT mappings, and bans to standby node via dedicated sync socket (`sentinelfw/ha.py`).
- Failover takes over active sessions with zero connection resets.

### 2.10 Multi-Tenancy / VDOM Isolation Verification
- Enforce strict interface uniqueness (one VDOM per interface).
- API endpoints enforce `tenant_id` token scoping to prevent cross-tenant data leakage.
- Enforce tenant quotas (max policies, max bandwidth, max sessions).

### 2.11 AI Layer Safety Guardrails
- Pipeline: Telemetry $\rightarrow$ AI Recommendation $\rightarrow$ Deterministic Rule Validator $\rightarrow$ Mandatory Human Confirmation $\rightarrow$ Policy Engine.
- Hard safety rails: AI can never ban loopback, RFC 1918, or active admin sessions.
- Mandatory TTL and rollback timer on all automated actions.

---

## Phase 3: Verification & Quality Gates
1. Unit and integration tests for:
   - Process CPU% sampling on Windows and Linux (verifying non-zero values for active processes).
   - Web UI CSP header allowing CDN, fonts, tiles, and worker blobs.
   - Live Security Services API endpoint.
   - Endpoint posture transition triggering automated quarantine enclave in policy engine.
   - Telegram error backoff suppressing repeated log spam.
2. Pytest test suite execution (zero failures).
3. Release hygiene audit verification (`python scripts/check_release_hygiene.py`).
4. Packaging verification (`python scripts/package_release.py`).
