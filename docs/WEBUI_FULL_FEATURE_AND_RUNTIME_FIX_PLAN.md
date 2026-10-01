# SentinelFW Web UI Full Feature Plan & Runtime Anomaly/Self-Protect Fixes

**Author**: SentinelFW Core Engineering Team  
**Date**: October 2026  
**Status**: APPROVED & UNDER IMPLEMENTATION  
**Target Version**: SentinelFW Enterprise 4.1.0  

---

## 1. Executive Summary & Root Cause Analysis

### 1.1 Root Cause Analysis: Runtime Terminal Issues

The user reported four distinct runtime anomalies observed in the `sfwctl run` execution log:

```text
[2026-10-01T23:25:43+0530] HIGH anomaly_detected metric=connections_per_minute val=488 mean=278.04 sigma=2.84 hst_score=1.0 ...
[2026-10-01T23:25:43+0530] HIGH anomaly_detected metric=bandwidth_in_kbps val=0.0 mean=0.0 sigma=0.0 hst_score=1.0 ...
[2026-10-01T23:26:45+0530] CRITICAL source_code_tampered count=1 files=['modified: webui.py']
[2026-10-01T23:26:45+0530] CRITICAL self_protect_alert violations=['modified: webui.py']
Failed to send Telegram alert: HTTP Error 404: Not Found
```

#### Issue 1: HSTree Unprimed Inverse-Mass Anomaly False Positives (`val=0.0 mean=0.0 sigma=0.0 hst_score=1.0`)
- **Root Cause**: In `sentinelfw/anomaly.py`:
  1. `HalfSpaceTreeEnsemble.anomaly_score(point)` uses the inverse mass formula:
     $$\text{score} = \frac{1.0}{1.0 + \ln(1 + \text{avg\_mass})}$$
     On startup, when reference windows have not yet accumulated mass (or during quiescent periods when mass is $0.0$), $\ln(1 + 0) = 0$, producing a mathematical score of $\mathbf{1.0}$ (maximal anomaly)!
  2. In `BaselineEngine.evaluate_tick()`:
     ```python
     for name, metric in self.metrics.items():
         if len(metric.window) >= 10:
             z = metric.z_score(val)
             if z >= self.alert_sigma or hst_score >= 0.85:
                 ... # triggers anomaly!
     ```
     Because `hst_score >= 0.85` was evaluated inside the individual metric loop, the moment HSTree produced $1.0$, **every single metric** (`bandwidth_in_kbps`, `bandwidth_out_kbps`, `dns_queries_per_minute`, `new_processes_per_minute`) fired a high-severity alert even though `val == 0.0` and `mean == 0.0`!
- **Fix**:
  1. HSTree must require minimum reference samples ($\ge 30$ observations and $\ge 1$ window rotation) before returning non-zero anomaly scores. If unprimed, return $0.0$.
  2. Suppress metric alerts if $\text{val} = 0.0$ and $\text{mean} = 0.0$ or $\sigma < 0.001$.
  3. Decouple multivariate HSTree alerts from univariate metric alerts. A single multivariate anomaly event is emitted when HSTree detects high-dimensional drift, rather than 5 repetitive false alarms on quiet metrics.

#### Issue 2: Self-Protection Tamper Alarms on Live Code Updates
- **Root Cause**: `sentinelfw/selfprotect.py` computes SHA-256 digests of all `.py` files in `PKG_DIR` at startup (`build_manifest()`). When code files (`webui.py`, `telegram_bot.py`, `waf/proxy.py`) are updated while the daemon is running, the 60-second background watchdog discovers hash mismatches and raises `source_code_tampered` and `self_protect_alert`.
- **Fix**:
  1. Provide a programmatic `rebaseline()` and control-plane API endpoint `/api/v1/system/rebaseline` to re-hash the manifest cleanly when updates are committed.
  2. In interactive development/run mode, provide an automatic grace period or reload signal rather than spamming critical alarms.

#### Issue 3: Telegram Alert HTTP 404 Flooding
- **Root Cause**: When placeholder or unconfigured BotFather tokens exist in `config.json`, sending alerts to `https://api.telegram.org/bot<TOKEN>/sendMessage` returns HTTP 404. In the older daemon loop, failures printed unhandled errors to stdout.
- **Fix**: The newly updated `sentinelfw/telegram_bot.py` auto-pauses the notifier immediately upon receiving HTTP 401 or 404, drains pending queues, and logs a single warning instead of flooding the terminal.

---

## 2. Web UI Architecture & Performance Optimization

### 2.1 Refinement of App Map and Flow Map ("Slow Map" Solution)

The existing App Map and Flow Map experienced performance lag because:
1. **DOM Thrashing**: On every 3-second poll interval, `renderConnFlowmap()` wiped out and recreated the entire SVG DOM using raw `box.innerHTML = ...`. This caused layout thrashing and lost hover state.
2. **Unnecessary Canvas / GeoJSON Retessellation**: `renderConnAppMap()` called MapLibre GL's `setData()` every 3 seconds even when connections were completely identical.
3. **Un-gated Background Execution**: Both map renderers ran even when their parent tab or sub-view was hidden.

#### The Optimization Solution:
- **Topology Signature Dirty-Checking**: Compute a lightweight hash of `[app, remote_ip, port, rate_bucket]`. If the signature has not changed between 3s intervals, only update numerical throughput labels, without destroying SVG elements or re-baking Bezier curves.
- **Selective Rendering**: Check if the tab (`connections` or `network`) and active view mode (`map`, `chart`, or `appmap`) are visible before executing DOM or WebGL updates.
- **MapLibre GeoJSON Throttling**: Only invoke `appMapObj.getSource("app-flows").setData()` when flow endpoints or active states change, with a minimum 2-second debounce for particle animations.

---

## 3. Dedicated Enterprise Web UI Tabs & Views Specification

To give full visual control and operational visibility over all SentinelFW security engines, 7 dedicated tabs are added to the Web UI sidebar:

| Nav Tab ID | Display Label | Security Subsystem | Core Capabilities |
|:---|:---|:---|:---|
| `waf` | **WAF & API Guard** | `sentinelfw.waf` | OWASP CRS 3.3 rules, Paranoia Level (1–4), Bot Mitigator, API Schema Guard, Credential Shield |
| `dlp` | **Data Loss Prevention** | `sentinelfw.dlp` | Sensitive regex rules (Luhn CC, SSN, API Keys, Private Keys), Leak actions (Mask, Block, Alert), Privacy Bypass List |
| `ztna` | **Zero Trust & Posture** | `sentinelfw.identity` | Continuous posture scoring (EDR, BitLocker, OS), App microsegmentation, Dynamic JIT rules |
| `threatintel` | **Threat Intelligence** | `sentinelfw.feeds`, `threatintel` | Ingested feed status (FireHOL, Feodo, URLhaus), Anti-poisoning stats, Manual IOC reputation lookup |
| `playbooks` | **SOAR Automation** | `sentinelfw.playbook` | Automated incident response rules, Dry-Run simulation runner, Execution audit history |
| `identity` | **Identity & Devices** | `sentinelfw.identity` | Authoritative IP -> User -> Device mapping, Anti-IP spoof/drift detector, Session revoker |
| `ai-analyst` | **AI Security Analyst** | `sentinelfw.ai_analyst`, `sarvam` | Interactive natural language analyst, Prompt-injection sanitizer badge, 1-Click Rollback |

---

## 4. REST API Endpoint Mapping

The following endpoints in `sentinelfw/webui.py` supply data and control hooks for the frontend:

```text
GET  /api/v1/waf/status           -> WAF proxy status, paranoia level, CRS stats, bot blocked
POST /api/v1/waf/config           -> Update paranoia level, bot mitigations, CRS rules
GET  /api/v1/dlp/status            -> DLP engine state, active rule count, privacy bypass patterns
POST /api/v1/dlp/test             -> Test string/payload against DLP regexes
GET  /api/v1/ztna/status           -> Posture evaluations, device health scores, microsegmentation
POST /api/v1/ztna/evaluate         -> Run real-time posture check on client device
GET  /api/v1/threatintel/summary   -> Feed counts, IOC database stats, anti-poisoning metrics
POST /api/v1/threatintel/lookup    -> Query IP/domain/hash reputation
GET  /api/v1/soar/playbooks        -> List all declarative playbooks and execution counters
POST /api/v1/soar/execute         -> Dry-run or live execute a playbook against test event
GET  /api/v1/identity/directory    -> List all active IP-to-User bindings and posture states
POST /api/v1/identity/bind         -> Manually bind or update user/device identity
POST /api/v1/system/rebaseline     -> Re-hash source integrity manifest to silence tamper alarms
```

---

## 5. Verification & Test Plan

1. **Unit Testing**:
   - Test HSTree zero-variance behavior in `test_anomaly.py`. Verify 0.0 score on zero traffic.
   - Test Self-Protection `rebaseline()` in `test_selfprotect.py`.
   - Test new Web UI endpoints with authentication and mock payloads.
2. **Browser & UI Verification**:
   - Verify all 7 new navigation tabs render cleanly with FortiGate-style dark aesthetics.
   - Verify App Map and Flow Map render smoothly with zero DOM lag or frame drops.
   - Test interactive forms (WAF paranoia slider, DLP test payload, Threat Intel IOC search, SOAR dry-run).
