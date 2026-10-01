# Zero Trust Network Access (ZTNA) & Endpoint Posture Assessment

SentinelFW implements a Zero Trust Network Access architecture (`sentinelfw/identity.py`, `sentinelfw/waf/proxy.py`, `sentinelfw/agent_daemon.py`) replacing traditional perimeter VPNs with per-request contextual authorization.

## 1. 4-State Posture Evaluation

Endpoints are evaluated into four definitive states:
- `COMPLIANT`: EDR running, disk encryption active, firewall enabled, OS patched within policy window.
- `NON_COMPLIANT`: Minor security defect (e.g., outdated antivirus definitions); restricted access granted to remediation portals.
- `UNKNOWN`: Unregistered device or stale posture report (>15 minutes old).
- `COMPROMISED`: Active malware detection, disabled security telemetry, or cryptographic tampering. Immediate total isolation.

## 2. Cryptographic Telemetry Signing

Posture reports collected by the SentinelFW Agent Daemon (`collect_local_posture`) are signed using an HMAC-SHA256 device key. The management gateway validates the cryptographic signature before updating device state in the Identity Directory.

## 3. Ephemeral ZTNA Session Tokens

Upon successful authorization, a signed JWT session token is minted containing:
- `sub`: User ID
- `device_id`: Enrolled endpoint identifier
- `posture_state`: `COMPLIANT`
- `exp`: 15-minute validity ceiling

Reverse proxy and gateway inspection points validate token integrity and verify non-revocation in memory before splicing application connections.
