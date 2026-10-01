# Content-Aware Data Loss Prevention (DLP) Engine

SentinelFW includes a real-time deep content inspection DLP engine (`sentinelfw/dlp.py`) designed to prevent intellectual property theft, PII exfiltration, and compliance violations across cleartext and decrypted TLS traffic.

## 1. Detection Capabilities

- **Pattern Matching:** Regular expressions for Credit Cards (Visa, MasterCard, Amex with Luhn checksum validation), Social Security Numbers (SSN), Aadhaar IDs, and corporate secrets.
- **Credential & API Key Extraction:** High-entropy token detection identifying AWS Secret Access Keys, GitHub Personal Access Tokens, JWTs, and RSA/SSH private keys.
- **Source Code Leakage:** Identification of proprietary code fragments and file headers.

## 2. Enforcement Actions

- `ALLOW`: Content passes without modification.
- `LOG`: Audit event recorded in security lake.
- `REDACT`: Sensitive sequences masked in-place (e.g., `4532-XXXX-XXXX-8921`) before transmission.
- `BLOCK`: Stream terminated with HTTP 403 / TCP RST.
- `QUARANTINE`: Host quarantined and forensic bundle generated.
