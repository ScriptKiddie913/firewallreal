# Transparent TLS Inspection Engine Architecture

SentinelFW provides transparent, high-performance TLS MITM decryption and inspection implemented in `pkg/tlsproxy/proxy.go` and `sentinelfw/protocols/tls.py`.

## 1. TLS Inspection Flow

```
Client TLS Handshake
       │
       ▼
[peekSNI & ClientHello Buffer]
       │
       ├──► Is domain in Privacy Bypass List? (Banking, Healthcare, Gov)
       │         │
       │         └──► YES: Splice raw TCP stream (Zero Decryption)
       │
       ├──► Has domain exceeded Certificate Pinning failure threshold?
       │         │
       │         └──► YES: Auto-bypass to prevent user disruption
       │
       ▼
[Dynamic Leaf Certificate Generation] ◄── Signed by SentinelFW CA
       │
       ▼
[Decrypted Cleartext Traffic Stream]
       │
       ├──► Layer 7 App-ID & URL Categorization
       ├──► Inline IPS Pattern Matching
       ├──► Antivirus & File Hash Reputation Scanning
       └──► Content-Aware Data Loss Prevention (DLP)
       │
       ▼
[Upstream SAN & Expiry Validation] ──► Re-encrypted to Origin Server
```

## 2. Privacy Exemptions & Regulatory Compliance

To adhere to GDPR, HIPAA, and PCI-DSS requirements:
- Healthcare (`*.health`, `*.mychart.com`)
- Financial Institutions (`*.chase.com`, `*.wellsfargo.com`, `*.fidelity.com`)
- Government Portals (`*.gov`, `*.mil`)

These categories are automatically bypassed at the TLS ClientHello SNI stage without decrypting payload data.

## 3. Certificate Pinning Resilience

Applications employing HTTP Public Key Pinning (HPKP) or hardcoded certificate pinning fail when intercepted. SentinelFW tracks TLS alert `bad_certificate` and handshake reset frequencies. Upon reaching 3 consecutive failures within 60 seconds, the target FQDN is dynamically added to the ephemeral bypass cache for 24 hours.
