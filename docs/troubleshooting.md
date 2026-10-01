# SentinelFW Troubleshooting Guide & Diagnostics

Systematic triage procedures for diagnosing dataplane, proxy, and management plane anomalies.

## 1. Dataplane Diagnostic Commands

```bash
# Check nftables rule evaluation and packet drops
nft list ruleset | grep -E "drop|reject|sentinelfw"

# View active stateful connection tracking table
python3 -c "from sentinelfw.conntrack import conntrack; print(conntrack.summary())"

# Dump eBPF/XDP map statistics
bpftool map dump name blocklist_v4
```

## 2. TLS Proxy Interception Triage

- **Symptom:** Browser shows `SEC_ERROR_UNKNOWN_ISSUER` or `ERR_CERT_AUTHORITY_INVALID`.
  - **Resolution:** Verify that SentinelFW Root CA certificate is installed in client trust store (Windows Certificate Store / Linux `/etc/ssl/certs`).
- **Symptom:** Application drops connection with `CERTIFICATE_VERIFY_FAILED: certificate pinned`.
  - **Resolution:** Check pinning failure log in `events.jsonl`. Verify that auto-bypass kicks in after 3 attempts or add the domain to `privacy_bypass_domains` in `config.json`.

## 3. Web UI & Management API Diagnostics

- **Symptom:** HTTP 429 Too Many Requests.
  - **Resolution:** Client IP has exceeded the 240 req/min rate limit. Wait 60 seconds or configure trusted IPs in `config.json`.
- **Symptom:** HTTP 403 Forbidden on API POST.
  - **Resolution:** Ensure `X-CSRF-Token` header matches `sfw_csrf` cookie value, or use a Bearer token.
