# Inline Intrusion Prevention System (IPS) Architecture

SentinelFW embeds an inline Intrusion Prevention System (`sentinelfw/ips.py`) operating directly on reassembled TCP streams and UDP datagrams.

## 1. Engine Modes & Verdicts

The IPS engine evaluates ingress and egress payloads against versioned rule packs, returning deterministic verdicts:

- `PASS`: No malicious signatures matched; traffic proceeds immediately.
- `ALERT`: Signature matched with low confidence; logged to security lake without interrupting flow.
- `DROP`: High-confidence exploit attempt; packet discarded at dataplane.
- `RESET`: Active TCP connection terminated via spoofed TCP RST sequence.
- `QUARANTINE`: Hostile payload; immediate source IP isolation and automated containment.

## 2. Fail-Open vs Fail-Closed Semantics

Under resource starvation or engine failure:
- **Fail-Open:** Critical enterprise connectivity is prioritized; uninspected packets pass through with audit warnings.
- **Fail-Closed:** High-security enclave mode; all uninspected traffic is dropped until engine health is restored.

## 3. Atomic Rule Pack Hot-Reload & Rollback

Rule packs are distributed as signed JSON packages:
- Atomic in-memory swapping ensures zero downtime or dropped packets during signature updates.
- If signature compilation encounters a syntax anomaly or catastrophic backtracking regex, the engine automatically rolls back to the previous known-good rule pack.
