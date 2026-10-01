# Threat Intelligence Platform (TIP) & C2 / Botnet Defense

SentinelFW ingests, normalizes, and operationalizes threat feeds from global intelligence sources and behavioral detection engines (`sentinelfw/feeds.py`, `sentinelfw/c2.py`).

## 1. Feed Ingestion & Standardization

- **STIX 2.1 & MISP Ingestion:** Parses JSON threat indicators (IP addresses, CIDRs, domains, file hashes).
- **Anti-Poisoning Validation:** Strictly rejects private RFC 1918 addresses, loopbacks, and configured enterprise subnets from ever being ingested as threat indicators, preventing external feed poisoning and self-inflicted denial of service.
- **Confidence Aging:** Indicators decay over a configurable TTL window to prevent stale blocking.

## 2. Statistical C2 Beacon Detection

Advanced malware and APT implants avoid fixed beacon frequencies by injecting randomized jitter. SentinelFW's `StatisticalBeaconDetector`:
- Computes flow inter-arrival intervals over sliding observation windows.
- Calculates coefficient of variation (CV = std_dev / mean) and periodicity score.
- Flags flows with regular beaconing characteristics (CV < 0.22) even when obfuscated across TLS or DNS tunnels.
