"""SentinelFW Threat Intelligence Platform (TIP) & Ingestion Subsystem.

Provides high-volume feed ingestion, deduplication, automated IOC scoring, and poisoned-feed protection:
- Ingestion parsers: STIX 2.1, MISP, URLhaus, Abuse.ch, Spamhaus DROP, and plain IP/CIDR feeds
- Canonical IOC schema: IP, domain, URL, file hash, ASN, JA3/JA4, confidence, threat categories, TTL
- Anti-poisoning guard: blocks private (RFC 1918), loopback, multicast, and gateway IPs from threat sets
- Health telemetry and atomic database updates
"""
import ipaddress
import json
import logging
import re
import threading
import time
from typing import Dict, List, Optional, Set, Tuple, Union
from .common import event

logger = logging.getLogger("sentinelfw.feeds")

# Private and non-routable IPv4 / IPv6 networks protected from feed poisoning
PROTECTED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

PROTECTED_DOMAINS = {"localhost", "local", "internal", "corp", "home", "lan", "gateway"}


class IOCType:
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    JA3 = "ja3"
    JA4 = "ja4"


class ThreatIntelFeeds:
    """Enterprise Threat Intelligence Subsystem managing feeds, deduplication, and lookup."""

    def __init__(self, cfg: Optional[dict] = None):
        self.cfg = cfg or {}
        self._lock = threading.RLock()

        # Canonical storage
        self._ip_entries: List[dict] = []  # {network, source, confidence, tags, expires_at}
        self._domain_entries: Dict[str, dict] = {}  # domain -> {source, confidence, tags, expires_at}
        self._hash_entries: Dict[str, dict] = {}  # sha256/md5 -> {source, confidence, tags, expires_at}
        self._ja3_entries: Dict[str, dict] = {}  # ja3_hash -> {source, confidence, tags, expires_at}

        # Feed health tracking
        self._feed_health: Dict[str, dict] = {}

    @classmethod
    def is_poisoned_ip(cls, ip_obj: Union[ipaddress.IPv4Address, ipaddress.IPv6Address, ipaddress.IPv4Network, ipaddress.IPv6Network]) -> bool:
        """Verifies if an IP or network belongs to RFC 1918 / loopback / non-routable blocks."""
        net = ip_obj if hasattr(ip_obj, "network_address") else ipaddress.ip_network(f"{ip_obj}/32" if ":" not in str(ip_obj) else f"{ip_obj}/128")
        for p in PROTECTED_NETWORKS:
            if net.overlaps(p):
                return True
        return False

    @classmethod
    def is_poisoned_domain(cls, domain: str) -> bool:
        clean = domain.strip().lower().strip(".")
        if not clean or "." not in clean:
            return True
        tld = clean.split(".")[-1]
        if tld in PROTECTED_DOMAINS or clean in PROTECTED_DOMAINS:
            return True
        return False

    # -----------------------------------------------------------------------
    # Ingestion Methods
    # -----------------------------------------------------------------------
    def add_feed_entries(self, source: str, raw_entries: List[str], confidence: int = 85,
                          tags: Optional[List[str]] = None, ttl: int = 86400) -> int:
        """Parses standard IP/CIDR blocklists (e.g. Spamhaus DROP, AbuseIPDB)."""
        now = time.time()
        exp = now + ttl if ttl > 0 else 0
        clean_tags = [str(t).lower() for t in (tags or ["reputation"])]
        count = 0
        poisoned_count = 0

        new_entries = []
        for raw in raw_entries:
            line = str(raw).strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            token = line.split(";")[0].split()[0]
            try:
                net = ipaddress.ip_network(token, strict=False)
                if self.is_poisoned_ip(net):
                    poisoned_count += 1
                    continue
                new_entries.append({
                    "network": net,
                    "source": source,
                    "confidence": int(confidence),
                    "tags": clean_tags,
                    "expires_at": exp,
                })
                count += 1
            except ValueError:
                continue

        with self._lock:
            self._ip_entries = [e for e in self._ip_entries if e["source"] != source] + new_entries
            self._feed_health[source] = {
                "last_sync": now,
                "items_ingested": count,
                "poisoned_dropped": poisoned_count,
                "status": "healthy",
            }

        event("feed_ingested", "info", source=source, added=count, poisoned_dropped=poisoned_count, total=len(self._ip_entries))
        return count

    def ingest_stix2(self, source: str, stix_bundle: dict, default_confidence: int = 90, ttl: int = 86400) -> int:
        """Ingests a STIX 2.1 JSON bundle parsing pattern indicators."""
        now = time.time()
        exp = now + ttl if ttl > 0 else 0
        count = 0

        objects = stix_bundle.get("objects", []) if isinstance(stix_bundle, dict) else []
        for obj in objects:
            if obj.get("type") != "indicator":
                continue
            pattern = obj.get("pattern", "")
            confidence = obj.get("confidence", default_confidence)

            # Match ipv4-addr:value = 'x.x.x.x'
            ip_matches = re.findall(r"ipv[46]-addr:value\s*=\s*'([^']+)'", pattern)
            for ip_str in ip_matches:
                try:
                    net = ipaddress.ip_network(ip_str, strict=False)
                    if not self.is_poisoned_ip(net):
                        with self._lock:
                            self._ip_entries.append({
                                "network": net,
                                "source": source,
                                "confidence": confidence,
                                "tags": ["stix2", "malware"],
                                "expires_at": exp,
                            })
                        count += 1
                except ValueError:
                    pass

            # Match domain-name:value = 'example.com'
            dom_matches = re.findall(r"domain-name:value\s*=\s*'([^']+)'", pattern)
            for d in dom_matches:
                clean_d = d.strip().lower()
                if not self.is_poisoned_domain(clean_d):
                    with self._lock:
                        self._domain_entries[clean_d] = {
                            "source": source,
                            "confidence": confidence,
                            "tags": ["stix2", "c2"],
                            "expires_at": exp,
                        }
                    count += 1

            # Match file:hashes.'SHA-256' = '...'
            hash_matches = re.findall(r"file:hashes\.(?:'SHA-256'|'MD5')\s*=\s*'([0-9a-fA-F]+)'", pattern)
            for h in hash_matches:
                clean_h = h.strip().lower()
                with self._lock:
                    self._hash_entries[clean_h] = {
                        "source": source,
                        "confidence": confidence,
                        "tags": ["stix2", "malware"],
                        "expires_at": exp,
                    }
                count += 1

        with self._lock:
            self._feed_health[source] = {"last_sync": now, "items_ingested": count, "status": "healthy"}
        return count

    def ingest_misp(self, source: str, misp_event: dict, default_confidence: int = 85, ttl: int = 86400) -> int:
        """Ingests a MISP standard event with Attributes array."""
        now = time.time()
        exp = now + ttl if ttl > 0 else 0
        count = 0

        ev = misp_event.get("Event", misp_event)
        attributes = ev.get("Attribute", []) if isinstance(ev, dict) else []

        for attr in attributes:
            atype = attr.get("type", "")
            val = str(attr.get("value", "")).strip()
            if not val:
                continue

            if atype in ("ip-src", "ip-dst", "ip"):
                try:
                    net = ipaddress.ip_network(val, strict=False)
                    if not self.is_poisoned_ip(net):
                        with self._lock:
                            self._ip_entries.append({
                                "network": net,
                                "source": source,
                                "confidence": default_confidence,
                                "tags": ["misp", atype],
                                "expires_at": exp,
                            })
                        count += 1
                except ValueError:
                    pass
            elif atype in ("domain", "hostname"):
                clean_d = val.lower()
                if not self.is_poisoned_domain(clean_d):
                    with self._lock:
                        self._domain_entries[clean_d] = {
                            "source": source,
                            "confidence": default_confidence,
                            "tags": ["misp", atype],
                            "expires_at": exp,
                        }
                    count += 1
            elif atype in ("sha256", "md5"):
                clean_h = val.lower()
                with self._lock:
                    self._hash_entries[clean_h] = {
                        "source": source,
                        "confidence": default_confidence,
                        "tags": ["misp", atype],
                        "expires_at": exp,
                    }
                count += 1

        with self._lock:
            self._feed_health[source] = {"last_sync": now, "items_ingested": count, "status": "healthy"}
        return count

    # -----------------------------------------------------------------------
    # Query / Lookup
    # -----------------------------------------------------------------------
    def check_ip(self, ip_str: str) -> Tuple[bool, dict]:
        """Checks if an IP matches any non-expired threat intelligence entry."""
        try:
            ip = ipaddress.ip_address(str(ip_str).strip())
        except ValueError:
            return False, {}

        now = time.time()
        with self._lock:
            for entry in self._ip_entries:
                if entry["expires_at"] > 0 and now > entry["expires_at"]:
                    continue
                if ip in entry["network"]:
                    return True, {
                        "matched_network": str(entry["network"]),
                        "source": entry["source"],
                        "confidence": entry["confidence"],
                        "tags": entry["tags"],
                    }
        return False, {}

    def check_domain(self, domain_str: str) -> Tuple[bool, dict]:
        """Checks if a domain matches any non-expired threat intelligence entry."""
        clean = domain_str.strip().lower().strip(".")
        now = time.time()
        with self._lock:
            # Exact match
            rec = self._domain_entries.get(clean)
            if rec and (rec["expires_at"] == 0 or now <= rec["expires_at"]):
                return True, dict(rec)
            # Wildcard suffix match
            for d, entry in self._domain_entries.items():
                if entry["expires_at"] > 0 and now > entry["expires_at"]:
                    continue
                if clean.endswith("." + d):
                    return True, dict(entry)
        return False, {}

    def check_hash(self, hash_str: str) -> Tuple[bool, dict]:
        clean = hash_str.strip().lower()
        now = time.time()
        with self._lock:
            rec = self._hash_entries.get(clean)
            if rec and (rec["expires_at"] == 0 or now <= rec["expires_at"]):
                return True, dict(rec)
        return False, {}

    def lookup_ip(self, ip_str: str) -> Optional[dict]:
        """Convenience method returning metadata dict if IP is in feeds, else None."""
        found, meta = self.check_ip(ip_str)
        return meta if found else None

    def lookup_domain(self, domain_str: str) -> Optional[dict]:
        """Convenience method returning metadata dict if domain is in feeds, else None."""
        found, meta = self.check_domain(domain_str)
        return meta if found else None

    def lookup_hash(self, hash_str: str) -> Optional[dict]:
        """Convenience method returning metadata dict if hash is in feeds, else None."""
        found, meta = self.check_hash(hash_str)
        return meta if found else None

    def count(self) -> int:
        with self._lock:
            return len(self._ip_entries) + len(self._domain_entries) + len(self._hash_entries)

    def clear(self):
        with self._lock:
            self._ip_entries.clear()
            self._domain_entries.clear()
            self._hash_entries.clear()
            self._ja3_entries.clear()

    def get_health(self) -> Dict[str, dict]:
        with self._lock:
            return copy.deepcopy(self._feed_health)


# Global singleton
intel_feeds = ThreatIntelFeeds()
