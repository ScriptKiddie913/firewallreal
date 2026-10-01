import collections
import math
import re
import threading
import time
from typing import Dict, List, Optional, Set, Tuple


def shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = {}
    for ch in data:
        counts[ch] = counts.get(ch, 0) + 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


class DNSInspector:
    """Performs deep behavioral inspection on DNS queries and responses."""

    _flux_lock = threading.Lock()
    _flux_cache: Dict[str, List[Tuple[float, str]]] = collections.defaultdict(list)

    @classmethod
    def record_resolution(cls, domain: str, ip: str, max_window: float = 300.0,
                          threshold_distinct_ips: int = 5) -> Optional[dict]:
        """Tracks fast-flux domain activity (frequent IP rotation within a short window)."""
        domain = domain.strip(".").lower()
        now = time.time()
        with cls._flux_lock:
            history = cls._flux_cache[domain]
            # prune expired resolutions outside window
            cls._flux_cache[domain] = [(t, addr) for t, addr in history if now - t <= max_window]
            cls._flux_cache[domain].append((now, ip))
            distinct_ips = set(addr for _, addr in cls._flux_cache[domain])
            if len(distinct_ips) >= threshold_distinct_ips:
                return {
                    "domain": domain,
                    "distinct_ips": sorted(list(distinct_ips)),
                    "count": len(distinct_ips),
                    "window_seconds": max_window,
                    "threat": "c2_fast_flux"
                }
        return None

    @classmethod
    def inspect_query(cls, qname: str, qtype: str = "A") -> Tuple[Optional[str], dict]:
        """
        Analyzes a DNS query name for tunneling, DGA, or exfiltration indicators.
        Returns: (attack_type or None, details_dict)
        """
        if not qname:
            return None, {}

        labels = qname.strip(".").split(".")
        if len(labels) < 2:
            return None, {}

        subdomain = ".".join(labels[:-2]) if len(labels) > 2 else labels[0]
        longest_label = max(labels, key=len)
        entropy = shannon_entropy(longest_label)

        # 1. DNS Tunneling Detection (Large payload, high entropy, base32/hex characters)
        is_hex_or_b32 = bool(re.fullmatch(r"[0-9a-fA-F]+|[2-7a-zA-Z=]+", longest_label))
        if len(longest_label) > 30 and (entropy > 3.8 or (len(longest_label) > 45 and is_hex_or_b32)):
            return "c2_dns_tunnel", {
                "qname": qname,
                "label_len": len(longest_label),
                "entropy": round(entropy, 2),
                "qtype": qtype
            }

        # Long total query name (tunneling indicator)
        if len(qname) > 180 and entropy > 3.5:
            return "c2_dns_tunnel", {
                "qname": qname,
                "total_len": len(qname),
                "entropy": round(entropy, 2),
                "qtype": qtype
            }

        # 2. DGA Domain Detection (high entropy second-level domain)
        sld = labels[-2] if len(labels) >= 2 else labels[0]
        if len(sld) >= 10 and shannon_entropy(sld) >= 3.2 and not re.search(r"[aeiou]{2,}", sld):
            return "c2_domain_gen", {
                "qname": qname,
                "sld": sld,
                "entropy": round(shannon_entropy(sld), 2)
            }

        # 3. Zone Transfer (AXFR) Attempt
        if qtype.upper() in ("AXFR", "IXFR", "252", "251"):
            return "dns_zone_transfer", {"qname": qname, "qtype": qtype}

        return None, {"qname": qname, "entropy": round(entropy, 2)}


class DNSSinkholeManager:
    """Manages DNS sinkholing and Response Policy Zones (RPZ) for C2/malware containment."""

    def __init__(self, sinkhole_ip: str = "10.254.254.254", default_ttl: int = 60):
        self.sinkhole_ip = sinkhole_ip
        self.default_ttl = default_ttl
        self._rpz_rules: Dict[str, str] = {}  # domain -> action (sinkhole, nxdomain, drop)
        self._sinkholed_events: List[dict] = []
        self._lock = threading.RLock()

    def add_rpz_rule(self, domain: str, action: str = "sinkhole"):
        with self._lock:
            self._rpz_rules[domain.strip(".").lower()] = action.lower()

    def remove_rpz_rule(self, domain: str):
        with self._lock:
            self._rpz_rules.pop(domain.strip(".").lower(), None)

    def evaluate_and_route(self, qname: str, client_ip: str = "0.0.0.0", qtype: str = "A") -> dict:
        """Evaluates domain query against RPZ rules and behavioral threat checks."""
        clean_qname = qname.strip(".").lower()
        now = time.time()

        # 1. Direct RPZ check
        action = None
        matched_rule = None
        with self._lock:
            if clean_qname in self._rpz_rules:
                action = self._rpz_rules[clean_qname]
                matched_rule = clean_qname
            else:
                for rule_domain, act in self._rpz_rules.items():
                    if clean_qname.endswith("." + rule_domain) or rule_domain == "*":
                        action = act
                        matched_rule = rule_domain
                        break

        # 2. Behavioral inspection if no explicit RPZ
        threat_type = None
        if not action:
            threat, details = DNSInspector.inspect_query(clean_qname, qtype)
            if threat:
                action = "sinkhole"
                threat_type = threat

        if action == "sinkhole":
            event_record = {
                "timestamp": now,
                "client_ip": client_ip,
                "qname": clean_qname,
                "qtype": qtype,
                "action": "sinkhole",
                "resolved_ip": self.sinkhole_ip,
                "reason": f"RPZ match: {matched_rule}" if matched_rule else f"Behavioral threat: {threat_type}",
            }
            with self._lock:
                self._sinkholed_events.append(event_record)
                if len(self._sinkholed_events) > 5000:
                    self._sinkholed_events.pop(0)
            return {
                "action": "SINKHOLE",
                "sinkhole_ip": self.sinkhole_ip,
                "ttl": self.default_ttl,
                "event": event_record,
            }
        elif action == "nxdomain":
            return {"action": "NXDOMAIN", "sinkhole_ip": None, "ttl": 0}
        elif action == "drop":
            return {"action": "DROP", "sinkhole_ip": None, "ttl": 0}

        return {"action": "FORWARD", "sinkhole_ip": None, "ttl": 0}

    def get_sinkhole_events(self, limit: int = 50) -> List[dict]:
        with self._lock:
            return list(self._sinkholed_events[-limit:])


class DoHDoTDetector:
    """Detects unauthorized DNS over HTTPS (DoH) and DNS over TLS (DoT) bypass attempts."""

    KNOWN_DOH_SERVERS = {
        "cloudflare-dns.com", "dns.google", "dns.quad9.net", "doh.opendns.com",
        "dns.adguard.com", "doh.cleanbrowsing.org", "dns.nextdns.io"
    }

    @classmethod
    def is_dot_packet(cls, dport: int, proto: str = "tcp") -> bool:
        """DNS-over-TLS (RFC 7858) typically runs on standard port 853."""
        return int(dport) == 853 and proto.lower() == "tcp"

    @classmethod
    def is_doh_request(cls, host: str, path: str = "") -> Tuple[bool, str]:
        """Identifies DoH queries over HTTP/HTTPS by endpoint host and standard paths."""
        clean_host = host.split(":")[0].strip().lower()
        if clean_host in cls.KNOWN_DOH_SERVERS:
            return True, f"Known public DoH provider: {clean_host}"
        if path.startswith("/dns-query") or path.startswith("/resolve?name="):
            return True, f"Standard DoH protocol path: {path}"
        return False, ""
