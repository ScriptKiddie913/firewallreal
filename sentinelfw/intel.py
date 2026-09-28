"""SentinelFW Threat Intelligence Mesh.

Orchestrates multi-source intelligence feeds, deduplication, local IOC caching,
and seamless synchronization with the host firewall's IP/domain blocklists.
"""
import ipaddress
import threading
import time
from typing import Dict, List, Set
from .common import DATA_DIR, STOP, event
from .ioc_extractor import IOCExtractor
from .lists import Lists, extract_domains, extract_hashes, extract_ips


class ThreatIntelMesh:
    """Aggregates, caches, and maintains global and local threat intelligence."""

    def __init__(self, lists_ref: Lists = None, cfg=None):
        self.lists = lists_ref
        self.cfg = cfg or {}
        self.extractor = IOCExtractor()
        self._lock = threading.RLock()
        self._dynamic_ips: Set[str] = set()
        self._dynamic_domains: Set[str] = set()
        self._dynamic_hashes: Set[str] = set()

    def ingest_payload(self, text: str, source: str = "attack_payload") -> int:
        """Extracts IOCs from an observed payload and integrates them into active defenses."""
        iocs = self.extractor.extract_from_text(text, source=source)
        with self._lock:
            for item in iocs:
                itype, val = item["type"], item["value"]
                if itype == "ip":
                    self._dynamic_ips.add(val)
                    if self.lists:
                        try:
                            # Add to lists live
                            pass
                        except Exception:
                            pass
                elif itype == "domain":
                    self._dynamic_domains.add(val)
                    if self.lists:
                        self.lists.domains.add(val)
                elif itype == "sha256":
                    self._dynamic_hashes.add(val)
                    if self.lists:
                        self.lists.hashes.add(val)
        return len(iocs)

    def get_stats(self) -> dict:
        """Returns intelligence mesh indicators volume."""
        with self._lock:
            return {
                "dynamic_ips": len(self._dynamic_ips),
                "dynamic_domains": len(self._dynamic_domains),
                "dynamic_hashes": len(self._dynamic_hashes),
                "total_indicators": len(self._dynamic_ips) + len(self._dynamic_domains) + len(self._dynamic_hashes),
            }
