"""SentinelFW IOC (Indicator of Compromise) Extractor.

Automatically mines IPs, domains, hashes, and URLs from honeypot interactions,
sandbox detonation reports, and IDS alerts to enrich local blocklists.
"""
import hashlib
import ipaddress
import re
import time
from typing import Dict, List, Set

IP_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
DOMAIN_REGEX = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
SHA256_REGEX = re.compile(r"\b[0-9a-fA-F]{64}\b")
URL_REGEX = re.compile(r"https?://[^\s<>\"']+")


class IOCExtractor:
    """Extracts network and host indicators from raw attack payloads."""

    def __init__(self):
        self._extracted_ips: Set[str] = set()
        self._extracted_domains: Set[str] = set()
        self._extracted_hashes: Set[str] = set()

    def extract_from_text(self, text: str, source: str = "general") -> List[dict]:
        """Scans arbitrary text or payload string for IOCs."""
        if not text:
            return []

        results = []
        now = time.time()

        # 1. IP Addresses
        for ip in IP_REGEX.findall(text):
            try:
                ip_obj = ipaddress.ip_address(ip)
                # Filter strictly loopback, link-local, and RFC1918 LAN
                is_local = (
                    ip_obj.is_loopback or
                    ip_obj.is_link_local or
                    ip_obj in ipaddress.ip_network("10.0.0.0/8") or
                    ip_obj in ipaddress.ip_network("172.16.0.0/12") or
                    ip_obj in ipaddress.ip_network("192.168.0.0/16")
                )
                if not is_local:
                    if ip not in self._extracted_ips:
                        self._extracted_ips.add(ip)
                        results.append({"type": "ip", "value": ip, "source": source, "timestamp": now})
            except ValueError:
                pass

        # 2. SHA-256 Hashes
        for h in SHA256_REGEX.findall(text):
            h_low = h.lower()
            if h_low not in self._extracted_hashes:
                self._extracted_hashes.add(h_low)
                results.append({"type": "sha256", "value": h_low, "source": source, "timestamp": now})

        # 3. Domains
        for d in DOMAIN_REGEX.findall(text):
            d_low = d.lower()
            if not d_low.endswith((".local", ".arpa", ".internal")) and len(d_low) > 4:
                if d_low not in self._extracted_domains:
                    self._extracted_domains.add(d_low)
                    results.append({"type": "domain", "value": d_low, "source": source, "timestamp": now})

        return results

    def extract_from_sandbox_report(self, report: dict) -> List[dict]:
        """Extracts indicators from a sandbox detonation report."""
        text = str(report)
        return self.extract_from_text(text, source="sandbox_report")
