"""SentinelFW WAF Virtual Hosts Management.

Provides per-site configuration, upstream mapping, and isolated security profiles:
* Domain and wildcard hostname routing (*.example.com)
* Per-vhost WAF toggles, paranoia levels, and anomaly thresholds
* Per-vhost rate limits and upstream reverse-proxy targets
"""
import fnmatch
import threading
from typing import Dict, List, Optional, Union


class VHost:
    """Represents a virtual host / site configuration."""

    def __init__(self, id: str, domain: str, upstream: str, aliases: Optional[List[str]] = None,
                 waf_enabled: bool = True, paranoia_level: int = 1, anomaly_threshold: int = 5,
                 rate_limit_rpm: int = 600, enabled: bool = True):
        self.id = str(id).strip()
        self.domain = str(domain).strip().lower()
        self.aliases = [str(a).strip().lower() for a in (aliases or [])]
        self.upstream = str(upstream).strip()
        self.waf_enabled = bool(waf_enabled)
        self.paranoia_level = max(1, min(4, int(paranoia_level)))
        self.anomaly_threshold = max(1, int(anomaly_threshold))
        self.rate_limit_rpm = int(rate_limit_rpm)
        self.enabled = bool(enabled)

    def matches(self, host: str) -> bool:
        if not host or not self.enabled:
            return False
        clean_host = host.split(":")[0].strip().lower()
        if clean_host == self.domain or fnmatch.fnmatch(clean_host, self.domain):
            return True
        for alias in self.aliases:
            if clean_host == alias or fnmatch.fnmatch(clean_host, alias):
                return True
        return False

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "domain": self.domain,
            "aliases": self.aliases,
            "upstream": self.upstream,
            "waf_enabled": self.waf_enabled,
            "paranoia_level": self.paranoia_level,
            "anomaly_threshold": self.anomaly_threshold,
            "rate_limit_rpm": self.rate_limit_rpm,
            "enabled": self.enabled,
        }


class VHostManager:
    """Thread-safe manager for virtual host configurations."""

    def __init__(self, vhosts_data: Optional[Union[dict, list]] = None):
        self._vhosts: Dict[str, VHost] = {}
        self._lock = threading.RLock()
        if vhosts_data:
            if isinstance(vhosts_data, list):
                for item in vhosts_data:
                    if isinstance(item, dict):
                        self.add_vhost(item)
            elif isinstance(vhosts_data, dict):
                for k, v in vhosts_data.items():
                    if isinstance(v, dict):
                        spec = dict(v)
                        if "domain" not in spec:
                            spec["domain"] = k
                        self.add_vhost(spec)

    def add_vhost(self, spec: dict) -> VHost:
        with self._lock:
            vh = VHost(
                id=spec.get("id") or spec.get("domain"),
                domain=spec.get("domain", ""),
                upstream=spec.get("upstream", "http://127.0.0.1:8080"),
                aliases=spec.get("aliases", []),
                waf_enabled=spec.get("waf_enabled", True),
                paranoia_level=spec.get("paranoia_level", 1),
                anomaly_threshold=spec.get("anomaly_threshold", 5),
                rate_limit_rpm=spec.get("rate_limit_rpm", 600),
                enabled=spec.get("enabled", True),
            )
            self._vhosts[vh.id] = vh
            return vh

    def remove_vhost(self, vhost_id: str) -> bool:
        with self._lock:
            if vhost_id in self._vhosts:
                del self._vhosts[vhost_id]
                return True
            return False

    def get_vhost(self, vhost_id: str) -> Optional[VHost]:
        with self._lock:
            return self._vhosts.get(vhost_id)

    def match_host(self, host: str) -> Optional[VHost]:
        """Finds the first matching active virtual host for the given hostname."""
        with self._lock:
            for vh in self._vhosts.values():
                if vh.matches(host):
                    return vh
            return None

    def list_vhosts(self) -> List[dict]:
        with self._lock:
            return [vh.to_dict() for vh in self._vhosts.values()]
