"""SentinelFW: Central Gateway Federation & mTLS Synchronization Client.

Performs a REAL check-in over HTTPS (optional mTLS with client cert/key) and
reports the host posture as it actually is. When no gateway is configured the
client does nothing and reports not_configured — no fake policies, no fake
EDR status. The offline cache only ever holds what a real gateway sent.
"""
import json
import logging
import os
import ssl
import sys
import time
import urllib.request
from pathlib import Path
from typing import Optional, Union

from .common import HOME, VERSION

logger = logging.getLogger("sentinelfw.sync")


class GatewaySyncClient:
    def __init__(self, gateway_url: Optional[Union[dict, str]] = None,
                 client_cert: Optional[str] = None, client_key: Optional[str] = None,
                 posture_provider=None, **kwargs):
        if isinstance(gateway_url, dict):
            gw_cfg = gateway_url.get("gateway_sync", {}) or {}
            self.gateway_url = str(gw_cfg.get("gateway_url") or gateway_url.get("gateway_url") or "").strip()
            self.client_cert = gw_cfg.get("client_cert") or client_cert
            self.client_key = gw_cfg.get("client_key") or client_key
        else:
            self.gateway_url = (gateway_url or kwargs.get("gateway_url_or_cfg") or "").strip()
            self.client_cert = client_cert
            self.client_key = client_key
        self.policy_cache_path = HOME / "cached_policy.json"
        self.last_sync = None
        self.last_error = ""
        # posture_provider() -> dict of REAL subsystem states; injected so the
        # client never fabricates health data itself
        self._posture_provider = posture_provider or (lambda: {})

    def configured(self) -> bool:
        return bool(self.gateway_url)

    def collect_posture(self) -> dict:
        """Assembles host telemetry from the provider; only real signals."""
        p = {
            "version": VERSION,
            "platform": sys.platform,
            "os_name": os.name,
            "pid": os.getpid(),
            "timestamp": time.time(),
        }
        p.update(self._posture_provider())
        return p

    def sync_with_gateway(self) -> bool:
        """POSTs the posture to the gateway and caches the policy it returns.

        Returns False (and caches nothing) when unconfigured or unreachable.
        """
        if not self.configured():
            self.last_error = "no gateway configured"
            return False
        posture = self.collect_posture()
        try:
            req = urllib.request.Request(
                self.gateway_url.rstrip("/") + "/api/gw/checkin",
                data=json.dumps(posture).encode(),
                headers={"Content-Type": "application/json"}, method="POST")
            if self.client_cert and self.client_key:
                ctx = ssl.create_default_context()
                ctx.load_cert_chain(self.client_cert, self.client_key)
                opener = urllib.request.build_opener(
                    urllib.request.HTTPSHandler(context=ctx))
            else:
                opener = urllib.request.build_opener()
            with opener.open(req, timeout=15) as r:
                policy = json.loads(r.read().decode("utf-8", "replace") or "{}")
            self.policy_cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.policy_cache_path.write_text(json.dumps(policy, indent=2))
            self.last_sync = time.time()
            self.last_error = ""
            return True
        except Exception as e:
            self.last_error = str(e)[:200]
            logger.warning("gateway sync failed: %s", self.last_error)
            return False

    def load_cached_policy(self) -> dict:
        """Policy from the last SUCCESSFUL sync (offline fallback)."""
        try:
            return json.loads(self.policy_cache_path.read_text())
        except Exception:
            return {}


def translate_python_to_gateway_config(py_cfg: dict) -> dict:
    """Translates SentinelFW Python config model into SentinelGate GatewayConfig format."""
    gw_policies = []
    for pol in py_cfg.get("firewall_policies", []):
        rule = {
            "id": pol.get("id", 1),
            "name": pol.get("name", "Rule"),
            "src_zone": pol.get("src_zone", "lan"),
            "dst_zone": pol.get("dst_zone", "wan"),
            "src_addr": pol.get("src") or ["any"],
            "dst_addr": pol.get("dst") or ["any"],
            "services": pol.get("services") or ["ANY"],
            "apps": pol.get("apps") or [],
            "action": pol.get("action", "deny"),
            "log_traffic": bool(pol.get("log") or pol.get("log_traffic")),
            "enabled": pol.get("enabled", True),
        }
        if pol.get("users"):
            rule["users"] = pol["users"]
        if pol.get("groups"):
            rule["groups"] = pol["groups"]
        if pol.get("devices"):
            rule["devices"] = pol["devices"]
        if pol.get("device_posture"):
            rule["device_posture"] = pol["device_posture"]
        if pol.get("domains"):
            rule["domains"] = pol["domains"]
        if pol.get("ttl"):
            rule["ttl"] = pol["ttl"]
        if pol.get("tenant_id"):
            rule["tenant_id"] = pol["tenant_id"]
        if pol.get("nat"):
            rule["nat"] = {"type": pol.get("nat_type", "masquerade")}
            if pol.get("nat_target"):
                rule["nat"]["target_ip"] = pol["nat_target"]
        if pol.get("ips") or pol.get("ips_profile"):
            rule.setdefault("inspection", {})["ips_profile"] = pol.get("ips_profile", "default")
        gw_policies.append(rule)

    addresses = []
    for name, members in (py_cfg.get("address_groups") or {}).items():
        addresses.append({"name": name, "members": members})

    return {
        "version": "4.0.0",
        "system": {
            "hostname": "sentinelfw-host",
            "flowtable_offload": True,
            "xdp_prefilter": True,
        },
        "interfaces": [
            {"name": "eth0", "zone": "wan", "ip_addresses": ["198.51.100.1/24"], "offload": True},
            {"name": "eth1", "zone": "lan", "ip_addresses": ["192.168.1.1/24"], "offload": True},
        ],
        "addresses": addresses,
        "services": [
            {"name": "HTTP_HTTPS", "protocol": "tcp", "ports": "80,443"},
            {"name": "DNS", "protocol": "udp", "ports": "53"},
            {"name": "SSH", "protocol": "tcp", "ports": "22"},
        ],
        "policies": gw_policies,
    }


def translate_gateway_to_python_config(gw_cfg: dict) -> dict:
    """Translates SentinelGate GatewayConfig format into SentinelFW Python config model."""
    py_policies = []
    for pol in gw_cfg.get("policies", []):
        rule = {
            "id": pol.get("id", 1),
            "name": pol.get("name", "Rule"),
            "src_zone": pol.get("src_zone", "lan"),
            "dst_zone": pol.get("dst_zone", "wan"),
            "direction": "both",
            "src": pol.get("src_addr") or ["any"],
            "dst": pol.get("dst_addr") or ["any"],
            "services": pol.get("services") or ["ANY"],
            "apps": pol.get("apps") or [],
            "action": pol.get("action", "deny"),
            "log": pol.get("log_traffic", True),
            "enabled": pol.get("enabled", True),
        }
        if pol.get("users"):
            rule["users"] = pol["users"]
        if pol.get("groups"):
            rule["groups"] = pol["groups"]
        if pol.get("devices"):
            rule["devices"] = pol["devices"]
        if pol.get("device_posture"):
            rule["device_posture"] = pol["device_posture"]
        if pol.get("domains"):
            rule["domains"] = pol["domains"]
        if pol.get("ttl"):
            rule["ttl"] = pol["ttl"]
        if pol.get("tenant_id"):
            rule["tenant_id"] = pol["tenant_id"]
        if pol.get("nat"):
            rule["nat"] = True
            rule["nat_type"] = pol["nat"].get("type", "masquerade")
            if pol["nat"].get("target_ip"):
                rule["nat_target"] = pol["nat"]["target_ip"]
        if pol.get("inspection", {}).get("ips_profile"):
            rule["ips"] = True
            rule["ips_profile"] = pol["inspection"]["ips_profile"]
        py_policies.append(rule)

    address_groups = {}
    for ag in gw_cfg.get("addresses", []):
        address_groups[ag["name"]] = ag.get("members", [])

    return {
        "firewall_policies": py_policies,
        "address_groups": address_groups,
    }
