"""SentinelFW Virtual Domains (VDOMs) & Multi-Tenancy Engine (Phase 29).

Provides logical isolation of network policies, interfaces, routing tables,
and tenant resource quotas across multiple independent organizations or departments.
"""
import copy
import json
import logging
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .common import DATA_DIR, atomic_write, event

logger = logging.getLogger("sentinelfw.vdom")

VDOMS_FILE = DATA_DIR / "vdoms.json"


class VDOMQuotaExceeded(Exception):
    """Raised when a tenant violates its allocated resource quota."""
    pass


class VDOMInterfaceConflict(Exception):
    """Raised when an interface is assigned to more than one VDOM."""
    pass


class VDOMPermissionDenied(Exception):
    """Raised on cross-tenant access violation."""
    pass


class VDOM:
    """Represents a virtual firewall instance with isolated policies, routes, and quotas."""

    def __init__(
        self,
        vdom_id: str,
        name: str,
        interfaces: Optional[List[str]] = None,
        quotas: Optional[Dict[str, int]] = None,
        enabled: bool = True,
        description: str = "",
    ):
        self.vdom_id = str(vdom_id).strip().lower()
        self.name = str(name).strip()
        self.description = description
        self.interfaces: Set[str] = set(interfaces or [])
        self.enabled = bool(enabled)
        self.created_at = time.time()
        
        # Default resource quotas
        self.quotas = {
            "max_policies": 500,
            "max_rules": 2000,
            "max_sessions": 50000,
            "max_bandwidth_mbps": 1000,
        }
        if quotas:
            self.quotas.update(quotas)

        # Isolated routing table and policies
        self.policies: List[Dict[str, Any]] = []
        self.routes: List[Dict[str, Any]] = []
        
        # Runtime metrics
        self.stats = {
            "active_sessions": 0,
            "total_packets": 0,
            "total_bytes": 0,
            "dropped_packets": 0,
        }

    def to_dict(self) -> dict:
        return {
            "vdom_id": self.vdom_id,
            "name": self.name,
            "description": self.description,
            "interfaces": sorted(list(self.interfaces)),
            "enabled": self.enabled,
            "created_at": self.created_at,
            "quotas": dict(self.quotas),
            "policy_count": len(self.policies),
            "route_count": len(self.routes),
            "stats": dict(self.stats),
        }

    def check_policy_quota(self, additional_count: int = 1):
        """Validates whether adding policies violates the tenant quota."""
        max_p = self.quotas.get("max_policies", 500)
        if len(self.policies) + additional_count > max_p:
            raise VDOMQuotaExceeded(
                f"VDOM '{self.vdom_id}' exceeded policy quota ({len(self.policies)}/{max_p})"
            )

    def check_session_quota(self):
        """Validates active session count against allocated quota."""
        max_s = self.quotas.get("max_sessions", 50000)
        if self.stats["active_sessions"] >= max_s:
            raise VDOMQuotaExceeded(
                f"VDOM '{self.vdom_id}' reached concurrent session ceiling ({max_s})"
            )

    def add_policy(self, policy: dict) -> dict:
        self.check_policy_quota(1)
        p = copy.deepcopy(policy)
        p["tenant_id"] = self.vdom_id
        if "id" not in p:
            p["id"] = len(self.policies) + 1
        self.policies.append(p)
        return p

    def record_traffic(self, packets: int, octets: int, dropped: bool = False):
        self.stats["total_packets"] += packets
        self.stats["total_bytes"] += octets
        if dropped:
            self.stats["dropped_packets"] += packets


class VDOMManager:
    """Manages virtual domains, interface associations, and cross-tenant boundaries."""

    def __init__(self, storage_path: Optional[Path] = None):
        self.storage_path = storage_path or VDOMS_FILE
        self._lock = threading.RLock()
        self.vdoms: Dict[str, VDOM] = {}
        self._interface_map: Dict[str, str] = {}  # interface -> vdom_id
        self._init_default_vdom()
        self.load()

    def _init_default_vdom(self):
        root = VDOM(
            vdom_id="root",
            name="Default Root VDOM",
            description="Global management and default traffic domain",
            interfaces=["lo", "any"],
            quotas={"max_policies": 10000, "max_rules": 50000, "max_sessions": 500000, "max_bandwidth_mbps": 10000},
        )
        self.vdoms["root"] = root
        for iface in root.interfaces:
            self._interface_map[iface] = "root"

    def create_vdom(
        self,
        vdom_id: str,
        name: str,
        interfaces: Optional[List[str]] = None,
        quotas: Optional[Dict[str, int]] = None,
        description: str = "",
    ) -> VDOM:
        vdom_id = vdom_id.strip().lower()
        if not vdom_id:
            raise ValueError("vdom_id cannot be empty")
        
        with self._lock:
            if vdom_id in self.vdoms:
                raise ValueError(f"VDOM '{vdom_id}' already exists")

            interfaces = interfaces or []
            # Check for interface conflicts
            for iface in interfaces:
                if iface in self._interface_map and self._interface_map[iface] != vdom_id:
                    owner = self._interface_map[iface]
                    raise VDOMInterfaceConflict(
                        f"Interface '{iface}' is already assigned to VDOM '{owner}'"
                    )

            vdom = VDOM(
                vdom_id=vdom_id,
                name=name,
                interfaces=interfaces,
                quotas=quotas,
                description=description,
            )
            self.vdoms[vdom_id] = vdom
            for iface in interfaces:
                self._interface_map[iface] = vdom_id

            self.save()
            event("vdom_created", "info", vdom_id=vdom_id, name=name)
            return vdom

    def delete_vdom(self, vdom_id: str):
        vdom_id = vdom_id.strip().lower()
        if vdom_id == "root":
            raise ValueError("Root VDOM cannot be deleted")

        with self._lock:
            if vdom_id not in self.vdoms:
                raise KeyError(f"VDOM '{vdom_id}' not found")

            vdom = self.vdoms.pop(vdom_id)
            for iface in vdom.interfaces:
                if self._interface_map.get(iface) == vdom_id:
                    del self._interface_map[iface]

            self.save()
            event("vdom_deleted", "info", vdom_id=vdom_id)

    def assign_interface(self, vdom_id: str, interface: str):
        vdom_id = vdom_id.strip().lower()
        interface = interface.strip()
        with self._lock:
            if vdom_id not in self.vdoms:
                raise KeyError(f"VDOM '{vdom_id}' not found")

            existing_owner = self._interface_map.get(interface)
            if existing_owner and existing_owner != vdom_id:
                raise VDOMInterfaceConflict(
                    f"Interface '{interface}' is already owned by VDOM '{existing_owner}'"
                )

            self.vdoms[vdom_id].interfaces.add(interface)
            self._interface_map[interface] = vdom_id
            self.save()

    def get_vdom_for_interface(self, interface: str) -> VDOM:
        """Resolves packet or flow incoming interface to its owning VDOM."""
        with self._lock:
            vdom_id = self._interface_map.get(interface, "root")
            return self.vdoms.get(vdom_id, self.vdoms["root"])

    def validate_tenant_access(self, requesting_tenant: Optional[str], target_tenant: str):
        """Enforces strict tenant isolation preventing cross-tenant leakage."""
        if not requesting_tenant or requesting_tenant == "root":
            # Root/SuperAdmin has global access
            return
        if requesting_tenant.lower() != target_tenant.lower():
            raise VDOMPermissionDenied(
                f"Tenant '{requesting_tenant}' denied access to resource belonging to '{target_tenant}'"
            )

    def list_vdoms(self, requesting_tenant: Optional[str] = None) -> List[dict]:
        with self._lock:
            if requesting_tenant and requesting_tenant != "root":
                v = self.vdoms.get(requesting_tenant.lower())
                return [v.to_dict()] if v else []
            return [v.to_dict() for v in self.vdoms.values()]

    def get_vdom(self, vdom_id: str, requesting_tenant: Optional[str] = None) -> Optional[VDOM]:
        vdom_id = vdom_id.strip().lower()
        self.validate_tenant_access(requesting_tenant, vdom_id)
        with self._lock:
            return self.vdoms.get(vdom_id)

    def save(self):
        data = {
            "vdoms": {
                vid: {
                    "vdom_id": v.vdom_id,
                    "name": v.name,
                    "description": v.description,
                    "interfaces": list(v.interfaces),
                    "enabled": v.enabled,
                    "created_at": v.created_at,
                    "quotas": v.quotas,
                    "policies": v.policies,
                    "routes": v.routes,
                }
                for vid, v in self.vdoms.items()
            }
        }
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(self.storage_path, json.dumps(data, indent=2))

    def load(self):
        if not self.storage_path.exists():
            return
        try:
            with open(self.storage_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            stored = data.get("vdoms", {})
            with self._lock:
                for vid, vdata in stored.items():
                    vdom = VDOM(
                        vdom_id=vdata["vdom_id"],
                        name=vdata.get("name", vid),
                        interfaces=vdata.get("interfaces", []),
                        quotas=vdata.get("quotas", {}),
                        enabled=vdata.get("enabled", True),
                        description=vdata.get("description", ""),
                    )
                    vdom.created_at = vdata.get("created_at", time.time())
                    vdom.policies = vdata.get("policies", [])
                    vdom.routes = vdata.get("routes", [])
                    self.vdoms[vdom.vdom_id] = vdom
                    for iface in vdom.interfaces:
                        self._interface_map[iface] = vdom.vdom_id
        except Exception as ex:
            logger.warning("Failed to load VDOMs from disk: %s", ex)


vdom_manager = VDOMManager()
