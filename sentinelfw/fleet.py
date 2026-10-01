"""SentinelFW Fleet Management & Cluster Synchronization Engine.

Provides multi-node coordination and fleet-wide threat intelligence sharing:
* Node membership, roles (leader, follower), and heartbeat monitoring
* Distributed ban sharing: Instant cluster-wide synchronization of banned IPs
* Configuration drift detection across fleet nodes
"""
import threading
import time
from typing import Dict, List, Optional, Union
from .common import event


class FleetNode:
    """Represents a member node in the SentinelFW fleet cluster."""

    def __init__(self, node_id: str, hostname: str, ip: str, version: str = "4.0.0",
                 role: str = "follower"):
        self.node_id = str(node_id).strip()
        self.hostname = str(hostname).strip()
        self.ip = str(ip).strip()
        self.version = str(version).strip()
        self.role = str(role).lower()  # leader or follower
        self.last_heartbeat = time.time()
        self.config_hash = ""
        self.status = "online"

    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "hostname": self.hostname,
            "ip": self.ip,
            "version": self.version,
            "role": self.role,
            "status": self.status,
            "last_heartbeat": self.last_heartbeat,
            "config_hash": self.config_hash,
        }


class FleetManager:
    """Manages multi-node fleet coordination, ban sharing, and drift tracking."""

    def __init__(self, local_node_id: Optional[Union[dict, str]] = "node-local", **kwargs):
        val = local_node_id if local_node_id != "node-local" else (kwargs.get("local_node_id_or_cfg") or local_node_id)
        if isinstance(val, dict):
            self.local_node_id = str(val.get("fleet", {}).get("node_id") or
                                     val.get("node_id") or "node-local")
        else:
            self.local_node_id = str(val or "node-local")
        self._nodes: Dict[str, FleetNode] = {}
        self._shared_bans: Dict[str, dict] = {}  # ip -> {reason, source_node, timestamp, duration}
        self._lock = threading.RLock()

    def register_node(self, node_id: str, hostname: str, ip: str,
                      version: str = "4.0.0", role: str = "follower") -> FleetNode:
        """Registers a node into the fleet directory."""
        with self._lock:
            node = FleetNode(node_id, hostname, ip, version, role)
            self._nodes[node.node_id] = node
            event("fleet_node_registered", "info", node_id=node.node_id, ip=ip, role=role)
            return node

    def record_heartbeat(self, node_id: str, config_hash: str = "") -> bool:
        """Updates the heartbeat timestamp and config hash for a node."""
        with self._lock:
            node = self._nodes.get(node_id)
            if not node:
                return False
            node.last_heartbeat = time.time()
            node.status = "online"
            if config_hash:
                node.config_hash = config_hash
            return True

    def share_ban(self, ip: str, reason: str, duration: int = 3600,
                  source_node: Optional[str] = None) -> dict:
        """Broadcasts or records a shared ban across the fleet."""
        clean_ip = str(ip).strip()
        record = {
            "ip": clean_ip,
            "reason": str(reason),
            "duration": int(duration),
            "source_node": source_node or self.local_node_id,
            "timestamp": time.time(),
        }
        with self._lock:
            self._shared_bans[clean_ip] = record
            event("fleet_ban_shared", "info", ip=clean_ip, source=record["source_node"])
            return record

    def get_shared_bans(self) -> List[dict]:
        """Returns all active shared bans."""
        now = time.time()
        with self._lock:
            active = []
            for ip, b in list(self._shared_bans.items()):
                if b["duration"] > 0 and (now - b["timestamp"]) > b["duration"]:
                    del self._shared_bans[ip]
                else:
                    active.append(dict(b))
            return active

    def detect_fleet_drift(self, expected_config_hash: str) -> List[dict]:
        """Identifies fleet nodes whose config does not match the leader baseline."""
        drifted = []
        with self._lock:
            for node in self._nodes.values():
                if node.config_hash and node.config_hash != expected_config_hash:
                    drifted.append(node.to_dict())
        return drifted

    def list_nodes(self) -> List[dict]:
        """Returns all registered fleet nodes, marking timed-out nodes offline."""
        now = time.time()
        with self._lock:
            res = []
            for node in self._nodes.values():
                if (now - node.last_heartbeat) > 60.0:
                    node.status = "offline"
                res.append(node.to_dict())
            return res


# Global singleton
fleet_mgr = FleetManager()
