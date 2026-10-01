"""SentinelFW Reverse-Proxy Load Balancer.

Provides upstream server pool balancing and health management:
* Algorithms: Round-robin, Least-connections, IP-hash
* Session stickiness (cookie-based routing)
* Health checking (TCP socket ping)
* Dynamic failover across healthy backends
"""
import hashlib
import socket
import threading
import time
from typing import Dict, List, Optional, Tuple


class UpstreamBackend:
    """Represents a single upstream destination server."""

    def __init__(self, id: str, address: str, port: int, weight: int = 1,
                 is_healthy: bool = True):
        self.id = str(id).strip()
        self.address = str(address).strip()
        self.port = int(port)
        self.weight = max(1, int(weight))
        self.is_healthy = bool(is_healthy)
        self.active_conns = 0
        self.total_requests = 0
        self.last_check_ts = 0.0

    def check_health(self, timeout: float = 2.0) -> bool:
        """Performs a TCP connect health check."""
        self.last_check_ts = time.time()
        try:
            with socket.create_connection((self.address, self.port), timeout=timeout):
                self.is_healthy = True
                return True
        except Exception:
            self.is_healthy = False
            return False

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "address": self.address,
            "port": self.port,
            "weight": self.weight,
            "is_healthy": self.is_healthy,
            "active_conns": self.active_conns,
            "total_requests": self.total_requests,
            "last_check": self.last_check_ts,
        }


class LoadBalancer:
    """Load balancer managing one or more upstream pools."""

    def __init__(self, algorithm: str = "round_robin"):
        self.algorithm = algorithm.lower()  # round_robin, least_conn, ip_hash
        self._pools: Dict[str, List[UpstreamBackend]] = {}
        self._rr_indexes: Dict[str, int] = {}
        self._lock = threading.RLock()

    def add_backend(self, pool_name: str, id: str, address: str, port: int,
                    weight: int = 1) -> UpstreamBackend:
        with self._lock:
            pool = self._pools.setdefault(pool_name, [])
            for b in pool:
                if b.id == id:
                    b.address = address
                    b.port = port
                    b.weight = weight
                    return b
            be = UpstreamBackend(id, address, port, weight)
            pool.append(be)
            return be

    def remove_backend(self, pool_name: str, id: str) -> bool:
        with self._lock:
            pool = self._pools.get(pool_name, [])
            for i, b in enumerate(pool):
                if b.id == id:
                    del pool[i]
                    return True
            return False

    def select_backend(self, pool_name: str, client_ip: str = "",
                       sticky_cookie: Optional[str] = None) -> Tuple[Optional[UpstreamBackend], Optional[str]]:
        """Selects a healthy backend from the pool and returns (backend, cookie_to_set)."""
        with self._lock:
            pool = self._pools.get(pool_name, [])
            healthy = [b for b in pool if b.is_healthy]
            if not healthy:
                return None, None

            # 1. Sticky Cookie Match
            if sticky_cookie:
                for b in healthy:
                    if b.id == sticky_cookie:
                        b.active_conns += 1
                        b.total_requests += 1
                        return b, sticky_cookie

            chosen = None
            if self.algorithm == "least_conn":
                chosen = min(healthy, key=lambda b: b.active_conns)
            elif self.algorithm == "ip_hash" and client_ip:
                idx = int(hashlib.md5(client_ip.encode()).hexdigest(), 16) % len(healthy)
                chosen = healthy[idx]
            else:  # round_robin default
                idx = self._rr_indexes.get(pool_name, 0) % len(healthy)
                chosen = healthy[idx]
                self._rr_indexes[pool_name] = (idx + 1) % len(healthy)

            chosen.active_conns += 1
            chosen.total_requests += 1
            return chosen, chosen.id

    def release_connection(self, backend: UpstreamBackend):
        """Decrements active connection counter when request finishes."""
        with self._lock:
            if backend:
                backend.active_conns = max(0, backend.active_conns - 1)

    def list_pool(self, pool_name: str) -> List[dict]:
        with self._lock:
            pool = self._pools.get(pool_name, [])
            return [b.to_dict() for b in pool]
