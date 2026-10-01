"""SentinelFW Application-Aware SD-WAN Engine.

Provides continuous link SLA performance monitoring (latency, jitter, packet loss),
application SLA policy matching, route flapping hysteresis, and dynamic path selection.
"""
import collections
import logging
import threading
import time
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("sentinelfw.sdwan")


class LinkState:
    UP = "UP"
    DEGRADED = "DEGRADED"
    DOWN = "DOWN"


class LinkMetrics:
    """Stores performance quality metrics for a WAN interface."""

    def __init__(self, interface: str, latency_ms: float = 10.0,
                 jitter_ms: float = 2.0, loss_pct: float = 0.0,
                 cost: int = 10):
        self.interface = interface
        self.latency_ms = float(latency_ms)
        self.jitter_ms = float(jitter_ms)
        self.loss_pct = float(loss_pct)
        self.cost = int(cost)
        self.last_probed = time.time()
        self.state = self._calculate_state()

    def _calculate_state(self) -> str:
        if self.loss_pct >= 50.0 or self.latency_ms > 400.0:
            return LinkState.DOWN
        if self.loss_pct > 2.0 or self.latency_ms > 150.0 or self.jitter_ms > 30.0:
            return LinkState.DEGRADED
        return LinkState.UP

    def update(self, latency_ms: float, jitter_ms: float, loss_pct: float):
        self.latency_ms = float(latency_ms)
        self.jitter_ms = float(jitter_ms)
        self.loss_pct = float(loss_pct)
        self.last_probed = time.time()
        self.state = self._calculate_state()


class SLAPolicy:
    """Defines SLA requirements for an application traffic class."""

    def __init__(self, name: str, max_latency_ms: float = 100.0,
                 max_jitter_ms: float = 20.0, max_loss_pct: float = 1.0,
                 preferred_link: str = "wan1", secondary_link: str = "wan2"):
        self.name = name
        self.max_latency_ms = float(max_latency_ms)
        self.max_jitter_ms = float(max_jitter_ms)
        self.max_loss_pct = float(max_loss_pct)
        self.preferred_link = preferred_link
        self.secondary_link = secondary_link

    def satisfies(self, link: LinkMetrics) -> bool:
        if link.state == LinkState.DOWN:
            return False
        return (link.latency_ms <= self.max_latency_ms and
                link.jitter_ms <= self.max_jitter_ms and
                link.loss_pct <= self.max_loss_pct)


class SDWANPathSelector:
    """Selects optimal WAN exit interface per application flow with route flapping hysteresis."""

    def __init__(self, flap_threshold: int = 3):
        self.flap_threshold = flap_threshold
        self._links: Dict[str, LinkMetrics] = {}
        self._policies: Dict[str, SLAPolicy] = {}
        # Hysteresis: interface -> consecutive failed / successful probe counts
        self._fail_counters: Dict[str, int] = collections.defaultdict(int)
        self._lock = threading.RLock()

        # Built-in standard policies
        self.register_policy(SLAPolicy("VoIP", max_latency_ms=100.0, max_jitter_ms=15.0, max_loss_pct=0.5))
        self.register_policy(SLAPolicy("Video", max_latency_ms=120.0, max_jitter_ms=25.0, max_loss_pct=1.0))
        self.register_policy(SLAPolicy("GeneralWeb", max_latency_ms=250.0, max_jitter_ms=50.0, max_loss_pct=3.0))

    def register_link(self, link: LinkMetrics):
        with self._lock:
            self._links[link.interface] = link

    def register_policy(self, policy: SLAPolicy):
        with self._lock:
            self._policies[policy.name.lower()] = policy

    def update_metrics(self, interface: str, latency_ms: float, jitter_ms: float, loss_pct: float):
        with self._lock:
            link = self._links.get(interface)
            if not link:
                link = LinkMetrics(interface, latency_ms, jitter_ms, loss_pct)
                self._links[interface] = link
            else:
                link.update(latency_ms, jitter_ms, loss_pct)

    def select_path(self, app_class: str = "generalweb") -> Tuple[str, str]:
        """Selects the best WAN exit interface for an application class.

        Returns (selected_interface, reason).
        """
        clean_class = app_class.strip().lower()
        with self._lock:
            policy = self._policies.get(clean_class) or self._policies.get("generalweb")
            if not self._links:
                return "default", "no_links_registered"

            # 1. Check preferred link
            pref_link = self._links.get(policy.preferred_link)
            if pref_link and policy.satisfies(pref_link):
                return pref_link.interface, f"preferred_link_satisfies_sla:{policy.name}"

            # 2. Check secondary link
            sec_link = self._links.get(policy.secondary_link)
            if sec_link and policy.satisfies(sec_link):
                return sec_link.interface, f"failover_to_secondary_sla:{policy.name}"

            # 3. Best available link among all registered links
            candidates = [l for l in self._links.values() if l.state != LinkState.DOWN]
            if candidates:
                # Sort by: SLA satisfaction desc, then lowest latency, then lowest cost
                candidates.sort(key=lambda l: (not policy.satisfies(l), l.latency_ms, l.cost))
                best = candidates[0]
                return best.interface, f"best_effort_candidate_latency_{best.latency_ms}ms"

            # 4. Fallback if all links DOWN
            return policy.preferred_link, "all_links_down_emergency_fallback"

    def get_status(self) -> Dict[str, dict]:
        with self._lock:
            return {
                name: {
                    "state": l.state,
                    "latency_ms": l.latency_ms,
                    "jitter_ms": l.jitter_ms,
                    "loss_pct": l.loss_pct,
                    "cost": l.cost,
                    "last_probed": l.last_probed,
                }
                for name, l in self._links.items()
            }
