"""SentinelFW Cyber Kill Chain Tracker.

Correlates individual attack events into multi-stage attack campaigns per source IP
and dynamically escalates defensive actions as attackers progress through phases.
"""
import collections
import threading
import time
from typing import Dict, List, Optional, Union
from .attack_classifier import AttackEvent
from .common import event

KILL_CHAIN_STAGES = [
    "reconnaissance",
    "initial_access",
    "delivery",
    "exploitation",
    "installation",
    "command_and_control",
    "actions_on_objectives",
    "exfiltration",
]

STAGE_SCORES = {
    "reconnaissance": 10,
    "initial_access": 30,
    "delivery": 40,
    "exploitation": 60,
    "installation": 80,
    "command_and_control": 100,
    "actions_on_objectives": 120,
    "exfiltration": 150,
}


class AttackCampaign:
    """Tracks a sequence of correlated attack events originating from a single source."""

    def __init__(self, source_ip: str):
        self.source_ip = source_ip
        self.first_seen = time.time()
        self.last_seen = self.first_seen
        self.events: List[AttackEvent] = []
        self.stages_reached = set()
        self.highest_stage_idx = 0
        self.total_score = 0
        self.escalation_level = "monitor"  # monitor, ban, critical_lockdown

    def add_event(self, ev: AttackEvent):
        self.last_seen = time.time()
        self.events.append(ev)
        phase = ev.kill_chain_phase.lower()
        self.stages_reached.add(phase)
        self.total_score += STAGE_SCORES.get(phase, 20)

        if phase in KILL_CHAIN_STAGES:
            idx = KILL_CHAIN_STAGES.index(phase)
            if idx > self.highest_stage_idx:
                self.highest_stage_idx = idx

        # Determine escalation policy
        if self.highest_stage_idx >= 5 or self.total_score >= 200:
            self.escalation_level = "critical_lockdown"
        elif self.highest_stage_idx >= 3 or self.total_score >= 70:
            self.escalation_level = "ban"
        else:
            self.escalation_level = "monitor"

    def to_dict(self) -> dict:
        return {
            "source_ip": self.source_ip,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration": round(self.last_seen - self.first_seen, 2),
            "event_count": len(self.events),
            "stages_reached": list(self.stages_reached),
            "highest_stage": KILL_CHAIN_STAGES[self.highest_stage_idx],
            "total_score": self.total_score,
            "escalation_level": self.escalation_level,
        }


class KillChainTracker:
    """Aggregates security events and manages multi-stage threat campaigns."""

    def __init__(self, window_seconds: Optional[Union[dict, int]] = 1800, engine=None, **kwargs):
        if isinstance(window_seconds, dict):
            self.window_seconds = int(window_seconds.get("killchain", {}).get("window_seconds") or
                                      window_seconds.get("window_seconds") or 1800)
            if engine is None and "engine" in window_seconds:
                engine = window_seconds["engine"]
        else:
            self.window_seconds = int(window_seconds if window_seconds is not None else (kwargs.get("window_seconds_or_cfg") or 1800))
        self.engine = engine
        self._lock = threading.RLock()
        self._campaigns: Dict[str, AttackCampaign] = {}

    def track(self, attack: AttackEvent) -> AttackCampaign:
        """Records an attack event and computes campaign escalation."""
        src_ip = attack.source_ip
        if not src_ip or src_ip in ("127.0.0.1", "::1", "0.0.0.0"):
            return None

        now = time.time()
        with self._lock:
            camp = self._campaigns.get(src_ip)
            if camp is None or (now - camp.last_seen > self.window_seconds):
                camp = AttackCampaign(src_ip)
                self._campaigns[src_ip] = camp

            old_level = camp.escalation_level
            camp.add_event(attack)
            new_level = camp.escalation_level

            # Act on escalation change
            if new_level != old_level:
                event(
                    "killchain_escalation",
                    "critical" if new_level == "critical_lockdown" else "high",
                    src=src_ip,
                    old_level=old_level,
                    new_level=new_level,
                    highest_stage=camp.to_dict()["highest_stage"],
                    score=camp.total_score,
                )

                if self.engine and not self.engine.guard.protected(src_ip):
                    if new_level == "critical_lockdown":
                        self.engine.ban(src_ip, f"killchain_critical:{camp.highest_stage_idx}", 604800)  # 7-day ban
                    elif new_level == "ban":
                        self.engine.ban(src_ip, f"killchain_exploit:{camp.highest_stage_idx}", 86400)

            # Cleanup expired campaigns
            expired = [ip for ip, c in self._campaigns.items() if now - c.last_seen > self.window_seconds * 2]
            for ip in expired:
                del self._campaigns[ip]

            return camp

    def get_campaign(self, ip: str) -> Optional[dict]:
        with self._lock:
            c = self._campaigns.get(ip)
            return c.to_dict() if c else None

    def get_all_campaigns(self) -> List[dict]:
        with self._lock:
            return [c.to_dict() for c in self._campaigns.values()]

    def export_mermaid(self, source_ip: str = "") -> str:
        """Exports the cyber kill chain progression as a standard Mermaid flowchart."""
        lines = [
            "graph LR",
            "    classDef reached fill:#cf1322,stroke:#ff4d4f,color:#ffffff,stroke-width:2px;",
            "    classDef pending fill:#1f1f1f,stroke:#434343,color:#8c8c8c;",
        ]
        camp = self.get_campaign(source_ip) if source_ip else None
        reached_stages = set(camp.get("stages_reached", [])) if camp else set()

        for idx, stage in enumerate(KILL_CHAIN_STAGES):
            sid = f"S{idx}"
            sname = stage.replace("_", " ").title()
            lines.append(f'    {sid}["{sname}"]')
            if stage in reached_stages:
                lines.append(f"    class {sid} reached;")
            else:
                lines.append(f"    class {sid} pending;")

            if idx > 0:
                prev_sid = f"S{idx-1}"
                lines.append(f"    {prev_sid} --> {sid}")

        return "\n".join(lines) + "\n"

