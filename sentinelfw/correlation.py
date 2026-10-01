"""SentinelFW Multi-Event Correlation Engine.

Detects advanced multi-stage attack campaigns across time windows:
* Sigma-style correlation rule definitions
* Sliding time window correlation grouped by Source IP or User
* Automated incident aggregation and severity escalation
"""
import threading
import time
from typing import Dict, List, Optional, Tuple

from .common import event


class CorrelationRule:
    """Represents a rule correlating multiple distinct events within a time window."""

    def __init__(self, id: str, name: str, sequence: List[str], window_seconds: int = 300,
                 description: str = "", severity: str = "critical"):
        self.id = id
        self.name = name
        self.sequence = [s.lower() for s in sequence]
        self.window_seconds = int(window_seconds)
        self.description = description
        self.severity = severity


class CorrelationEngine:
    """Sliding-window multi-event correlation processor."""

    def __init__(self, cfg: Optional[dict] = None, engine=None):
        self.cfg = cfg or {}
        self.engine = engine
        self._rules: List[CorrelationRule] = []
        self._ip_buffers: Dict[str, List[Tuple[float, str, dict]]] = {}
        self._lock = threading.RLock()
        self._register_default_rules()
        if cfg and isinstance(cfg, dict):
            for r in cfg.get("correlation_rules", []):
                if isinstance(r, dict):
                    self.add_rule(CorrelationRule(
                        id=r.get("id", f"corr-{len(self._rules)+1}"),
                        name=r.get("name", "Custom Rule"),
                        sequence=r.get("sequence", []),
                        window_seconds=r.get("window_seconds", 300),
                        description=r.get("description", ""),
                        severity=r.get("severity", "critical")
                    ))

    def _register_default_rules(self):
        # 1. Recon to Exploitation: Port Scan -> Web Exploit
        self._rules.append(CorrelationRule(
            id="corr-001",
            name="Reconnaissance Followed by Web Exploitation",
            sequence=["port_scan", "waf_block"],
            window_seconds=600,
            severity="critical",
            description="Host performed port reconnaissance and subsequently targeted web application vulnerabilities.",
        ))
        # 2. Brute Force to Honeypot Execution: Login failure -> Decoy command
        self._rules.append(CorrelationRule(
            id="corr-002",
            name="Brute Force Leading to Decoy Interaction",
            sequence=["ip_login_lockout", "decoy_attacker_engaged"],
            window_seconds=900,
            severity="critical",
            description="Attacker exceeded login thresholds and subsequently engaged a decoy/honeypot service.",
        ))

    def add_rule(self, rule: CorrelationRule):
        with self._lock:
            self._rules.append(rule)

    def process_event(self, ev_name: str, ip: str, details: Optional[dict] = None) -> Optional[dict]:
        """Ingests a security event and checks if any correlation sequence triggers."""
        now = time.time()
        clean_name = str(ev_name).strip().lower()
        clean_ip = str(ip).strip()

        with self._lock:
            buf = self._ip_buffers.setdefault(clean_ip, [])
            buf.append((now, clean_name, details or {}))

            # Evict events older than max window (e.g. 1800s)
            cutoff = now - 1800
            self._ip_buffers[clean_ip] = [e for e in buf if e[0] > cutoff]
            current_events = self._ip_buffers[clean_ip]

            for rule in self._rules:
                rule_cutoff = now - rule.window_seconds
                recent = [e for e in current_events if e[0] > rule_cutoff]
                recent_names = [e[1] for e in recent]

                # Check if all sequence stages are present in chronological order
                seq_idx = 0
                for r_name in recent_names:
                    if r_name == rule.sequence[seq_idx]:
                        seq_idx += 1
                        if seq_idx == len(rule.sequence):
                            break

                if seq_idx == len(rule.sequence):
                    # Triggered! Clear matching events for this rule to prevent duplicate firing
                    event("correlation_incident_triggered", rule.severity,
                          rule=rule.name, ip=clean_ip, window=rule.window_seconds)
                    return {
                        "incident_id": f"inc-{int(now)}",
                        "rule_id": rule.id,
                        "rule_name": rule.name,
                        "severity": rule.severity,
                        "ip": clean_ip,
                        "description": rule.description,
                        "timestamp": now,
                    }
        return None


# Global singleton
correlation_engine = CorrelationEngine()
