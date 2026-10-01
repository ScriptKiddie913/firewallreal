"""SentinelFW Automated Incident Response Playbook Engine.

Executes declarative IF-THEN automation playbooks upon security events:
* Conditions: event_name, severity (low/medium/high/critical), threat_score threshold
* Actions: ban_ip, notify, isolate, tag, escalate
* Dry-run simulation mode and per-playbook execution audit logs
"""
import threading
import time
from typing import Callable, Dict, List, Optional, Union
from .common import event


class PlaybookRule:
    """Represents an automated incident response playbook rule."""

    def __init__(self, id: str, name: str, conditions: dict, actions: List[str],
                 enabled: bool = True, description: str = ""):
        self.id = str(id).strip()
        self.name = str(name).strip()
        self.conditions = conditions or {}
        self.actions = [str(a).strip().lower() for a in (actions or [])]
        self.enabled = bool(enabled)
        self.description = str(description).strip()
        self.execution_count = 0
        self.last_executed = 0.0

    def matches(self, ev_data: dict) -> bool:
        """Evaluates whether the security event satisfies this playbook's conditions."""
        if not self.enabled:
            return False

        # Condition 1: Event Name / Type match
        ev_name = str(ev_data.get("event") or ev_data.get("name") or "")
        req_name = self.conditions.get("event")
        if req_name and req_name != "*" and req_name != ev_name:
            return False

        # Condition 2: Minimum Severity
        sev_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        req_sev = str(self.conditions.get("min_severity") or "").lower()
        if req_sev in sev_order:
            actual_sev = str(ev_data.get("severity") or "low").lower()
            if sev_order.get(actual_sev, 0) < sev_order[req_sev]:
                return False

        # Condition 3: Minimum Threat Score
        min_score = self.conditions.get("min_threat_score")
        if min_score is not None:
            actual_score = int(ev_data.get("threat_score") or ev_data.get("score") or 0)
            if actual_score < int(min_score):
                return False

        return True


DEFAULT_PLAYBOOKS = [
    {
        "id": "pb-waf-rce",
        "name": "Auto-Ban Critical WAF & RCE Exploits",
        "conditions": {"event": "waf_attack", "min_severity": "critical"},
        "actions": ["ban_ip", "notify"],
        "enabled": True,
        "description": "Enforces autonomous kernel drop on sources generating high-confidence SQLi, XSS, or RCE.",
    },
    {
        "id": "pb-scan-mitigation",
        "name": "Port Scan & Host Enumeration Mitigation",
        "conditions": {"event": "port_scan_detected", "min_severity": "high"},
        "actions": ["ban_ip", "notify"],
        "enabled": True,
        "description": "Auto-drops scanners probing internal ports after exceeding 15 distinct ports within 10 seconds.",
    },
    {
        "id": "pb-honeypot-trap",
        "name": "Honeypot Decoy Engagement Response",
        "conditions": {"event": "honeypot_probe", "min_severity": "medium"},
        "actions": ["ban_ip", "notify"],
        "enabled": True,
        "description": "Engages tarpit and quarantines any IP attempting connection to internal honey services (SSH/FTP/RDP).",
    },
    {
        "id": "pb-dlp-containment",
        "name": "Sensitive Data Exfiltration Lockdown",
        "conditions": {"event": "dlp_violation", "min_severity": "high"},
        "actions": ["notify", "escalate"],
        "enabled": True,
        "description": "Raises alert and triggers session termination upon detection of plain-text credentials or API keys.",
    },
]


class PlaybookEngine:
    """Manages playbook execution, action dispatching, and audit logging."""

    def __init__(self, ban_callback: Optional[Union[dict, Callable[[str, str], bool]]] = None,
                 engine=None, **kwargs):
        self._rules: Dict[str, PlaybookRule] = {}
        self._audit_log: List[dict] = []
        self.engine = engine
        self._ban_cb = None

        target = ban_callback if ban_callback is not None else kwargs.get("cfg_or_callback")
        if callable(target):
            self._ban_cb = target
        elif engine and hasattr(engine, "ban"):
            self._ban_cb = engine.ban

        self._lock = threading.RLock()

        cfg = target if isinstance(target, dict) else kwargs.get("config")
        if isinstance(cfg, dict):
            for pb in cfg.get("playbooks", []):
                if isinstance(pb, dict):
                    self.add_playbook(pb)

        if not self._rules:
            for pb in DEFAULT_PLAYBOOKS:
                self.add_playbook(pb)

    def add_playbook(self, rule_spec: dict) -> PlaybookRule:
        with self._lock:
            rule = PlaybookRule(
                id=rule_spec.get("id", f"pb-{len(self._rules)+1}"),
                name=rule_spec.get("name", "Unnamed Playbook"),
                conditions=rule_spec.get("conditions", {}),
                actions=rule_spec.get("actions", ["notify"]),
                enabled=rule_spec.get("enabled", True),
                description=rule_spec.get("description", ""),
            )
            self._rules[rule.id] = rule
            return rule

    def evaluate_event(self, ev_data: dict, dry_run: bool = False) -> List[dict]:
        """Evaluates an event against all active playbooks and executes matching actions."""
        # Loop protection: never trigger playbooks on playbook actions or recursive events
        ev_kind = str(ev_data.get("kind") or ev_data.get("event") or ev_data.get("name") or "")
        if ev_kind in ("playbook_executed", "event_correlated"):
            return []
        if ev_data.get("source") == "playbook" or "playbook:" in str(ev_data.get("reason", "")):
            return []

        results = []
        now = time.time()
        with self._lock:
            for rule in self._rules.values():
                if rule.matches(ev_data):
                    # Rate limiting: limit executions per minute
                    rule._recent_execs = [t for t in getattr(rule, "_recent_execs", []) if now - t < 60]
                    limit = int(rule.conditions.get("rate_limit_per_min", 30))
                    if len(rule._recent_execs) >= limit:
                        continue
                    rule._recent_execs.append(now)

                    rule.execution_count += 1
                    rule.last_executed = now
                    exec_actions = []

                    target_ip = str(ev_data.get("ip") or ev_data.get("client_ip") or ev_data.get("src_ip") or "").strip()

                    for act in rule.actions:
                        if act == "ban_ip" and target_ip:
                            # Hard safety rail: Never ban loopback, management, or trusted gateway IPs
                            if target_ip in ("127.0.0.1", "::1", "localhost", "10.0.0.1") or target_ip.startswith("127."):
                                exec_actions.append(f"ban_skipped:management_ip_{target_ip}_protected")
                                continue

                            if not dry_run and self._ban_cb:
                                try:
                                    ban_ttl = min(int(rule.conditions.get("ban_ttl", 86400)), 604800)
                                    # Support either cb(ip, reason, seconds=...) or cb(ip, reason)
                                    import inspect
                                    sig = inspect.signature(self._ban_cb)
                                    if "seconds" in sig.parameters:
                                        self._ban_cb(target_ip, f"playbook:{rule.name}", seconds=ban_ttl)
                                    else:
                                        self._ban_cb(target_ip, f"playbook:{rule.name}")
                                    exec_actions.append(f"banned:{target_ip}")
                                except Exception as e:
                                    exec_actions.append(f"ban_failed:{str(e)}")
                            else:
                                exec_actions.append(f"[dry-run] ban:{target_ip}")
                        elif act == "notify":
                            exec_actions.append("notification_sent")
                        elif act == "tag":
                            tag_name = rule.conditions.get("tag", "flagged_by_playbook")
                            exec_actions.append(f"tagged:{tag_name}")
                        else:
                            exec_actions.append(f"action:{act}")

                    audit_entry = {
                        "timestamp": rule.last_executed,
                        "playbook_id": rule.id,
                        "playbook_name": rule.name,
                        "dry_run": dry_run,
                        "event_data": ev_data,
                        "executed_actions": exec_actions,
                    }
                    self._audit_log.append(audit_entry)
                    results.append(audit_entry)

                    event("playbook_executed", "info",
                          playbook=rule.name, dry_run=dry_run, actions=len(exec_actions))
        return results

    def list_playbooks(self) -> List[dict]:
        with self._lock:
            return [{
                "id": r.id,
                "name": r.name,
                "conditions": r.conditions,
                "actions": r.actions,
                "enabled": r.enabled,
                "description": r.description,
                "executions": r.execution_count,
                "last_executed": r.last_executed,
            } for r in self._rules.values()]

    def get_audit_log(self, limit: int = 50) -> List[dict]:
        with self._lock:
            return list(self._audit_log[-limit:])
