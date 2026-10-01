"""SentinelFW Production Inline IPS (Intrusion Prevention System) Architecture.

Provides deterministic inline attack prevention with bi-directional verdict support:
- Actions: PASS, ALERT, DROP, RESET (TCP RST / ICMP unreachable), QUARANTINE (host isolation)
- Configurable Failure Modes: fail-open vs fail-closed per profile
- Versioned Rule Packs with CVE cross-references, MITRE ATT&CK techniques, and hot-reload/rollback
- Real-time metrics and deterministic verdict pipeline
"""
import copy
import logging
import re
import threading
import time
from typing import Dict, List, Optional, Tuple, Union

logger = logging.getLogger("sentinelfw.ips")


class IPSAction:
    PASS = "PASS"
    ALERT = "ALERT"
    DROP = "DROP"
    RESET = "RESET"
    QUARANTINE = "QUARANTINE"

    ALL_ACTIONS = {PASS, ALERT, DROP, RESET, QUARANTINE}


class IPSFailureMode:
    FAIL_OPEN = "fail-open"
    FAIL_CLOSED = "fail-closed"


class IPSRule:
    """Represents a compiled, versioned IPS signature rule."""

    def __init__(self, rule_id: Union[int, str], name: str, pattern: str,
                 proto: str = "any", dst_ports: Optional[List[int]] = None,
                 action: str = IPSAction.DROP, severity: int = 1,
                 cve_refs: Optional[List[str]] = None, mitre_attack: str = "",
                 enabled: bool = True):
        self.rule_id = str(rule_id)
        self.name = name
        self.raw_pattern = pattern
        self.regex = re.compile(pattern.encode("utf-8") if isinstance(pattern, str) else pattern, re.IGNORECASE | re.DOTALL)
        self.proto = proto.lower()
        self.dst_ports = set(dst_ports) if dst_ports else None
        self.action = action.upper() if action.upper() in IPSAction.ALL_ACTIONS else IPSAction.DROP
        self.severity = int(severity)
        self.cve_refs = cve_refs or []
        self.mitre_attack = mitre_attack
        self.enabled = enabled

    def matches(self, proto: str, dst_port: int, payload: bytes) -> bool:
        if not self.enabled:
            return False
        if self.proto != "any" and self.proto != proto.lower():
            return False
        if self.dst_ports is not None and dst_port not in self.dst_ports:
            return False
        if not payload:
            return False
        return bool(self.regex.search(payload))


# Standard enterprise signature baseline
DEFAULT_SIGNATURES = [
    {
        "rule_id": 2001001,
        "name": "ET EXPLOIT Apache Log4j RCE (CVE-2021-44228)",
        "pattern": r"\$\{jndi:(?:ldap|rmi|dns|nis):[^\}]+\}",
        "proto": "any",
        "action": IPSAction.DROP,
        "severity": 1,
        "cve_refs": ["CVE-2021-44228"],
        "mitre_attack": "T1190: Exploit Public-Facing Application",
    },
    {
        "rule_id": 2001002,
        "name": "ET EXPLOIT Spring4Shell RCE (CVE-2022-22965)",
        "pattern": r"class\.module\.classLoader",
        "proto": "tcp",
        "dst_ports": [80, 443, 8080, 8443],
        "action": IPSAction.DROP,
        "severity": 1,
        "cve_refs": ["CVE-2022-22965"],
        "mitre_attack": "T1190: Exploit Public-Facing Application",
    },
    {
        "rule_id": 2001003,
        "name": "ET EXPLOIT GNU Bash Shellshock Environment RCE (CVE-2014-6271)",
        "pattern": r"\(\)\s*\{[^\}]*\};\s*",
        "proto": "tcp",
        "action": IPSAction.DROP,
        "severity": 1,
        "cve_refs": ["CVE-2014-6271"],
        "mitre_attack": "T1059: Command and Scripting Interpreter",
    },
    {
        "rule_id": 2001004,
        "name": "ET WEB_SPECIFIC_APPS Generic SQL Injection UNION SELECT",
        "pattern": r"(?i)\bunion\s+(?:all\s+)?select\b",
        "proto": "tcp",
        "action": IPSAction.DROP,
        "severity": 2,
        "cve_refs": [],
        "mitre_attack": "T1190: Exploit Public-Facing Application",
    },
    {
        "rule_id": 2001005,
        "name": "ET WEB_SPECIFIC_APPS Path Traversal Sequence",
        "pattern": r"(?:\.\.[\\/]){2,}",
        "proto": "tcp",
        "action": IPSAction.DROP,
        "severity": 2,
        "cve_refs": [],
        "mitre_attack": "T1083: File and Directory Discovery",
    },
    {
        "rule_id": 2001006,
        "name": "ET MALWARE Meterpreter Reverse TCP Stage Handshake",
        "pattern": r"\x00\x00\x00\x0c.*meterpreter",
        "proto": "tcp",
        "action": IPSAction.RESET,
        "severity": 1,
        "cve_refs": [],
        "mitre_attack": "T1071: Application Layer Protocol",
    },
    {
        "rule_id": 2001007,
        "name": "ET MALWARE Cobalt Strike Active Beacon Watermark",
        "pattern": r"(?i)cobaltstrike_beacon_watermark",
        "proto": "any",
        "action": IPSAction.QUARANTINE,
        "severity": 1,
        "cve_refs": [],
        "mitre_attack": "T1071: Application Layer Protocol",
    },
]


class IPSRulePackManager:
    """Manages versioned IPS rule packs with atomic hot-reload and rollback support."""

    def __init__(self, initial_rules: Optional[List[dict]] = None, version: str = "v1.0.0"):
        self.lock = threading.RLock()
        self.version = version
        self._history: List[Tuple[str, List[IPSRule]]] = []
        raw_rules = initial_rules if initial_rules is not None else DEFAULT_SIGNATURES
        self.rules: List[IPSRule] = [self._compile_rule(r) for r in raw_rules]

    def _compile_rule(self, r: dict) -> IPSRule:
        return IPSRule(
            rule_id=r.get("rule_id", 0),
            name=r.get("name", "Unnamed Rule"),
            pattern=r.get("pattern", ""),
            proto=r.get("proto", "any"),
            dst_ports=r.get("dst_ports"),
            action=r.get("action", IPSAction.DROP),
            severity=r.get("severity", 2),
            cve_refs=r.get("cve_refs", []),
            mitre_attack=r.get("mitre_attack", ""),
            enabled=r.get("enabled", True),
        )

    def hot_reload(self, new_rules: List[dict], new_version: str) -> bool:
        """Atomically validates and loads a new rule pack revision."""
        compiled = []
        for r in new_rules:
            try:
                c = self._compile_rule(r)
                compiled.append(c)
            except Exception as e:
                logger.error(f"Failed to compile IPS rule {r.get('rule_id')}: {e}")
                return False

        with self.lock:
            self._history.append((self.version, list(self.rules)))
            # Keep up to 5 rollback snapshots
            if len(self._history) > 5:
                self._history.pop(0)
            self.rules = compiled
            self.version = new_version
            logger.info(f"IPS rules atomically reloaded: version {new_version} ({len(self.rules)} rules)")
            return True

    def rollback(self) -> bool:
        """Reverts the active rule pack to the immediate previous valid version."""
        with self.lock:
            if not self._history:
                return False
            prev_version, prev_rules = self._history.pop()
            self.version = prev_version
            self.rules = prev_rules
            logger.warning(f"IPS rules rolled back to version {prev_version} ({len(self.rules)} rules)")
            return True

    def get_rule_count(self) -> int:
        with self.lock:
            return len(self.rules)


class InlineIPSEngine:
    """Production inline intrusion prevention engine with deterministic verdict pipeline."""

    def __init__(self, rule_pack: Optional[IPSRulePackManager] = None,
                 failure_mode: str = IPSFailureMode.FAIL_CLOSED,
                 profile_name: str = "default"):
        self.rule_pack = rule_pack or IPSRulePackManager()
        self.failure_mode = failure_mode  # fail-closed or fail-open
        self.profile_name = profile_name
        self.lock = threading.RLock()
        self.stats = {
            "packets_inspected": 0,
            "packets_passed": 0,
            "alerts_generated": 0,
            "packets_dropped": 0,
            "packets_reset": 0,
            "hosts_quarantined": 0,
            "fail_open_events": 0,
            "fail_closed_events": 0,
        }
        self.quarantined_hosts: Dict[str, float] = {}  # ip -> timestamp

    def inspect_packet(self, packet_meta: dict) -> dict:
        """Inspects a packet through the IPS signature pipeline.

        Returns verdict dict with keys:
          - action: PASS, ALERT, DROP, RESET, QUARANTINE
          - rule_id, rule_name, severity, cve_refs, mitre_attack, reason
        """
        proto = str(packet_meta.get("proto", "tcp")).lower()
        dst_port = int(packet_meta.get("dst_port", 0) or 0)
        src_ip = str(packet_meta.get("src_ip", "0.0.0.0")).strip()
        payload = packet_meta.get("payload", b"")
        if isinstance(payload, str):
            payload = payload.encode("utf-8", errors="replace")

        with self.lock:
            self.stats["packets_inspected"] += 1

            # Check if host is already under active quarantine
            if src_ip in self.quarantined_hosts:
                self.stats["packets_dropped"] += 1
                return {
                    "action": IPSAction.DROP,
                    "reason": f"Host {src_ip} is in active IPS quarantine",
                    "rule_id": "QUARANTINED",
                    "rule_name": "Host Isolation",
                    "severity": 1,
                    "cve_refs": [],
                    "mitre_attack": "T1071",
                }

        try:
            with self.rule_pack.lock:
                for rule in self.rule_pack.rules:
                    if rule.matches(proto, dst_port, payload):
                        action = rule.action
                        with self.lock:
                            if action == IPSAction.ALERT:
                                self.stats["alerts_generated"] += 1
                                self.stats["packets_passed"] += 1
                            elif action == IPSAction.DROP:
                                self.stats["packets_dropped"] += 1
                            elif action == IPSAction.RESET:
                                self.stats["packets_reset"] += 1
                            elif action == IPSAction.QUARANTINE:
                                self.stats["hosts_quarantined"] += 1
                                self.quarantined_hosts[src_ip] = time.time()

                        return {
                            "action": action,
                            "reason": f"IPS signature triggered: {rule.name}",
                            "rule_id": rule.rule_id,
                            "rule_name": rule.name,
                            "severity": rule.severity,
                            "cve_refs": list(rule.cve_refs),
                            "mitre_attack": rule.mitre_attack,
                        }

            with self.lock:
                self.stats["packets_passed"] += 1
            return {
                "action": IPSAction.PASS,
                "reason": "clean_no_signature_match",
                "rule_id": None,
                "rule_name": None,
                "severity": 0,
                "cve_refs": [],
                "mitre_attack": "",
            }

        except Exception as ex:
            logger.error(f"IPS inspection error for {src_ip}: {ex}")
            with self.lock:
                if self.failure_mode == IPSFailureMode.FAIL_OPEN:
                    self.stats["fail_open_events"] += 1
                    self.stats["packets_passed"] += 1
                    return {
                        "action": IPSAction.PASS,
                        "reason": f"fail_open_on_error: {str(ex)[:100]}",
                        "rule_id": "FAIL_OPEN",
                        "rule_name": "Failure Mode Open",
                        "severity": 1,
                        "cve_refs": [],
                        "mitre_attack": "",
                    }
                else:
                    self.stats["fail_closed_events"] += 1
                    self.stats["packets_dropped"] += 1
                    return {
                        "action": IPSAction.DROP,
                        "reason": f"fail_closed_on_error: {str(ex)[:100]}",
                        "rule_id": "FAIL_CLOSED",
                        "rule_name": "Failure Mode Closed",
                        "severity": 1,
                        "cve_refs": [],
                        "mitre_attack": "",
                    }

    def unquarantine(self, ip: str) -> bool:
        with self.lock:
            if ip in self.quarantined_hosts:
                del self.quarantined_hosts[ip]
                return True
            return False
