"""SentinelFW Attack Classifier Module.

Classifies raw security events from Suricata, the internal packet sniffer,
process monitors, honeypots, and AppWall into structured, MITRE-mapped attack records.
"""
from dataclasses import asdict, dataclass, field
import time
import uuid
from typing import Any, Dict, List, Optional
from .mitre_mapper import MITREMapper


@dataclass
class AttackEvent:
    timestamp: float
    attack_id: str
    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    protocol: str
    attack_type: str
    attack_subtype: str
    mitre_tactic: str
    mitre_technique: str
    mitre_name: str
    kill_chain_phase: str
    severity: str
    confidence: float
    raw_evidence: Dict[str, Any] = field(default_factory=dict)
    related_events: List[str] = field(default_factory=list)
    response_taken: str = "none"
    process_context: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AttackClassifier:
    """Classifies events and enriches them with kill chain and MITRE metadata."""

    def __init__(self):
        self.mapper = MITREMapper()

    def classify(self, source: str, event_data: dict) -> AttackEvent:
        """Translates heterogeneous alerts into a normalized AttackEvent."""
        now = time.time()
        ev_id = uuid.uuid4().hex[:16]

        if source == "suricata":
            return self._from_suricata(ev_id, now, event_data)
        elif source == "sniffer":
            return self._from_sniffer(ev_id, now, event_data)
        elif source == "appwall":
            return self._from_appwall(ev_id, now, event_data)
        elif source == "honeypot":
            return self._from_honeypot(ev_id, now, event_data)
        elif source == "monitor":
            return self._from_monitor(ev_id, now, event_data)

        # Generic fallback
        return AttackEvent(
            timestamp=now,
            attack_id=ev_id,
            source_ip=event_data.get("src", event_data.get("source_ip", "")),
            source_port=int(event_data.get("sport", event_data.get("source_port", 0))),
            dest_ip=event_data.get("dst", event_data.get("dest_ip", "")),
            dest_port=int(event_data.get("dport", event_data.get("dest_port", 0))),
            protocol=event_data.get("proto", "tcp").lower(),
            attack_type=event_data.get("type", "generic_threat"),
            attack_subtype="generic",
            mitre_tactic="TA0043",
            mitre_technique="T1595",
            mitre_name="Generic Detection",
            kill_chain_phase="reconnaissance",
            severity=event_data.get("severity", "medium"),
            confidence=0.8,
            raw_evidence=event_data,
        )

    def _from_suricata(self, ev_id: str, now: float, ev: dict) -> AttackEvent:
        alert = ev.get("alert", {})
        sig = alert.get("signature", "Suricata Alert")
        sid = alert.get("signature_id", 0)
        sev_num = alert.get("severity", 3)
        severity = "critical" if sev_num == 1 else ("high" if sev_num == 2 else "medium")

        # Guess attack type from signature or category
        sig_low = sig.lower()
        atype = "suricata_alert"
        if "sql" in sig_low:
            atype = "sql_injection_union"
        elif "log4j" in sig_low or "jndi" in sig_low:
            atype = "log4shell"
        elif "spring4shell" in sig_low:
            atype = "spring4shell"
        elif "shellshock" in sig_low:
            atype = "shellshock"
        elif "scan" in sig_low or "sweep" in sig_low:
            atype = "port_scan_tcp_syn"
        elif "brute" in sig_low or "login" in sig_low:
            atype = "ssh_brute"

        mitre = self.mapper.map_attack(atype)
        return AttackEvent(
            timestamp=now,
            attack_id=ev_id,
            source_ip=ev.get("src_ip", ""),
            source_port=int(ev.get("src_port", 0)),
            dest_ip=ev.get("dest_ip", ""),
            dest_port=int(ev.get("dest_port", 0)),
            protocol=ev.get("proto", "tcp").lower(),
            attack_type=atype,
            attack_subtype=f"sid_{sid}",
            mitre_tactic=mitre["tactic"],
            mitre_technique=mitre["technique"],
            mitre_name=mitre["name"],
            kill_chain_phase=self._tactic_to_phase(mitre["tactic"]),
            severity=severity,
            confidence=0.95,
            raw_evidence=ev,
        )

    def _from_sniffer(self, ev_id: str, now: float, ev: dict) -> AttackEvent:
        sig_name = ev.get("name", "unknown_signature")
        mitre = self.mapper.map_attack(sig_name)
        return AttackEvent(
            timestamp=now,
            attack_id=ev_id,
            source_ip=ev.get("src", ""),
            source_port=int(ev.get("sport", 0)),
            dest_ip=ev.get("dst", ""),
            dest_port=int(ev.get("dport", 0)),
            protocol=ev.get("proto", "tcp").lower(),
            attack_type=sig_name,
            attack_subtype="packet_inspection",
            mitre_tactic=mitre["tactic"],
            mitre_technique=mitre["technique"],
            mitre_name=mitre["name"],
            kill_chain_phase=self._tactic_to_phase(mitre["tactic"]),
            severity=ev.get("severity", "high"),
            confidence=0.9,
            raw_evidence=ev,
        )

    def _from_appwall(self, ev_id: str, now: float, ev: dict) -> AttackEvent:
        return AttackEvent(
            timestamp=now,
            attack_id=ev_id,
            source_ip="127.0.0.1",
            source_port=0,
            dest_ip=ev.get("remote_ip", ""),
            dest_port=int(ev.get("remote_port", 0)),
            protocol=ev.get("proto", "tcp").lower(),
            attack_type="application_policy_violation",
            attack_subtype=ev.get("action", "block"),
            mitre_tactic="TA0005",
            mitre_technique="T1059",
            mitre_name="Defense Evasion: Unauthorized Process Network Access",
            kill_chain_phase="execution",
            severity="high",
            confidence=1.0,
            raw_evidence=ev,
            process_context={
                "pid": ev.get("pid"),
                "exe": ev.get("exe"),
                "reason": ev.get("reason"),
            },
        )

    def _from_honeypot(self, ev_id: str, now: float, ev: dict) -> AttackEvent:
        service = ev.get("service", "generic")
        atype = f"{service}_brute" if "login" in ev.get("action", "") else f"{service}_probe"
        mitre = self.mapper.map_attack(atype)
        return AttackEvent(
            timestamp=now,
            attack_id=ev_id,
            source_ip=ev.get("src_ip", ""),
            source_port=int(ev.get("src_port", 0)),
            dest_ip=ev.get("dest_ip", "127.0.0.1"),
            dest_port=int(ev.get("dest_port", 0)),
            protocol="tcp",
            attack_type=atype,
            attack_subtype=f"honeypot_{service}",
            mitre_tactic=mitre["tactic"],
            mitre_technique=mitre["technique"],
            mitre_name=mitre["name"],
            kill_chain_phase=self._tactic_to_phase(mitre["tactic"]),
            severity="high",
            confidence=1.0,
            raw_evidence=ev,
            response_taken="redirected_to_decoy",
        )

    def _from_monitor(self, ev_id: str, now: float, ev: dict) -> AttackEvent:
        kind = ev.get("kind", "process_alert")
        return AttackEvent(
            timestamp=now,
            attack_id=ev_id,
            source_ip="",
            source_port=0,
            dest_ip="",
            dest_port=0,
            protocol="",
            attack_type=kind,
            attack_subtype=ev.get("action", "alert"),
            mitre_tactic="TA0002",
            mitre_technique="T1204",
            mitre_name="Execution: Malicious Process Activity",
            kill_chain_phase="installation",
            severity="high",
            confidence=0.9,
            raw_evidence=ev,
            process_context={"pid": ev.get("pid"), "exe": ev.get("exe")},
        )

    def _tactic_to_phase(self, tactic: str) -> str:
        tactic_map = {
            "TA0043": "reconnaissance",
            "TA0042": "resource_development",
            "TA0001": "initial_access",
            "TA0002": "execution",
            "TA0003": "persistence",
            "TA0004": "privilege_escalation",
            "TA0005": "defense_evasion",
            "TA0006": "credential_access",
            "TA0007": "discovery",
            "TA0008": "lateral_movement",
            "TA0009": "collection",
            "TA0011": "command_and_control",
            "TA0010": "exfiltration",
            "TA0040": "impact",
        }
        return tactic_map.get(tactic, "exploitation")
