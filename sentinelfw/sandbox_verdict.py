"""SentinelFW Sandbox Verdict Engine.

Calculates behavioral risk scores from sandbox observations and renders security verdicts
(CLEAN, SUSPICIOUS, MALICIOUS, EXPLOIT) with explainable indicator breakdown.
"""
from typing import Dict, List


class SandboxVerdict:
    """Evaluates behavioral indicators observed during detonation."""

    RULE_SCORES = {
        "creates_temp_executable": (20, "Created executable binary in temporary directory"),
        "mass_file_modification": (40, "Rapid modification of multiple files with differing extensions (Ransomware indicator)"),
        "bad_network_connection": (50, "Attempted network connection to known malicious or blocklisted host"),
        "spawns_system_shell": (15, "Spawned interactive system shell (cmd.exe, powershell.exe, sh, bash)"),
        "modifies_persistence_keys": (30, "Modified startup persistence keys or scheduled tasks"),
        "disables_security_controls": (60, "Attempted to tamper with or disable Defender/Firewall services"),
        "drops_and_executes_payload": (70, "Downloaded and attempted execution of secondary payload"),
        "reads_credential_stores": (50, "Attempted access to security credential stores (/etc/shadow, SAM, LSASS)"),
        "suspicious_dns_query": (35, "Generated high-entropy DGA or C2 DNS queries"),
        "ransomware_note_detected": (50, "Created ransom note or instructions on filesystem"),
    }

    @classmethod
    def evaluate(cls, indicators: List[str], details: Dict = None) -> dict:
        total_score = 0
        matched_rules = []

        for ind in indicators:
            if ind in cls.RULE_SCORES:
                score, desc = cls.RULE_SCORES[ind]
                total_score += score
                matched_rules.append({"rule": ind, "score": score, "description": desc})

        # Extra checks from detailed activity
        if details:
            modified_count = len(details.get("files_modified", []))
            if modified_count >= 10:
                score, desc = cls.RULE_SCORES["mass_file_modification"]
                if "mass_file_modification" not in indicators:
                    total_score += score
                    matched_rules.append({"rule": "mass_file_modification", "score": score, "description": desc})

        if total_score >= 100:
            verdict = "MALICIOUS"
        elif total_score >= 40:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"

        return {
            "verdict": verdict,
            "total_score": total_score,
            "matched_rules": matched_rules,
            "is_threat": verdict in ("MALICIOUS", "SUSPICIOUS"),
        }
