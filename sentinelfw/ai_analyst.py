"""SentinelFW Enterprise AI Security Analyst (Advisory Layer).

Provides agentic threat synthesis, root-cause hypothesis generation,
and safe firewall rule suggestions with strict prompt injection guardrails
and mandatory human confirmation.
"""
import json
import logging
import re
import time
from typing import Dict, List, Optional, Tuple, Union

logger = logging.getLogger("sentinelfw.ai_analyst")

PROMPT_INJECTION_PATTERNS = [
    re.compile(r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior)\s+instructions\b"),
    re.compile(r"(?i)\byou\s+are\s+now\s+(?:in\s+)?(?:developer|god|dan)\s+mode\b"),
    re.compile(r"(?i)<\s*/?\s*(?:system|prompt|assistant|human)\s*>"),
    re.compile(r"(?i)\bdisregard\s+(?:the\s+above|system\s+prompt)\b"),
    re.compile(r"(?i)\bdo\s+anything\s+now\b"),
]


class PromptSanitizer:
    """Sanitizes untrusted raw telemetry and payloads before submitting to LLM context."""

    @classmethod
    def sanitize(cls, text: str) -> Tuple[str, bool]:
        """Returns (sanitized_text, injection_detected)."""
        clean_text = text
        injection_detected = False
        for pat in PROMPT_INJECTION_PATTERNS:
            if pat.search(clean_text):
                injection_detected = True
                clean_text = pat.sub("[PROMPT_INJECTION_ATTEMPT_REDACTED]", clean_text)
        return clean_text, injection_detected


class SecurityAnalystAdvisory:
    """Generates structured threat advisory reports and recommended policy rules."""

    @classmethod
    def analyze_incident(cls, incident_data: dict) -> dict:
        """Synthesizes an incident bundle into an executive advisory report."""
        now = time.time()
        title = incident_data.get("title", "Security Alert")
        events = incident_data.get("events", [])
        src_ip = incident_data.get("src_ip", "unknown")

        # 1. Sanitize text inputs against prompt injection
        sanitized_title, inj1 = PromptSanitizer.sanitize(title)
        threat_score = int(incident_data.get("threat_score", 70) or 70)

        # 2. Extract observed MITRE techniques
        mitre_hits = []
        for ev in events:
            mitre = ev.get("mitre_attack") or ev.get("details", {}).get("mitre_attack")
            if mitre and mitre not in mitre_hits:
                mitre_hits.append(mitre)

        # 3. Formulate Root Cause Hypothesis
        hypothesis = "Attacker initiated automated exploitation against public-facing services."
        if any("sql" in str(ev).lower() for ev in events):
            hypothesis = "Web application vulnerability exploitation attempt (SQL Injection / OWASP A03)."
        elif any("log4j" in str(ev).lower() or "cve-2021-44228" in str(ev).lower() for ev in events):
            hypothesis = "Known critical remote code execution attempt targeting Apache Log4j (CVE-2021-44228)."
        elif any("brute" in str(ev).lower() or "auth" in str(ev).lower() for ev in events):
            hypothesis = "Distributed credential stuffing or brute force against authentication endpoint."

        # 4. Synthesize Proposed Policy Rules (Dry-Run / Preview)
        proposed_rules = []
        if src_ip and src_ip != "0.0.0.0" and src_ip != "unknown":
            proposed_rules.append({
                "rule_name": f"AI-Advisory-Ban-{src_ip}",
                "action": "deny",
                "src_ip": src_ip,
                "dst_ip": "any",
                "dport": "any",
                "proto": "any",
                "ttl_seconds": 86400,
                "reason": f"Advisory mitigation for {sanitized_title}",
            })

        return {
            "timestamp": now,
            "incident_title": sanitized_title,
            "threat_score": threat_score,
            "executive_summary": f"High-confidence threat detected from {src_ip} (Threat Score: {threat_score}). {hypothesis}",
            "root_cause_hypothesis": hypothesis,
            "mitre_techniques": mitre_hits,
            "proposed_policy_rules": proposed_rules,
            "prompt_injection_flagged": inj1,
            "mandatory_human_confirmation": True,  # Guardrail: Never execute autonomously without admin signoff
            "status": "pending_admin_review",
        }
