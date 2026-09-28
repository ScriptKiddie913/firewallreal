"""SentinelFW Deep SMTP Protocol Inspector.

Analyzes cleartext SMTP traffic for bulk data exfiltration, relaying, and phishing indicators.
"""
from typing import Dict, Optional, Tuple


class SMTPInspector:
    """Inspects SMTP conversations."""

    @classmethod
    def inspect_command(cls, line: str) -> Tuple[Optional[str], dict]:
        clean = line.strip()
        if not clean:
            return None, {}

        parts = clean.split(" ", 1)
        verb = parts[0].upper()
        arg = parts[1] if len(parts) > 1 else ""

        if verb == "AUTH" and "LOGIN" in arg.upper():
            return None, {"verb": "AUTH", "method": "LOGIN"}

        if verb in ("VRFY", "EXPN"):
            return "service_fingerprint", {"verb": verb, "target": arg}

        return None, {"verb": verb, "arg": arg}
