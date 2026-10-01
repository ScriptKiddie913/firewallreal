"""SentinelFW Data Loss Prevention (DLP) & Content Inspection Engine.

Zero-dependency regex and algorithmic inspection to detect sensitive data leaks
(Luhn-verified credit cards, SSNs, cryptographic private keys, cloud/API tokens)
with configurable TLS privacy bypass exemptions for banking, medical, and government services.
"""
import fnmatch
import math
import re
from typing import Dict, List, Optional, Tuple, Union

# Default privacy bypass patterns for regulated industries (HIPAA, GLBA)
DEFAULT_PRIVACY_BYPASS = [
    "*.chase.com", "*.bankofamerica.com", "*.wellsfargo.com", "*.citibank.com",
    "*.mychart.com", "*.epic.com", "*.cerner.com",
    "*.irs.gov", "*.healthcare.gov", "*.medicare.gov", "*.ssa.gov",
]

# Regular expressions for sensitive data patterns
SSN_REGEX = re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
PRIVATE_KEY_REGEX = re.compile(r"-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----")
AWS_KEY_REGEX = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
GITHUB_TOKEN_REGEX = re.compile(r"\b(gh[pousr]_[0-9a-zA-Z]{36})\b")
SLACK_TOKEN_REGEX = re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b")
JWT_TOKEN_REGEX = re.compile(r"\b(eyJ[A-Za-z0-9-_=]{10,}\.eyJ[A-Za-z0-9-_=]{10,}\.[A-Za-z0-9-_.+/=]{10,})\b")

# Credit card candidate pattern: 13-19 digits, optionally spaced or hyphenated
CREDIT_CARD_CANDIDATE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")


def luhn_check(card_number: str) -> bool:
    """Validates a credit card number using the Luhn checksum algorithm."""
    digits = [int(c) for c in card_number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    # Check leading IIN/BIN prefixes (Visa 4, MC 51-55 or 22-27, Amex 34/37, Discover 6)
    s = "".join(str(d) for d in digits)
    if not (s.startswith("4") or s.startswith(("51", "52", "53", "54", "55")) or
            s.startswith(("34", "37")) or s.startswith(("6011", "65")) or
            (len(s) >= 4 and 2221 <= int(s[:4]) <= 2720)):
        return False

    checksum = 0
    alternate = False
    for d in reversed(digits):
        if alternate:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
        alternate = not alternate
    return checksum % 10 == 0


def calculate_entropy(data: bytes) -> float:
    """Computes byte Shannon entropy."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


class DLPInspector:
    """Performs deep content inspection to prevent data loss and secret exfiltration."""

    def __init__(self, privacy_bypass_or_cfg: Optional[Union[dict, List[str]]] = None):
        if isinstance(privacy_bypass_or_cfg, dict):
            self.privacy_bypass_list = privacy_bypass_or_cfg.get("privacy_bypass_list") or list(DEFAULT_PRIVACY_BYPASS)
        elif isinstance(privacy_bypass_or_cfg, list):
            self.privacy_bypass_list = list(privacy_bypass_or_cfg)
        else:
            self.privacy_bypass_list = list(DEFAULT_PRIVACY_BYPASS)

    def is_exempt_domain(self, domain: str) -> bool:
        """Checks if a domain is exempted from deep TLS/content inspection."""
        if not domain:
            return False
        d = domain.strip(".").lower()
        for rule in self.privacy_bypass_list:
            r = rule.strip(".").lower()
            if r.startswith("*."):
                base = r[2:]
                if d == base or d.endswith("." + base):
                    return True
            elif fnmatch.fnmatch(d, r) or d == r:
                return True
        return False

    def scan_content(self, content: str, domain: Optional[str] = None) -> List[dict]:
        """
        Scans textual payload for sensitive information leaks.
        Returns a list of detected DLP violations.
        """
        if domain and self.is_exempt_domain(domain):
            return []

        findings = []

        # 1. Private Key Detection
        for match in PRIVATE_KEY_REGEX.finditer(content):
            findings.append({
                "type": "dlp_private_key",
                "severity": "critical",
                "match": match.group()[:40] + "...",
                "description": "Cryptographic private key header exposed"
            })

        # 2. Credit Card Numbers (with Luhn validation)
        for candidate in CREDIT_CARD_CANDIDATE.finditer(content):
            num = re.sub(r"\D", "", candidate.group())
            if luhn_check(num):
                # Mask all but last 4 digits
                masked = ("*" * (len(num) - 4)) + num[-4:]
                findings.append({
                    "type": "dlp_credit_card",
                    "severity": "high",
                    "match": masked,
                    "description": "Luhn-valid credit card number detected in cleartext"
                })

        # 3. Social Security Numbers (SSN)
        for match in SSN_REGEX.finditer(content):
            ssn = match.group()
            masked = "***-**-" + ssn[-4:]
            findings.append({
                "type": "dlp_ssn",
                "severity": "high",
                "match": masked,
                "description": "US Social Security Number format detected"
            })

        # 4. API & Cloud Access Tokens
        for match in AWS_KEY_REGEX.finditer(content):
            findings.append({
                "type": "dlp_api_token",
                "severity": "critical",
                "provider": "AWS",
                "match": match.group()[:6] + "..." + match.group()[-4:],
                "description": "Amazon Web Services Access Key ID exposed"
            })

        for match in GITHUB_TOKEN_REGEX.finditer(content):
            findings.append({
                "type": "dlp_api_token",
                "severity": "critical",
                "provider": "GitHub",
                "match": match.group()[:7] + "..." + match.group()[-4:],
                "description": "GitHub Personal Access Token exposed"
            })

        for match in SLACK_TOKEN_REGEX.finditer(content):
            findings.append({
                "type": "dlp_api_token",
                "severity": "critical",
                "provider": "Slack",
                "match": match.group()[:8] + "...",
                "description": "Slack API token exposed"
            })

        for match in JWT_TOKEN_REGEX.finditer(content):
            findings.append({
                "type": "dlp_api_token",
                "severity": "medium",
                "provider": "JWT",
                "match": match.group()[:15] + "...",
                "description": "JSON Web Token (JWT) exposed in cleartext"
            })

        return findings

    def inspect_raw_payload(self, raw_bytes: bytes, domain: Optional[str] = None) -> Tuple[Optional[str], dict]:
        """
        Inspects raw binary payload for high entropy (encrypted C2 tunnels/obfuscation)
        and textual DLP violations.
        """
        if domain and self.is_exempt_domain(domain):
            return None, {}

        # 1. High-entropy tunnel or packed shellcode heuristic (> 7.4 bits/byte for length > 64)
        if len(raw_bytes) >= 64:
            ent = calculate_entropy(raw_bytes)
            if ent > 7.5:
                return "encrypted_tunnel_heuristic", {
                    "entropy": round(ent, 3),
                    "length": len(raw_bytes),
                    "note": "Payload exhibits near-maximum Shannon entropy typical of covert tunnels or encrypted C2"
                }

        # 2. Textual DLP scan
        try:
            text = raw_bytes.decode("utf-8", errors="ignore")
            dlp_hits = self.scan_content(text, domain=domain)
            if dlp_hits:
                return dlp_hits[0]["type"], {"violations": dlp_hits}
        except Exception:
            pass

        return None, {}


dlp_inspector = DLPInspector()
DLPManager = DLPInspector


class DLPAction:
    ALLOW = "ALLOW"
    LOG = "LOG"
    BLOCK = "BLOCK"
    QUARANTINE = "QUARANTINE"
    REDACT = "REDACT"


class EnterpriseDLPManager(DLPInspector):
    """Enterprise Content-Aware DLP Engine with redaction, custom patterns, and stream policies."""

    def __init__(self, privacy_bypass_or_cfg: Optional[Union[dict, List[str]]] = None,
                 default_action: str = DLPAction.BLOCK):
        super().__init__(privacy_bypass_or_cfg)
        self.default_action = default_action
        self._custom_patterns: List[Tuple[str, re.Pattern, str, str]] = []  # (name, regex, severity, action)

    def add_custom_pattern(self, name: str, pattern: str, severity: str = "high",
                           action: str = DLPAction.BLOCK):
        """Registers a custom corporate regex pattern (e.g. employee IDs, proprietary tags)."""
        compiled = re.compile(pattern, re.IGNORECASE)
        self._custom_patterns.append((name, compiled, severity, action))

    def scan_content_with_custom(self, content: str, domain: Optional[str] = None) -> List[dict]:
        findings = self.scan_content(content, domain=domain)
        if domain and self.is_exempt_domain(domain):
            return []

        for name, pat, sev, act in self._custom_patterns:
            for match in pat.finditer(content):
                findings.append({
                    "type": "dlp_custom_pattern",
                    "severity": sev,
                    "action": act,
                    "provider": name,
                    "match": match.group()[:30] + ("..." if len(match.group()) > 30 else ""),
                    "description": f"Custom corporate DLP rule hit: {name}",
                })
        return findings

    def redact_content(self, content: str, domain: Optional[str] = None) -> Tuple[str, List[dict]]:
        """Redacts credit cards, SSNs, and exposed API keys in-place, returning sanitized text."""
        findings = self.scan_content_with_custom(content, domain=domain)
        if not findings or (domain and self.is_exempt_domain(domain)):
            return content, []

        sanitized = content

        # 1. Redact Credit Cards
        for candidate in CREDIT_CARD_CANDIDATE.finditer(content):
            num = re.sub(r"\D", "", candidate.group())
            if luhn_check(num):
                masked = ("*" * (len(num) - 4)) + num[-4:]
                sanitized = sanitized.replace(candidate.group(), masked)

        # 2. Redact SSNs
        for match in SSN_REGEX.finditer(content):
            ssn = match.group()
            masked = "***-**-" + ssn[-4:]
            sanitized = sanitized.replace(ssn, masked)

        # 3. Redact API Keys
        for match in AWS_KEY_REGEX.finditer(content):
            sanitized = sanitized.replace(match.group(), "[REDACTED_AWS_KEY]")

        for match in GITHUB_TOKEN_REGEX.finditer(content):
            sanitized = sanitized.replace(match.group(), "[REDACTED_GITHUB_TOKEN]")

        for match in SLACK_TOKEN_REGEX.finditer(content):
            sanitized = sanitized.replace(match.group(), "[REDACTED_SLACK_TOKEN]")

        # 4. Redact Private Keys
        sanitized = PRIVATE_KEY_REGEX.sub("[REDACTED_CRYPTOGRAPHIC_PRIVATE_KEY]", sanitized)

        return sanitized, findings

    def evaluate_stream(self, data: Union[str, bytes], direction: str = "upload",
                        domain: Optional[str] = None, policy_action: Optional[str] = None) -> dict:
        """Evaluates payload stream returning verdict action, findings, and sanitized data if redacted."""
        text = data if isinstance(data, str) else data.decode("utf-8", errors="ignore")
        findings = self.scan_content_with_custom(text, domain=domain)

        # Check entropy if bytes
        raw_bytes = data if isinstance(data, bytes) else data.encode("utf-8")
        entropy = calculate_entropy(raw_bytes)
        if len(raw_bytes) >= 64 and entropy > 7.5:
            findings.append({
                "type": "dlp_high_entropy_secret",
                "severity": "high",
                "action": DLPAction.BLOCK,
                "description": f"High Shannon entropy secret/tunnel detected ({entropy:.2f}/8.0)",
            })

        action = policy_action or self.default_action
        if not findings:
            return {
                "action": DLPAction.ALLOW,
                "findings": [],
                "data": data,
                "reason": "clean_no_dlp_hits",
            }

        # Determine effective action
        effective_action = action
        if any(f.get("severity") == "critical" for f in findings) and action == DLPAction.ALLOW:
            effective_action = DLPAction.LOG

        sanitized_data = data
        if effective_action == DLPAction.REDACT:
            sanitized_text, _ = self.redact_content(text, domain=domain)
            sanitized_data = sanitized_text if isinstance(data, str) else sanitized_text.encode("utf-8")

        return {
            "action": effective_action,
            "findings": findings,
            "data": sanitized_data,
            "direction": direction,
            "reason": f"DLP violation: {findings[0]['type']}",
        }
