"""SentinelFW Secure Web Gateway (SWG) & URL Filtering Engine.

Provides deep URL categorization, domain reputation scoring, newly registered domain (NRD) heuristics,
typosquatting detection, and HTTP header/URL policy enforcement.
"""
import re
import time
from typing import Dict, List, Optional, Set, Tuple


class WebCategory:
    MALWARE = "Malware"
    PHISHING = "Phishing"
    C2 = "CommandAndControl"
    GAMBLING = "Gambling"
    ADULT = "Adult"
    SOCIAL_MEDIA = "SocialMedia"
    STREAMING = "Streaming"
    CLOUD_STORAGE = "CloudStorage"
    DEVELOPER_TOOLS = "DeveloperTools"
    FINANCIAL = "FinancialServices"
    HEALTHCARE = "Healthcare"
    GOVERNMENT = "Government"
    UNKNOWN = "Unknown"


# Built-in category catalog baseline
DEFAULT_CATEGORY_CATALOG = {
    WebCategory.MALWARE: [
        "*.malicious-c2.net", "*.evil-payload.xyz", "*.ransomware-drop.top", "*.trojan-dist.cc"
    ],
    WebCategory.PHISHING: [
        "*.secure-login-chase-update.com", "*.paypal-account-verify.info", "*.microsoft-login-alert.club"
    ],
    WebCategory.GAMBLING: [
        "*.bet365.com", "*.bovada.lv", "*.pokerstars.com", "*.draftkings.com"
    ],
    WebCategory.ADULT: [
        "*.pornhub.com", "*.xvideos.com", "*.onlyfans.com"
    ],
    WebCategory.SOCIAL_MEDIA: [
        "*.facebook.com", "*.twitter.com", "*.x.com", "*.instagram.com", "*.tiktok.com", "*.reddit.com"
    ],
    WebCategory.STREAMING: [
        "*.netflix.com", "*.youtube.com", "*.hulu.com", "*.disneyplus.com", "*.twitch.tv"
    ],
    WebCategory.CLOUD_STORAGE: [
        "*.dropbox.com", "*.box.com", "*.drive.google.com", "*.onedrive.live.com", "*.mega.nz"
    ],
    WebCategory.DEVELOPER_TOOLS: [
        "*.github.com", "*.gitlab.com", "*.stackoverflow.com", "*.docker.com", "*.pypi.org"
    ],
    WebCategory.FINANCIAL: [
        "*.chase.com", "*.bankofamerica.com", "*.wellsfargo.com", "*.fidelity.com"
    ],
    WebCategory.HEALTHCARE: [
        "*.mychart.com", "*.epic.com", "*.cdc.gov", "*.who.int"
    ],
    WebCategory.GOVERNMENT: [
        "*.irs.gov", "*.login.gov", "*.whitehouse.gov", "*.gov.uk"
    ],
}

SUSPICIOUS_TLDS = {
    "top", "xyz", "click", "buzz", "fit", "rest", "country", "gq", "tk", "ml", "cf", "ga", "work", "loan"
}

HIGH_VALUE_BRANDS = [
    "google", "microsoft", "apple", "amazon", "paypal", "netflix", "facebook", "chase", "bankofamerica"
]


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculates Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


class URLCategorizer:
    """Categorizes URLs and domain names into security and business categories."""

    def __init__(self, custom_catalog: Optional[Dict[str, List[str]]] = None):
        self._rules: List[Tuple[str, str]] = []  # (pattern, category)
        catalog = custom_catalog or DEFAULT_CATEGORY_CATALOG
        for category, patterns in catalog.items():
            for pat in patterns:
                self.add_pattern(pat, category)

    def add_pattern(self, pattern: str, category: str):
        clean_pat = pattern.strip().lower()
        self._rules.append((clean_pat, category))

    def categorize_domain(self, domain: str) -> Tuple[str, str]:
        """Returns (category, matched_rule)."""
        clean_domain = domain.strip().lower().strip(".")
        if not clean_domain:
            return WebCategory.UNKNOWN, "none"

        for pat, cat in self._rules:
            if pat.startswith("*."):
                suffix = pat[1:]  # e.g. .facebook.com
                if clean_domain.endswith(suffix) or clean_domain == pat[2:]:
                    return cat, pat
            elif clean_domain == pat:
                return cat, pat

        return WebCategory.UNKNOWN, "default"


class DomainReputationEngine:
    """Evaluates domain reputation, suspicious TLDs, newly registered domains, and typosquatting."""

    @classmethod
    def check_suspicious_tld(cls, domain: str) -> Tuple[bool, str]:
        parts = domain.strip().lower().split(".")
        if len(parts) >= 2:
            tld = parts[-1]
            if tld in SUSPICIOUS_TLDS:
                return True, f"High-risk top-level domain: .{tld}"
        return False, "standard_tld"

    @classmethod
    def check_typosquatting(cls, domain: str) -> Tuple[bool, str]:
        """Detects typosquatting against high-value target brands (e.g. go0gle, paypa1, micros0ft)."""
        parts = domain.strip().lower().split(".")
        if len(parts) < 2:
            return False, ""
        sld = parts[-2]

        # Normalize common character substitutions (leetspeak)
        normalized = sld.replace("0", "o").replace("1", "l").replace("3", "e").replace("5", "s").replace("@", "a")

        for brand in HIGH_VALUE_BRANDS:
            # Exact match with official brand is safe
            if sld == brand:
                continue
            # Check Levenshtein distance on raw and normalized sld
            dist_raw = levenshtein_distance(sld, brand)
            dist_norm = levenshtein_distance(normalized, brand)
            if dist_raw in (1, 2) or dist_norm in (1, 2) or (brand in sld and len(sld) <= len(brand) + 5):
                return True, f"Possible typosquatting imitation of '{brand}' (detected: {sld})"

        return False, "clean"

    @classmethod
    def check_newly_registered(cls, domain: str, registration_timestamp: Optional[float] = None,
                               nrd_threshold_days: int = 30) -> Tuple[bool, str]:
        """Identifies newly registered domains (NRDs) which present elevated risk for malware/phishing."""
        if registration_timestamp is None:
            return False, "unknown_age"
        age_seconds = time.time() - float(registration_timestamp)
        age_days = age_seconds / 86400.0
        if age_days < nrd_threshold_days:
            return True, f"Newly registered domain (age: {age_days:.1f} days, threshold: {nrd_threshold_days} days)"
        return False, "mature_domain"


class SWGPolicyEnforcer:
    """Enforces enterprise secure web gateway policies across categories, headers, and reputations."""

    def __init__(self, categorizer: Optional[URLCategorizer] = None,
                 blocked_categories: Optional[List[str]] = None,
                 block_suspicious_tlds: bool = True,
                 block_typosquatting: bool = True):
        self.categorizer = categorizer or URLCategorizer()
        self.blocked_categories = set(blocked_categories or [WebCategory.MALWARE, WebCategory.PHISHING, WebCategory.C2, WebCategory.GAMBLING, WebCategory.ADULT])
        self.block_suspicious_tlds = block_suspicious_tlds
        self.block_typosquatting = block_typosquatting
        self.stats = {
            "evaluated": 0,
            "allowed": 0,
            "blocked_category": 0,
            "blocked_tld": 0,
            "blocked_typo": 0,
        }

    def evaluate_request(self, host: str, url: str = "/", headers: Optional[dict] = None) -> dict:
        """Evaluates an HTTP request against SWG security policies."""
        clean_host = host.split(":")[0].strip().lower()
        self.stats["evaluated"] += 1

        # 1. Typosquatting Check
        if self.block_typosquatting:
            is_typo, typo_reason = DomainReputationEngine.check_typosquatting(clean_host)
            if is_typo:
                self.stats["blocked_typo"] += 1
                return {
                    "action": "BLOCK",
                    "reason": typo_reason,
                    "category": WebCategory.PHISHING,
                    "host": clean_host,
                }

        # 2. Suspicious TLD Check
        if self.block_suspicious_tlds:
            is_tld, tld_reason = DomainReputationEngine.check_suspicious_tld(clean_host)
            if is_tld:
                self.stats["blocked_tld"] += 1
                return {
                    "action": "BLOCK",
                    "reason": tld_reason,
                    "category": WebCategory.UNKNOWN,
                    "host": clean_host,
                }

        # 3. Category Evaluation
        cat, rule = self.categorizer.categorize_domain(clean_host)
        if cat in self.blocked_categories:
            self.stats["blocked_category"] += 1
            return {
                "action": "BLOCK",
                "reason": f"Category '{cat}' is blocked by corporate SWG policy (rule: {rule})",
                "category": cat,
                "host": clean_host,
            }

        # Allowed request
        self.stats["allowed"] += 1
        return {
            "action": "ALLOW",
            "reason": "category_permitted",
            "category": cat,
            "host": clean_host,
        }
