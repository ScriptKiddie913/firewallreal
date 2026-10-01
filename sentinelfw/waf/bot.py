"""SentinelFW WAF Bot Mitigation Engine.

Detects automated crawlers, scrapers, headless browsers, and vulnerability scanners:
* Bad bots & scanner detection (sqlmap, nikto, gobuster, dirsearch, masscan, nuclei)
* Headless browser fingerprinting (Puppeteer, Playwright, Selenium, PhantomJS)
* Good bot verification (Googlebot, Bingbot, DuckDuckBot)
* Proof-of-Work / JS challenge token generator & validator
"""
import hashlib
import hmac
import re
import time
from typing import Dict, Optional, Tuple


BAD_BOT_PATTERNS = [
    r"(?i)\b(sqlmap|nikto|dirbuster|gobuster|wpscan|masscan|nuclei|zgrab|nmap|acunetix)\b",
    r"(?i)\b(nessus|openvas|hydra|metasploit|burpcollaborator|havij|arachni)\b",
    r"(?i)\b(python-requests|aiohttp|curl\/[0-9]|wget\/[0-9]|libwww-perl|go-http-client)\b",
]

HEADLESS_PATTERNS = [
    r"(?i)\b(headlesschrome|phantomjs|puppeteer|playwright|selenium|webdriver)\b",
]

GOOD_BOT_PATTERNS = [
    r"(?i)\b(googlebot|bingbot|duckduckbot|yandexbot|baiduspider|slurp)\b",
]


class BotMitigator:
    """Classifies incoming HTTP clients and provides challenge validation."""

    def __init__(self, challenge_secret: str = "sentinelfw-challenge-secret"):
        self.challenge_secret = challenge_secret.encode("utf-8")
        self._compiled_bad = [re.compile(p) for p in BAD_BOT_PATTERNS]
        self._compiled_headless = [re.compile(p) for p in HEADLESS_PATTERNS]
        self._compiled_good = [re.compile(p) for p in GOOD_BOT_PATTERNS]

    def classify(self, user_agent: str, headers: Optional[Dict[str, str]] = None,
                 client_ip: str = "") -> dict:
        """Classifies the client into category: good_bot, bad_bot, headless, browser, unknown."""
        ua = (user_agent or "").strip()
        hdrs = headers or {}

        # 1. Missing user-agent is highly suspicious
        if not ua:
            return {
                "category": "bad_bot",
                "action": "block",
                "confidence": "high",
                "reason": "Missing User-Agent header",
            }

        # 2. Known bad bots / scanners
        for pat in self._compiled_bad:
            if pat.search(ua):
                return {
                    "category": "bad_bot",
                    "action": "block",
                    "confidence": "high",
                    "reason": f"Matched malicious scanner or scraper pattern: {pat.pattern}",
                }

        # 3. Headless browser automation
        for pat in self._compiled_headless:
            if pat.search(ua):
                return {
                    "category": "headless_browser",
                    "action": "challenge",
                    "confidence": "high",
                    "reason": f"Matched headless automation tool: {pat.pattern}",
                }

        # Check for Sec-CH-UA or automation flags if available
        for k, v in hdrs.items():
            if "webdriver" in k.lower() or "selenium" in v.lower():
                return {
                    "category": "headless_browser",
                    "action": "challenge",
                    "confidence": "high",
                    "reason": "Browser automation header detected",
                }

        # 4. Known good search engines
        for pat in self._compiled_good:
            if pat.search(ua):
                return {
                    "category": "good_bot",
                    "action": "allow",
                    "confidence": "high",
                    "reason": f"Matched legitimate search crawler: {pat.pattern}",
                }

        # 5. Check missing standard browser headers
        hdr_keys = [k.lower() for k in hdrs.keys()]
        if "accept" not in hdr_keys and "accept-language" not in hdr_keys:
            return {
                "category": "suspicious",
                "action": "challenge",
                "confidence": "medium",
                "reason": "Missing standard browser negotiation headers (Accept / Accept-Language)",
            }

        return {
            "category": "browser",
            "action": "allow",
            "confidence": "high",
            "reason": "Legitimate browser profile",
        }

    def generate_challenge(self, client_ip: str) -> str:
        """Generates a cryptographic challenge cookie value valid for 5 minutes."""
        ts = int(time.time())
        msg = f"{client_ip}:{ts}".encode("utf-8")
        mac = hmac.new(self.challenge_secret, msg, hashlib.sha256).hexdigest()[:32]
        return f"{ts}_{mac}"

    def verify_challenge(self, client_ip: str, token: str, max_age: int = 300) -> bool:
        """Validates a submitted challenge token."""
        if not token or "_" not in token:
            return False
        parts = token.split("_", 1)
        try:
            ts = int(parts[0])
        except ValueError:
            return False
        if abs(time.time() - ts) > max_age:
            return False
        expected_msg = f"{client_ip}:{ts}".encode("utf-8")
        expected_mac = hmac.new(self.challenge_secret, expected_msg, hashlib.sha256).hexdigest()[:32]
        return hmac.compare_digest(parts[1], expected_mac)
