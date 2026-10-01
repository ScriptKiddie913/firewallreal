"""SentinelFW WAF Inspection Middleware.

Extracts and normalizes HTTP request components (URI, headers, query args,
cookies, body) and evaluates them against the active WAF rule set.
"""
import html
import json
import os
import urllib.parse
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
from .rules import WAFRuleEngine
from ..common import event


def normalize_string(val: str) -> str:
    """Normalizes an input string to defeat common obfuscation techniques."""
    if not val:
        return ""
    s = str(val).replace("\x00", "")
    # Multiple URL-decoding passes (up to 2) to catch double-encoding
    for _ in range(2):
        decoded = urllib.parse.unquote(s)
        if decoded == s:
            break
        s = decoded
    # HTML unescaping
    s = html.unescape(s)
    # Collapse multiple backslashes / slashes
    s = s.replace("\\\\", "\\")
    return s


class WAFMiddleware:
    """WAF inspection middleware for incoming HTTP requests."""

    def __init__(self, rule_engine: Optional[WAFRuleEngine] = None,
                 paranoia_level: int = 1, anomaly_threshold: int = 5):
        if rule_engine:
            self.engine = rule_engine
        else:
            self.engine = WAFRuleEngine(paranoia_level=paranoia_level, anomaly_threshold=anomaly_threshold)
            # Load bundled basic rules
            bundled_path = Path(__file__).resolve().parent.parent / "bundled" / "waf" / "crs-basic.json"
            if bundled_path.exists():
                try:
                    self.engine.load_rules_from_json(str(bundled_path))
                except Exception as e:
                    event("waf_rules_load_error", "warning", error=str(e))

    def inspect_request(self, method: str, uri: str, headers: Optional[Dict[str, str]] = None,
                        body: Union[str, bytes] = "", client_ip: str = "") -> dict:
        """Inspects an incoming HTTP request across Phase 1 and Phase 2.

        Returns:
            dict with {block: bool, score: int, matched_rules: list, status_code: int, message: str}
        """
        hdrs = headers or {}
        norm_uri = normalize_string(uri)

        # Parse query arguments
        parsed_url = urllib.parse.urlparse(uri)
        query_dict = urllib.parse.parse_qs(parsed_url.query, keep_blank_values=True)
        query_vals = []
        for k, vlist in query_dict.items():
            query_vals.append(normalize_string(k))
            query_vals.extend(normalize_string(v) for v in vlist)

        # Extract headers and cookies
        hdr_strings = [f"{k}: {v}" for k, v in hdrs.items()]
        cookies_raw = hdrs.get("Cookie") or hdrs.get("cookie") or ""
        cookies = [normalize_string(c.strip()) for c in cookies_raw.split(";") if c.strip()]

        # Phase 1: Headers, URI, Args, Cookies
        targets_phase1 = {
            "REQUEST_URI": norm_uri,
            "ARGS": query_vals,
            "REQUEST_HEADERS": hdr_strings,
            "REQUEST_COOKIES": cookies,
        }
        b1, s1, m1 = self.engine.evaluate(targets_phase1, phase=1)

        # Phase 2: Body
        norm_body = ""
        if body:
            if isinstance(body, bytes):
                norm_body = normalize_string(body.decode("utf-8", "replace"))
            else:
                norm_body = normalize_string(str(body))

        targets_phase2 = {
            "REQUEST_BODY": norm_body,
            "ARGS": query_vals,
        }
        b2, s2, m2 = self.engine.evaluate(targets_phase2, phase=2)

        total_score = s1 + s2
        all_matches = m1 + m2
        should_block = total_score >= self.engine.anomaly_threshold

        if should_block:
            event("waf_block", "high",
                  client_ip=client_ip,
                  method=method,
                  uri=norm_uri[:100],
                  score=total_score,
                  rule_count=len(all_matches))
            return {
                "block": True,
                "score": total_score,
                "status_code": 403,
                "matched_rules": all_matches,
                "client_ip": client_ip,
                "message": f"Request blocked by SentinelFW WAF (anomaly score: {total_score})",
            }

        return {
            "block": False,
            "score": total_score,
            "status_code": 200,
            "matched_rules": all_matches,
            "client_ip": client_ip,
            "message": "Passed",
        }
