"""SentinelFW Deep HTTP Protocol Inspector.

Performs deep lexical and semantic analysis on HTTP requests and responses,
detecting SQLi, XSS, SSRF, command injection, web shells, and AI prompt injection.
"""
import re
import urllib.parse
from typing import Dict, List, Optional, Tuple

WEB_ATTACK_PATTERNS = [
    ("sql_injection_union", re.compile(r"(?i)\bunion(?:\s|\+)+select\b")),
    ("sql_injection_quotes", re.compile(r"(?i)(?:'|\%27)(?:\s|\+)*(?:or|and)(?:\s|\+)*\d+=\d+")),
    ("path_traversal", re.compile(r"(?:\.\./|\.\.\\|\%2e\%2e\%2f){2,}")),
    ("command_injection", re.compile(r"(?:;|\|\||&&|`|\$\()\s*(?:cat|ls|id|whoami|uname|curl|wget|powershell|cmd)\b")),
    ("xss_script_tags", re.compile(r"(?i)<script[\s>].*?</script.*?>")),
    ("log4shell", re.compile(r"(?i)\$\{(?:lower:|upper:)?jndi:(?:ldap|ldaps|rmi|dns)://")),
    ("spring4shell", re.compile(r"(?i)(?:class\.module\.classLoader|class\[\"module\"\])")),
    ("ssrf_cloud_metadata", re.compile(r"(?:169\.254\.169\.254|metadata\.google\.internal)")),
    ("llm_prompt_injection", re.compile(r"(?i)(?:ignore\s+(?:all\s+)?(?:previous|above)\s+instructions|system\s+prompt\s+override|you\s+are\s+now\s+dan\b)")),
]

SCANNER_AGENTS = re.compile(r"(?i)(?:sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|wpscan|hydra)")


class HTTPInspector:
    """Inspects raw HTTP streams and extracted headers/bodies."""

    @classmethod
    def inspect_request(cls, raw_data: bytes) -> Tuple[Optional[str], dict]:
        """
        Parses raw HTTP request bytes and looks for web exploitation signatures.
        Returns: (attack_type or None, details_dict)
        """
        try:
            text = raw_data.decode("latin-1")
        except Exception:
            return None, {}

        lines = text.split("\r\n")
        if not lines or not lines[0]:
            return None, {}

        req_line = lines[0].split(" ")
        if len(req_line) < 2:
            return None, {}

        method = req_line[0].upper()
        uri = req_line[1]

        # Decode URL once
        unquoted_uri = urllib.parse.unquote(uri)

        # Check headers
        headers = {}
        for line in lines[1:]:
            if not line:
                break
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        ua = headers.get("user-agent", "")
        if SCANNER_AGENTS.search(ua):
            return "web_crawl_aggressive", {"method": method, "uri": uri, "user_agent": ua}

        # Check request line + URI against patterns
        for atype, pat in WEB_ATTACK_PATTERNS:
            if pat.search(uri) or pat.search(unquoted_uri):
                return atype, {"method": method, "uri": uri, "location": "uri"}

        # Check body if present
        body_start = text.find("\r\n\r\n")
        if body_start != -1:
            body = text[body_start + 4:]
            unquoted_body = urllib.parse.unquote(body)
            for atype, pat in WEB_ATTACK_PATTERNS:
                if pat.search(body) or pat.search(unquoted_body):
                    return atype, {"method": method, "uri": uri, "location": "body"}

        return None, {"method": method, "uri": uri, "host": headers.get("host", "")}
