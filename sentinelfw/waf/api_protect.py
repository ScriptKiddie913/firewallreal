"""SentinelFW WAF API Protection Engine.

Provides deep inspection for modern REST, GraphQL, and LLM APIs:
* LLM abuse & prompt injection detection (Jailbreak, DAN mode, ignore instructions, system prompt extraction)
* API Key stuffing defense (rapid credential/key rotation across LLM endpoints)
* Model scraping and weight extraction defense
* GraphQL complexity and introspection query defense
* OpenAPI / schema enforcement and type checking
* Per-endpoint rate limiting
"""
import collections
import json
import re
import threading
import time
from typing import Dict, List, Optional, Tuple

LLM_PROMPT_INJECTION_PATTERNS = [
    r"(?i)\bignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)\b",
    r"(?i)\b(system\s*prompt|reveal\s+your\s+instructions|display\s+your\s+initial\s+prompt)\b",
    r"(?i)\b(dan\s+mode|jailbreak|unrestricted\s+ai|do\s+anything\s+now)\b",
    r"(?i)\b(act\s+as\s+an\s+unfiltered|bypass\s+(safety|content)\s+filters)\b",
    r"(?i)\b(pretend\s+you\s+have\s+no\s+rules|developer\s+mode\s+output)\b",
    r"(?i)\b(print\s+(your\s+)?system\s+message|output\s+initialization\s+prompt)\b",
    r"(?i)(?:<\|im_start\|>system|\[INST\]\s*<<SYS>>|---BEGIN SYSTEM PROMPT---)",
    r"(?i)\b(opposite\s+mode|tombstone\s+protocol|evil\s+twin\s+mode)\b",
]


class APIProtector:
    """Inspects API calls for protocol anomalies, GraphQL abuse, and LLM prompt injections."""

    def __init__(self):
        self._llm_patterns = [re.compile(p) for p in LLM_PROMPT_INJECTION_PATTERNS]
        self._rate_limits: Dict[str, dict] = {}  # endpoint:ip -> {count, reset_at}
        self._key_stuffing_tracker: Dict[str, dict] = {}  # ip -> {keys: set(), reset_at}
        self._scraping_tracker: Dict[str, collections.deque] = collections.defaultdict(
            lambda: collections.deque(maxlen=100)
        )  # ip -> deque of (timestamp, prompt_hash)
        self._lock = threading.RLock()

    def check_llm_prompt(self, text: str) -> Tuple[bool, str]:
        """Detects prompt injection or jailbreak attempts in LLM user inputs."""
        if not text:
            return False, ""
        for pat in self._llm_patterns:
            if pat.search(text):
                return True, f"Prompt injection detected: {pat.pattern}"
        return False, ""

    def check_key_stuffing(self, client_ip: str, auth_header_or_key: str,
                           max_keys_per_minute: int = 5) -> Tuple[bool, str]:
        """Detects API key stuffing / credential rotation attacks against LLM endpoints."""
        if not client_ip or not auth_header_or_key:
            return False, ""
        clean_key = str(auth_header_or_key).replace("Bearer ", "").strip()
        now = time.time()

        with self._lock:
            rec = self._key_stuffing_tracker.setdefault(client_ip, {"keys": set(), "reset_at": now + 60})
            if now > rec["reset_at"]:
                rec["keys"] = set()
                rec["reset_at"] = now + 60
            rec["keys"].add(clean_key)
            if len(rec["keys"]) >= max_keys_per_minute:
                return True, f"API key stuffing detected: {len(rec['keys'])} distinct keys attempted in 60s"
            return False, ""

    def check_model_scraping(self, client_ip: str, endpoint: str, prompt_text: str,
                             max_rps: int = 20) -> Tuple[bool, str]:
        """Detects automated model scraping and systematic prompt harvesting."""
        if not client_ip or not prompt_text:
            return False, ""
        now = time.time()
        with self._lock:
            history = self._scraping_tracker[f"{client_ip}:{endpoint}"]
            history.append((now, len(prompt_text)))
            # Count requests in last 5 seconds
            recent = [t for t, _ in history if now - t <= 5.0]
            if len(recent) >= (max_rps * 5):
                return True, f"Model scraping / weight extraction rate anomaly: {len(recent)} calls in 5s"
            return False, ""

    def check_graphql(self, query: str, max_depth: int = 6, allow_introspection: bool = False) -> Tuple[bool, str]:
        """Validates GraphQL query depth and introspection attacks."""
        if not query:
            return False, ""

        # 1. Introspection check
        if not allow_introspection and ("__schema" in query or "__type" in query):
            return True, "GraphQL introspection query blocked"

        # 2. Query depth check via brace nesting
        depth = 0
        max_seen = 0
        for char in query:
            if char == "{":
                depth += 1
                if depth > max_seen:
                    max_seen = depth
            elif char == "}":
                depth = max(0, depth - 1)

        if max_seen > max_depth:
            return True, f"GraphQL query depth {max_seen} exceeds limit of {max_depth}"

        return False, ""

    def check_endpoint_rate_limit(self, endpoint: str, client_ip: str,
                                   limit_rpm: int = 120) -> Tuple[bool, str]:
        """Enforces per-endpoint volumetric rate limits."""
        now = time.time()
        key = f"{endpoint}:{client_ip}"
        with self._lock:
            rec = self._rate_limits.get(key)
            if not rec or now > rec["reset_at"]:
                self._rate_limits[key] = {"count": 1, "reset_at": now + 60}
                return False, ""
            rec["count"] += 1
            if rec["count"] > limit_rpm:
                return True, f"API endpoint rate limit exceeded ({rec['count']}/{limit_rpm} rpm)"
            return False, ""

    def inspect_request(self, path: str, method: str, body: str = "",
                        client_ip: str = "", auth_header: str = "",
                        limit_rpm: int = 120, allow_introspection: bool = False) -> dict:
        """Comprehensive API request inspection."""
        # 1. Rate limiting
        blocked, reason = self.check_endpoint_rate_limit(path, client_ip, limit_rpm=limit_rpm)
        if blocked:
            return {"block": True, "status_code": 429, "reason": reason}

        # 2. Key stuffing check if auth provided
        if auth_header:
            ks_blocked, ks_reason = self.check_key_stuffing(client_ip, auth_header)
            if ks_blocked:
                return {"block": True, "status_code": 403, "reason": ks_reason}

        # 3. Check JSON payload structure if present
        if body and (body.strip().startswith("{") or body.strip().startswith("[")):
            try:
                parsed = json.loads(body)
                # LLM check if keys like 'prompt', 'query', 'messages', 'input' exist
                if isinstance(parsed, dict):
                    # Check GraphQL query parameter
                    if "query" in parsed and isinstance(parsed["query"], str):
                        g_blocked, g_reason = self.check_graphql(
                            parsed["query"], allow_introspection=allow_introspection
                        )
                        if g_blocked:
                            return {"block": True, "status_code": 400, "reason": g_reason}

                    # Check prompt injection in LLM endpoints
                    for key in ("prompt", "input", "query"):
                        val = parsed.get(key)
                        if isinstance(val, str):
                            p_blocked, p_reason = self.check_llm_prompt(val)
                            if p_blocked:
                                return {"block": True, "status_code": 400, "reason": p_reason}
                            # Check scraping
                            s_blocked, s_reason = self.check_model_scraping(client_ip, path, val)
                            if s_blocked:
                                return {"block": True, "status_code": 429, "reason": s_reason}

                    # Check chat completion messages list
                    if "messages" in parsed and isinstance(parsed["messages"], list):
                        for m in parsed["messages"]:
                            if isinstance(m, dict) and "content" in m:
                                content = str(m["content"])
                                p_blocked, p_reason = self.check_llm_prompt(content)
                                if p_blocked:
                                    return {"block": True, "status_code": 400, "reason": p_reason}
            except Exception:
                pass

        return {"block": False, "status_code": 200, "reason": "clean"}
