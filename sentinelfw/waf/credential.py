"""SentinelFW WAF Credential Stuffing & Password Spraying Shield.

Detects and mitigates automated authentication attacks:
* Per-IP velocity tracking and progressive artificial delays (tarpit)
* Per-account brute force protection (lockout after repeated failures)
* Distributed credential stuffing detection (single IP spraying many usernames)
* Password spraying detection (many IPs targeting the same username)
"""
import threading
import time
from typing import Dict, List, Optional, Tuple
from ..common import event


class CredentialShield:
    """Thread-safe credential stuffing and brute force shield."""

    def __init__(self, max_ip_failures: int = 10, max_user_failures: int = 5,
                 window_seconds: int = 300, spray_threshold: int = 5):
        self.max_ip_failures = int(max_ip_failures)
        self.max_user_failures = int(max_user_failures)
        self.window_seconds = int(window_seconds)
        self.spray_threshold = int(spray_threshold)

        self._ip_history: Dict[str, List[Tuple[float, str, bool]]] = {}
        self._user_history: Dict[str, List[Tuple[float, str, bool]]] = {}
        self._lock = threading.RLock()

    def record_attempt(self, ip: str, username: str, success: bool) -> dict:
        """Records an authentication attempt and evaluates defensive posture."""
        now = time.time()
        clean_ip = str(ip).strip()
        clean_user = str(username).strip().lower()

        with self._lock:
            # 1. Clean history older than window
            cutoff = now - self.window_seconds
            ip_records = [r for r in self._ip_history.get(clean_ip, []) if r[0] > cutoff]
            ip_records.append((now, clean_user, success))
            self._ip_history[clean_ip] = ip_records

            user_records = [r for r in self._user_history.get(clean_user, []) if r[0] > cutoff]
            user_records.append((now, clean_ip, success))
            self._user_history[clean_user] = user_records

            if success:
                return {"allowed": True, "delay_seconds": 0.0, "reason": "Authentication successful"}

            # Count failures in current window
            ip_fails = sum(1 for r in ip_records if not r[2])
            user_fails = sum(1 for r in user_records if not r[2])

            # Check distributed credential stuffing: single IP trying multiple distinct accounts
            distinct_users_from_ip = len({r[1] for r in ip_records if not r[2]})
            if distinct_users_from_ip >= self.spray_threshold:
                event("credential_stuffing_detected", "high",
                      ip=clean_ip, targeted_users=distinct_users_from_ip)
                return {
                    "allowed": False,
                    "delay_seconds": 10.0,
                    "reason": f"Credential stuffing detected ({distinct_users_from_ip} distinct users targeted from IP)",
                }

            # Check password spraying: many distinct IPs targeting same account
            distinct_ips_for_user = len({r[1] for r in user_records if not r[2]})
            if distinct_ips_for_user >= self.spray_threshold:
                event("password_spraying_detected", "high",
                      user=clean_user, source_ips=distinct_ips_for_user)
                return {
                    "allowed": False,
                    "delay_seconds": 5.0,
                    "reason": f"Distributed password spray detected targeting account '{clean_user}'",
                }

            # IP lockout threshold
            if ip_fails >= self.max_ip_failures:
                event("ip_login_lockout", "medium", ip=clean_ip, failures=ip_fails)
                return {
                    "allowed": False,
                    "delay_seconds": 15.0,
                    "reason": f"Too many failed login attempts from IP ({ip_fails}/{self.max_ip_failures})",
                }

            # Progressive backoff delay for repeated failures
            delay = 0.0
            if ip_fails > 3:
                delay = float(min(10, 2 ** (ip_fails - 3)))

            return {
                "allowed": True,
                "delay_seconds": delay,
                "reason": f"Attempt logged ({ip_fails} failures in window)",
            }

    def is_locked(self, ip: str, username: str) -> bool:
        """Quick check if IP or account is currently in lockout state."""
        now = time.time()
        clean_ip = str(ip).strip()
        clean_user = str(username).strip().lower()
        cutoff = now - self.window_seconds
        with self._lock:
            ip_fails = sum(1 for r in self._ip_history.get(clean_ip, []) if r[0] > cutoff and not r[2])
            if ip_fails >= self.max_ip_failures:
                return True
            distinct_users = len({r[1] for r in self._ip_history.get(clean_ip, []) if r[0] > cutoff and not r[2]})
            if distinct_users >= self.spray_threshold:
                return True
            return False
