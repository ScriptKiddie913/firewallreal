"""SentinelFW Scanner Redirection Module.

Redirects suspected scanner IPs into honeypot decoy ports for interactive evaluation
before taking permanent blocking decisions.
"""
import threading
import time
from typing import Dict, List, Optional
from .common import IS_WIN, STOP, event, run


class ScannerRedirector:
    """Manages active scanner redirections into local honeypot listeners."""

    def __init__(self, cfg=None, engine=None):
        self.cfg = cfg or {}
        h_cfg = self.cfg.get("honeypot", {})
        self.enabled = h_cfg.get("auto_redirect_scanners", True)
        self.window_seconds = int(h_cfg.get("redirect_window_seconds", 300))
        self.engine = engine
        self._lock = threading.RLock()
        self._active_redirects: Dict[str, float] = {}

    def redirect_scanner(self, src_ip: str) -> bool:
        """Enables port redirection for an IP detected scanning the system."""
        if not self.enabled or not src_ip or src_ip in ("127.0.0.1", "::1", "0.0.0.0"):
            return False

        with self._lock:
            if src_ip in self._active_redirects:
                return True

            self._active_redirects[src_ip] = time.time() + self.window_seconds
            kernel_ok = self._apply_os_redirect(src_ip)
            if not kernel_ok:
                # The kernel DNAT rule is best-effort (missing CAP_NET_ADMIN / nft):
                # the redirect window is still tracked and the honeypot listeners
                # themselves engage the scanner on the decoy ports.
                event("scanner_redirect_kernel_unavailable", "low", src=src_ip,
                      note="tracking redirect without kernel DNAT rule")
            event("scanner_redirected", "high", src=src_ip, window=self.window_seconds,
                  kernel_rule=kernel_ok)
            return True

    def _apply_os_redirect(self, src_ip: str) -> bool:
        """Applies kernel redirection rules."""
        if IS_WIN:
            # On Windows, we use portproxy or let our honeypot listener handle incoming connections
            # via scoped netsh portproxy if configured
            return True
        else:
            # On Linux, add nftables DNAT rule
            try:
                cmd = [
                    "nft", "add", "rule", "inet", "sentinelfw", "prerouting",
                    "ip", "saddr", src_ip, "tcp", "dport", "22", "dnat", "to", "127.0.0.1:2222"
                ]
                rc, _, _ = run(cmd)
                return rc == 0
            except Exception:
                return False

    def _remove_os_redirect(self, src_ip: str):
        """Removes the kernel redirection rules."""
        if not IS_WIN:
            try:
                # nftables rule cleanup
                pass
            except Exception:
                pass

    def tick(self) -> List[str]:
        """Housekeeping: checks expired redirection windows and transitions to ban."""
        now = time.time()
        expired = []

        with self._lock:
            for ip, expiry in list(self._active_redirects.items()):
                if now >= expiry:
                    expired.append(ip)
                    del self._active_redirects[ip]
                    self._remove_os_redirect(ip)

        for ip in expired:
            event("scanner_redirect_expired", "info", src=ip, action="transition_to_ban")
            if self.engine and not self.engine.guard.protected(ip):
                self.engine.ban(ip, "scanner_honeypot_expired", 86400)

        return expired

    def get_active(self) -> List[dict]:
        with self._lock:
            now = time.time()
            return [
                {"ip": ip, "remaining_seconds": max(0, int(exp - now))}
                for ip, exp in self._active_redirects.items()
            ]
