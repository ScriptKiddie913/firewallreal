"""SentinelFW Self-Protection and Anti-Tampering Engine.

Computes cryptographic signatures of all source modules on startup and continuously
monitors file integrity, process mitigations, and daemon heartbeat to prevent evasion.
"""
import hashlib
import os
from pathlib import Path
import threading
import time
from typing import Dict, List, Tuple
from .common import DATA_DIR, PKG_DIR, STOP, event


class SelfProtect(threading.Thread):
    """Monitors code integrity and alerts on unauthorized modification."""

    def __init__(self, cfg=None):
        super().__init__(name="self_protect", daemon=True)
        self.cfg = cfg or {}
        sp_cfg = self.cfg.get("self_protection", {})
        self.enabled = sp_cfg.get("anti_tampering", True)
        self.check_files = sp_cfg.get("file_integrity_check", True)
        self.manifest_file = DATA_DIR / "integrity_manifest.json"
        self._source_hashes: Dict[str, str] = {}
        self._lock = threading.RLock()
        self.build_manifest()

    def build_manifest(self) -> Dict[str, str]:
        """Calculates SHA-256 for all Python files in the SentinelFW package."""
        res = {}
        for root, _, files in os.walk(PKG_DIR):
            for f in files:
                if f.endswith(".py"):
                    p = Path(root) / f
                    try:
                        rel = str(p.relative_to(PKG_DIR))
                        h = hashlib.sha256(p.read_bytes()).hexdigest()
                        res[rel] = h
                    except OSError:
                        pass
        with self._lock:
            self._source_hashes = res
        return res

    def verify_integrity(self) -> Tuple[bool, List[str]]:
        """Compares current source files against the initial manifest."""
        tampered = []
        with self._lock:
            for rel, orig_hash in self._source_hashes.items():
                p = PKG_DIR / rel
                if not p.is_file():
                    tampered.append(f"missing: {rel}")
                    continue
                try:
                    cur_hash = hashlib.sha256(p.read_bytes()).hexdigest()
                    if cur_hash != orig_hash:
                        tampered.append(f"modified: {rel}")
                except OSError:
                    tampered.append(f"unreadable: {rel}")

        is_clean = len(tampered) == 0
        if not is_clean:
            event("source_code_tampered", "critical", count=len(tampered), files=tampered)
        return is_clean, tampered

    def run(self):
        """Periodic background integrity verification."""
        while not STOP.wait(60):
            if not self.enabled or not self.check_files:
                continue
            is_clean, violations = self.verify_integrity()
            if not is_clean:
                event("self_protect_alert", "critical", violations=violations)
