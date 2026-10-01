"""SentinelFW Watchdog & Anti-Tamper Engine.

Ensures continuous firewall process availability, integrity, and safety:
* Anti-tamper verification: SHA-256 baseline hashing of critical configuration and modules
* Configuration drift detection: Alerts on out-of-band file modifications
* Fail-Open vs Fail-Closed safety rails: Deterministic behavior if engine thread halts
* Watchdog heartbeat tracker
"""
import hashlib
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Union
from .common import DATA_DIR, event


class WatchdogGuard:
    """Monitors engine liveness, file integrity, and enforces fail-safe posture."""

    def __init__(self, fail_mode: Optional[Union[dict, str]] = "fail_open", **kwargs):
        val = fail_mode if fail_mode != "fail_open" else (kwargs.get("fail_mode_or_cfg") or fail_mode)
        if isinstance(val, dict):
            self.fail_mode = str(val.get("watchdog", {}).get("fail_mode") or
                                 val.get("fail_mode") or "fail_open").lower()
        else:
            self.fail_mode = str(val or "fail_open").lower()
        self._baselines: Dict[str, str] = {}  # path_str -> sha256
        self._last_heartbeat = time.time()
        self._lock = threading.RLock()
        self.is_healthy = True

    def record_baseline(self, file_path: Path):
        """Records the baseline SHA-256 hash of a critical file."""
        p = Path(file_path)
        if p.exists() and p.is_file():
            content = p.read_bytes()
            h = hashlib.sha256(content).hexdigest()
            with self._lock:
                self._baselines[str(p.resolve())] = h

    def verify_integrity(self) -> List[dict]:
        """Checks watched files against known baselines to detect tampering or drift."""
        violations = []
        with self._lock:
            for path_str, expected_hash in self._baselines.items():
                p = Path(path_str)
                if not p.exists():
                    violations.append({
                        "path": path_str,
                        "status": "missing",
                        "error": "File was deleted or moved",
                    })
                    continue
                actual_hash = hashlib.sha256(p.read_bytes()).hexdigest()
                if actual_hash != expected_hash:
                    violations.append({
                        "path": path_str,
                        "status": "modified",
                        "expected_hash": expected_hash,
                        "actual_hash": actual_hash,
                    })

        if violations:
            event("anti_tamper_violation", "critical",
                  violation_count=len(violations),
                  paths=[v["path"] for v in violations])
        return violations

    def heartbeat(self):
        """Called periodically by core engine loop to prove liveness."""
        with self._lock:
            self._last_heartbeat = time.time()
            self.is_healthy = True

    def check_liveness(self, max_interval: float = 30.0) -> bool:
        """Evaluates whether the engine has stalled."""
        with self._lock:
            stalled = (time.time() - self._last_heartbeat) > max_interval
            if stalled and self.is_healthy:
                self.is_healthy = False
                event("engine_liveness_timeout", "critical",
                      seconds_since_heartbeat=round(time.time() - self._last_heartbeat, 1),
                      fail_mode=self.fail_mode)
            return not stalled


# Global singleton
watchdog = WatchdogGuard()
