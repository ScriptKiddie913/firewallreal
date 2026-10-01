"""SentinelFW ClamAV integration — on-access scheduled system antivirus.

Wraps the local ClamAV installation (clamdscan / clamscan / freshclam) behind
one cross-platform interface:

  * status()      — is ClamAV installed, DB age, last scan / update results
  * update_now() — run freshclam (definitions auto-update, also scheduled daily)
  * scan(paths)   — scan files/directories; findings are reported (and
                    optionally quarantined) with full SentinelFW events

Runs identically on Ubuntu (apt install clamav clamav-daemon) and Windows
(ClamAV official install). When ClamAV is not installed everything degrades
to a clear status message — the firewall keeps working without it.
"""
import os
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import List, Optional, Dict

from .common import IS_WIN, STOP, QUAR, event

_WIN_DIRS = [
    r"C:\Program Files\ClamAV",
    r"C:\Program Files (x86)\ClamAV",
    r"C:\Tools\ClamAV",
    r"C:\ClamAV",
]

DEFAULT_PATHS_WIN = [
    os.path.expandvars(r"%USERPROFILE%\Downloads"),
    os.path.expandvars(r"%TEMP%"),
    os.path.expandvars(r"%USERPROFILE%\Desktop"),
    os.path.expandvars(r"%USERPROFILE%\Documents"),
]
DEFAULT_PATHS_LINUX = ["/tmp", "/home", "/var/www", "/var/tmp", "/root"]

MAX_FINDINGS = 500


def _find_binary(name: str, extra_dirs: Optional[List[str]] = None) -> str:
    found = shutil.which(name)
    if found:
        return found
    for d in extra_dirs or []:
        cand = os.path.join(d, name + (".exe" if IS_WIN else ""))
        if os.path.isfile(cand):
            return cand
    return ""


class ClamAvManager:
    """Finds and drives the local ClamAV toolset."""

    def __init__(self, cfg: Optional[dict] = None, quarantine_hook=None):
        self.cfg = cfg or {}
        self._quarantine = quarantine_hook  # callable(path, reason)
        self._last_update: Dict = {}
        self._last_scan: Dict = {}
        self._busy = threading.Lock()
        self._updater_thread = threading.Thread(target=self._daily_update_loop,
                                                daemon=True, name="clamav_updater")
        self._updater_thread.start()

    # ------------------------------------------------------------- discovery
    @property
    def enabled(self) -> bool:
        return bool(self.cfg.get("enabled", True))

    def _scan_bin(self) -> str:
        """Prefer clamdscan (daemon, fast); fall back to clamscan."""
        dirs = _WIN_DIRS if IS_WIN else []
        if self.cfg.get("clamdscan_path"):
            return str(self.cfg["clamdscan_path"])
        b = _find_binary("clamdscan", dirs)
        if b:
            return b
        if self.cfg.get("clamscan_path"):
            return str(self.cfg["clamscan_path"])
        return _find_binary("clamscan", dirs)

    def _freshclam_bin(self) -> str:
        if self.cfg.get("freshclam_path"):
            return str(self.cfg["freshclam_path"])
        return _find_binary("freshclam", _WIN_DIRS if IS_WIN else [])

    def installed(self) -> bool:
        return bool(self._scan_bin())

    def is_available(self) -> bool:
        return self.installed()

    # ------------------------------------------------------------- status
    def status(self) -> dict:
        """Dashboard-facing status block."""
        st = {
            "enabled": self.enabled,
            "installed": self.installed(),
            "scan_binary": self._scan_bin(),
            "daemon": "clamdscan" in (self._scan_bin() or ""),
            "daily_update": bool(self.cfg.get("daily_update", True)),
            "last_update": dict(self._last_update) or None,
            "last_scan": dict(self._last_scan) or None,
        }
        if not st["installed"]:
            st["detail"] = ("ClamAV not detected. Ubuntu: 'sudo apt install clamav clamav-daemon'. "
                            "Windows: install ClamAV from clamav.net (or choco install clamav). "
                            "SentinelFW keeps protecting the system without it.")
        if self._last_update.get("ts"):
            age_h = (time.time() - self._last_update["ts"]) / 3600
            st["db_age_hours"] = round(age_h, 1)
            st["db_stale"] = age_h > 48
        return st

    # ------------------------------------------------------------- update
    def update_now(self, timeout: int = 900) -> dict:
        """Runs freshclam to refresh the virus definitions."""
        if not self.enabled:
            return {"error": "ClamAV integration disabled in config"}
        binp = self._freshclam_bin()
        if not binp:
            self._last_update = {"ok": False, "error": "freshclam not found", "ts": time.time()}
            return {"error": "freshclam not found — install ClamAV"}
        try:
            r = subprocess.run([binp], capture_output=True, text=True,
                               timeout=timeout, creationflags=0x08000000 if IS_WIN else 0)
            out = (r.stdout or "") + (r.stderr or "")
            ok = r.returncode == 0
            self._last_update = {"ok": ok, "ts": time.time(), "output": out[-1500:]}
            event("clamav_update" if ok else "clamav_update_failed",
                  "info" if ok else "warning", output=out[-300:])
            return {"ok": ok, "output": out[-1500:]}
        except Exception as e:  # noqa: BLE001
            self._last_update = {"ok": False, "error": str(e)[:200], "ts": time.time()}
            event("clamav_update_failed", "warning", error=str(e)[:200])
            return {"error": str(e)[:300]}

    def _daily_update_loop(self):
        """Auto-updates the signature database once a day (default 03:30 local)."""
        import random
        hour = float(self.cfg.get("update_hour", 3.5))
        while not STOP.is_set():
            try:
                now = time.localtime()
                target = now.tm_hour + now.tm_min / 60.0
                due = abs(target - hour) < 0.5  # within the update half-hour
                already_today = (self._last_update.get("ts") and
                                 time.strftime("%Y%m%d", time.localtime(self._last_update["ts"]))
                                 == time.strftime("%Y%m%d"))
                if self.enabled and self.cfg.get("daily_update", True) and due and not already_today:
                    self.update_now()
            except Exception:
                pass
            STOP.wait(random.randint(1500, 2100))

    # ------------------------------------------------------------- scanning
    def default_paths(self) -> List[str]:
        p = self.cfg.get("scan_paths")
        if p:
            return list(p)
        return [d for d in (DEFAULT_PATHS_WIN if IS_WIN else DEFAULT_PATHS_LINUX) if os.path.isdir(d)]

    def scan(self, paths: Optional[List[str]] = None, quarantine: bool = False,
             timeout: int = 3600) -> dict:
        """Scans files/directories; returns findings and (optionally) quarantines."""
        if not self.enabled:
            return {"error": "ClamAV integration disabled in config"}
        binp = self._scan_bin()
        if not binp:
            return {"error": "ClamAV not installed — see Settings → Antivirus"}
        with self._busy:
            targets = paths or self.default_paths()
            targets = [t for t in targets if os.path.exists(t)]
            if not targets:
                return {"error": "no existing paths to scan"}
            t0 = time.time()
            findings: List[dict] = []
            partial = False
            try:
                # directory-by-directory so one huge dir cannot eat the whole run
                for t in targets:
                    cmd = [binp, "--infected", "--no-summary"]
                    if "clamscan" in os.path.basename(binp).lower() and binp.endswith("clamscan") \
                            or os.path.basename(binp).lower().startswith("clamscan"):
                        cmd.append("--suppress-ok-results")
                    cmd.append(t)
                    r = subprocess.run(cmd, capture_output=True, text=True, timeout=max(60, timeout // max(1, len(targets))),
                                       creationflags=0x08000000 if IS_WIN else 0)
                    out = (r.stdout or "") + (r.stderr or "")
                    for line in out.splitlines():
                        line = line.strip()
                        if line.endswith(" FOUND"):
                            path = line[:-len(" FOUND")].strip()
                            # clamdscan prints "<path>: Eicar-Test-Signature FOUND"
                            path, _, sig = path.rpartition(": ") if ": " in path else (path, "", "")
                            if path and sig:
                                findings.append({"path": path, "signature": sig})
                    if r.returncode == 2:
                        partial = True
                    if len(findings) >= MAX_FINDINGS:
                        break
            except subprocess.TimeoutExpired:
                partial = True
            except Exception as e:  # noqa: BLE001
                return {"error": f"scan failed: {str(e)[:200]}"}
            quarantined = []
            if findings and (quarantine or self.cfg.get("auto_quarantine")):
                from .procinfo import dispose_file
                for f in findings[:MAX_FINDINGS]:
                    try:
                        res = dispose_file(f["path"], f"ClamAV: {f['signature']}", "quarantine")
                        if res and res.get("status") in ("quarantined", "moved", "deleted"):
                            quarantined.append(f["path"])
                    except Exception:
                        pass
            result = {
                "ok": True,
                "scanned": targets,
                "files_scanned": "?",  # clamdscan --no-summary hides it; keep findings meaningful
                "findings": findings,
                "quarantined": quarantined,
                "partial": partial,
                "duration_seconds": round(time.time() - t0, 1),
            }
            self._last_scan = {"ts": time.time(), "findings": len(findings),
                               "paths": len(targets), "quarantined": len(quarantined)}
            event("clamav_scan_complete" if not findings else "clamav_threats_found",
                  "info" if not findings else "critical",
                  threats=len(findings), quarantined=len(quarantined),
                  duration=result["duration_seconds"])
            return result
