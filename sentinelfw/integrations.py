"""SentinelFW 3.0 — integration manager, Go service supervisor, key handling.

Pulls Suricata / ClamAV in automatically when possible, supervises the Go
sentinelgated daemon when a Go toolchain exists, and lets API keys come from
environment variables instead of the plaintext config.
"""
import os
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional

from .common import HOME, IS_WIN, event

IS_LINUX = not IS_WIN
GO_ROOT = Path(__file__).resolve().parents[1]  # repo root containing go.mod
GO_BIN_DIR = HOME / "bin"


# =====================================================================
# API keys from environment variables
# =====================================================================
def get_key(cfg: dict, section: str, field: str, envvar: str) -> str:
    """Returns an API key/token: environment variable wins over config.

    This lets enterprises inject secrets via systemd Environment= / Windows
    user env vars instead of storing them in the plaintext config.json.
    """
    env = os.environ.get(envvar, "").strip()
    if env:
        return env
    try:
        return str((cfg.get(section) or {}).get(field) or "")
    except Exception:
        return ""


# =====================================================================
# Suricata / ClamAV: detect + auto-provision ("pulled by default")
# =====================================================================
class IntegrationManager:
    """Detects (and on Linux, optionally installs) Suricata and ClamAV.

    auto_install is OFF by default (explicit opt-in required): the engine tries
    `apt-get install -y suricata clamav clamav-daemon` once only when configured
    with integrations.auto_install = true. Every attempt degrades gracefully
    (non-root, non-Linux, no apt, offline) with a clear event — never a crash.
    """

    DEBS = ("suricata", "clamav", "clamav-daemon")

    def __init__(self, cfg_get):
        self._cfg_get = cfg_get
        self._install_attempted = False
        self.lock = threading.Lock()

    def _cfg(self) -> dict:
        try:
            return self._cfg_get().get("integrations", {}) or {}
        except Exception:
            return {}

    @staticmethod
    def _which(names) -> Optional[str]:
        for n in names:
            p = shutil.which(n)
            if p:
                return p
        return None

    def detect(self) -> dict:
        return {
            "suricata": bool(self._which(("suricata",))),
            "clamav": bool(self._which(("clamscan", "clamdscan", "clamd"))),
            "freshclam": bool(self._which(("freshclam",))),
        }

    def _can_install(self) -> tuple:
        if IS_WIN:
            return False, "windows: install ClamAV/Suricata manually (see docs/DEPLOYMENT.md)"
        if not self._which(("apt-get",)):
            return False, "apt-get not available on this host"
        if os.geteuid() != 0:
            return False, "root required for auto-install (run via service/systemd)"
        return True, ""

    def auto_install(self) -> dict:
        """One best-effort attempt to install missing engine integrations."""
        out = {"attempted": False, "installed": [], "note": ""}
        with self.lock:
            if self._install_attempted:
                return out
            self._install_attempted = True
        cfg = self._cfg()
        if not cfg.get("auto_install", False):
            out["note"] = "auto_install disabled in config"
            return out
        det = self.detect()
        missing = [d for d, present in (("suricata", det["suricata"]),
                                        ("clamav", det["clamav"])) if not present]
        if not missing:
            out["note"] = "all integrations already present"
            return out
        ok, why = self._can_install()
        if not ok:
            out["note"] = why
            event("integration_auto_install_skipped", "info", missing=missing, reason=why)
            return out
        out["attempted"] = True
        pkgs = [p for p in self.DEBS if p in missing or p == "clamav"]
        try:
            r = subprocess.run(["apt-get", "install", "-y", *dict.fromkeys(pkgs)],
                               capture_output=True, text=True, timeout=600)
            if r.returncode == 0:
                out["installed"] = pkgs
                event("integration_auto_installed", "info", packages=pkgs)
            else:
                out["note"] = (r.stderr or r.stdout or "")[:200]
                event("integration_auto_install_failed", "warning",
                      packages=pkgs, error=out["note"])
        except Exception as e:
            out["note"] = str(e)[:200]
            event("integration_auto_install_failed", "warning", error=str(e)[:200])
        return out

    def ensure(self):
        """Called once at daemon start: install if missing, then report."""
        res = self.auto_install()
        det = self.detect()
        event("integrations_detected", "info", suricata=det["suricata"],
              clamav=det["clamav"], auto_install=res.get("attempted", False),
              note=res.get("note", ""))

    def status(self) -> dict:
        det = self.detect()
        return {"suricata": det["suricata"], "clamav": det["clamav"],
                "freshclam": det["freshclam"],
                "auto_install": bool(self._cfg().get("auto_install", False))}


# =====================================================================
# Go services supervisor (sentinelgated + future per-service binaries)
# =====================================================================
class GoServiceSupervisor:
    """Builds and supervises the Go data-plane daemon (sentinelgated).

    Honest status model — the supervisor never pretends a service is
    running when it is not:

      go_not_installed  no Go toolchain on this host
      build_failed      `go build` failed (see event output)
      stopped           built, not started (config disabled)
      running           process alive
      crashed           process exited (exit code in status)
    """

    def __init__(self, cfg_get):
        self._cfg_get = cfg_get
        self.proc: Optional[subprocess.Popen] = None
        self.bin_path: Optional[Path] = None
        self.build_error = ""
        self.lock = threading.Lock()
        self._watcher: Optional[threading.Thread] = None

    def _cfg(self) -> dict:
        try:
            return self._cfg_get().get("go_services", {}) or {}
        except Exception:
            return {}

    def enabled(self) -> bool:
        return bool(self._cfg().get("enabled"))

    @staticmethod
    def go_available() -> bool:
        return shutil.which("go") is not None

    def build(self) -> bool:
        """go build -o <data>/bin/sentinelgated ./cmd/sentinelgated"""
        if not self.go_available():
            self.build_error = "go toolchain not installed"
            return False
        try:
            GO_BIN_DIR.mkdir(parents=True, exist_ok=True)
            out = GO_BIN_DIR / "sentinelgated"
            r = subprocess.run(["go", "build", "-o", str(out), "./cmd/sentinelgated"],
                               cwd=str(GO_ROOT), capture_output=True, text=True, timeout=300)
            if r.returncode == 0 and out.exists():
                self.bin_path = out
                self.build_error = ""
                return True
            self.build_error = (r.stderr or r.stdout or "")[-400:]
            event("go_build_failed", "warning", error=self.build_error[:200])
            return False
        except Exception as e:
            self.build_error = str(e)[:200]
            return False

    def start(self, force: bool = False) -> bool:
        with self.lock:
            if self.proc and self.proc.poll() is None:
                return True  # already running
            if not (self.enabled() or force):
                return False
            if (not self.bin_path or not self.bin_path.exists()):
                if not self._cfg().get("build_if_missing", True):
                    return False
                if not self.build():
                    return False
            try:
                self.proc = subprocess.Popen(
                    [str(self.bin_path),
                     "-listen", str(self._cfg().get("listen", ":8443")),
                     "-socket", str(HOME / "sentinelgate.sock")],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    start_new_session=True)
            except Exception as e:
                event("go_service_start_failed", "warning", error=str(e)[:200])
                return False
            event("go_service_started", "info", pid=self.proc.pid)
            self._watcher = threading.Thread(target=self._watch, daemon=True,
                                             name="sfw_go_supervisor")
            self._watcher.start()
            return True

    def stop(self):
        with self.lock:
            if self.proc and self.proc.poll() is None:
                try:
                    self.proc.terminate()
                    self.proc.wait(timeout=10)
                except Exception:
                    try:
                        self.proc.kill()
                    except Exception:
                        pass
                event("go_service_stopped", "info")

    def _watch(self):
        """Restart-once-on-crash with backoff; health = process liveness."""
        while True:
            time.sleep(10)
            with self.lock:
                p = self.proc
            if p is None:
                return
            rc = p.poll()
            if rc is not None:
                event("go_service_crashed", "high", exit_code=rc)
                with self.lock:
                    self.proc = None
                if self.enabled():
                    time.sleep(5)
                    self.start()

    def status(self) -> dict:
        built = bool(self.bin_path and self.bin_path.exists())
        if self.proc is not None and self.proc.poll() is None:
            state = "running"
        elif self.proc is not None:
            state = "crashed"
        elif not self.go_available():
            state = "go_not_installed"
        elif self.build_error and not built:
            state = "build_failed"
        elif built:
            state = "stopped"
        else:
            state = "not_built"
        return {"state": state, "enabled": self.enabled(),
                "pid": self.proc.pid if self.proc and self.proc.poll() is None else None,
                "binary": str(self.bin_path) if built else "",
                "build_error": self.build_error[:200],
                "note": ("sentinelgated is a skeleton control daemon; its data-plane "
                         "packages (tlsproxy / vpn / sdwan) are not wired to listeners yet")}


# =====================================================================
# TLS helpers for the console
# =====================================================================
def generate_self_signed(cert: Path, key: Path, days: int = 825,
                         cn: str = "sentinelfw") -> bool:
    """Generates self-signed TLS certificate and private key.

    Tries the bundled sfw-certgen Go helper first, openssl only as fallback,
    so it works reliably on stock Windows and Ubuntu.
    """
    cert = Path(cert)
    key = Path(key)
    try:
        cert.parent.mkdir(parents=True, exist_ok=True)
        key.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass

    # 1. Bundled or built sfw-certgen helper
    sfw_certgen = shutil.which("sfw-certgen") or shutil.which("sfw-certgen.exe")
    if not sfw_certgen:
        candidate = GO_BIN_DIR / ("sfw-certgen.exe" if IS_WIN else "sfw-certgen")
        if candidate.exists():
            sfw_certgen = str(candidate)

    if sfw_certgen:
        try:
            r = subprocess.run([
                sfw_certgen, "generate",
                "-cert", str(cert), "-key", str(key),
                "-cn", cn, "-days", str(days)
            ], capture_output=True, text=True, timeout=30)
            if r.returncode == 0 and cert.exists() and key.exists():
                return True
        except Exception:
            pass

    # 2. Go toolchain invocation of ./cmd/sfw-certgen
    if shutil.which("go") is not None:
        try:
            r = subprocess.run([
                "go", "run", "./cmd/sfw-certgen", "generate",
                "-cert", str(cert), "-key", str(key),
                "-cn", cn, "-days", str(days)
            ], capture_output=True, text=True, timeout=60, cwd=str(REPO_ROOT))
            if r.returncode == 0 and cert.exists() and key.exists():
                return True
        except Exception:
            pass

    # 3. OpenSSL CLI fallback
    if shutil.which("openssl") is not None:
        try:
            import tempfile
            with tempfile.NamedTemporaryFile(mode="w", suffix=".cnf", delete=False) as cnf:
                cnf.write("[req]\ndistinguished_name=req_dn\n[req_dn]\n")
                cnf_path = cnf.name
            try:
                r = subprocess.run(
                    ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                     "-days", str(days), "-config", cnf_path, "-subj", f"/CN={cn}",
                     "-keyout", str(key), "-out", str(cert)],
                    capture_output=True, text=True, timeout=60)
                if r.returncode == 0 and cert.exists() and key.exists():
                    return True
            finally:
                try:
                    os.unlink(cnf_path)
                except OSError:
                    pass
        except Exception:
            pass

    return cert.exists() and key.exists()
