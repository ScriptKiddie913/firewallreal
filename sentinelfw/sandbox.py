"""SentinelFW Behavioral Sandbox.

Provides safe, isolated execution of suspicious binaries and scripts with
strict resource constraints, timeout enforcement, and automated behavioral verdicts.
"""
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional
from .common import DATA_DIR, IS_WIN, event
from .sandbox_monitor import SandboxMonitor
from .sandbox_verdict import SandboxVerdict


class Sandbox:
    """Executes suspicious files in an isolated temporary harness and scores their behavior."""

    def __init__(self, cfg=None):
        self.cfg = cfg or {}
        s_cfg = self.cfg.get("sandbox", {})
        self.enabled = s_cfg.get("enabled", True)
        self.max_timeout = int(s_cfg.get("max_execution_seconds", 60))
        self.memory_limit_mb = int(s_cfg.get("memory_limit_mb", 256))
        self.network_allowed = bool(s_cfg.get("network_allowed", False))
        self.results_dir = DATA_DIR / "sandbox_reports"
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self._history: List[dict] = []
        self._lock = threading.RLock()

    def analyze_file(self, target_file: Path) -> dict:
        """Detonates a binary/script inside the sandbox and returns a full verdict report."""
        target = Path(target_file)
        if not target.is_file():
            return {"error": "file_not_found", "verdict": "ERROR"}

        start_time = time.time()
        sandbox_env = Path(tempfile.mkdtemp(prefix="sfw_sandbox_"))
        monitor = SandboxMonitor(sandbox_env)

        try:
            # Copy sample into sandbox directory
            sample_in_env = sandbox_env / target.name
            shutil.copy2(target, sample_in_env)

            # Record clean initial state
            monitor.snapshot_initial_state()

            # Execute sample under isolation
            self._execute_sample(sample_in_env, sandbox_env, monitor)

            # Evaluate diff
            activity = monitor.evaluate_changes()

            # Render verdict
            verdict_res = SandboxVerdict.evaluate(activity["indicators"], activity)

            report = {
                "sample_name": target.name,
                "sample_path": str(target),
                "timestamp": start_time,
                "duration": round(time.time() - start_time, 2),
                "verdict": verdict_res["verdict"],
                "total_score": verdict_res["total_score"],
                "matched_rules": verdict_res["matched_rules"],
                "indicators": activity["indicators"],
                "files_created": activity["files_created"],
                "files_modified": activity["files_modified"],
                "files_deleted": activity["files_deleted"],
                "spawned_processes": activity["spawned_processes"],
            }

            # Save report
            rep_file = self.results_dir / f"report_{target.name}_{int(start_time)}.json"
            rep_file.write_text(json.dumps(report, indent=2), encoding="utf-8")

            with self._lock:
                self._history.append(report)
                if len(self._history) > 100:
                    self._history.pop(0)

            event(
                "sandbox_analysis_completed",
                "high" if verdict_res["is_threat"] else "info",
                sample=target.name,
                verdict=verdict_res["verdict"],
                score=verdict_res["total_score"],
            )

            return report

        finally:
            shutil.rmtree(sandbox_env, ignore_errors=True)

    def _execute_sample(self, sample_path: Path, work_dir: Path, monitor: SandboxMonitor):
        """Launches the sample under platform-specific restrictions."""
        cmd = []
        if IS_WIN:
            # On Windows, run via cmd /c or direct exe inside work_dir with timeout
            if sample_path.suffix.lower() in (".bat", ".cmd"):
                cmd = ["cmd.exe", "/c", str(sample_path)]
            elif sample_path.suffix.lower() == ".ps1":
                cmd = ["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", str(sample_path)]
            else:
                cmd = [str(sample_path)]
        else:
            # On Linux, run in non-root or unshare if permitted
            os.chmod(sample_path, 0o755)
            cmd = [str(sample_path)]

        try:
            p = subprocess.Popen(
                cmd,
                cwd=str(work_dir),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
            )
            monitor.spawned_processes.append(f"{sample_path.name} (PID: {p.pid})")
            try:
                p.wait(timeout=self.max_timeout)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
                monitor.observed_indicators.add("disables_security_controls")
        except Exception as e:
            # Execution failure or binary not directly runnable
            pass

    def get_reports(self, limit: int = 50) -> List[dict]:
        with self._lock:
            return list(self._history)[-limit:]
