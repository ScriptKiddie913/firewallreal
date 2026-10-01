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

    def __init__(self, cfg=None, engine=None):
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
        self.engine = engine

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

            if verdict_res.get("verdict") == "MALICIOUS" and self.engine and hasattr(self.engine, "ban"):
                source_ip = getattr(target, "source_ip", None)
                if source_ip:
                    self.engine.ban(source_ip, reason=f"Sandbox detonation detected malicious sample {target.name}")

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
        """
        Launches sample strictly inside an isolated microVM or disposable container.
        CRITICAL: Never executes untrusted attacker binaries directly on the firewall host.
        """
        remote_url = self.cfg.get("sandbox", {}).get("remote_microvm_url")
        if remote_url:
            # Ship sample to dedicated isolated sandbox microVM
            try:
                import urllib.request
                with open(sample_path, "rb") as f:
                    req = urllib.request.Request(f"{remote_url}/detonate", data=f.read(),
                                                 headers={"Content-Type": "application/octet-stream"})
                    with urllib.request.urlopen(req, timeout=self.max_timeout) as resp:
                        res = json.loads(resp.read().decode())
                        monitor.spawned_processes.extend(res.get("spawned_processes", []))
                        for ind in res.get("indicators", []):
                            monitor.observed_indicators.add(ind)
                        return
            except Exception as e:
                event("sandbox_remote_error", "warning", error=str(e))

        docker_bin = shutil.which("docker") or shutil.which("podman")
        if docker_bin and not IS_WIN:
            # Run inside disposable container with zero network and dropped capabilities
            cmd = [
                docker_bin, "run", "--rm",
                "--network", "none",
                "--cap-drop", "ALL",
                "--read-only",
                "-m", f"{self.memory_limit_mb}m",
                "-v", f"{work_dir}:/sandbox:rw",
                "sentinelgate/sandbox-worker:latest",
                f"/sandbox/{sample_path.name}"
            ]
            try:
                p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                monitor.spawned_processes.append(f"container:{sample_path.name} (PID: {p.pid})")
                p.wait(timeout=self.max_timeout)
            except Exception:
                pass
            return

        # AIRGAP FALLBACK: Perform deep static analysis without executing code on the firewall host
        self._static_inspection(sample_path, monitor)

    def _static_inspection(self, sample_path: Path, monitor: SandboxMonitor):
        """Extracts indicators from binary structure without executing on the firewall host."""
        try:
            data = sample_path.read_bytes()
            # 1. Header parsing
            if data.startswith(b"MZ"):
                monitor.observed_indicators.add("windows_pe_executable")
            elif data.startswith(b"\x7fELF"):
                monitor.observed_indicators.add("linux_elf_executable")

            # 2. Entropy calculation
            import math, collections
            if data:
                c = collections.Counter(data)
                entropy = -sum((cnt / len(data)) * math.log2(cnt / len(data)) for cnt in c.values())
                if entropy > 7.2:
                    monitor.observed_indicators.add("high_entropy_packed_binary")

            # 3. Malicious pattern extraction
            suspicious_terms = [b"cmd.exe", b"powershell", b"/bin/sh", b"WScript.Shell",
                                b"URLDownloadToFile", b"VirtualAlloc", b"CreateRemoteThread",
                                b"reg add", b"/etc/shadow", b"xmrig", b"stratum+tcp"]
            for term in suspicious_terms:
                if term in data:
                    monitor.observed_indicators.add(f"string:{term.decode('ascii', 'ignore')}")
        except Exception:
            pass

    def get_reports(self, limit: int = 50) -> List[dict]:
        with self._lock:
            return list(self._history)[-limit:]
