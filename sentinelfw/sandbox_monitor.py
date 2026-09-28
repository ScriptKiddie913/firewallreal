"""SentinelFW Sandbox Monitor.

Tracks file modifications, process spawn behavior, network attempts,
and IOC artifacts generated during an isolated sandbox execution.
"""
import hashlib
import os
from pathlib import Path
from typing import Dict, List, Set


class SandboxMonitor:
    """Monitors artifacts and behavior inside an isolated sandbox directory."""

    def __init__(self, sandbox_dir: Path):
        self.sandbox_dir = Path(sandbox_dir)
        self._initial_files: Dict[str, str] = {}
        self.files_created: List[str] = []
        self.files_modified: List[str] = []
        self.files_deleted: List[str] = []
        self.spawned_processes: List[str] = []
        self.observed_indicators: Set[str] = set()

    def snapshot_initial_state(self):
        """Records initial file state of the sandbox container."""
        self._initial_files = self._scan_dir()

    def _scan_dir(self) -> Dict[str, str]:
        res = {}
        if not self.sandbox_dir.exists():
            return res
        for root, _, files in os.walk(self.sandbox_dir):
            for f in files:
                p = Path(root) / f
                try:
                    rel = str(p.relative_to(self.sandbox_dir))
                    res[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
                except OSError:
                    pass
        return res

    def evaluate_changes(self) -> dict:
        """Compares post-execution state with initial state and derives indicators."""
        current = self._scan_dir()

        # Files created or modified
        for rel_path, cur_hash in current.items():
            if rel_path not in self._initial_files:
                self.files_created.append(rel_path)
                # Check for ransomware note or executable drops
                low = rel_path.lower()
                if low.endswith((".exe", ".dll", ".bat", ".cmd", ".ps1", ".sh", ".bin")):
                    self.observed_indicators.add("creates_temp_executable")
                if "readme" in low or "decrypt" in low or "restore" in low:
                    self.observed_indicators.add("ransomware_note_detected")
            elif self._initial_files[rel_path] != cur_hash:
                self.files_modified.append(rel_path)

        # Files deleted
        for rel_path in self._initial_files:
            if rel_path not in current:
                self.files_deleted.append(rel_path)

        if len(self.files_modified) + len(self.files_created) >= 10:
            self.observed_indicators.add("mass_file_modification")

        return {
            "files_created": self.files_created,
            "files_modified": self.files_modified,
            "files_deleted": self.files_deleted,
            "spawned_processes": self.spawned_processes,
            "indicators": list(self.observed_indicators),
        }
