"""SentinelFW Application Firewall and Process Inventory.

Provides granular per-application network security policies, continuous process
tree inventory, binary hash tracking, and multi-layer OS enforcement.
"""
import fnmatch
import hashlib
import ipaddress
import os
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from .common import DATA_DIR, IS_WIN, event, run
from .procinfo import dispose_file, is_protected_path, kill_process, sha256_file, win_exe


class ApplicationInventory:
    """Maintains a live catalog of all running processes with binary hashes and hierarchy."""

    def __init__(self):
        self._lock = threading.RLock()
        self._procs: Dict[int, dict] = {}
        self._hashes: Dict[str, str] = {}
        self._signatures: Dict[str, dict] = {}

    def scan(self) -> Dict[int, dict]:
        """Scans the operating system process table."""
        active = {}
        if IS_WIN:
            active = self._scan_windows()
        else:
            active = self._scan_linux()

        with self._lock:
            self._procs = active
        return dict(active)

    def _scan_linux(self) -> Dict[int, dict]:
        res = {}
        for d in os.listdir("/proc"):
            if not d.isdigit():
                continue
            pid = int(d)
            try:
                exe = os.readlink(f"/proc/{pid}/exe")
            except OSError:
                exe = ""
            try:
                cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(errors="ignore").strip()
            except OSError:
                cmdline = ""
            try:
                status = Path(f"/proc/{pid}/status").read_text(errors="ignore")
                ppid = 0
                for line in status.splitlines():
                    if line.startswith("PPid:"):
                        ppid = int(line.split()[1])
                        break
            except OSError:
                ppid = 0

            sha256 = self.get_hash(exe) if exe and not exe.endswith(" (deleted)") else ""
            res[pid] = {
                "pid": pid,
                "ppid": ppid,
                "exe": exe,
                "name": os.path.basename(exe) if exe else f"[{pid}]",
                "cmdline": cmdline,
                "sha256": sha256,
                "signed": True if is_protected_path(exe) else False,
            }
        return res

    def _scan_windows(self) -> Dict[int, dict]:
        res = {}
        rc, out, _ = run(["tasklist", "/FO", "CSV", "/V", "/NH"])
        if rc != 0 or not out:
            return res

        for row in out.splitlines():
            row = row.strip()
            if not row or not row.startswith('"'):
                continue
            parts = [p.strip('"') for p in row.split('","')]
            if len(parts) >= 2 and parts[1].isdigit():
                pid = int(parts[1])
                name = parts[0]
                user = parts[6] if len(parts) > 6 else ""
                exe = win_exe(pid) if pid > 4 else f"C:\\Windows\\System32\\{name}"
                sha = self.get_hash(exe) if exe else ""
                res[pid] = {
                    "pid": pid,
                    "ppid": 0,
                    "exe": exe,
                    "name": name,
                    "user": user,
                    "sha256": sha,
                    "signed": True if is_protected_path(exe) else False,
                }
        return res

    def get_hash(self, path: str) -> str:
        """Returns cached SHA-256 for a binary."""
        if not path or not os.path.isfile(path):
            return ""
        if path in self._hashes:
            return self._hashes[path]
        try:
            h = sha256_file(path)
            self._hashes[path] = h
            return h
        except Exception:
            return ""

    def get_process(self, pid: int) -> Optional[dict]:
        with self._lock:
            return self._procs.get(pid)

    def get_all(self) -> List[dict]:
        with self._lock:
            return list(self._procs.values())


class AppPolicyRule:
    """A single per-application firewall policy specification."""

    def __init__(self, data: dict):
        self.raw = data
        self.match = data.get("match", {})
        self.allow_outbound = set(p.lower() for p in data["allow_outbound"]) if "allow_outbound" in data else None
        self.allow_inbound = set(p.lower() for p in data["allow_inbound"]) if "allow_inbound" in data else None
        self.allow_dests = [ipaddress.ip_network(n, strict=False) for n in data.get("allow_destinations", [])]
        self.deny_dests = [ipaddress.ip_network(n, strict=False) for n in data.get("deny_destinations", [])]
        self.action = data.get("action_on_violation", "block+alert").lower()

    def matches(self, exe: str, sha256: str = "", user: str = "") -> bool:
        """Checks if a process satisfies rule matching criteria."""
        norm_exe = exe.replace("\\", "/").lower()

        if "exe_path" in self.match:
            target = self.match["exe_path"].replace("\\", "/").lower()
            if norm_exe != target:
                return False

        if "exe_glob" in self.match:
            glob_pat = self.match["exe_glob"].replace("\\", "/").lower()
            if not fnmatch.fnmatch(norm_exe, glob_pat):
                return False

        if "sha256" in self.match:
            if sha256.lower() != self.match["sha256"].lower():
                return False

        if "user" in self.match:
            if user.lower() != self.match["user"].lower():
                return False

        return True

    def evaluate(self, direction: str, proto: str, remote_ip: str, remote_port: int) -> Tuple[bool, str]:
        """Evaluates whether the network connection is permitted by this policy."""
        proto = proto.lower()
        port_spec = f"{proto}/{remote_port}"

        # 1. Port authorization
        if direction == "outbound":
            if self.allow_outbound is not None and port_spec not in self.allow_outbound and "*" not in self.allow_outbound:
                return False, f"outbound port {port_spec} not allowed"
        elif direction == "inbound":
            if self.allow_inbound is not None and port_spec not in self.allow_inbound and "*" not in self.allow_inbound:
                return False, f"inbound port {port_spec} not allowed"

        # 2. Destination IP restrictions
        if remote_ip and remote_ip not in ("0.0.0.0", "::", "127.0.0.1"):
            try:
                ip_obj = ipaddress.ip_address(remote_ip)
                for net in self.deny_dests:
                    if ip_obj in net:
                        return False, f"destination {remote_ip} in denied CIDR {net}"

                if self.allow_dests:
                    allowed = any(ip_obj in net for net in self.allow_dests)
                    if not allowed:
                        return False, f"destination {remote_ip} not in allowed CIDRs"
            except ValueError:
                pass

        return True, "permitted"


class ApplicationFirewall:
    """Orchestrates per-application policies and enforces network rules."""

    def __init__(self, cfg=None, inventory=None):
        self.cfg = cfg or {}
        af_cfg = self.cfg.get("application_firewall", {})
        self.enabled = af_cfg.get("enabled", True)
        self.default_policy = af_cfg.get("default_policy", "allow").lower()
        self.inventory = inventory or ApplicationInventory()
        self.rules: List[AppPolicyRule] = []
        self._applied_os_rules = set()
        self._violations: List[dict] = []
        self._vlock = threading.RLock()
        self.load_policies(af_cfg.get("policies", []))

    def get_policies(self) -> List[dict]:
        """Returns the raw active policy list for the Web UI."""
        af_cfg = self.cfg.get("application_firewall", {})
        return af_cfg.get("policies", [])

    def get_violations(self, limit: int = 100) -> List[dict]:
        """Returns recent policy violations (newest first)."""
        with self._vlock:
            return list(reversed(self._violations))[:limit]

    def load_policies(self, policy_list: List[dict]):
        """Parses and updates the list of active policy rules."""
        self.rules = [AppPolicyRule(p) for p in policy_list]

    def evaluate_connection(self, pid: int, exe: str, direction: str, proto: str,
                            remote_ip: str, remote_port: int) -> Tuple[bool, str, str]:
        """
        Evaluates a process network attempt.
        Returns: (allowed: bool, reason: str, action: str)
        """
        if not self.enabled:
            return True, "appwall_disabled", "none"

        proc_info = self.inventory.get_process(pid) if pid else None
        sha = proc_info.get("sha256", "") if proc_info else ""
        user = proc_info.get("user", "") if proc_info else ""

        for r in self.rules:
            if r.matches(exe, sha, user):
                allowed, detail = r.evaluate(direction, proto, remote_ip, remote_port)
                if not allowed:
                    return False, f"policy_violation: {detail}", r.action
                return True, "matched_allow_policy", "none"

        # Protected system services default to allow if not explicitly restricted
        if is_protected_path(exe):
            return True, "system_protected", "none"

        # Default policy fallback
        if self.default_policy == "deny":
            return False, "default_deny_policy", "block+alert"
        return True, "default_allow", "none"

    def enforce_violation(self, pid: int, exe: str, reason: str, action: str):
        """Executes the assigned remediation action for a violating application."""
        event("appwall_violation", "high", pid=pid, exe=exe, reason=reason, action=action)
        with self._vlock:
            self._violations.append({
                "ts": time.time(), "pid": pid, "exe": exe,
                "reason": reason, "action": action,
            })
            if len(self._violations) > 1000:
                self._violations = self._violations[-500:]

        if "kill" in action:
            kill_process(pid)
        if "quarantine" in action and exe:
            dispose_file(exe, reason, "quarantine")
        elif "delete" in action and exe:
            dispose_file(exe, reason, "delete")
        if "block" in action and IS_WIN and exe:
            self._apply_windows_block(exe)

    def _apply_windows_block(self, exe: str):
        """Creates an OS-level Windows firewall rule for an executable."""
        rule_name = f"SentinelFW_Block_{hashlib.md5(exe.encode()).hexdigest()[:8]}"
        if rule_name in self._applied_os_rules:
            return
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=out",
            "action=block",
            f"program={exe}",
            "enable=yes",
        ]
        rc, _, _ = run(cmd)
        if rc == 0:
            self._applied_os_rules.add(rule_name)
            event("appwall_os_rule_added", "info", rule=rule_name, exe=exe)
