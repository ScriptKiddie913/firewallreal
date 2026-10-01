"""SentinelFW Suricata Manager.

Manages Suricata IDS/IPS process lifecycle, configuration generation,
rule updates, and EVE JSON output streams.
"""
import os
import shutil
import signal
import subprocess
import threading
import time
from pathlib import Path
from .common import DATA_DIR, IS_WIN, LOGS, STOP, event, run

SURICATA_DEFAULT_YAML = """%YAML 1.1
---
default-rule-path: {rules_dir}
rule-files:
  - suricata.rules

vars:
  address-groups:
    HOME_NET: "[{home_net}]"
    EXTERNAL_NET: "!$HOME_NET"
    HTTP_SERVERS: "$HOME_NET"
    SQL_SERVERS: "$HOME_NET"
    DNS_SERVERS: "$HOME_NET"

default-log-dir: {log_dir}

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            payload: yes
            payload-buffer-size: 4kb
            payload-printable: yes
            metadata: yes
            http-body: yes
        - http:
            extended: yes
        - dns:
            query: yes
            answer: yes
        - tls:
            extended: yes
        - files:
            force-magic: yes
        - smtp:
            extended: yes
        - ssh
        - flow
        - anomaly:
            enabled: yes
            types:
              decode: yes
              stream: yes
              applayer: yes

app-layer:
  protocols:
    tls:
      enabled: yes
      detection-ports:
        dp: 443
    http:
      enabled: yes
    dns:
      tcp:
        enabled: yes
      udp:
        enabled: yes
    ftp:
      enabled: yes
    smtp:
      enabled: yes
    ssh:
      enabled: yes
    smb:
      enabled: yes

af-packet:
  - interface: default
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
"""


class SuricataManager:
    """Manages the Suricata process lifecycle, configuration, and rules."""

    def __init__(self, cfg=None):
        self.cfg = cfg or {}
        suricata_cfg = self.cfg.get("suricata", {})
        self.enabled = suricata_cfg.get("enabled", True)
        self.binary = suricata_cfg.get("binary", "auto")
        self.config_dir = DATA_DIR / "suricata"
        self.rules_dir = self.config_dir / "rules"
        self.log_dir = LOGS / "suricata"
        self.eve_path = self.log_dir / "eve.json"
        self.process = None
        self._thread = None
        self._suricata_bin = self._find_binary()

    def _find_binary(self) -> str:
        """Locates the Suricata executable on Windows or Linux."""
        if self.binary and self.binary != "auto":
            if Path(self.binary).is_file():
                return str(self.binary)

        # Check standard PATH
        found = shutil.which("suricata")
        if found:
            return found

        # Check common Windows install locations
        if IS_WIN:
            candidates = [
                r"C:\Program Files\Suricata\suricata.exe",
                r"C:\Program Files (x86)\Suricata\suricata.exe",
                r"C:\Tools\suricata\suricata.exe",
                r"C:\ProgramData\chocolatey\bin\suricata.exe",
                os.path.expandvars(r"%LOCALAPPDATA%\Programs\Suricata\suricata.exe"),
                os.path.expandvars(r"%USERPROFILE%\scoop\apps\suricata\current\suricata.exe"),
            ]
            for c in candidates:
                if os.path.isfile(c):
                    return c
        else:
            candidates = [
                "/usr/bin/suricata",
                "/usr/local/bin/suricata",
                "/sbin/suricata",
                "/usr/sbin/suricata",
            ]
            for c in candidates:
                if os.path.isfile(c):
                    return c
        return ""

    def is_available(self) -> bool:
        """Returns True if a valid Suricata binary is detected."""
        return bool(self._suricata_bin and os.path.isfile(self._suricata_bin))

    def status(self) -> dict:
        """Rich state for the dashboard: running / installed / not_installed / disabled."""
        if not self.cfg_enabled():
            return {"state": "disabled", "detail": "disabled in config"}
        if not self.is_available():
            return {"state": "not_installed",
                    "detail": "Suricata binary not found — optional component. "
                              "Install it (choco install suricata / apt install suricata) "
                              "or set suricata.binary in config.json; the built-in Python "
                              "sniffer keeps protecting you meanwhile."}
        if self.process and self.process.poll() is None:
            return {"state": "running", "detail": f"PID {self.process.pid}"}
        return {"state": "installed", "detail": "binary detected; starts with the engine"}

    def cfg_enabled(self) -> bool:
        try:
            return bool(self.cfg.get("enabled", True))
        except Exception:
            return True

    def ensure_directories(self):
        """Creates configuration and log directories."""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def generate_config(self, interface: str = "auto", home_net: str = "auto") -> Path:
        """Generates suricata.yaml tailored for SentinelFW."""
        self.ensure_directories()
        hnet = home_net if home_net != "auto" else "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,127.0.0.1/32"
        content = SURICATA_DEFAULT_YAML.format(
            rules_dir=str(self.rules_dir).replace("\\", "/"),
            home_net=hnet,
            log_dir=str(self.log_dir).replace("\\", "/"),
        )
        cfg_file = self.config_dir / "suricata.yaml"
        cfg_file.write_text(content, encoding="utf-8")

        # Create basic default rules file if none exists
        default_rules = self.rules_dir / "suricata.rules"
        if not default_rules.exists():
            default_rules.write_text(
                '# SentinelFW default Suricata rules\n'
                'alert tcp any any -> any any (msg:"SentinelFW SQLi Test Probe"; content:"UNION SELECT"; nocase; sid:9000001; rev:1;)\n'
                'alert tcp any any -> any any (msg:"SentinelFW Log4Shell JNDI Exploit"; content:"${jndi:"; nocase; sid:9000002; rev:1;)\n'
                'alert tcp any any -> any any (msg:"SentinelFW Spring4Shell RCE"; content:"class.module.classLoader"; nocase; sid:9000003; rev:1;)\n'
                'alert tcp any any -> any any (msg:"SentinelFW Shellshock CVE-2014-6271"; content:"() { :;};"; sid:9000004; rev:1;)\n',
                encoding="utf-8"
            )
        return cfg_file

    def update_rules(self) -> bool:
        """Runs suricata-update if installed or downloads community rules."""
        updater = shutil.which("suricata-update")
        if updater:
            try:
                event("suricata_rules_updating", "info", tool="suricata-update")
                rc, out, err = run([updater])
                if rc == 0:
                    event("suricata_rules_updated", "info")
                    self.reload_rules()
                    return True
            except Exception as e:
                event("suricata_update_error", "medium", error=str(e))
        return False

    def start(self, interface: str = "auto") -> bool:
        """Starts the Suricata process in the background with health monitoring."""
        if not self.is_available():
            event("suricata_missing", "info", msg="Suricata not detected, fallback to Python sniffer")
            return False

        if self.process and self.process.poll() is None:
            return True

        cfg_file = self.generate_config(interface=interface)
        cmd = [self._suricata_bin, "-c", str(cfg_file)]

        if IS_WIN:
            # On Windows, use pcap or WinDivert if specified
            cmd.extend(["-l", str(self.log_dir)])
        else:
            if interface != "auto":
                cmd.extend(["--af-packet=" + interface])
            else:
                cmd.extend(["--af-packet"])

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL
            )
            event("suricata_started", "info", pid=self.process.pid, eve_log=str(self.eve_path))
            self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name="suricata_procmon")
            self._thread.start()
            return True
        except Exception as e:
            event("suricata_start_failed", "high", error=str(e))
            self.process = None
            return False

    def _monitor_loop(self):
        """Watches the Suricata process and attempts restart if unexpectedly terminated."""
        while not STOP.is_set():
            if self.process and self.process.poll() is not None:
                code = self.process.poll()
                event("suricata_crashed", "high", exit_code=code)
                self.process = None
                time.sleep(5)
                if not STOP.is_set() and self.enabled:
                    event("suricata_restarting", "info")
                    self.start()
                break
            time.sleep(2)

    def reload_rules(self):
        """Sends signal or command to reload rules live."""
        if not self.process or self.process.poll() is not None:
            return
        try:
            if not IS_WIN:
                os.kill(self.process.pid, signal.SIGUSR2)
                event("suricata_rules_reloaded", "info")
            else:
                # suricatasc or restart on Windows
                pass
        except OSError as e:
            event("suricata_reload_failed", "low", error=str(e))

    def stop(self):
        """Gracefully stops Suricata."""
        if self.process and self.process.poll() is None:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass
            event("suricata_stopped", "info")
            self.process = None
