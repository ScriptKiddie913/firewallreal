"""SentinelFW Suricata EVE Ingestion Engine.

Ingests real-time EVE JSON logs (alerts, DNS, HTTP, TLS, flows, anomalies, fileinfo)
and routes them into SentinelFW's detection and response subsystem.
"""
import json
import os
import threading
import time
from pathlib import Path
from typing import Callable, Dict, Optional
from .common import STOP, event


class SuricataIngest(threading.Thread):
    """Monitors and parses the Suricata EVE JSON log stream."""

    def __init__(self, eve_path: Path, on_event: Optional[Callable[[Dict], None]] = None, engine=None):
        super().__init__(name="suricata_ingest", daemon=True)
        self.eve_path = Path(eve_path)
        self.on_event = on_event
        self.engine = engine
        self._stats = {
            "alerts": 0,
            "flows": 0,
            "dns": 0,
            "http": 0,
            "tls": 0,
            "files": 0,
            "anomalies": 0,
            "total": 0,
            "errors": 0,
        }

    @property
    def stats(self) -> Dict[str, int]:
        return dict(self._stats)

    def run(self):
        """Main tail loop with file rotation handling."""
        f = None
        current_inode = None
        while not STOP.is_set():
            if not self.eve_path.exists():
                time.sleep(1)
                continue

            try:
                st = self.eve_path.stat()
                file_inode = getattr(st, "st_ino", None) or (st.st_dev, st.st_size)

                # Open or re-open on inode change / rotation
                if f is None or file_inode != current_inode:
                    if f is not None:
                        try:
                            f.close()
                        except Exception:
                            pass
                    f = open(self.eve_path, "r", encoding="utf-8", errors="replace")
                    # Start at end of file if it's large and fresh
                    if st.st_size > 1024 * 1024 and current_inode is None:
                        f.seek(0, os.SEEK_END)
                    current_inode = file_inode

                line = f.readline()
                if line:
                    self._process_line(line.strip())
                else:
                    # Check if file was truncated or rotated
                    if st.st_size < f.tell():
                        f.seek(0, os.SEEK_SET)
                    time.sleep(0.05)
            except Exception as e:
                self._stats["errors"] += 1
                time.sleep(0.5)

        if f is not None:
            try:
                f.close()
            except Exception:
                pass

    def _process_line(self, raw_line: str):
        if not raw_line:
            return
        try:
            ev = json.loads(raw_line)
        except json.JSONDecodeError:
            self._stats["errors"] += 1
            return

        self._stats["total"] += 1
        event_type = ev.get("event_type")

        if event_type == "alert":
            self._handle_alert(ev)
        elif event_type == "dns":
            self._handle_dns(ev)
        elif event_type == "http":
            self._handle_http(ev)
        elif event_type == "tls":
            self._handle_tls(ev)
        elif event_type == "fileinfo":
            self._handle_fileinfo(ev)
        elif event_type == "flow":
            self._handle_flow(ev)
        elif event_type == "anomaly":
            self._handle_anomaly(ev)

        if self.on_event:
            try:
                self.on_event(ev)
            except Exception:
                pass

    def _handle_alert(self, ev: Dict):
        self._stats["alerts"] += 1
        alert = ev.get("alert", {})
        src_ip = ev.get("src_ip", "")
        dst_ip = ev.get("dest_ip", "")
        src_port = ev.get("src_port", 0)
        dst_port = ev.get("dest_port", 0)
        proto = ev.get("proto", "")
        sig = alert.get("signature", "Unknown Suricata Alert")
        category = alert.get("category", "")
        severity = alert.get("severity", 3)
        sid = alert.get("signature_id", 0)

        # Map Suricata severity (1=High, 2=Medium, 3=Low)
        sev_label = "critical" if severity == 1 else ("high" if severity == 2 else "medium")

        event(
            "suricata_alert",
            sev_label,
            src=src_ip,
            sport=src_port,
            dst=dst_ip,
            dport=dst_port,
            proto=proto,
            sid=sid,
            sig=sig,
            category=category,
        )

        if self.engine and src_ip:
            # Auto-ban or act on severe threats
            if severity in (1, 2) and not self.engine.guard.protected(src_ip):
                self.engine.ban(src_ip, f"suricata:{sid}:{sig}", 86400)

    def _handle_dns(self, ev: Dict):
        self._stats["dns"] += 1
        dns = ev.get("dns", {})
        qname = dns.get("rrname", "")
        qtype = dns.get("rrtype", "")
        rcode = dns.get("rcode", "")
        answers = dns.get("answers", [])
        src_ip = ev.get("src_ip", "")

        if self.engine and qname:
            if self.engine.domain_blocked(qname):
                event("suricata_dns_blocked", "high", src=src_ip, domain=qname)
                if src_ip and not self.engine.guard.protected(src_ip):
                    self.engine.ban(src_ip, f"blocked_domain:{qname}")

    def _handle_http(self, ev: Dict):
        self._stats["http"] += 1
        http = ev.get("http", {})
        hostname = http.get("hostname", "")
        url = http.get("url", "")
        method = http.get("http_method", "")
        ua = http.get("http_user_agent", "")
        src_ip = ev.get("src_ip", "")

        if self.engine and hostname and self.engine.domain_blocked(hostname):
            event("suricata_http_blocked_host", "high", src=src_ip, host=hostname, url=url)
            if src_ip and not self.engine.guard.protected(src_ip):
                self.engine.ban(src_ip, f"blocked_http_host:{hostname}")

    def _handle_tls(self, ev: Dict):
        self._stats["tls"] += 1
        tls = ev.get("tls", {})
        sni = tls.get("sni", "")
        ja3 = tls.get("ja3", {}).get("hash", "") if isinstance(tls.get("ja3"), dict) else tls.get("ja3", "")
        src_ip = ev.get("src_ip", "")

        if self.engine and sni and self.engine.domain_blocked(sni):
            event("suricata_tls_blocked_sni", "high", src=src_ip, sni=sni, ja3=ja3)
            if src_ip and not self.engine.guard.protected(src_ip):
                self.engine.ban(src_ip, f"blocked_tls_sni:{sni}")

    def _handle_fileinfo(self, ev: Dict):
        self._stats["files"] += 1
        fileinfo = ev.get("fileinfo", {})
        sha256 = fileinfo.get("sha256", "")
        filename = fileinfo.get("filename", "")
        size = fileinfo.get("size", 0)
        src_ip = ev.get("src_ip", "")

        if self.engine and sha256:
            if sha256 in self.engine.lists.hashes:
                event("suricata_malicious_file", "critical", sha256=sha256, filename=filename, src=src_ip)
                if src_ip and not self.engine.guard.protected(src_ip):
                    self.engine.ban(src_ip, f"malicious_file_sha256:{sha256}")

    def _handle_flow(self, ev: Dict):
        self._stats["flows"] += 1

    def _handle_anomaly(self, ev: Dict):
        self._stats["anomalies"] += 1
        anomaly = ev.get("anomaly", {})
        event(
            "suricata_anomaly",
            "medium",
            src=ev.get("src_ip", ""),
            dst=ev.get("dest_ip", ""),
            event=anomaly.get("event", ""),
            type=anomaly.get("type", "")
        )
