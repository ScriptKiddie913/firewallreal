"""SentinelFW Connection Tracker Module.

Maintains a comprehensive real-time table of all network connections,
associating sockets with processes, bandwidth counters, GeoIP, and reputation.
"""
import collections
import ipaddress
import os
import threading
import time
from typing import Dict, List, Optional
from .common import STOP, event
from .geoip import GeoIPResolver
from .procinfo import get_connections


class ConnectionRecord:
    """Represents an active or recently seen network flow."""

    def __init__(self, key: str, proto: str, laddr: str, lport: int, raddr: str, rport: int,
                 pid: int, exe: str, state: str = ""):
        self.key = key
        self.proto = proto.lower()
        self.laddr = laddr
        self.lport = lport
        self.raddr = raddr
        self.rport = rport
        self.pid = pid
        self.exe = exe
        self.state = state
        self.first_seen = time.time()
        self.last_seen = self.first_seen
        self.bytes_in = 0
        self.bytes_out = 0
        self.packets_in = 0
        self.packets_out = 0
        self.geo = {}
        self.l7_proto = "unknown"

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "proto": self.proto,
            "laddr": self.laddr,
            "lport": self.lport,
            "raddr": self.raddr,
            "rport": self.rport,
            "pid": self.pid,
            "exe": self.exe,
            "state": self.state,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration": round(self.last_seen - self.first_seen, 2),
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "packets_in": self.packets_in,
            "packets_out": self.packets_out,
            "country": self.geo.get("country", "LOCAL" if not self.raddr else "UNKNOWN"),
            "asn": self.geo.get("asn", 0),
            "org": self.geo.get("org", ""),
            "l7_proto": self.l7_proto,
        }


class ConnectionTracker(threading.Thread):
    """Continuously tracks, snapshots, and updates all system network connections."""

    def __init__(self, cfg=None, geoip_resolver=None):
        super().__init__(name="conntrack", daemon=True)
        self.cfg = cfg or {}
        ct_cfg = self.cfg.get("connection_tracker", {})
        self.enabled = ct_cfg.get("enabled", True)
        self.interval = float(ct_cfg.get("snapshot_interval_seconds", 2))
        self.geoip = geoip_resolver or GeoIPResolver(ct_cfg.get("geoip_db_path"))
        self.lock = threading.RLock()
        self._table: Dict[str, ConnectionRecord] = {}
        self._history = collections.deque(maxlen=5000)
        self._app_bandwidth = collections.defaultdict(lambda: {"in": 0, "out": 0})
        # rolling rate samples: (ts, bytes_in, bytes_out, packets_in, packets_out)
        self._rate_samples = collections.deque(maxlen=240)
        self._last_totals = None

    def run(self):
        """Background poll loop."""
        while not STOP.wait(self.interval):
            if not self.enabled:
                continue
            try:
                self.snapshot()
            except Exception as e:
                event("conntrack_error", "low", error=str(e))

    def _make_key(self, proto: str, laddr: str, lport: int, raddr: str, rport: int) -> str:
        return f"{proto}:{laddr}:{lport}->{raddr}:{rport}"

    def snapshot(self) -> List[dict]:
        """Takes an instant snapshot of live connections and merges into tracker state."""
        raw_conns = get_connections()
        now = time.time()
        active_keys = set()
        snapshot_records = []
        bytes_in_total = 0
        bytes_out_total = 0
        pkin_total = 0
        pkout_total = 0

        with self.lock:
            for c in raw_conns:
                key = self._make_key(c["proto"], c["laddr"], c["lport"], c["raddr"], c["rport"])
                active_keys.add(key)
                rec = self._table.get(key)
                if rec is None:
                    rec = ConnectionRecord(
                        key=key,
                        proto=c["proto"],
                        laddr=c["laddr"],
                        lport=c["lport"],
                        raddr=c["raddr"],
                        rport=c["rport"],
                        pid=c["pid"],
                        exe=c["exe"],
                        state=c.get("state", ""),
                    )
                    if c["raddr"]:
                        rec.geo = self.geoip.resolve(c["raddr"])
                    self._table[key] = rec
                else:
                    rec.last_seen = now
                    rec.state = c.get("state", "")
                    if c.get("exe") and not rec.exe:
                        rec.exe = c["exe"]
                    if c.get("pid") and not rec.pid:
                        rec.pid = c["pid"]

                snapshot_records.append(rec.to_dict())

            # Expire closed connections older than 10 seconds
            closed = []
            for k, rec in list(self._table.items()):
                if k not in active_keys and (now - rec.last_seen > 10):
                    closed.append(k)
                    self._history.append(rec.to_dict())
            for k in closed:
                del self._table[k]

            # rate sampling over cumulative per-flow counters
            for rec in self._table.values():
                bytes_in_total += rec.bytes_in
                bytes_out_total += rec.bytes_out
                pkin_total += rec.packets_in
                pkout_total += rec.packets_out
            totals = (bytes_in_total, bytes_out_total, pkin_total, pkout_total)
            if self._last_totals is not None:
                lb, ob, lpk, opk = self._last_totals
                self._rate_samples.append((
                    now,
                    max(0, bytes_in_total - lb),
                    max(0, bytes_out_total - ob),
                    max(0, pkin_total - lpk),
                    max(0, pkout_total - opk),
                ))
            self._last_totals = totals

        return snapshot_records

    def get_rates(self, window: float = 10.0) -> dict:
        """Real-time bandwidth / packet rates computed from flow counters."""
        with self.lock:
            if not self._rate_samples:
                return {"bps_in": 0, "bps_out": 0, "pps_in": 0, "pps_out": 0}
            now = time.time()
            bi = bo = pkin = pkout = 0.0
            span = 0.0
            for ts, b_in, b_out, p_in, p_out in self._rate_samples:
                if now - ts > window:
                    continue
                bi += b_in
                bo += b_out
                pkin += p_in
                pkout += p_out
            span = max(1e-6, min(window, now - self._rate_samples[0][0]))
            return {
                "bps_in": int(bi * 8 / span),
                "bps_out": int(bo * 8 / span),
                "pps_in": int(pkin / span),
                "pps_out": int(pkout / span),
            }

    def update_flow_stats(self, proto: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int,
                          bytes_count: int, packets_count: int = 1, l7_proto: str = None):
        """Enriches connection statistics from sniffer or Suricata flow events."""
        key1 = self._make_key(proto, src_ip, src_port, dst_ip, dst_port)
        key2 = self._make_key(proto, dst_ip, dst_port, src_ip, src_port)

        with self.lock:
            rec = self._table.get(key1)
            if rec:
                rec.bytes_out += bytes_count
                rec.packets_out += packets_count
                if l7_proto:
                    rec.l7_proto = l7_proto
                if rec.exe:
                    self._app_bandwidth[rec.exe]["out"] += bytes_count
                return

            rec = self._table.get(key2)
            if rec:
                rec.bytes_in += bytes_count
                rec.packets_in += packets_count
                if l7_proto:
                    rec.l7_proto = l7_proto
                if rec.exe:
                    self._app_bandwidth[rec.exe]["in"] += bytes_count

    def get_active(self, pid: Optional[int] = None, exe: Optional[str] = None) -> List[dict]:
        """Returns active connections filtered by PID or executable."""
        with self.lock:
            res = []
            for rec in self._table.values():
                if pid is not None and rec.pid != pid:
                    continue
                if exe is not None and exe.lower() not in rec.exe.lower():
                    continue
                res.append(rec.to_dict())
            return res

    def get_history(self, limit: int = 100) -> List[dict]:
        """Returns recently closed connection history."""
        with self.lock:
            return list(self._history)[-limit:]

    def get_app_stats(self) -> dict:
        """Returns cumulative bandwidth per executable."""
        with self.lock:
            return {k: dict(v) for k, v in self._app_bandwidth.items()}
