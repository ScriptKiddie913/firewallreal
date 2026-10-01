"""SentinelFW Asset & Flow Map Engine.

Records and analyzes network flows using a lightweight SQLite time-series store:
* Flow aggregation: (src_ip, dst_ip, proto, dport, app, bytes, packets)
* Active asset inventory and service discovery
* Top communicators and traffic volume rollups
"""
import contextlib
import ipaddress
import sqlite3
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Union
from .common import DATA_DIR


class AssetFlowMap:
    """Manages flow recording and asset tracking in SQLite."""

    def __init__(self, db_path: Optional[Union[dict, Path, str]] = None, **kwargs):
        val = db_path if db_path is not None else kwargs.get("db_path_or_cfg")
        if isinstance(val, dict):
            p = val.get("assetmap_db")
            self.db_path = Path(p) if p else (DATA_DIR / "asset_flow.db")
        elif isinstance(val, (str, Path)):
            self.db_path = Path(val)
        else:
            self.db_path = DATA_DIR / "asset_flow.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._init_db()

    @contextlib.contextmanager
    def _get_conn(self):
        conn = sqlite3.connect(str(self.db_path), timeout=5.0)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_db(self):
        with self._lock:
            with self._get_conn() as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS flows (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp REAL,
                        src_ip TEXT,
                        dst_ip TEXT,
                        proto TEXT,
                        dport INTEGER,
                        app TEXT,
                        bytes INTEGER,
                        packets INTEGER
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_flow_time ON flows (timestamp)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_flow_src ON flows (src_ip)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_flow_dst ON flows (dst_ip)")
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS assets (
                        ip TEXT PRIMARY KEY,
                        mac_address TEXT,
                        hostname TEXT,
                        vendor TEXT,
                        device_type TEXT,
                        os_guess TEXT,
                        dhcp_fingerprint TEXT,
                        tcp_fingerprint TEXT,
                        risk_level TEXT,
                        policy_tag TEXT,
                        first_seen REAL,
                        last_seen REAL,
                        role TEXT,
                        open_ports TEXT
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS flow_rollups (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        bucket_timestamp INTEGER,
                        src_ip TEXT,
                        dst_ip TEXT,
                        proto TEXT,
                        app TEXT,
                        total_bytes INTEGER,
                        total_packets INTEGER,
                        flow_count INTEGER,
                        UNIQUE(bucket_timestamp, src_ip, dst_ip, proto, app)
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_rollup_time ON flow_rollups (bucket_timestamp)")

    def record_flow(self, src_ip: str, dst_ip: str, proto: str, dport: int,
                    app: str = "Unknown", bytes_count: int = 0, packets_count: int = 1):
        """Records a single network flow event."""
        now = time.time()
        with self._lock:
            with self._get_conn() as conn:
                conn.execute("""
                    INSERT INTO flows (timestamp, src_ip, dst_ip, proto, dport, app, bytes, packets)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (now, str(src_ip).strip(), str(dst_ip).strip(), str(proto).lower(),
                      int(dport), str(app).strip(), int(bytes_count), int(packets_count)))
                # Update asset last seen
                conn.execute("""
                    INSERT INTO assets (ip, first_seen, last_seen, role, open_ports)
                    VALUES (?, ?, ?, 'host', '')
                    ON CONFLICT(ip) DO UPDATE SET last_seen = ?
                """, (str(src_ip).strip(), now, now, now))

    def get_top_talkers(self, limit: int = 10, window_seconds: int = 3600) -> List[dict]:
        """Returns top source IP communicators by flow count in the given time window."""
        cutoff = time.time() - window_seconds
        with self._lock:
            with self._get_conn() as conn:
                cur = conn.execute("""
                    SELECT src_ip, COUNT(*) as flow_count, SUM(bytes) as total_bytes
                    FROM flows
                    WHERE timestamp > ?
                    GROUP BY src_ip
                    ORDER BY flow_count DESC
                    LIMIT ?
                """, (cutoff, limit))
                return [dict(r) for r in cur.fetchall()]

    def get_app_distribution(self, window_seconds: int = 3600) -> List[dict]:
        """Returns application breakdown in the given time window."""
        cutoff = time.time() - window_seconds
        with self._lock:
            with self._get_conn() as conn:
                cur = conn.execute("""
                    SELECT app, COUNT(*) as flow_count, SUM(bytes) as total_bytes
                    FROM flows
                    WHERE timestamp > ?
                    GROUP BY app
                    ORDER BY flow_count DESC
                """, (cutoff,))
                return [dict(r) for r in cur.fetchall()]

    def list_assets(self) -> List[dict]:
        """Lists all discovered network assets."""
        with self._lock:
            with self._get_conn() as conn:
                cur = conn.execute("SELECT * FROM assets ORDER BY last_seen DESC")
                return [dict(r) for r in cur.fetchall()]

    def record_device_discovery(self, ip: str, mac_address: str = "", hostname: str = "",
                                vendor: str = "", dhcp_fp: str = "", tcp_fp: str = "",
                                open_ports: str = "", user_agent: str = "") -> dict:
        """Classifies and records a discovered device with risk rating and NAC policy tags."""
        now = time.time()
        clean_ip = str(ip).strip()
        ua_lower = user_agent.lower()
        host_lower = hostname.lower()
        ports_set = {int(p) for p in open_ports.split(",") if p.isdigit()}

        # Classification heuristic
        device_type = "unknown"
        risk_level = "LOW"
        policy_tag = "standard"
        os_guess = "Unknown"

        if any(k in ua_lower or k in host_lower for k in ("iphone", "ipad", "android", "mobile")):
            device_type = "mobile"
            os_guess = "iOS" if "iphone" in ua_lower or "ipad" in ua_lower else "Android"
            risk_level = "LOW"
            policy_tag = "byod_vlan"
        elif any(k in ua_lower or k in host_lower for k in ("camera", "hikvision", "dahua", "axis", "nvr")) or (554 in ports_set):
            device_type = "camera"
            risk_level = "MEDIUM"
            policy_tag = "internet_only"
        elif any(k in ua_lower or k in host_lower for k in ("printer", "canon", "epson", "xerox", "brother")) or any(p in ports_set for p in (515, 631, 9100)):
            device_type = "printer"
            risk_level = "LOW"
            policy_tag = "printer_isolated"
        elif any(p in ports_set for p in (22, 3389, 445, 80, 443, 3306, 5432)) and any(k in host_lower for k in ("srv", "server", "dc", "sql", "prod")):
            device_type = "server"
            os_guess = "Linux" if 22 in ports_set else "Windows Server"
            risk_level = "MEDIUM"
            policy_tag = "restricted_mgmt"
        elif mac_address and not open_ports and not hostname:
            device_type = "unknown"
            risk_level = "HIGH"
            policy_tag = "quarantine_vlan"
        else:
            device_type = "workstation"
            os_guess = "Windows" if 135 in ports_set or 445 in ports_set else "Desktop OS"
            risk_level = "LOW"
            policy_tag = "corporate_lan"

        with self._lock:
            with self._get_conn() as conn:
                conn.execute("""
                    INSERT INTO assets (
                        ip, mac_address, hostname, vendor, device_type, os_guess,
                        dhcp_fingerprint, tcp_fingerprint, risk_level, policy_tag,
                        first_seen, last_seen, role, open_ports
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'device', ?)
                    ON CONFLICT(ip) DO UPDATE SET
                        mac_address = CASE WHEN excluded.mac_address != '' THEN excluded.mac_address ELSE assets.mac_address END,
                        hostname = CASE WHEN excluded.hostname != '' THEN excluded.hostname ELSE assets.hostname END,
                        vendor = CASE WHEN excluded.vendor != '' THEN excluded.vendor ELSE assets.vendor END,
                        device_type = excluded.device_type,
                        os_guess = excluded.os_guess,
                        dhcp_fingerprint = CASE WHEN excluded.dhcp_fingerprint != '' THEN excluded.dhcp_fingerprint ELSE assets.dhcp_fingerprint END,
                        tcp_fingerprint = CASE WHEN excluded.tcp_fingerprint != '' THEN excluded.tcp_fingerprint ELSE assets.tcp_fingerprint END,
                        risk_level = excluded.risk_level,
                        policy_tag = excluded.policy_tag,
                        last_seen = excluded.last_seen,
                        open_ports = CASE WHEN excluded.open_ports != '' THEN excluded.open_ports ELSE assets.open_ports END
                """, (
                    clean_ip, mac_address, hostname, vendor, device_type, os_guess,
                    dhcp_fp, tcp_fp, risk_level, policy_tag, now, now, open_ports
                ))
            return {
                "ip": clean_ip,
                "mac": mac_address,
                "device_type": device_type,
                "os_guess": os_guess,
                "risk_level": risk_level,
                "policy_tag": policy_tag,
            }

    def get_device_policy(self, ip: str) -> Optional[dict]:
        """Returns the current NAC device policy classification for an IP."""
        clean_ip = str(ip).strip()
        with self._lock:
            with self._get_conn() as conn:
                cur = conn.execute("SELECT * FROM assets WHERE ip = ?", (clean_ip,))
                row = cur.fetchone()
                return dict(row) if row else None

    def compute_rollups(self, bucket_seconds: int = 3600) -> int:
        """Aggregates raw flow rows into periodic summary rollups and prunes old raw rows."""
        now = time.time()
        bucket_now = int(now // bucket_seconds) * bucket_seconds
        inserted = 0

        with self._lock:
            with self._get_conn() as conn:
                cur = conn.execute("""
                    SELECT CAST(timestamp / ? AS INTEGER) * ? as bucket,
                           src_ip, dst_ip, proto, app,
                           SUM(bytes) as total_bytes,
                           SUM(packets) as total_packets,
                           COUNT(*) as flow_count
                    FROM flows
                    WHERE timestamp <= ?
                    GROUP BY bucket, src_ip, dst_ip, proto, app
                """, (bucket_seconds, bucket_seconds, now))
                rows = cur.fetchall()

                for r in rows:
                    conn.execute("""
                        INSERT INTO flow_rollups
                        (bucket_timestamp, src_ip, dst_ip, proto, app, total_bytes, total_packets, flow_count)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(bucket_timestamp, src_ip, dst_ip, proto, app) DO UPDATE SET
                            total_bytes = total_bytes + excluded.total_bytes,
                            total_packets = total_packets + excluded.total_packets,
                            flow_count = flow_count + excluded.flow_count
                    """, (r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]))
                    inserted += 1

                # Clean up raw flows aggregated into rollups
                conn.execute("DELETE FROM flows WHERE timestamp <= ?", (now,))
        return inserted

    def get_time_series_rollups(self, window_seconds: int = 86400) -> List[dict]:
        """Returns time-series rollup buckets for trend visualization."""
        cutoff = int(time.time() - window_seconds)
        with self._lock:
            with self._get_conn() as conn:
                cur = conn.execute("""
                    SELECT bucket_timestamp,
                           SUM(total_bytes) as total_bytes,
                           SUM(total_packets) as total_packets,
                           SUM(flow_count) as total_flows
                    FROM flow_rollups
                    WHERE bucket_timestamp >= ?
                    GROUP BY bucket_timestamp
                    ORDER BY bucket_timestamp ASC
                """, (cutoff,))
                return [dict(r) for r in cur.fetchall()]


# Global singleton
flow_map = AssetFlowMap()
AssetMap = AssetFlowMap
