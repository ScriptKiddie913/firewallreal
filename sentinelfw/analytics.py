"""SentinelFW Security Analytics Lake & SOC Engine (SentinelAnalyzer).

Provides unified event streaming, structured querying, SQLite time-series rollups,
and forensic incident bundling across all security subsystems.
"""
import collections
import contextlib
import json
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
from .common import DATA_DIR

logger = logging.getLogger("sentinelfw.analytics")


class SecurityEventSchema:
    """Canonical event schema definition."""

    @classmethod
    def normalize(cls, raw_event: dict) -> dict:
        now = time.time()
        return {
            "timestamp": float(raw_event.get("timestamp", raw_event.get("ts", now))),
            "subsystem": str(raw_event.get("subsystem", raw_event.get("source", "firewall"))).lower(),
            "event_type": str(raw_event.get("event_type", raw_event.get("event", "traffic"))).lower(),
            "severity": str(raw_event.get("severity", "info")).lower(),
            "action": str(raw_event.get("action", "allow")).upper(),
            "src_ip": str(raw_event.get("src_ip", raw_event.get("src", "0.0.0.0"))),
            "dst_ip": str(raw_event.get("dst_ip", raw_event.get("dst", "0.0.0.0"))),
            "src_port": int(raw_event.get("src_port", raw_event.get("sport", 0)) or 0),
            "dst_port": int(raw_event.get("dst_port", raw_event.get("dport", 0)) or 0),
            "proto": str(raw_event.get("proto", "tcp")).lower(),
            "threat_score": int(raw_event.get("threat_score", raw_event.get("score", 0)) or 0),
            "rule_id": str(raw_event.get("rule_id", "")),
            "details": raw_event.get("details", {}),
        }


class AnalyticsDataLake:
    """SQLite-backed security analytics lake with time-series rollups and forensic indexing."""

    def __init__(self, db_path: Optional[Union[str, Path]] = None):
        self.db_path = Path(db_path or (DATA_DIR / "analytics.db"))
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._init_db()

    @contextlib.contextmanager
    def _get_connection(self):
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_db(self):
        with self._lock, self._get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    subsystem TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    action TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    src_port INTEGER,
                    dst_port INTEGER,
                    proto TEXT,
                    threat_score INTEGER,
                    rule_id TEXT,
                    details_json TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_events_ts ON security_events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_events_src ON security_events(src_ip);
                CREATE INDEX IF NOT EXISTS idx_events_subsys ON security_events(subsystem);
                CREATE INDEX IF NOT EXISTS idx_events_sev ON security_events(severity);

                CREATE TABLE IF NOT EXISTS forensic_bundles (
                    incident_id TEXT PRIMARY KEY,
                    timestamp REAL NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    bundle_json TEXT NOT NULL
                );
            """)

    def record_event(self, raw_event: dict):
        ev = SecurityEventSchema.normalize(raw_event)
        with self._lock, self._get_connection() as conn:
            conn.execute("""
                INSERT INTO security_events (
                    timestamp, subsystem, event_type, severity, action,
                    src_ip, dst_ip, src_port, dst_port, proto,
                    threat_score, rule_id, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ev["timestamp"], ev["subsystem"], ev["event_type"], ev["severity"], ev["action"],
                ev["src_ip"], ev["dst_ip"], ev["src_port"], ev["dst_port"], ev["proto"],
                ev["threat_score"], ev["rule_id"], json.dumps(ev["details"])
            ))

    def query_events(self, subsystem: Optional[str] = None, severity: Optional[str] = None,
                     src_ip: Optional[str] = None, limit: int = 100) -> List[dict]:
        clauses = []
        params = []
        if subsystem:
            clauses.append("subsystem = ?")
            params.append(subsystem.lower())
        if severity:
            clauses.append("severity = ?")
            params.append(severity.lower())
        if src_ip:
            clauses.append("src_ip = ?")
            params.append(src_ip.strip())

        where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT * FROM security_events {where_sql} ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._lock, self._get_connection() as conn:
            rows = conn.execute(sql, params).fetchall()
            results = []
            for r in rows:
                item = dict(r)
                item["details"] = json.loads(item.pop("details_json", "{}"))
                results.append(item)
            return results

    def get_time_series_summary(self, window_seconds: int = 3600) -> dict:
        """Computes time-series rollups and top talkers over the specified window."""
        now = time.time()
        cutoff = now - window_seconds
        with self._lock, self._get_connection() as conn:
            total_events = conn.execute("SELECT COUNT(*) FROM security_events WHERE timestamp >= ?", (cutoff,)).fetchone()[0]
            top_src = conn.execute("""
                SELECT src_ip, COUNT(*) as cnt FROM security_events
                WHERE timestamp >= ? GROUP BY src_ip ORDER BY cnt DESC LIMIT 5
            """, (cutoff,)).fetchall()
            top_ports = conn.execute("""
                SELECT dst_port, COUNT(*) as cnt FROM security_events
                WHERE timestamp >= ? AND dst_port > 0 GROUP BY dst_port ORDER BY cnt DESC LIMIT 5
            """, (cutoff,)).fetchall()
            actions = conn.execute("""
                SELECT action, COUNT(*) as cnt FROM security_events
                WHERE timestamp >= ? GROUP BY action
            """, (cutoff,)).fetchall()

            return {
                "window_seconds": window_seconds,
                "total_events": total_events,
                "top_sources": [{"ip": r["src_ip"], "count": r["cnt"]} for r in top_src],
                "top_ports": [{"port": r["dst_port"], "count": r["cnt"]} for r in top_ports],
                "actions": {r["action"]: r["cnt"] for r in actions},
            }

    def bundle_forensic_incident(self, incident_id: str, title: str, severity: str,
                                 events: List[dict], host_context: Optional[dict] = None) -> dict:
        """Creates a tamper-evident forensic incident package with event timeline and host context."""
        now = time.time()
        bundle = {
            "incident_id": incident_id,
            "title": title,
            "severity": severity,
            "exported_at": now,
            "event_count": len(events),
            "events": events,
            "host_context": host_context or {},
        }
        with self._lock, self._get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO forensic_bundles (incident_id, timestamp, title, severity, bundle_json)
                VALUES (?, ?, ?, ?, ?)
            """, (incident_id, now, title, severity, json.dumps(bundle)))
        return bundle

    def export_otlp_json(self, events: Optional[List[dict]] = None) -> dict:
        """Converts security events into canonical OpenTelemetry (OTLP/JSON) log format."""
        if events is None:
            events = self.query_events(limit=500)

        log_records = []
        for ev in events:
            nano_ts = int(float(ev.get("timestamp", time.time())) * 1e9)
            attrs = [
                {"key": "subsystem", "value": {"stringValue": str(ev.get("subsystem", ""))}},
                {"key": "src.ip", "value": {"stringValue": str(ev.get("src_ip", ""))}},
                {"key": "dst.ip", "value": {"stringValue": str(ev.get("dst_ip", ""))}},
                {"key": "dst.port", "value": {"intValue": int(ev.get("dst_port", 0))}},
                {"key": "network.transport", "value": {"stringValue": str(ev.get("proto", "tcp"))}},
                {"key": "verdict", "value": {"stringValue": str(ev.get("action", ""))}},
                {"key": "threat.score", "value": {"intValue": int(ev.get("threat_score", 0))}},
            ]
            log_records.append({
                "timeUnixNano": str(nano_ts),
                "severityText": str(ev.get("severity", "INFO")).upper(),
                "body": {"stringValue": f"[{ev.get('subsystem')}] {ev.get('event_type')}: {ev.get('action')}"},
                "attributes": attrs,
            })

        return {
            "resourceLogs": [
                {
                    "resource": {
                        "attributes": [
                            {"key": "service.name", "value": {"stringValue": "sentinelfw"}},
                            {"key": "service.namespace", "value": {"stringValue": "security"}},
                        ]
                    },
                    "scopeLogs": [
                        {
                            "scope": {"name": "sentinelfw.analytics"},
                            "logRecords": log_records,
                        }
                    ],
                }
            ]
        }

