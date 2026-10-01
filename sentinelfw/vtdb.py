"""SentinelFW local intelligence database (SQLite).

Stores full VirusTotal IP reports and Sarvam AI threat assessments so the
console can show complete evidence on demand without re-querying paid APIs.
"""
import json
import sqlite3
import threading
import time
from pathlib import Path

from .common import HOME

DB_FILE = HOME / "intel.db"
_lock = threading.Lock()


def _conn() -> sqlite3.Connection:
    HOME.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(DB_FILE), timeout=15)
    c.row_factory = sqlite3.Row
    return c


def init() -> None:
    with _lock, _conn() as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS vt_reports (
                ip TEXT PRIMARY KEY,
                ts REAL NOT NULL,
                verdict TEXT,
                malicious INTEGER DEFAULT 0,
                suspicious INTEGER DEFAULT 0,
                harmless INTEGER DEFAULT 0,
                undetected INTEGER DEFAULT 0,
                reputation INTEGER DEFAULT 0,
                as_owner TEXT,
                raw_json TEXT
            );
            CREATE TABLE IF NOT EXISTS ai_assessments (
                ip TEXT PRIMARY KEY,
                ts REAL NOT NULL,
                model TEXT,
                verdict TEXT,
                confidence REAL,
                threat_type TEXT,
                summary TEXT,
                recommended_actions TEXT,
                raw_json TEXT
            );
            """
        )


def save_vt(ip: str, rec: dict, raw_attributes: dict = None) -> None:
    """Upsert a VirusTotal report. raw_attributes is the full VT API payload."""
    try:
        with _lock, _conn() as c:
            c.execute(
                """INSERT INTO vt_reports (ip, ts, verdict, malicious, suspicious, harmless,
                                          undetected, reputation, as_owner, raw_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(ip) DO UPDATE SET ts=excluded.ts, verdict=excluded.verdict,
                     malicious=excluded.malicious, suspicious=excluded.suspicious,
                     harmless=excluded.harmless, undetected=excluded.undetected,
                     reputation=excluded.reputation, as_owner=excluded.as_owner,
                     raw_json=excluded.raw_json""",
                (str(ip), float(rec.get("ts") or time.time()), str(rec.get("verdict") or ""),
                 int(rec.get("malicious") or 0), int(rec.get("suspicious") or 0),
                 int(rec.get("harmless") or 0), int(rec.get("undetected") or 0),
                 int(rec.get("reputation") or 0), str(rec.get("as_owner") or ""),
                 json.dumps(raw_attributes if raw_attributes is not None else rec)),
            )
    except Exception:
        pass


def get_vt(ip: str) -> dict:
    with _lock, _conn() as c:
        row = c.execute("SELECT * FROM vt_reports WHERE ip = ?", (str(ip),)).fetchone()
    if not row:
        return {}
    out = dict(row)
    try:
        out["raw"] = json.loads(out.pop("raw_json") or "{}")
    except Exception:
        out["raw"] = {}
    return out


def save_ai(ip: str, assessment: dict) -> None:
    try:
        with _lock, _conn() as c:
            c.execute(
                """INSERT INTO ai_assessments (ip, ts, model, verdict, confidence, threat_type,
                                              summary, recommended_actions, raw_json)
                   VALUES (?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(ip) DO UPDATE SET ts=excluded.ts, model=excluded.model,
                     verdict=excluded.verdict, confidence=excluded.confidence,
                     threat_type=excluded.threat_type, summary=excluded.summary,
                     recommended_actions=excluded.recommended_actions, raw_json=excluded.raw_json""",
                (str(ip), float(assessment.get("ts") or time.time()),
                 str(assessment.get("model") or ""), str(assessment.get("verdict") or ""),
                 float(assessment.get("confidence") or 0), str(assessment.get("threat_type") or ""),
                 str(assessment.get("summary") or ""),
                 json.dumps(assessment.get("recommended_actions") or []),
                 json.dumps(assessment)),
            )
    except Exception:
        pass


def get_ai(ip: str) -> dict:
    with _lock, _conn() as c:
        row = c.execute("SELECT * FROM ai_assessments WHERE ip = ?", (str(ip),)).fetchone()
    if not row:
        return {}
    out = dict(row)
    try:
        out["recommended_actions"] = json.loads(out.get("recommended_actions") or "[]")
        out["raw"] = json.loads(out.pop("raw_json") or "{}")
    except Exception:
        out["recommended_actions"] = []
        out["raw"] = {}
    return out


def analyzed_ips() -> set:
    with _lock, _conn() as c:
        return {r["ip"] for r in c.execute("SELECT ip FROM ai_assessments").fetchall()}


init()
