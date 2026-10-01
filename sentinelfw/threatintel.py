"""SentinelFW Threat Intelligence module — VirusTotal IP reputation.

Every remote IP is looked up at most once against the VirusTotal v3 API:

* A detection (>= min_malicious_votes engines flagging the IP) is cached
  **permanently** — a known-bad IP is never re-scanned.
* Clean / undetected results are re-validated after `clean_rescan_days`
  (default 7) because verdicts can change over time.
* All queries are serialized through a rate limiter so the free API quota
  (4 requests/minute) is respected even when many new IPs appear.

An optional background scanner picks up new remote IPs from the connection
tracker / packet recorder, scans them in order of traffic volume, and can
auto-ban IPs confirmed malicious (threat_intel.auto_ban_malicious).

The cache lives in DATA_DIR/virustotal_cache.json so verdicts survive restarts.
"""
import json
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from .common import DATA_DIR, STOP, event

VT_API_DEFAULT = "https://www.virustotal.com/api/v3/ip_addresses/{}"
DEFAULTS = {
    "virustotal_api_key": "",
    "auto_scan_new_ips": True,
    "auto_ban_malicious": False,
    "min_malicious_votes": 3,
    "clean_rescan_days": 7,
    "request_interval_seconds": 16,
    "max_scans_per_hour": 220,
}


class ThreatIntel:
    """VirusTotal-backed IP reputation with permanent-detection caching."""

    def __init__(self, cfg=None, engine=None):
        self.cfg = (cfg or {}).get("threat_intel", {}) if isinstance(cfg, dict) else {}
        self.engine = engine
        self.cache_path = DATA_DIR / "virustotal_cache.json"
        self.lock = threading.RLock()
        self._cache: dict = self._load_cache()
        self._last_query_ts = 0.0
        self._scan_window: list = []  # timestamps of queries in the last hour
        self._thread = None
        self._pending: list = []

    # ------------------------------------------------------------ config helpers
    def _opt(self, key):
        val = self.cfg.get(key)
        return DEFAULTS[key] if val in (None, "") else val

    @property
    def api_key(self) -> str:
        k = str(self._opt("virustotal_api_key") or "")
        if not k:
            try:
                from .mgmt import secrets_vault
                k = str(secrets_vault.get("virustotal_api_key") or "")
            except Exception:
                pass
        return k

    @property
    def api_url(self) -> str:
        # overridable for testing / VT proxies
        return str(self.cfg.get("api_url") or VT_API_DEFAULT)

    def display_record(self, ip: str) -> dict:
        """Last known VT record for display, regardless of rescan staleness.

        Unlike cached(), a clean record older than clean_rescan_days is still
        shown (the UI marks it stale); malicious records are permanent anyway.
        """
        with self.lock:
            rec = self._cache.get(ip)
        if not rec:
            return {}
        out = dict(rec)
        mal = int(rec.get("malicious") or 0)
        if not mal:
            age_days = (time.time() - rec.get("ts", 0)) / 86400
            if age_days >= int(self._opt("clean_rescan_days")):
                out["stale"] = True
        return out

    def configured(self) -> bool:
        return len(self.api_key) >= 20

    def configure(self, **kwargs):
        """Updates threat_intel options, persisting through the engine config."""
        with self.lock:
            if "virustotal_api_key" in kwargs and kwargs["virustotal_api_key"]:
                self.cfg["virustotal_api_key"] = str(kwargs["virustotal_api_key"]).strip()
            for k in ("auto_scan_new_ips", "auto_ban_malicious"):
                if k in kwargs and kwargs[k] is not None:
                    self.cfg[k] = bool(kwargs[k])
            for k in ("min_malicious_votes", "clean_rescan_days", "request_interval_seconds", "max_scans_per_hour"):
                if k in kwargs and kwargs[k] not in (None, ""):
                    try:
                        self.cfg[k] = int(kwargs[k])
                    except (TypeError, ValueError):
                        pass
            if kwargs.get("api_url"):
                self.cfg["api_url"] = str(kwargs["api_url"]).strip()
            if self.engine is not None and getattr(self.engine, "config_persist", None):
                try:
                    self.engine.config_persist()
                except Exception:
                    pass
            if self.configured() and (self._thread is None or not self._thread.is_alive()):
                self.start_background()
            return self.status()

    # ------------------------------------------------------------ cache
    def _load_cache(self) -> dict:
        try:
            if self.cache_path.exists():
                data = json.loads(self.cache_path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    return data
        except Exception as e:  # noqa: BLE001
            event("vt_cache_load_failed", "low", error=str(e))
        return {}

    def _save_cache(self):
        try:
            tmp = self.cache_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._cache, indent=0), encoding="utf-8")
            tmp.replace(self.cache_path)
        except Exception as e:  # noqa: BLE001
            event("vt_cache_save_failed", "low", error=str(e))

    # ------------------------------------------------------------ rate limiting
    def _throttle_ok(self, interval: float = None) -> bool:
        now = time.time()
        if interval is None:
            interval = max(1, int(self._opt("request_interval_seconds")))
        max_hour = max(1, int(self._opt("max_scans_per_hour")))
        self._scan_window = [t for t in self._scan_window if now - t < 3600]
        if now - self._last_query_ts < interval:
            return False
        if len(self._scan_window) >= max_hour:
            return False
        self._last_query_ts = now
        self._scan_window.append(now)
        return True

    # ------------------------------------------------------------ core lookup
    def cached(self, ip: str) -> dict:
        """Cached record for an IP (or {} if never scanned / needs rescan)."""
        with self.lock:
            rec = self._cache.get(ip)
        if not rec:
            return {}
        now = time.time()
        malicious = int(rec.get("malicious") or 0)
        if malicious > 0:
            # detected once — noted permanently, never rescanned
            return rec
        age_days = (now - rec.get("ts", 0)) / 86400
        if age_days >= int(self._opt("clean_rescan_days")):
            return {}  # stale clean record — eligible for a rescan
        return rec

    def lookup(self, ip: str, force: bool = False, manual: bool = False) -> dict:
        """Returns the VT record for an IP, querying the API when needed.

        Respects both the permanent-detection rule and the rate limiter;
        when throttled it returns the cached record (or a 'throttled' marker).
        Manual scans (operator clicked VT SCAN) get priority over the
        background scanner: they only need a short 4s spacing instead of the
        full free-tier interval, sharing the same hourly budget.
        """
        cached = self.cached(ip)
        if cached and not force:
            return cached
        if not self.configured():
            return {"error": "no VirusTotal API key configured",
                    "cached": cached or None}
        if not self._throttle_ok(interval=4 if manual else None):
            if cached:
                return cached
            return {"error": "rate-limited (free tier: 4 queries/minute) — try again shortly",
                    "cached": cached or None}
        rec = self._query_vt(ip)
        if rec is None:
            return {"error": "VirusTotal query failed", "cached": cached or None}
        self._store(ip, rec)
        self._act_on(ip, rec)
        return rec

    def _query_vt(self, ip: str) -> dict:
        try:
            req = urllib.request.Request(self.api_url.format(ip), headers={
                "x-apikey": self.api_key,
                "accept": "application/json",
                "User-Agent": "SentinelFW/3",
            })
            with urllib.request.urlopen(req, timeout=25) as resp:
                body = json.loads(resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {"ip": ip, "ts": time.time(), "malicious": 0, "suspicious": 0,
                        "harmless": 0, "undetected": 0, "verdict": "CLEAN",
                        "reputation": 0, "as_owner": "", "note": "no VT record"}
            event("vt_api_error", "low", ip=ip, status=e.code)
            return None
        except Exception as e:  # noqa: BLE001
            event("vt_api_error", "low", ip=ip, error=str(e)[:200])
            return None
        try:
            attrs = body.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {}) or {}
            rec = {
                "ip": ip,
                "ts": time.time(),
                "malicious": int(stats.get("malicious") or 0),
                "suspicious": int(stats.get("suspicious") or 0),
                "harmless": int(stats.get("harmless") or 0),
                "undetected": int(stats.get("undetected") or 0),
                "reputation": int(attrs.get("reputation") or 0),
                "as_owner": str(attrs.get("as_owner") or "")[:80],
            }
            votes = rec["malicious"] + rec["suspicious"]
            rec["verdict"] = "MALICIOUS" if rec["malicious"] >= int(self._opt("min_malicious_votes")) \
                else ("SUSPICIOUS" if votes > 0 else "CLEAN")
            try:
                from . import vtdb
                vtdb.save_vt(ip, rec, attrs)  # full report (per-engine results) in SQLite
            except Exception:
                pass
            return rec
        except Exception as e:  # noqa: BLE001
            event("vt_parse_error", "low", ip=ip, error=str(e)[:200])
            return None

    def _store(self, ip: str, rec: dict):
        with self.lock:
            self._cache[ip] = rec
            self._save_cache()

    def _act_on(self, ip: str, rec: dict):
        """Events / enforcement for a fresh scan result."""
        verdict = rec.get("verdict")
        if verdict == "MALICIOUS":
            event("vt_ip_malicious", "critical", ip=ip,
                  malicious=rec.get("malicious"), suspicious=rec.get("suspicious"),
                  as_owner=rec.get("as_owner", ""))
            if self._opt("auto_ban_malicious") and self.engine is not None:
                try:
                    self.engine.ban(ip, "VirusTotal: confirmed malicious IP", 86400,
                                    source="virustotal", force=True)
                except Exception:
                    pass
        elif verdict == "SUSPICIOUS":
            event("vt_ip_suspicious", "warning", ip=ip, votes=rec.get("suspicious"))

    # ------------------------------------------------------------ background scanner
    def offer_ips(self, ips):
        """Queues unseen remote IPs for background scanning (best-effort)."""
        if not self.configured() or not self._opt("auto_scan_new_ips"):
            return
        fresh = []
        for ip in ips or []:
            if isinstance(ip, str) and ip and not self.cached(ip):
                fresh.append(ip)
        if fresh:
            with self.lock:
                for ip in fresh:
                    if ip not in self._pending:
                        self._pending.append(ip)

    def _bg_loop(self):
        while not STOP.is_set() and self.configured():
            if not self._opt("auto_scan_new_ips"):
                STOP.wait(10)
                continue
            # offer fresh remote endpoints from the engine for scanning
            if self.engine is not None:
                try:
                    self.offer_ips(self.engine.remote_ips())
                except Exception:
                    pass
            with self.lock:
                pending = list(self._pending)
                self._pending.clear()
            for ip in pending:
                if STOP.is_set() or not self.configured():
                    break
                try:
                    self.lookup(ip)
                except Exception:
                    pass
                STOP.wait(2)
            STOP.wait(10)

    def start_background(self):
        if self._thread and self._thread.is_alive():
            return
        if not self.configured():
            return
        self._thread = threading.Thread(target=self._bg_loop, daemon=True, name="vt_scanner")
        self._thread.start()

    # ------------------------------------------------------------ status
    def status(self) -> dict:
        with self.lock:
            cached = list(self._cache.values())
        detected = sum(1 for r in cached if int(r.get("malicious") or 0) > 0)
        return {
            "configured": self.configured(),
            "auto_scan_new_ips": bool(self._opt("auto_scan_new_ips")),
            "auto_ban_malicious": bool(self._opt("auto_ban_malicious")),
            "min_malicious_votes": int(self._opt("min_malicious_votes")),
            "clean_rescan_days": int(self._opt("clean_rescan_days")),
            "cached_ips": len(cached),
            "detected_malicious": detected,
            "background_running": bool(self._thread and self._thread.is_alive()),
        }

    def detected_ips(self) -> list:
        with self.lock:
            return [dict(r, ip=ip) for ip, r in self._cache.items()
                    if int(r.get("malicious") or 0) > 0]
