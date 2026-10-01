"""SentinelFW 2.8 — forensics & operations-safety layer.

Pure stdlib: an in-memory PCAP ring buffer that dumps Wireshark-readable
captures around alerts, a cross-platform persistence-mechanism watcher
(cron / systemd / Run keys / autostart / scheduled tasks), and JA3 TLS
client-fingerprint helpers. Commit-confirm staging lives on the Engine.
"""
import hashlib
import json
import os
import struct
import threading
import time
from collections import deque
from pathlib import Path
from typing import List, Optional

from .common import HOME, event

IS_WINDOWS = os.name == "nt"
PCAP_DIR = HOME / "pcaps"

# GREASE values (RFC 8701) must be stripped from JA3 strings
GREASE = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a,
          0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}


# =====================================================================
# JA3 TLS client fingerprint (from a ClientHello payload)
# =====================================================================
def ja3_from_client_hello(payload: bytes) -> Optional[dict]:
    """Parses a TLS ClientHello and returns {ja3, ja3_string, sni} or None.

    JA3 = MD5("version,ciphers,extensions,curves,formats").
    """
    try:
        if len(payload) < 44 or payload[0] != 0x16 or payload[5] != 0x01:
            return None
        ver = struct.unpack("!H", payload[9:11])[0]  # ClientHello version, not record layer
        o = 43  # 5 (record) + 4 (handshake) + 2 (legacy ver) + 32 (random)
        sid_len = payload[o]
        o += 1 + sid_len
        cs_len = struct.unpack("!H", payload[o:o + 2])[0]
        ciphers = [c for c in struct.unpack(f"!{cs_len // 2}H", payload[o + 2:o + 2 + cs_len])
                   if c not in GREASE]
        o += 2 + cs_len
        comp_len = payload[o]
        o += 1 + comp_len
        exts: List[int] = []
        curves: List[int] = []
        formats: List[int] = []
        sni = ""
        if o + 2 <= len(payload):
            ext_len = struct.unpack("!H", payload[o:o + 2])[0]
            o += 2
            end_ext = min(o + ext_len, len(payload))
            while o + 4 <= end_ext:
                et, el = struct.unpack("!HH", payload[o:o + 4])
                body = payload[o + 4:o + 4 + el]
                if et not in GREASE:
                    exts.append(et)
                if et == 0 and el >= 5:  # server_name
                    try:
                        nl = struct.unpack("!H", body[3:5])[0]
                        try:
                            sni = body[5:5 + nl].decode("idna")
                        except Exception:
                            sni = body[5:5 + nl].decode("utf-8", "replace")
                    except Exception:
                        pass
                elif et == 10 and len(body) >= 2:  # supported_groups
                    gl = struct.unpack("!H", body[:2])[0]
                    curves = [g for g in struct.unpack(f"!{gl // 2}H", body[2:2 + gl])
                              if g not in GREASE]
                elif et == 11 and len(body) >= 1:  # ec_point_formats
                    formats = list(body[1:1 + body[0]])
                o += 4 + el
        # JA3 string: fields joined by ",", values inside a field joined by "-"
        j = ",".join([
            str(ver),
            "-".join(str(c) for c in ciphers),
            "-".join(str(e) for e in exts),
            "-".join(str(c) for c in curves),
            "-".join(str(f) for f in formats),
        ])
        return {"ja3": hashlib.md5(j.encode()).hexdigest(), "ja3_string": j, "sni": sni,
                "ciphers": ciphers, "extensions": exts}
    except Exception:
        return None


# =====================================================================
# PCAP ring buffer (forensic capture around alerts)
# =====================================================================
class PcapRing:
    """Bounded in-memory ring of raw frames; dumps a .pcap on demand.

    Frames are stored with a linktype hint: eth=True means the buffer
    starts with an Ethernet header, eth=False means raw IP datagram.
    """

    def __init__(self, cfg_get):
        self._cfg_get = cfg_get
        self._frames: deque = deque()
        self._lock = threading.Lock()
        self._bytes = 0

    def _cfg(self) -> dict:
        try:
            return self._cfg_get().get("pcap_ring", {}) or {}
        except Exception:
            return {}

    def enabled(self) -> bool:
        return bool(self._cfg().get("enabled"))

    def clear(self):
        with self._lock:
            self._frames.clear()
            self._bytes = 0

    def add(self, ts: float, frame: bytes, eth: bool = False):
        if not self.enabled():
            return
        try:
            window = int(self._cfg().get("seconds", 20))
            max_bytes = int(self._cfg().get("max_mb", 64)) * 1024 * 1024
        except Exception:
            window, max_bytes = 20, 64 * 1024 * 1024
        cutoff = time.time() - window
        with self._lock:
            self._frames.append((ts, frame, eth))
            self._bytes += len(frame)
            while self._frames and (self._frames[0][0] < cutoff or self._bytes > max_bytes):
                _, old, _ = self._frames.popleft()
                self._bytes -= len(old)

    def snapshot(self) -> List[tuple]:
        with self._lock:
            return list(self._frames)

    # ------------------------------------------------------------ dump
    def dump(self, tag: str = "alert") -> Optional[Path]:
        """Writes the current ring to HOME/pcaps/<ts>_<tag>.pcap."""
        frames = self.snapshot()
        if not frames:
            return None
        PCAP_DIR.mkdir(parents=True, exist_ok=True)
        name = f"{time.strftime('%Y%m%d-%H%M%S')}_{tag}.pcap"
        out = PCAP_DIR / name
        eth_frames = sum(1 for _, _, e in frames if e)
        linktype = 1 if eth_frames > len(frames) // 2 else 101  # ethernet / raw IP
        with open(out, "wb") as f:
            # pcap global header: magic, v2.4, thiszone=0, sigfigs=0, snaplen, linktype
            f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
            n = 0
            for ts, frame, eth in frames:
                data = frame if (eth == (linktype == 1)) else (
                    b"\x00" * 12 + b"\x08\x00" + frame if linktype == 1 else _strip_eth(frame))
                if not data:
                    continue
                f.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(data), len(data)))
                f.write(data)
                n += 1
        return out if n else None

    def list_dumps(self) -> List[dict]:
        try:
            return [{"name": p.name, "size": p.stat().st_size,
                     "ts": p.stat().st_mtime} for p in sorted(PCAP_DIR.glob("*.pcap"))]
        except Exception:
            return []


def _strip_eth(frame: bytes) -> bytes:
    return frame[14:] if len(frame) > 14 else b""


# =====================================================================
# persistence-mechanism watcher (Linux + Windows)
# =====================================================================
class PersistenceWatch:
    """Baselines OS persistence locations and alerts on any drift."""

    def __init__(self, cfg_get):
        self._cfg_get = cfg_get
        self._lock = threading.Lock()
        self.state_file = HOME / "persistence_baseline.json"
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.last_changes: List[dict] = []

    def _cfg(self) -> dict:
        try:
            return self._cfg_get().get("persistence_watch", {}) or {}
        except Exception:
            return {}

    def enabled(self) -> bool:
        return bool(self._cfg().get("enabled"))

    # ------------------------------------------------------------ targets
    @staticmethod
    def _linux_targets() -> List[str]:
        home = str(Path.home())
        return [
            "/etc/crontab", "/etc/rc.local", "/etc/passwd", "/etc/shadow",
            f"{home}/.ssh/authorized_keys", f"{home}/.bashrc", f"{home}/.profile",
        ]

    @staticmethod
    def _linux_dirs() -> List[str]:
        home = str(Path.home())
        return ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly",
                "/etc/cron.monthly", "/var/spool/cron/crontabs", "/var/spool/cron",
                "/etc/systemd/system", "/etc/init.d", f"{home}/.config/autostart",
                f"{home}/.config/systemd/user", "/etc/profile.d"]

    @staticmethod
    def _windows_targets() -> List[str]:
        home = str(Path.home())
        return [f"{home}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
                "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp"]

    @staticmethod
    def _run_keys() -> List[tuple]:
        import winreg  # only on Windows
        return [(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce")]

    def _scan(self) -> dict:
        """Current fingerprint of every watched persistence location."""
        out: dict = {}

        def fp_file(p: str):
            try:
                st = os.stat(p)
                if st.st_size > 2_000_000:
                    return f"size={st.st_size}"
                with open(p, "rb") as f:
                    return hashlib.sha256(f.read()).hexdigest()
            except OSError:
                return None

        def fp_dir(d: str):
            try:
                entries = {}
                with os.scandir(d) as it:
                    for e in it:
                        try:
                            # lists (not tuples) so the JSON round-trip compares equal
                            entries[e.name] = [e.stat().st_mtime_ns, e.stat().st_size] \
                                if not e.is_dir() else "dir"
                        except OSError:
                            entries[e.name] = "?"
                return entries or {}
            except OSError:
                return None

        # If caller/test supplied custom target files or dirs
        if IS_WINDOWS and (getattr(self, "_linux_targets", None) != PersistenceWatch._linux_targets or
                           getattr(self, "_linux_dirs", None) != PersistenceWatch._linux_dirs):
            for p in self._linux_targets():
                h = fp_file(p)
                if h:
                    out[f"file:{p}"] = h
            for d in self._linux_dirs():
                r = fp_dir(d)
                if r is not None:
                    out[f"dir:{d}"] = r
        elif IS_WINDOWS:
            for d in self._windows_targets():
                r = fp_dir(d)
                if r is not None:
                    out[f"dir:{d}"] = r
            try:
                import winreg
                for hive, key_path in self._run_keys():
                    try:
                        with winreg.OpenKey(hive, key_path) as k:
                            vals = {}
                            i = 0
                            while True:
                                try:
                                    name, val, _ = winreg.EnumValue(k, i)
                                    vals[name] = str(val)
                                    i += 1
                                except OSError:
                                    break
                        out[f"reg:{key_path}"] = vals
                    except OSError:
                        pass
            except ImportError:
                pass
        else:
            for p in self._linux_targets():
                h = fp_file(p)
                if h:
                    out[f"file:{p}"] = h
            for d in self._linux_dirs():
                r = fp_dir(d)
                if r is not None:
                    out[f"dir:{d}"] = r
            # privileged uid-0 accounts
            try:
                with open("/etc/passwd", encoding="utf-8", errors="replace") as f:
                    out["uid0"] = sorted(l.split(":")[0] for l in f
                                        if l.strip() and l.split(":")[2] == "0")
            except OSError:
                pass
        return out

    # ------------------------------------------------------------ baseline
    def baseline(self) -> int:
        with self._lock:
            snap = self._scan()
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            self.state_file.write_text(json.dumps({"ts": time.time(), "state": snap}, indent=1))
            self.last_changes = []
            event("persistence_baseline_set", "info", entries=len(snap))
            return len(snap)

    def _load_baseline(self) -> dict:
        try:
            return json.loads(self.state_file.read_text()).get("state", {})
        except Exception:
            return {}

    def poll(self) -> List[dict]:
        """Diffs current state vs baseline; emits events; returns changes."""
        base = self._load_baseline()
        if not base:
            self.baseline()
            return []
        cur = self._scan()
        changes = []
        for key in sorted(set(base) | set(cur)):
            b, c = base.get(key), cur.get(key)
            if b == c:
                continue
            if isinstance(b, dict) and isinstance(c, dict):
                for name in sorted(set(b) | set(c)):
                    if b.get(name) != c.get(name):
                        kind = "added" if name not in b else ("removed" if name not in c
                                                             else "modified")
                        changes.append({"where": key, "item": str(name)[:200], "change": kind,
                                        "detail": f"{b.get(name)} -> {c.get(name)}"[:300]})
            elif b is None or c is None:
                item = ""
                if isinstance(c, dict):
                    item = ",".join(list(c.keys())[:5])
                changes.append({"where": key, "item": item,
                                "change": "added" if c else "removed",
                                "detail": ""})
            else:
                changes.append({"where": key, "item": "", "change": "modified",
                                "detail": "content changed"})
        with self._lock:
            self.last_changes = changes[-100:]
        for ch in changes:
            event("persistence_change", "high", **ch)
        return changes

    # ------------------------------------------------------------ loop
    def start(self):
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
        if not self._load_baseline():
            self.baseline()
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="sfw_persistence_watch")
        self._thread.start()
        event("persistence_watch_started", "info",
              interval_minutes=self._cfg().get("interval_minutes", 10))

    def stop(self):
        self._stop.set()

    def _loop(self):
        while not self._stop.wait(max(30, int(self._cfg().get("interval_minutes", 10)) * 60)):
            try:
                if self.enabled():
                    self.poll()
            except Exception:
                event("persistence_watch_error", "warning")


# =====================================================================
# SOC wiring: ring dump on alert events
# =====================================================================
def make_event_listener(ring: PcapRing, engine_get) -> "callable":
    """Returns an event listener that captures PCAPs on alert-worthy events."""
    ALERT_KINDS = {"ip_banned", "ids_signature", "honeypot_ssh_hit", "honeypot_ftp_creds",
                  "honeypot_telnet_creds", "honeypot_http_hit", "honeypot_rdp_hit",
                  "honeypot_smb_hit", "distributed_syn_flood", "sigma_rule_match",
                  "canary_file_deleted", "file_quarantined"}

    def listener(rec: dict):
        try:
            if not ring.enabled() or rec.get("kind") not in ALERT_KINDS:
                return
            ip = rec.get("src") or rec.get("remote") or rec.get("ip") or "alert"
            tag = str(ip).replace(":", "_").replace("/", "_")[:40]
            out = ring.dump(tag)
            if out:
                event("pcap_captured", "info", file=out.name, trigger=rec.get("kind"),
                      ip=tag, bytes=out.stat().st_size)
        except Exception:
            pass
    return listener


def generate_incident_bundle(identifier: str, engine=None, window_seconds: int = 300) -> dict:
    """Creates a unified forensic incident bundle: correlated events, verdicts, pcaps, and timeline."""
    import secrets
    now = time.time()
    cutoff = now - window_seconds
    clean_id = str(identifier).strip()

    # 1. Collect events matching identifier
    from . import common
    events_file = common.HOME / "logs" / "events.jsonl"
    matched_events = []
    if events_file.exists():
        try:
            lines = events_file.read_text(errors="replace").splitlines()
            for line in lines[-2000:]:
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                    if rec.get("ts", 0) >= cutoff and clean_id in json.dumps(rec):
                        matched_events.append(rec)
                except Exception:
                    continue
        except Exception:
            pass

    # 2. Find associated PCAP captures
    pcaps = []
    pcap_dir = common.HOME / "pcaps"
    if pcap_dir.exists():
        tag = clean_id.replace(":", "_").replace("/", "_")
        for p in pcap_dir.glob(f"*{tag}*.pcap"):
            try:
                pcaps.append({
                    "filename": p.name,
                    "size_bytes": p.stat().st_size,
                    "created": p.stat().st_mtime,
                })
            except OSError:
                pass

    # 3. Correlated verdicts & chronological timeline
    timeline = []
    for ev in sorted(matched_events, key=lambda x: x.get("ts", 0)):
        timeline.append({
            "timestamp": ev.get("ts", 0),
            "kind": ev.get("kind"),
            "severity": ev.get("sev", "info"),
            "summary": f"{ev.get('kind')} - {ev.get('src') or ev.get('ip') or ''}",
        })

    return {
        "incident_id": f"inc-{secrets.token_hex(4)}",
        "query": clean_id,
        "generated_at": now,
        "window_seconds": window_seconds,
        "event_count": len(matched_events),
        "events": matched_events[:100],
        "pcaps": pcaps,
        "timeline": timeline,
    }

