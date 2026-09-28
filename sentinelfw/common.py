"""SentinelFW common module."""
import argparse, bisect, collections, fnmatch, functools, hashlib, ipaddress, json, logging, logging.handlers, math, os, re, shutil, signal, socket, struct, subprocess, sys, threading, time, urllib.request, uuid
from pathlib import Path


PKG_DIR = Path(__file__).resolve().parent


VERSION = "3.0.0"


IS_WIN = os.name == "nt"


IS_LINUX = sys.platform.startswith("linux")


if IS_WIN:
    HOME = Path(os.environ.get("SENTINELFW_HOME") or os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "SentinelFW"))
    HOSTS = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
else:
    HOME = Path(os.environ.get("SENTINELFW_HOME") or "/var/lib/sentinelfw")
    HOSTS = Path("/etc/hosts")

DATA_DIR = HOME


CONFIG_FILE = HOME / "config.json"


STATE_FILE = HOME / "state.json"


LISTS = HOME / "lists"


QUAR = HOME / "quarantine"


LOGS = HOME / "logs"


PIDFILE = HOME / "sentinelfw.pid"


MARK_B = "# >>> SentinelFW BEGIN (managed block - do not edit)"


MARK_E = "# <<< SentinelFW END"


STOP = threading.Event()


def run(cmd, input=None, timeout=90):
    kw = {}
    if IS_WIN:
        kw["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
    try:
        p = subprocess.run(cmd, input=input, capture_output=True, text=True, timeout=timeout, **kw)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:  # noqa: BLE001
        return 1, "", str(e)


def is_admin():
    if IS_WIN:
        import ctypes
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:  # noqa: BLE001
            return False
    return os.geteuid() == 0


def atomic_write(path, text):
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def deep_merge(base, over):
    out = dict(base)
    for k, v in over.items():
        out[k] = deep_merge(base[k], v) if isinstance(v, dict) and isinstance(base.get(k), dict) else v
    return out


def parse_duration(s):
    m = re.fullmatch(r"(\d+)([smhd]?)", str(s).strip().lower())
    if not m:
        raise ValueError("duration must look like 30m, 12h, 7d or seconds")
    return int(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


def norm_path(p):
    return os.path.normcase(os.path.normpath(p))


def pid_alive(pid):
    if IS_WIN:
        _, out, _ = run(["tasklist", "/FI", f"PID eq {pid}", "/NH"])
        return str(pid) in out
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def addr(s):
    a = ipaddress.ip_address(s)
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    return a


def entropy(s):
    if not s:
        return 0.0
    c = collections.Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values())


_flog = logging.getLogger("sentinelfw.events")


def setup_logging():
    LOGS.mkdir(parents=True, exist_ok=True)
    if _flog.handlers:
        return
    h = logging.handlers.RotatingFileHandler(LOGS / "events.jsonl", maxBytes=25_000_000, backupCount=8, encoding="utf-8")
    h.setFormatter(logging.Formatter("%(message)s"))
    _flog.addHandler(h)
    _flog.setLevel(logging.INFO)
    _flog.propagate = False


_EVENT_LISTENERS = []


def register_event_listener(fn):
    if fn not in _EVENT_LISTENERS:
        _EVENT_LISTENERS.append(fn)


def event(kind, sev="info", **kw):
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "kind": kind, "severity": sev}
    rec.update(kw)
    try:
        _flog.info(json.dumps(rec, default=str))
    except Exception:  # noqa: BLE001
        pass
    print(f"[{rec['ts']}] {sev.upper():6} {kind} " + " ".join(f"{k}={v}" for k, v in kw.items()), flush=True)
    for listener in _EVENT_LISTENERS:
        try:
            listener(rec)
        except Exception:
            pass

