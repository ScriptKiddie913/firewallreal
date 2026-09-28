"""SentinelFW engine module."""
import argparse, bisect, collections, fnmatch, functools, hashlib, ipaddress, json, logging, logging.handlers, math, os, re, shutil, signal, socket, struct, subprocess, sys, threading, time, urllib.request, uuid
from pathlib import Path
from .common import *  # noqa
from .config import *  # noqa
from .lists import *  # noqa
from .backends import *  # noqa


def discover_local_ips():
    ips = {"127.0.0.1", "::1"}
    try:
        for *_, sa in socket.getaddrinfo(socket.gethostname(), None):
            ips.add(sa[0].split("%")[0])
    except OSError:
        pass
    for fam, tgt in ((socket.AF_INET, ("192.0.2.1", 9)), (socket.AF_INET6, ("2001:db8::1", 9))):
        try:
            s = socket.socket(fam, socket.SOCK_DGRAM)
            s.connect(tgt)  # UDP connect sends nothing; just selects the outgoing interface
            ips.add(s.getsockname()[0].split("%")[0])
            s.close()
        except OSError:
            pass
    if IS_LINUX:
        _, out, _ = run(["ip", "-j", "addr"])
        try:
            for itf in json.loads(out):
                for a in itf.get("addr_info", []):
                    ips.add(a["local"])
        except (ValueError, KeyError, TypeError):
            pass
    return {str(addr(i)) for i in ips if i}


class Guard:
    """Addresses that automatic enforcement must never ban (prevents self-lockout and spoof-DoS)."""

    def __init__(self, eng):
        self.e = eng
        self.local, self.extra = set(), set()
        self.cgnat = ipaddress.ip_network("100.64.0.0/10")
        self.refresh()

    def refresh(self):
        self.local = discover_local_ips()
        self.extra = set()
        if IS_LINUX:
            try:
                for ln in Path("/etc/resolv.conf").read_text().splitlines():
                    p = ln.split()
                    if len(p) == 2 and p[0] == "nameserver":
                        self.extra.add(str(addr(p[1].split("%")[0])))
            except (OSError, ValueError):
                pass
            _, out, _ = run(["ip", "route", "show", "default"])
            for m in re.finditer(r"via (\S+)", out):
                try:
                    self.extra.add(str(addr(m.group(1))))
                except ValueError:
                    pass

    def protected(self, ip):
        try:
            a = addr(ip)
        except ValueError:
            return True
        if a.is_loopback or a.is_multicast or a.is_link_local or a.is_unspecified or a.is_reserved:
            return True
        s = str(a)
        if s in self.local or s in self.extra:
            return True
        cfg = self.e.cfg
        if cfg["protect_private"] and (a.is_private or (a.version == 4 and a in self.cgnat)):
            return True
        for n in cfg["never_block"]:
            net = to_net(n)
            if net is not None and a.version == net.version and a in net:
                return True
        return False


def sync_hosts(eng):
    cfg = eng.cfg
    if not cfg["hosts_file_sinkhole"]:
        want = []
    else:
        man = sorted(eng.lists.manual_domains)
        rest = sorted(eng.lists.domains - eng.lists.manual_domains)
        want = (man + rest)[: int(cfg["hosts_file_max_domains"])]
    try:
        raw = HOSTS.read_bytes().decode("utf-8", "replace")
    except OSError as e:
        event("hosts_error", "medium", error=e)
        return False
    nl = "\r\n" if IS_WIN else "\n"
    stripped = re.sub(r"(?:\r?\n)?" + re.escape(MARK_B) + r".*?" + re.escape(MARK_E) + r"(?:\r?\n)?", nl, raw, flags=re.S).rstrip("\r\n") + nl
    new = stripped
    if want:
        new += nl.join([MARK_B] + [f"0.0.0.0 {d}" for d in want] + [MARK_E]) + nl
    if new == raw:
        return True
    try:
        tmp = HOSTS.with_name(HOSTS.name + ".sfw.tmp")
        tmp.write_bytes(new.encode("utf-8"))
        if not IS_WIN:
            shutil.copymode(HOSTS, tmp)
        try:
            os.replace(tmp, HOSTS)
        except OSError:
            HOSTS.write_bytes(new.encode("utf-8"))
            try:
                if tmp.exists():
                    tmp.unlink()
            except OSError:
                pass
    except OSError as e:
        event("hosts_error", "medium", error=e)
        return False
    run(["ipconfig", "/flushdns"] if IS_WIN else ["resolvectl", "flush-caches"])
    event("hosts_synced", domains=len(want))
    return True


class Engine:
    def __init__(self):
        self.store = Store()
        self.lists = Lists()
        self.backend = WinBackend() if IS_WIN else NftBackend()
        self.guard = Guard(self)
        self.stats = collections.Counter()
        self._skip_log = {}

        # SentinelFW 3.0 Enterprise Modules
        from .anomaly import BaselineEngine
        from .appwall import ApplicationFirewall
        from .conntrack import ConnectionTracker
        from .decoy import CanarySystem
        from .elastic import ElasticShipper
        from .honeypot import HoneypotManager
        from .netlens import PacketRecorder
        from .sandbox import Sandbox
        from .scanner_redirect import ScannerRedirector
        from .selfprotect import SelfProtect
        from .suricata_ingest import SuricataIngest
        from .suricata_manager import SuricataManager
        from .policies import FirewallPolicies
        from .threatintel import ThreatIntel

        self.conntrack = ConnectionTracker(self.cfg)
        self.appwall = ApplicationFirewall(self.cfg)

        def _persist_honeypot_cfg(cfg):
            from .common import CONFIG_FILE, atomic_write
            atomic_write(CONFIG_FILE, json.dumps(cfg, indent=2))

        self.honeypot = HoneypotManager(self.cfg, config_persist=_persist_honeypot_cfg)
        self.policies = FirewallPolicies(self.cfg, engine=self, config_persist=_persist_honeypot_cfg)
        self.intel = ThreatIntel(self.cfg, engine=self)
        self.recorder = PacketRecorder(capacity=8000)
        self.canary = CanarySystem(self.cfg)
        self.redirector = ScannerRedirector(self.cfg, engine=self)
        self.sandbox = Sandbox(self.cfg)
        self.elastic = ElasticShipper(self.cfg)
        self.baseline = BaselineEngine(self.cfg, conntrack=self.conntrack, engine=self)
        self.selfprotect = SelfProtect(self.cfg)
        self.suricata_mgr = SuricataManager(self.cfg)
        self.suricata_ingest = SuricataIngest(self.suricata_mgr.eve_path, engine=self)
        self.webui = None

    @property
    def cfg(self):
        return self.store.cfg

    def remote_ips(self, limit=200):
        """Unique remote endpoints seen by the engine (for threat-intel scans)."""
        out = {}
        try:
            for c in self.conntrack.get_active():
                r = c.get("raddr")
                if r and r not in ("127.0.0.1", "::1"):
                    out[r] = out.get(r, 0) + int(c.get("bytes_total") or 0) + 1
        except Exception:
            pass
        try:
            if self.recorder is not None:
                local = self.guard.local if hasattr(self.guard, "local") else set()
                for p in self.recorder.query(limit=1000):
                    r = p.get("dst") if p.get("direction") == "out" else p.get("src")
                    if r and r not in local:
                        out[r] = out.get(r, 0) + p.get("length", 0)
        except Exception:
            pass
        return sorted(out, key=lambda k: -out[k])[:limit]

    def blocked(self, ip):
        return ip in self.lists.ipset or ip in self.store.bans

    def domain_blocked(self, name):
        parts = name.lower().strip(".").split(".")
        d = self.lists.domains
        return any(".".join(parts[i:]) in d for i in range(len(parts) - 1))

    def config_persist(self):
        """Persists the current config (used by policy / intel modules)."""
        from .common import CONFIG_FILE, atomic_write
        atomic_write(CONFIG_FILE, json.dumps(self.cfg, indent=2))

    def apply_all(self):
        self.lists.refresh()
        b = self.backend
        b.begin()
        b.sync_static(self.lists.ipset.nets)
        b.sync_bans(self.store.bans)
        b.sync_programs(self.lists.exact_programs())
        if self.cfg["default_deny_inbound"]:
            b.harden(self.cfg["allow_inbound_ports"], True)
        b.commit()
        self.policies.apply()
        self.intel.start_background()
        sync_hosts(self)

    def ban(self, ip, reason, seconds=None, source="ids", force=False):
        try:
            ip = str(addr(ip))
        except ValueError:
            return False
        if not force and self.guard.protected(ip):
            t = time.monotonic()
            if t - self._skip_log.get(ip, 0) > 300:
                self._skip_log[ip] = t
                event("ban_skipped_protected", "low", ip=ip, reason=reason)
            return False
        with self.store.lock:
            if seconds is None:
                base = int(self.cfg["auto_ban_seconds"])
                n = self.store.offenses.get(ip, 0)
                seconds = min(base * (2 ** n), 30 * 86400)
            exp = 0 if seconds == 0 else time.time() + seconds
            cur = self.store.bans.get(ip)
            if cur and (cur["expires"] == 0 or (exp and cur["expires"] >= exp)):
                return False
            self.store.offenses[ip] = self.store.offenses.get(ip, 0) + 1
            self.store.bans[ip] = {"reason": reason, "source": source, "added": time.time(), "expires": exp}
            self.store.save()
        ok = self.backend.ban(ip, seconds)
        self.stats["bans"] += 1
        event("ip_banned", "high", ip=ip, reason=reason, seconds=seconds, source=source, enforced=ok)
        return True

    def unban(self, ip):
        with self.store.lock:
            had = self.store.bans.pop(ip, None) is not None
            if had:
                self.store.save()
        self.backend.unban(ip)
        return had
