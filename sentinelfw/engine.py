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
        # Non-elevated run cannot touch the system hosts file. Degrade
        # gracefully: say it once, clearly, and stop retrying every cycle.
        if not getattr(eng, "_hosts_denied_logged", False):
            eng._hosts_denied_logged = True
            event("hosts_sinkhole_unavailable", "info", error=e,
                  note="run as Administrator/root to enable hosts-file domain blocking; "
                       "DNS-layer blocking and the firewall keep working without it")
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
        # usually a non-elevated run: System32\drivers\etc\hosts needs Administrator.
        # Degrade gracefully: one clear message, then stop retrying every cycle.
        if not getattr(eng, "_hosts_write_denied", False):
            eng._hosts_write_denied = True
            event("hosts_sinkhole_unavailable", "info", error=e,
                  note="run as Administrator/root to enable hosts-file domain blocking; "
                       "DNS-layer blocking and the firewall keep working without it")
        return False
    run(["ipconfig", "/flushdns"] if IS_WIN else ["resolvectl", "flush-caches"])
    event("hosts_synced", domains=len(want))
    return True


class Engine:
    def __init__(self):
        self.store = Store()
        self._commit_deadline = None
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

        def _on_tarpit_hit(ip, banner):
            # SSH tarpit (port 22222) saw a seeker bot: remember + optionally ban.
            if self.cfg.get("honeypot", {}).get("tarpit_auto_block", True):
                self.ban(ip, "ssh-tarpit: automated seeker bot", 7 * 86400, "honeypot")
            else:
                event("tarpit_seeker_seen", "warning", ip=ip, client_banner=banner)

        self.honeypot = HoneypotManager(self.cfg, config_persist=_persist_honeypot_cfg,
                                        on_tarpit_hit=_on_tarpit_hit)
        self.policies = FirewallPolicies(self.cfg, engine=self, config_persist=_persist_honeypot_cfg)
        self.intel = ThreatIntel(self.cfg, engine=self)
        self.recorder = PacketRecorder(capacity=8000)
        self.canary = CanarySystem(self.cfg)
        self.redirector = ScannerRedirector(self.cfg, engine=self)
        self.sandbox = Sandbox(self.cfg)
        self.elastic = ElasticShipper(self.cfg)
        self.baseline = BaselineEngine(self.cfg, conntrack=self.conntrack, engine=self)
        from .clamav import ClamAvManager
        self.clamav = ClamAvManager(self.cfg.get("clamav", {}))
        self.selfprotect = SelfProtect(self.cfg)
        self.suricata_mgr = SuricataManager(self.cfg)
        self.suricata_ingest = SuricataIngest(self.suricata_mgr.eve_path, engine=self)
        self.webui = None

        # SentinelFW 4.0 Subsystems
        from .waf import WAFProxyServer
        from .identity import IdentityDirectory, MicrosegmentationManager, ZTNAEvaluator, JITRuleManager
        from .nat import NatManager
        from .objects import ObjectCatalog
        from .zones import ZoneManager
        from .appid import AppIdEngine
        from .dlp import DLPManager
        from .playbook import PlaybookEngine
        from .compliance import ComplianceAuditor
        from .correlation import CorrelationEngine
        from .assetmap import AssetMap
        from .feeds import ThreatIntelFeeds
        from .decoy_advanced import AdvancedDecoyManager
        from .tarpit import TarpitManager
        from .watchdog import WatchdogGuard
        from .fleet import FleetManager
        from .gateway_sync import GatewaySyncClient
        from .killchain import KillChainTracker
        from .protocols import ProtocolAnalyzer

        self.identity = IdentityDirectory(self.cfg)
        self.microseg = MicrosegmentationManager()
        self.ztna = ZTNAEvaluator(self.identity)
        self.jit = JITRuleManager(engine=self)
        self.nat_mgr = NatManager(self.cfg.get("nat_rules", []))
        self.objects = ObjectCatalog(self.cfg)
        self.zones = ZoneManager(self.cfg)
        self.appid = AppIdEngine(self.cfg)
        self.dlp = DLPManager(self.cfg.get("dlp", {}))
        self.playbooks = PlaybookEngine(self.cfg, engine=self)
        self.compliance = ComplianceAuditor()
        self.correlation = CorrelationEngine(self.cfg, engine=self)
        self.assetmap = AssetMap(self.cfg)
        self.feed_mgr = ThreatIntelFeeds(self.cfg)
        self.advanced_decoys = AdvancedDecoyManager(self.cfg, engine=self)
        self.tarpit = TarpitManager(self.cfg, engine=self)
        self.watchdog = WatchdogGuard(self.cfg)
        self.fleet_mgr = FleetManager(self.cfg)
        posture_cb = getattr(self, "posture", None)
        self.gateway_sync = GatewaySyncClient(self.cfg, posture_provider=posture_cb if callable(posture_cb) else None)
        self.killchain = KillChainTracker(self.cfg, engine=self)
        self.protocols = ProtocolAnalyzer(self.cfg)
        self.waf = WAFProxyServer(self.cfg, engine=self)
        from .stateful_engine import StatefulFirewallEngine
        self.stateful_engine = StatefulFirewallEngine(max_connections=500000)

        # Wire live event bus to correlation and playbooks
        def _on_event_bus(ev_data):
            try:
                kind = str(ev_data.get("kind") or "")
                src_ip = str(ev_data.get("ip") or ev_data.get("src") or "")
                if hasattr(self, "correlation") and kind and src_ip:
                    self.correlation.process_event(kind, src_ip, ev_data)
                if hasattr(self, "playbooks"):
                    self.playbooks.evaluate_event(ev_data)
            except Exception:
                pass
        from .common import register_event_listener
        register_event_listener(_on_event_bus)

        # Console credentials initialization (first-run random OTP, operator passwords never overwritten)
        w = self.cfg.setdefault("webui", {})
        if not w.get("username"):
            w["username"] = "admin"
        if not w.get("password_hash"):
            import secrets
            from .mgmt import hash_password
            otp = secrets.token_urlsafe(16)
            w["password_hash"] = hash_password(otp)
            w["must_change_password"] = True
            w["password_initialized"] = False

            # Print once to console
            print(f"\n{'='*64}\n  SENTINELFW FIRST-RUN CREDENTIALS\n  Username: {w['username']}\n  OTP Password: {otp}\n  You MUST change this password on first login.\n{'='*64}\n")

            # Write to root/admin-only file auth.initial
            try:
                from . import common
                auth_file = Path(common.HOME) / "auth.initial"
                auth_content = f"username={w['username']}\none_time_password={otp}\ngenerated_at={int(time.time())}\n"
                common.atomic_write(auth_file, auth_content)
                if not IS_WIN:
                    try:
                        os.chmod(auth_file, 0o600)
                    except OSError:
                        pass
            except Exception as ex:
                event("initial_creds_write_error", "warning", error=str(ex))

            try:
                self.config_persist()
            except Exception:
                pass

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

    def trusted(self, ip) -> bool:
        """Admin / management IPs that must never be banned or redirected."""
        try:
            nets = self.cfg.get("trusted_ips", []) or []
            import ipaddress as _ipa
            a = _ipa.ip_address(str(ip))
            if a.is_loopback:  # the machine itself is always trusted
                return True
            for n in nets:
                if isinstance(n, str) and n.strip():
                    if a in _ipa.ip_network(n.strip(), strict=False):
                        return True
        except ValueError:
            pass
        return False

    def domain_blocked(self, name):
        parts = name.lower().strip(".").split(".")
        d = self.lists.domains
        return any(".".join(parts[i:]) in d for i in range(len(parts) - 1))

    def config_persist(self):
        """Persists the current config (used by policy / intel modules).

        Goes through the Store's env-safe path so environment-injected API
        keys are never written back into config.json.
        """
        from .common import CONFIG_FILE, atomic_write
        st = getattr(self, "store", None)
        dump = lambda: atomic_write(CONFIG_FILE, json.dumps(self.cfg, indent=2))  # noqa: E731
        if st is not None and hasattr(st, "persist_env_safe"):
            st.persist_env_safe(dump)
        else:
            dump()

    # ----------------------------------------------------------------
    # commit-confirm: stage config changes, auto-rollback if unconfirmed
    # ----------------------------------------------------------------
    def commit_stage(self, ttl_minutes: int = None) -> dict:
        """Snapshots the live config; changes after this point are reverted
        unless commit_confirm() is called before the deadline."""
        from .common import atomic_write
        cc = self.cfg.setdefault("commit_confirm", {})
        ttl = int(ttl_minutes or cc.get("ttl_minutes", 5))
        snap = json.loads(json.dumps(self.cfg))
        snap.pop("commit_confirm_pending", None)
        snap["_commit_deadline"] = self._commit_deadline
        atomic_write(HOME / "config_staged.json", json.dumps(snap, indent=2))
        self._commit_deadline = time.time() + ttl * 60
        event("commit_staged", "warning", ttl_minutes=ttl,
              note="config changes will auto-rollback unless confirmed")
        return {"staged": True, "ttl_minutes": ttl,
                "confirm_by": time.strftime("%H:%M:%S", time.localtime(self._commit_deadline))}

    def commit_confirm(self) -> dict:
        if getattr(self, "_commit_deadline", None) is None:
            return {"staged": False, "note": "no staged session"}
        self._commit_deadline = None
        try:
            (HOME / "config_staged.json").unlink()
        except OSError:
            pass
        event("commit_confirmed", "info")
        return {"staged": False, "confirmed": True}

    def commit_rollback(self, reason: str = "manual") -> dict:
        """Restores the staged snapshot into the live config and re-applies."""
        f = HOME / "config_staged.json"
        if not f.exists():
            return {"rolled_back": False, "note": "nothing staged"}
        try:
            snap = json.loads(f.read_text())
            snap.pop("_commit_deadline", None)
            self._commit_deadline = None
            self.cfg.clear()
            self.cfg.update(snap)
            self.config_persist()
            try:
                self.apply_all()
            except Exception:  # backend re-sync is best-effort; config is restored
                event("config_rollback_backend_warning", "warning",
                      note="firewall backend re-sync failed; config file restored")
            f.unlink()
            event("config_rollback", "warning", reason=reason)
            return {"rolled_back": True, "reason": reason}
        except Exception as exc:
            event("config_rollback_failed", "critical", error=str(exc))
            return {"rolled_back": False, "error": str(exc)}

    def commit_status(self) -> dict:
        dl = getattr(self, "_commit_deadline", None)
        return {"staged": dl is not None,
                "seconds_left": max(0, int(dl - time.time())) if dl else 0}

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
        if self.trusted(ip):
            event("ban_skipped_trusted", "info", ip=ip, reason=reason)
            return False
        # operator allow-list + learning mode (detections logged, not enforced)
        d = self.cfg.get("detections", {}) or {}
        for entry in (d.get("allowlist") or []):
            try:
                eip = entry.get("ip")
                ip_hit = (ip in eip) if isinstance(eip, list) else (eip == ip)
                if eip and ip_hit:
                    event("ban_suppressed_allowlist", "info", ip=ip, reason=reason,
                          note="matching detection allow-list entry")
                    return False
                rc = entry.get("reason_contains")
                if rc and rc in str(reason):
                    event("ban_suppressed_allowlist", "info", ip=ip, reason=reason,
                          note="matching detection allow-list entry")
                    return False
            except Exception:
                pass
        if d.get("learning_mode"):
            event("ban_suppressed_learning", "warning", ip=ip, reason=reason,
                  note="learning mode: detections recorded, bans suppressed")
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

    def extend_ban(self, ip, seconds):
        """Extends (or makes permanent when seconds==0) an existing ban."""
        with self.store.lock:
            cur = self.store.bans.get(ip)
            if not cur:
                return False
            cur["expires"] = 0 if seconds == 0 else time.time() + seconds
            self.store.save()
        # re-push to the kernel with the new TTL (permanent when seconds == 0)
        self.backend.ban(ip, seconds)
        event("ban_extended", "info", ip=ip, seconds=seconds)
        return True

    def unban(self, ip):
        with self.store.lock:
            had = self.store.bans.pop(ip, None) is not None
            if had:
                self.store.save()
        self.backend.unban(ip)
        return had

    def quarantine_host(self, ip: str, reason: str = "Compromised host posture", seconds: int = 3600):
        """Enforces a host quarantine enclave, isolating lateral movement while allowing remediation."""
        try:
            ip = str(addr(ip))
        except ValueError:
            return False
        if hasattr(self, "stateful_engine"):
            self.stateful_engine.quarantine_host(ip, duration=seconds, reason=reason)
        # Also enforce in kernel / backend and ban store
        return self.ban(ip, reason=f"Quarantine Enclave: {reason}", seconds=seconds, source="quarantine", force=True)

    def unquarantine_host(self, ip: str):
        """Removes a host from quarantine enclave isolation."""
        try:
            ip = str(addr(ip))
        except ValueError:
            return False
        if hasattr(self, "stateful_engine"):
            self.stateful_engine.unquarantine_host(ip)
        return self.unban(ip)

    def is_quarantined(self, ip: str) -> bool:
        """Returns True if the host is currently in a quarantine enclave."""
        if hasattr(self, "stateful_engine"):
            return self.stateful_engine.is_quarantined(ip) is not None
        return False

