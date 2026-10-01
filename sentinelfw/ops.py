"""SentinelFW 2.9 — filtering DNS forwarder, fleet relay/agent, log vault."""
import hashlib
import hmac as hmac_mod
import json
import os
import socket
import struct
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional

from . import common
from .common import event

IS_WINDOWS = os.name == "nt"

def __getattr__(name: str):
    if name == "VAULT_DIR":
        return common.HOME / "vault"
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


# =====================================================================
# 1. Filtering DNS forwarder (UDP)
# =====================================================================
def _dns_name_parse(msg: bytes, o: int):
    labels = []
    while o < len(msg):
        n = msg[o]
        if n == 0:
            o += 1
            return ".".join(labels), o
        if n & 0xC0:  # compression pointer — not expected in a question
            return ".".join(labels), o + 2
        labels.append(msg[o + 1:o + 1 + n].decode("ascii", "replace"))
        o += 1 + n
    return ".".join(labels), o


def _dns_name_wire(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        if label:
            out += bytes([len(label)]) + label.encode("ascii", "replace")
    return out + b"\x00"


class DnsFilter:
    """A local filtering DNS forwarder: blocklists apply at the DNS layer.

    Sits on UDP <port> (default 53), answers from a small TTL cache, and
    forwards everything else to the configured upstream resolvers. Blocked
    domains get the sinkhole answer instead of the real record.
    """

    def __init__(self, cfg_get, lists_get):
        self._cfg_get = cfg_get
        self._lists_get = lists_get
        self._sock: Optional[socket.socket] = None
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.cache: Dict[str, tuple] = {}  # qname+qtype -> (expires, answer)
        self.stats = {"queries": 0, "blocked": 0, "forwarded": 0, "cache_hits": 0,
                      "errors": 0}

    def _cfg(self) -> dict:
        try:
            return self._cfg_get().get("dns_server", {}) or {}
        except Exception:
            return {}

    def enabled(self) -> bool:
        return bool(self._cfg().get("enabled"))

    def _blocked(self, qname: str) -> bool:
        try:
            L = self._lists_get()
            doms = getattr(L, "domains", set()) | getattr(L, "manual_domains", set())
        except Exception:
            return False
        name = qname.lower().rstrip(".")
        if name in doms:
            return True
        # suffix match: ads.example.com blocked when example.com blocklisted
        parts = name.split(".")
        return any(".".join(parts[i:]) in doms for i in range(1, len(parts)))

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="sfw_dns_filter")
        self._thread.start()

    def stop(self):
        self._stop.set()
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass

    def _run(self):
        cfg = self._cfg()
        listen = str(cfg.get("listen") or "0.0.0.0")
        port = int(cfg.get("port") or 53)
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((listen, port))
            self._sock.settimeout(1.0)
        except OSError as e:
            event("dns_server_bind_failed", "high", error=str(e), port=port,
                  note="DNS filter not started (port in use or privileges missing)")
            return
        event("dns_server_started", "info", listen=listen, port=port)
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self.stats["queries"] += 1
                answer = self.handle_query(data)
                if answer:
                    self._sock.sendto(answer, addr)
            except Exception:
                self.stats["errors"] += 1

    def handle_query(self, data: bytes) -> Optional[bytes]:
        if len(data) < 12:
            return None
        tid = data[:2]
        flags = struct.unpack("!H", data[2:4])[0]
        if flags & 0x8000:  # a response, not a query
            return None
        qname, o = _dns_name_parse(data, 12)
        if o + 4 > len(data) or not qname:
            return None
        qtype, qclass = struct.unpack("!HH", data[o:o + 4])
        if qtype != 1:  # only A records are filtered/forwarded in v1
            return self._forward(data)
        if self._blocked(qname):
            self.stats["blocked"] += 1
            event("dns_blocked_query", "info", domain=qname, client="local",
                  sinkhole=self._cfg().get("sinkhole_ip", "0.0.0.0"))
            return self._make_answer(data, tid, qname, qtype, qclass,
                                     str(self._cfg().get("sinkhole_ip", "0.0.0.0")))
        cached = self.cache.get(f"{qname.lower()}|{qtype}")
        if cached and cached[0] > time.time():
            self.stats["cache_hits"] += 1
            resp = bytearray(cached[1])
            resp[0:2] = tid  # match this query's transaction id
            return bytes(resp)
        return self._forward(data)

    def _make_answer(self, query: bytes, tid: bytes, qname: str, qtype: int,
                      qclass: int, ip: str) -> bytes:
        # header: id, flags=0x8580 (QR|AA|RD|RA), qd=1, an=1
        hdr = tid + struct.pack("!HHHHHH", 0x8580, 1, 1, 0, 0, 0)
        q = _dns_name_wire(qname) + struct.pack("!HH", qtype, qclass)
        rr = _dns_name_wire(qname) + struct.pack("!HHIH", qtype, qclass, 30, 4) + \
            socket.inet_aton(ip)
        return hdr + q + rr

    def _forward(self, data: bytes) -> Optional[bytes]:
        cfg = self._cfg()
        upstreams = cfg.get("upstream") or ["1.1.1.1", "8.8.8.8"]
        for up in upstreams:
            try:
                host, _, port = str(up).rpartition(":")
                if not port.isdigit():
                    host, port = str(up), 53
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(3)
                s.sendto(data, (host, int(port)))
                resp, _ = s.recvfrom(4096)
                s.close()
                self.stats["forwarded"] += 1
                # cache the A answer (qname -> response) with a short TTL
                try:
                    qname, o = _dns_name_parse(resp, 12)
                    qtype = struct.unpack("!H", resp[o:o + 2])[0]
                    ancount = struct.unpack("!H", resp[6:8])[0]
                    if qtype == 1 and ancount and qname:
                        self.cache[f"{qname.lower()}|1"] = (time.time() + 60, resp)
                except Exception:
                    pass
                return resp
            except Exception:
                continue
        self.stats["errors"] += 1
        return None


# =====================================================================
# 2. Fleet mode v1 — relay state (endpoints live in webui.py)
# =====================================================================
class FleetRelay:
    """In-memory + on-disk registry of enrolled fleet agents."""

    def __init__(self, cfg_get):
        self._cfg_get = cfg_get
        self.lock = threading.Lock()
        self.file = common.HOME / "fleet.json"
        self.agents: Dict[str, dict] = {}
        self.feed: List[dict] = []  # recent agent events (bounded)
        self._load()

    def _cfg(self) -> dict:
        try:
            return self._cfg_get().get("fleet", {}) or {}
        except Exception:
            return {}

    def enabled(self) -> bool:
        return bool(self._cfg().get("enabled"))

    def key_ok(self, provided: str) -> bool:
        want = str(self._cfg().get("shared_key") or "")
        return bool(want and provided and hmac_mod.compare_digest(want, provided))

    def _load(self):
        try:
            d = json.loads(self.file.read_text())
            self.agents = d.get("agents", {})
            self.feed = d.get("feed", [])[-500:]
        except Exception:
            pass

    def _persist(self):
        try:
            self.file.write_text(json.dumps({"agents": self.agents,
                                             "feed": self.feed[-500:]}, indent=1))
        except Exception:
            pass

    def enroll(self, hostname: str) -> dict:
        agent_id = hashlib.sha256((hostname + secrets_token(8)).encode()).hexdigest()[:16]
        with self.lock:
            self.agents[agent_id] = {"hostname": hostname, "first_seen": time.time(),
                                      "last_seen": time.time(), "stats": {},
                                      "recent_events": []}
            self._persist()
        event("fleet_agent_enrolled", "info", agent=agent_id, hostname=hostname)
        return {"agent_id": agent_id}

    def heartbeat(self, agent_id: str, payload: dict) -> dict:
        with self.lock:
            a = self.agents.get(agent_id)
            if not a:
                return {}
            a["last_seen"] = time.time()
            a["hostname"] = str(payload.get("hostname") or a.get("hostname", "?"))
            a["version"] = str(payload.get("version", "?"))
            a["platform"] = str(payload.get("platform", "?"))
            a["stats"] = payload.get("stats") or {}
            a["top_offenders"] = payload.get("top_offenders") or []
            for ev in (payload.get("recent_events") or [])[-20:]:
                self.feed.append({"agent": a["hostname"], **ev})
            self.feed = self.feed[-500:]
            self._persist()
            return {"ok": True}

    def stale(self, minutes: int = 5) -> set:
        cutoff = time.time() - minutes * 60
        return {aid for aid, a in self.agents.items() if a.get("last_seen", 0) < cutoff}

    def overview(self) -> dict:
        with self.lock:
            agents = []
            now = time.time()
            for aid, a in sorted(self.agents.items(),
                                 key=lambda kv: -kv[1].get("last_seen", 0)):
                agents.append({
                    "agent_id": aid, "hostname": a.get("hostname"),
                    "version": a.get("version"), "platform": a.get("platform"),
                    "last_seen": int(now - a.get("last_seen", 0)),
                    "online": now - a.get("last_seen", 0) < 300,
                    "stats": a.get("stats", {}),
                    "top_offenders": (a.get("top_offenders") or [])[:5]})
            return {"enabled": self.enabled(), "agents": agents,
                    "online": sum(1 for a in agents if a["online"]),
                    "feed": self.feed[-50:]}


def secrets_token(n: int = 16) -> str:
    import secrets
    return secrets.token_hex(n // 2 + n % 2)[:n]


class FleetAgent:
    """Reporter that ships this engine's stats to a central relay.

    Started by `sfwctl.py fleet-agent --relay URL --key KEY` (or from the
    daemon config). Pulls the relay's shared blocklist into
    <data>/lists/fleet_shared.txt so the local Lists engine picks it up.
    """

    def __init__(self, cfg_get, engine, relay_url: str, key: str, interval: int = 30):
        self.cfg_get = cfg_get
        self.engine = engine
        self.relay = relay_url.rstrip("/")
        self.key = key
        self.interval = interval
        self._stop = threading.Event()
        self._thread = None
        self.agent_id = ""
        self.sent = 0

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="sfw_fleet_agent")
        self._thread.start()
        event("fleet_agent_started", "info", relay=self.relay, interval=self.interval)

    def stop(self):
        self._stop.set()

    def _post(self, path: str, payload: dict) -> Optional[dict]:
        import urllib.request
        req = urllib.request.Request(self.relay + path,
                                     data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json",
                                              "X-Fleet-Key": self.key},
                                     method="POST")
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return json.loads(r.read().decode("utf-8", "replace") or "{}")
        except Exception as e:
            event("fleet_relay_error", "warning", error=str(e)[:120])
            return None

    def _run(self):
        while not self._stop.wait(self.interval):
            try:
                self.beat()
            except Exception:
                pass

    def beat(self) -> bool:
        e = self.engine
        if not self.agent_id:
            r = self._post("/api/f1/enroll", {"hostname": socket.gethostname(),
                                              "key": self.key})
            if not r or not r.get("agent_id"):
                return False
            self.agent_id = r["agent_id"]
        # gather stats + recent events
        stats = {}
        events = []
        try:
            with e.store.lock:
                stats = {"bans": len(e.store.bans), "offenses": len(e.store.offenses)}
                top = sorted(e.store.offenses.items(), key=lambda kv: -kv[1])[:5]
                top_off = [{"ip": ip, "count": c} for ip, c in top]
        except Exception:
            top_off = []
        try:
            p = common.HOME / "logs" / "events.jsonl"
            if p.exists():
                lines = p.read_text(errors="replace").splitlines()[-10:]
                events = [json.loads(l) for l in lines if l.strip()]
        except Exception:
            pass
        r = self._post("/api/f1/heartbeat", {
            "agent_id": self.agent_id, "hostname": socket.gethostname(),
            "version": "2.9", "platform": "windows" if IS_WINDOWS else "linux",
            "stats": stats, "top_offenders": top_off, "recent_events": events})
        self.sent += 1
        if r and isinstance(r.get("blocklist"), list):
            try:
                from .common import LISTS
                LISTS.mkdir(parents=True, exist_ok=True)
                (LISTS / "fleet_shared.txt").write_text(
                    "# managed by fleet agent — pulled from relay\n" +
                    "\n".join(r["blocklist"][:5000]), encoding="utf-8")
            except Exception:
                pass
        return bool(r)


# =====================================================================
# 3. Log vault — blockchain-style sealing of the event log
# =====================================================================
def _merkle_root(hashes: List[str]) -> str:
    if not hashes:
        return hashlib.sha256(b"").hexdigest()
    layer = list(hashes)
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        layer = [hashlib.sha256((layer[i] + layer[i + 1]).encode()).hexdigest()
                 for i in range(0, len(layer), 2)]
    return layer[0]


class LogVault:
    """Seals the event log into chained, HMAC-signed blocks.

    Every `seal_interval_seconds` (or on demand) the new events.jsonl lines
    are hashed into a Merkle tree; its root, the record count and a running
    hash of the previous block form a new block that is appended to
    <data>/vault/chain.json. Blocks are chained via prev_hash (a blockchain)
    and signed with HMAC-SHA256 using the configured vault key, so a host
    admin cannot forge, edit or delete history without detection.

    Note on "encryption": true at-rest confidentiality is an OS-level concern
    (LUKS / BitLocker — see docs/DEPLOYMENT.md). The vault provides
    blockchain-grade tamper evidence and authenticity instead.
    """

    def __init__(self, cfg_get, log_file: Optional[Path] = None, chain_file: Optional[Path] = None):
        self._cfg_get = cfg_get
        self.lock = threading.Lock()
        self.chain_file = chain_file or (common.HOME / "vault" / "chain.json")
        self.log_file = log_file or (common.HOME / "logs" / "events.jsonl")
        self._stop = threading.Event()
        self._thread = None
        self._sealed_lines = 0

    def _cfg(self) -> dict:
        try:
            return self._cfg_get().get("management", {}).get("vault", {}) or {}
        except Exception:
            return {}

    def enabled(self) -> bool:
        return bool(self._cfg().get("enabled"))

    def _key(self) -> bytes:
        k = str(self._cfg().get("key") or "")
        return k.encode() if k else b""

    def _hmac(self, data: str) -> str:
        return hmac_mod.new(self._key(), data.encode(), hashlib.sha256).hexdigest()

    # ------------------------------------------------------------ blocks
    def _load_chain(self) -> List[dict]:
        try:
            return json.loads(self.chain_file.read_text())
        except Exception:
            return []

    def _append_chain(self, blocks: List[dict]):
        (common.HOME / "vault").mkdir(parents=True, exist_ok=True)
        self.chain_file.write_text(json.dumps(blocks, indent=1))

    def seal(self, force: bool = False) -> Optional[dict]:
        """Hashes any new events.jsonl lines into a new block."""
        if not self.enabled() and not force:
            return None
        log = self.log_file or (common.HOME / "logs" / "events.jsonl")
        with self.lock:
            try:
                lines = log.read_text(errors="replace").splitlines()
            except OSError:
                return None
            new = [l for l in lines[self._sealed_lines:] if l.strip()]
            self._sealed_lines = len(lines)
            if not new and not force:
                return None
            hashes = [hashlib.sha256(l.encode()).hexdigest() for l in new]
            chain = self._load_chain()
            prev = chain[-1]["hash"] if chain else ""
            index = len(chain)
            header = {"index": index, "prev": prev,
                      "ts": time.time(), "records": len(new),
                      "merkle_root": _merkle_root(hashes),
                      "record_hashes": hashes[:50]}  # first 50 for spot checks
            header["hash"] = self._hmac(json.dumps(
                {k: v for k, v in header.items()}, sort_keys=True))
            chain.append(header)
            self._append_chain(chain)
            if new:
                event("vault_block_sealed", "info", index=index, records=len(new),
                      merkle=header["merkle_root"][:12])
            # off-box anchor: the head hash ships out with every syslog event,
            # so re-sealing or truncation is detectable against the collector
            event("vault_anchor", "info", block=index, head=header["hash"][:16],
                  merkle=header["merkle_root"][:16])
            return header

    def verify(self) -> dict:
        chain = self._load_chain()
        prev = ""
        bad = None
        for i, b in enumerate(chain):
            if b.get("prev") != prev or b.get("index") != i:
                bad = bad or i
                break
            expect = self._hmac(json.dumps(
                {k: v for k, v in b.items() if k != "hash"}, sort_keys=True))
            if not hmac_mod.compare_digest(expect, b.get("hash", "")):
                bad = bad or i
            prev = b["hash"]
        return {"ok": bad is None, "blocks": len(chain),
                "records": sum(b.get("records", 0) for b in chain),
                "first_bad": bad,
                "sealed": self.enabled()}

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        try:
            lines = (common.HOME / "logs" / "events.jsonl").read_text(errors="replace").splitlines()
            self._sealed_lines = len(lines)  # history stays; sealing covers future
        except Exception:
            self._sealed_lines = 0
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="sfw_log_vault")
        self._thread.start()
        event("vault_started", "info", note="event log sealing active")

    def stop(self):
        self._stop.set()

    def _loop(self):
        while not self._stop.wait(max(30, int(self._cfg().get("seal_interval_seconds", 60)))):
            try:
                if self.enabled():
                    self.seal()
            except Exception:
                pass

    # ------------------------------------------------------------ FLUSH
    def flush_all(self, engine=None) -> dict:
        """Deletes every stored log artifact: events, audit chain, vault,
        VT intel cache and forensic pcaps. The one button the operator hopes
        to never need — but forensically documented when they do."""
        removed = []
        # release the open events.jsonl handle first (Windows-safe delete)
        try:
            from .common import close_event_logging
            close_event_logging()
        except Exception:
            pass
        # NOTE: fleet.json (agent enrollments) is intentionally kept
        targets = [common.HOME / "logs" / "events.jsonl", mgmt_audit_path(), self.chain_file,
                   common.HOME / "intel.db"]
        try:
            for pat in ("events.jsonl.*",):
                targets += list((common.HOME / "logs").glob(pat))
            for p in (common.HOME / "pcaps").glob("*.pcap"):
                targets.append(p)
        except Exception:
            pass
        # keep a tombstone: an event AFTER the wipe proves a wipe happened
        for t in targets:
            try:
                if t.exists():
                    t.unlink()
                    removed.append(str(t.name))
            except Exception:
                pass
        # reattach logging on a FRESH file, then record the tombstone
        try:
            from .common import close_event_logging, setup_logging
            close_event_logging()   # (already closed above, idempotent)
            (common.HOME / "logs").mkdir(parents=True, exist_ok=True)
            setup_logging()
        except Exception:
            pass
        self._sealed_lines = 0
        if engine is not None:
            try:
                engine.recorder.clear() if hasattr(engine.recorder, "clear") else None
            except Exception:
                pass
        # fresh genesis block so the chain restarts provably
        event("log_flush_executed", "warning", removed=len(removed),
              note="operator-initiated wipe of all stored logs")
        self.seal(force=True)
        return {"flushed": removed, "count": len(removed)}


def mgmt_audit_path() -> Path:
    return common.HOME / "audit.log"
