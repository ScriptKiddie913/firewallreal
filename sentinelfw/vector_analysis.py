"""SentinelFW Traffic & Threat-Vector Analysis.

Builds a per-IP attack profile ("threat vectors") and a live traffic
description ("what is being transmitted") for every remote endpoint:

* Evidence sources: connection tracker, the deep-packet recorder (DNS
  queries, TLS SNI, HTTP request lines, TCP flags, port spread, packet
  timing), honeypot sessions, the security event log, active bans and the
  VirusTotal cache.
* Vectors: port scan, SYN scan, brute force / credential stuffing,
  DDoS / flood, C2 beaconing, cryptomining, exploit attempts, DNS
  tunneling, honeypot recon, canary triggers and VT malware reputation.
* Every vector carries human-readable evidence ("42 ports in 60s",
  "beacon every 60s ± 2.1s") so operators see WHY an IP was flagged.
"""
import json
import math
import re
import time
from collections import defaultdict
from pathlib import Path
from .common import DATA_DIR, LOGS

# ---------------------------------------------------------------------------
# Vector catalog: id -> (label, weight, base severity)
# ---------------------------------------------------------------------------
VECTORS = {
    "port_scan":   ("PORT SCAN", 25, "high"),
    "syn_scan":    ("SYN SCAN", 20, "high"),
    "brute_force": ("BRUTE FORCE", 30, "critical"),
    "cred_stuff":  ("CREDENTIAL STUFFING", 25, "critical"),
    "ddos":        ("DDoS / FLOOD", 35, "critical"),
    "beacon":      ("C2 / BEACONING", 35, "critical"),
    "mining":      ("CRYPTOMINING", 30, "critical"),
    "exploit":     ("EXPLOIT ATTEMPT", 30, "critical"),
    "malware":     ("MALWARE (VT)", 40, "critical"),
    "recon":       ("HONEYPOT RECON", 20, "high"),
    "dns_tunnel":  ("DNS TUNNELING", 25, "high"),
    "canary":      ("CANARY TRIGGERED", 30, "critical"),
    "sweep":       ("NETWORK SWEEP", 20, "high"),
    "suspicious":  ("SUSPICIOUS TRAFFIC", 10, "medium"),
}

_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$|^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$")

# event kind -> vector id (substring match on kind)
_EVENT_VECTORS = [
    ("port_scan", "port_scan"),
    ("syn_flood", "ddos"),
    ("distributed", "ddos"),
    ("brute", "brute_force"),
    ("auth_fail", "brute_force"),
    ("ids_signature", "exploit"),
    ("exploit", "exploit"),
    ("dns_tunnel", "dns_tunnel"),
    ("canary", "canary"),
    ("sweep", "sweep"),
    ("vt_ip_malicious", "malware"),
    ("honeypot_session", "recon"),
]

MINING_PORTS = {3333, 4444, 5555, 7777, 8888, 9999, 14433, 14444, 14444}
KNOWN_C2_PORTS = {4443, 5555, 8443, 8081, 1337, 4444, 31337, 6666, 6667}


def _looks_ip(v) -> bool:
    return isinstance(v, str) and bool(_IP_RE.match(v))


class TrafficAnalyzer:
    """Aggregates all evidence sources into per-IP flow + vector profiles.

    One instance lives on the webui; results are cached for `cache_seconds`
    so the map can poll freely without rescanning the event log each time.
    """

    def __init__(self, webui=None, cache_seconds=5.0):
        self.webui = webui
        self.cache_seconds = cache_seconds
        self._cache = None
        self._cache_ts = 0.0
        self._rate_prev = {}   # ip -> (ts, bytes_in, bytes_out)
        self._pub_ip = None
        self._pub_ip_ts = 0.0

    # ------------------------------------------------------------------ public
    def snapshot(self, force=False) -> dict:
        now = time.time()
        if not force and self._cache and now - self._cache_ts < self.cache_seconds:
            return self._cache
        self._cache = self._build()
        self._cache_ts = now
        return self._cache

    # ------------------------------------------------------------------ pieces
    def _server_public_ip(self):
        """Best-effort public IP of this server (cached 10 min)."""
        now = time.time()
        if self._pub_ip and now - self._pub_ip_ts < 600:
            return self._pub_ip
        try:
            import urllib.request
            req = urllib.request.Request("https://api.ipify.org", headers={"User-Agent": "SentinelFW/3"})
            with urllib.request.urlopen(req, timeout=4) as resp:
                ip = resp.read().decode("utf-8", "replace").strip()
            if _looks_ip(ip):
                self._pub_ip, self._pub_ip_ts = ip, now
                return ip
        except Exception:
            pass
        return None

    def _flows_from_conntrack(self, flows, apps):
        ct = getattr(self.webui, "conntrack", None)
        if not ct:
            return
        engine = getattr(self.webui, "engine", None)
        local = set()
        try:
            if engine:
                local = {str(i) for i in engine.guard.local}
        except Exception:
            pass
        for c in ct.get_active() + ct.get_history(limit=300):
            raddr = c.get("raddr") or ""
            if not raddr or raddr in local:
                continue
            f = flows[raddr]
            f["bytes_in"] += int(c.get("bytes_in") or 0)
            f["bytes_out"] += int(c.get("bytes_out") or 0)
            f["connections"] += 1
            f["last_seen"] = max(f["last_seen"], c.get("last_seen") or 0)
            f["proto"] = (c.get("proto") or "").lower() or f["proto"]
            if c.get("rport"):
                f["ports"].add(int(c["rport"]))
            exe = (c.get("exe") or "").strip()
            if exe:
                name = exe.replace("\\", "/").rsplit("/", 1)[-1]
                if name:
                    apps[raddr].add(name)

    def _flows_from_packets(self, flows, apps):
        engine = getattr(self.webui, "engine", None)
        rec = getattr(engine, "recorder", None) if engine else None
        if rec is None:
            return
        local = set()
        try:
            if engine:
                local = {str(i) for i in engine.guard.local}
        except Exception:
            pass
        for p in rec.query(limit=4000):
            d = p.get("direction")
            remote = p.get("dst") if d == "out" else p.get("src")
            if not remote or remote in local:
                continue
            f = flows[remote]
            ln = int(p.get("length") or 0)
            if d == "out":
                f["bytes_out"] += ln
            else:
                f["bytes_in"] += ln
            f["packets"] += 1
            f["last_seen"] = max(f["last_seen"], p.get("ts") or 0)
            port = p.get("dport") if d == "out" else p.get("dport")
            if d == "in":
                # inbound: the remote is probing OUR ports — track local dports
                port = p.get("dport")
            if port:
                f["ports"].add(int(port))
            proto = (p.get("protocol") or "").upper()
            if proto:
                f["protos"][proto] = f["protos"].get(proto, 0) + 1
            # application-layer intelligence
            lay = p.get("layers") or {}
            if isinstance(lay, dict):
                dns = lay.get("dns") or {}
                for q in (dns.get("questions") or [])[:3]:
                    if isinstance(q, str) and q:
                        f["dns"].add(q.split(",")[0][:80])
                tls = lay.get("tls") or {}
                sni = tls.get("sni")
                if sni:
                    f["sni"].add(sni[:80])
                http = lay.get("http") or {}
                rl = http.get("request_line")
                if rl:
                    f["http"].add(str(rl)[:100])
            raw_flags = p.get("flags")
            if isinstance(raw_flags, int):
                flags = "".join(nm for bit, nm in ((1, "F"), (2, "S"), (4, "R"), (8, "P"), (16, "A"), (32, "U")) if raw_flags & bit)
            else:
                flags = str(raw_flags or "")
            if d == "in":
                f["flags_in"] += 1
                if "S" in flags and "A" not in flags:
                    f["syn_only"] += 1
                if "R" in flags:
                    f["rst"] += 1
            if ln and ln <= 64:
                f["small_pkts"] += 1
            ts = p.get("ts") or 0
            if d == "in":
                f["arrivals"].append(ts)
            if int(p.get("dport") or 0) in MINING_PORTS or int(p.get("sport") or 0) in MINING_PORTS:
                f["mining_hits"] += 1

    def _events_by_ip(self):
        """Reads the recent event log and attributes events to IPs."""
        out = defaultdict(lambda: defaultdict(int))
        kinds_by_ip = defaultdict(set)
        path = LOGS / "events.jsonl"
        try:
            if path.exists():
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    lines = fh.readlines()[-600:]
                for line in lines:
                    try:
                        evt = json.loads(line)
                    except Exception:
                        continue
                    kind = str(evt.get("kind") or "")
                    ips = set()
                    for key in ("ip", "src", "remote", "attacker", "host", "peer"):
                        v = evt.get(key)
                        if _looks_ip(v):
                            ips.add(v)
                    if not ips and evt.get("data"):
                        data = evt.get("data")
                        if isinstance(data, dict):
                            for key in ("ip", "src", "remote", "attacker", "host", "peer"):
                                v = data.get(key)
                                if _looks_ip(v):
                                    ips.add(v)
                    for ip in ips:
                        out[ip][kind] += 1
                        kinds_by_ip[ip].add(kind)
        except OSError:
            pass
        return kinds_by_ip

    def _honeypot_by_ip(self):
        hp = getattr(self.webui, "honeypot", None)
        out = defaultdict(lambda: {"services": set(), "creds": 0, "commands": 0})
        if not hp:
            return out
        try:
            for s in hp.get_sessions(limit=400):
                ip = s.get("src_ip")
                if not _looks_ip(ip):
                    continue
                rec = out[ip]
                rec["services"].add(s.get("service") or "?")
                rec["creds"] += len(s.get("credentials") or [])
                rec["commands"] += len(s.get("commands") or [])
        except Exception:
            pass
        return out

    # ------------------------------------------------------------------ build
    def _build(self) -> dict:
        flows = defaultdict(lambda: {
            "bytes_in": 0, "bytes_out": 0, "packets": 0, "connections": 0,
            "last_seen": 0.0, "proto": "", "ports": set(), "protos": {},
            "dns": set(), "sni": set(), "http": set(),
            "syn_only": 0, "flags_in": 0, "rst": 0, "small_pkts": 0,
            "arrivals": [], "mining_hits": 0,
        })
        apps = defaultdict(set)
        self._flows_from_conntrack(flows, apps)
        self._flows_from_packets(flows, apps)

        event_kinds = self._events_by_ip()
        honeypots = self._honeypot_by_ip()
        bans = {}
        engine = getattr(self.webui, "engine", None)
        if engine:
            try:
                bans = {ip: b.get("reason", "") for ip, b in engine.store.bans.items()}
            except Exception:
                bans = {}
        vt_cache = {}
        intel = getattr(engine, "intel", None) if engine else None
        if intel:
            try:
                with intel.lock:
                    vt_cache = dict(intel._cache)
            except Exception:
                vt_cache = {}

        now = time.time()
        prev = self._rate_prev
        self._rate_prev = {}

        vectors_out = {}
        flow_list = []
        for ip, f in flows.items():
            # live rate via snapshot deltas
            bi, bo = f["bytes_in"], f["bytes_out"]
            rate_in = rate_out = 0.0
            p = prev.get(ip)
            if p and now - p[0] >= 0.5:
                rate_in = max(0.0, (bi - p[1]) / (now - p[0]))
                rate_out = max(0.0, (bo - p[2]) / (now - p[0]))
            self._rate_prev[ip] = (now, bi, bo)

            vecs = self._vectors_for(ip, f, event_kinds.get(ip, set()),
                                     honeypots.get(ip), bans.get(ip), vt_cache.get(ip))
            risk = min(100, sum(VECTORS[v["type"]][1] for v in vecs))

            flow_list.append({
                "ip": ip,
                "bytes_in": bi, "bytes_out": bo,
                "rate_in": round(rate_in, 1), "rate_out": round(rate_out, 1),
                "packets": f["packets"], "connections": f["connections"],
                "last_seen": f["last_seen"],
                "proto": f["proto"],
                "ports": sorted(f["ports"])[:10],
                "protos": dict(sorted(f["protos"].items(), key=lambda kv: -kv[1])[:6]),
                "dns": sorted(f["dns"])[:4],
                "sni": sorted(f["sni"])[:4],
                "http": sorted(f["http"])[:3],
                "apps": sorted(apps.get(ip, []))[:6],
                "risk": risk,
                "vectors": vecs,
            })
            if vecs:
                vectors_out[ip] = {"vectors": vecs, "risk": risk}

        flow_list.sort(key=lambda x: -(x["bytes_in"] + x["bytes_out"]))

        # aggregate summary
        summary = defaultdict(int)
        for v in vectors_out.values():
            for vec in v["vectors"]:
                summary[vec["type"]] += 1

        return {
            "server_ip": self._server_public_ip(),
            "flows": flow_list,
            "vectors": vectors_out,
            "summary": dict(sorted(summary.items(), key=lambda kv: -kv[1])),
        }

    # ------------------------------------------------------------------ vectors
    @staticmethod
    def _beacon_interval(ts_list):
        """Returns (mean, jitter_ratio) of arrival gaps if enough samples."""
        ts = sorted(t for t in ts_list if t)
        if len(ts) < 5:
            return None
        gaps = [b - a for a, b in zip(ts, ts[1:]) if 0 < b - a < 3600]
        if len(gaps) < 4:
            return None
        mean = sum(gaps) / len(gaps)
        if mean < 0.5 or mean > 600:
            return None
        var = sum((g - mean) ** 2 for g in gaps) / len(gaps)
        jitter = math.sqrt(var) / mean
        return mean, jitter

    def _vectors_for(self, ip, f, ev_kinds, hp, ban_reason, vt_rec):
        vecs = []

        def add(vtype, evidence):
            label, weight, sev = VECTORS[vtype]
            vecs.append({"type": vtype, "label": label, "severity": sev, "evidence": evidence})

        # --- packet-derived -------------------------------------------------
        in_pkts = f["flags_in"]
        if len(f["ports"]) >= 12:
            add("port_scan", f"{len(f['ports'])} distinct local ports touched in the capture window")
        if in_pkts >= 8 and f["syn_only"] / max(1, in_pkts) > 0.7:
            add("syn_scan", f"{f['syn_only']}/{in_pkts} inbound packets are bare SYN probes (no ACK)")
        if in_pkts >= 20 and f["small_pkts"] >= in_pkts * 1.5:
            add("ddos", f"{f['small_pkts']} tiny (<64B) packets — flood-like traffic shape")
        if f["mining_hits"] >= 2:
            add("mining", "traffic to known stratum/mining pool ports (3333/4444/5555/…)")
        beacon = self._beacon_interval(f["arrivals"])
        if beacon and beacon[1] < 0.35:
            m, j = beacon
            add("beacon", f"regular callback every {m:.0f}s ± {j * m:.1f}s (jitter {j * 100:.0f}%)")
        elif beacon and beacon[1] < 0.6 and sum(1 for _ in f["sni"]) == 0:
            m, j = beacon
            add("suspicious", f"metronomic traffic every {m:.0f}s without TLS SNI")

        # --- event-derived --------------------------------------------------
        for kind in ev_kinds:
            for frag, vtype in _EVENT_VECTORS:
                if frag in kind:
                    add(vtype, f"IDS event '{kind}' fired for this host")
                    break

        # --- honeypot -------------------------------------------------------
        if hp:
            svcs = ", ".join(sorted(hp["services"]))
            if hp["creds"]:
                add("brute_force", f"{hp['creds']} credential attempts against honeypot ({svcs})")
            elif hp["commands"]:
                add("recon", f"probed honeypot {svcs} with {hp['commands']} commands")
            else:
                add("recon", f"connected to honeypot {svcs}")

        # --- ban reason -----------------------------------------------------
        br = (ban_reason or "").lower()
        if "scan" in br:
            add("port_scan", f"previously banned: {ban_reason}")
        elif "brute" in br or "auth" in br:
            add("brute_force", f"previously banned: {ban_reason}")
        elif "flood" in br:
            add("ddos", f"previously banned: {ban_reason}")
        elif "signature" in br or "exploit" in br:
            add("exploit", f"previously banned: {ban_reason}")
        elif br and not vecs:
            add("suspicious", f"banned: {ban_reason}")

        # --- VirusTotal -----------------------------------------------------
        if vt_rec and int(vt_rec.get("malicious") or 0) > 0:
            add("malware", f"VirusTotal: {vt_rec['malicious']} engines flag this IP"
                           f"{' — ' + str(vt_rec.get('as_owner')) if vt_rec.get('as_owner') else ''}")

        # dedupe by type keeping the most detailed evidence
        seen = {}
        for v in vecs:
            cur = seen.get(v["type"])
            if cur is None or len(v["evidence"]) > len(cur["evidence"]):
                seen[v["type"]] = v
        return sorted(seen.values(), key=lambda v: -VECTORS[v["type"]][1])
