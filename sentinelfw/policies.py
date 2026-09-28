"""SentinelFW Firewall Policy engine — FortiGate-style policy management.

Policies are ordered, first-match 5-tuple rules stored in config.json under
"firewall_policies" and enforced by the platform firewall backend:

* Linux: compiled into an nftables table (inet sentinelfw_pol) with per-policy
  counters, so hit counts are real kernel counters.
* Windows: compiled into Windows Defender Firewall rules (SentinelFW-POL-*).

Each policy:
    id, name, enabled, action (accept|deny), direction (in|out|both),
    src (list of IP/CIDR or ["any"]), dst (same), services (list of service
    object names), log, nat, schedule ("always"), profiles (display-only),
    created (timestamp)

The default policy of the compiled chain is ACCEPT so a misconfigured rule
set can never lock a server out; explicit deny rules do the blocking.
"""
import ipaddress
import threading
import time
from .common import event, run

# ---------------------------------------------------------------------------
# Service objects (name -> list of (proto, port_min, port_max))
# ---------------------------------------------------------------------------
SERVICE_OBJECTS = {
    "ANY": [],
    "PING": [("icmp", 0, 0)],
    "HTTP": [("tcp", 80, 80)],
    "HTTPS": [("tcp", 443, 443)],
    "DNS": [("tcp", 53, 53), ("udp", 53, 53)],
    "SSH": [("tcp", 22, 22)],
    "FTP": [("tcp", 21, 21)],
    "SFTP": [("tcp", 22, 22)],
    "NTP": [("udp", 123, 123)],
    "SNMP": [("udp", 161, 162)],
    "SMTP": [("tcp", 25, 25)],
    "SMTPS": [("tcp", 465, 465)],
    "IMAP": [("tcp", 143, 143)],
    "IMAPS": [("tcp", 993, 993)],
    "POP3": [("tcp", 110, 110)],
    "POP3S": [("tcp", 995, 995)],
    "RDP": [("tcp", 3389, 3389)],
    "MYSQL": [("tcp", 3306, 3306)],
    "MSSQL": [("tcp", 1433, 1434)],
    "POSTGRESQL": [("tcp", 5432, 5432)],
    "SMB": [("tcp", 445, 445), ("tcp", 139, 139)],
    "LDAP": [("tcp", 389, 389)],
    "LDAPS": [("tcp", 636, 636)],
    "SIP": [("udp", 5060, 5061), ("tcp", 5060, 5061)],
    "VPN-IPSEC": [("udp", 500, 500), ("udp", 4500, 4500)],
    "VPN-WIREGUARD": [("udp", 51820, 51820)],
    "SENTINELFW-WEB": [("tcp", 443, 443)],
}

PROFILE_CATALOG = [
    {"id": "av", "name": "AntiVirus", "default": "g-default"},
    {"id": "web", "name": "Web Filter", "default": "g-default"},
    {"id": "dns", "name": "DNS Filter", "default": "default"},
    {"id": "app", "name": "Application Control", "default": "g-default"},
    {"id": "ips", "name": "IPS", "default": "g-default"},
    {"id": "ssl", "name": "SSL Inspection", "default": "certificate-inspection"},
]

VALID_ACTIONS = ("accept", "deny")
VALID_DIRECTIONS = ("in", "out", "both")


def _norm_addr_list(items):
    """Normalizes ['any'] / [] to None (no filter); validates and returns a
    list of (version, ip_network) tuples for matching."""
    if not items:
        return None
    if any(str(i).strip().lower() == "any" for i in items):
        return None
    nets = []
    for raw in items:
        try:
            if "/" in str(raw):
                nets.append(ipaddress.ip_network(str(raw).strip(), strict=False))
            else:
                nets.append(ipaddress.ip_network(str(raw).strip() + "/32" if "." in str(raw) else str(raw).strip() + "/128", strict=False))
        except ValueError:
            continue
    return nets or None


class FirewallPolicies:
    """Ordered CRUD policy manager with backend compilation."""

    def __init__(self, cfg=None, engine=None, config_persist=None):
        self._cfg = cfg if isinstance(cfg, dict) else {}
        self.engine = engine
        self._persist = config_persist
        self.lock = threading.RLock()

    @property
    def raw(self) -> list:
        pols = self._cfg.get("firewall_policies")
        if not isinstance(pols, list):
            pols = []
            self._cfg["firewall_policies"] = pols
        return pols

    def _save(self):
        if self._persist:
            try:
                self._persist(self._cfg)
            except Exception:
                pass

    # ------------------------------------------------------------------ CRUD
    def list(self, include_hits=False) -> list:
        with self.lock:
            out = []
            hits = self.hits() if include_hits else {}
            for i, p in enumerate(self.raw, start=1):
                q = dict(p)
                q["position"] = i
                q.setdefault("enabled", True)
                q.setdefault("action", "deny")
                q.setdefault("direction", "both")
                q.setdefault("src", ["any"])
                q.setdefault("dst", ["any"])
                q.setdefault("services", ["ANY"])
                q.setdefault("log", True)
                q.setdefault("nat", False)
                q.setdefault("profiles", {})
                q["hits"] = hits.get(str(p.get("id")), 0) if include_hits else None
                out.append(q)
            return out

    def _validate(self, data: dict, partial: bool = False) -> dict:
        clean = {}
        if not partial or "name" in data:
            clean["name"] = str(data.get("name") or f"Policy-{int(time.time())}").strip()[:64]
        if not partial or "action" in data:
            clean["action"] = str(data.get("action") or "deny").lower()
            if clean["action"] not in VALID_ACTIONS:
                clean["action"] = "deny"
        if not partial or "direction" in data:
            clean["direction"] = str(data.get("direction") or "both").lower()
            if clean["direction"] not in VALID_DIRECTIONS:
                clean["direction"] = "both"
        for key in ("src", "dst"):
            if not partial or key in data:
                val = data.get(key) or ["any"]
                if isinstance(val, str):
                    val = [v.strip() for v in val.replace(";", ",").split(",") if v.strip()]
                clean[key] = [str(v).strip() for v in val][:16] or ["any"]
        if not partial or "services" in data:
            val = data.get("services") or ["ANY"]
            if isinstance(val, str):
                val = [val]
            clean["services"] = [str(s).upper() for s in val if str(s).upper() in SERVICE_OBJECTS] or ["ANY"]
        if not partial or "log" in data:
            clean["log"] = bool(data.get("log", True))
        if not partial or "nat" in data:
            clean["nat"] = bool(data.get("nat", False))
        if not partial or "enabled" in data:
            clean["enabled"] = bool(data.get("enabled", True))
        if not partial or "profiles" in data:
            prof = data.get("profiles") or {}
            clean["profiles"] = {str(k): str(v)[:40] for k, v in prof.items()
                                 if str(k) in {p["id"] for p in PROFILE_CATALOG}}
        return clean

    def add(self, data: dict) -> dict:
        with self.lock:
            pol = self._validate(data)
            existing = self.raw
            pol["id"] = max([int(p.get("id", 0)) for p in existing], default=0) + 1
            pol["created"] = time.time()
            existing.append(pol)
            self._save()
            self.apply()
            event("policy_added", "info", id=pol["id"], name=pol["name"], action=pol["action"])
            return pol

    def update(self, pol_id: int, data: dict) -> dict:
        with self.lock:
            for i, p in enumerate(self.raw):
                if int(p.get("id", -1)) == int(pol_id):
                    p.update(self._validate(data, partial=True))
                    self._save()
                    self.apply()
                    event("policy_updated", "info", id=pol_id)
                    return p
            return {"error": f"policy {pol_id} not found"}

    def delete(self, pol_id: int) -> dict:
        with self.lock:
            for i, p in enumerate(self.raw):
                if int(p.get("id", -1)) == int(pol_id):
                    name = p.get("name")
                    del self.raw[i]
                    self._save()
                    self.apply()
                    event("policy_deleted", "info", id=pol_id, name=name)
                    return {"deleted": pol_id, "name": name}
            return {"error": f"policy {pol_id} not found"}

    def reorder(self, pol_id: int, up: bool = True) -> dict:
        with self.lock:
            raw = self.raw
            for i, p in enumerate(raw):
                if int(p.get("id", -1)) == int(pol_id):
                    j = i - 1 if up else i + 1
                    if 0 <= j < len(raw):
                        raw[i], raw[j] = raw[j], raw[i]
                        self._save()
                        self.apply()
                        return {"moved": pol_id, "from": i + 1, "to": j + 1}
                    return {"error": "already at edge"}
            return {"error": f"policy {pol_id} not found"}

    def toggle(self, pol_id: int) -> dict:
        with self.lock:
            for p in self.raw:
                if int(p.get("id", -1)) == int(pol_id):
                    p["enabled"] = not bool(p.get("enabled", True))
                    self._save()
                    self.apply()
                    event("policy_toggled", "info", id=pol_id, enabled=p["enabled"])
                    return p
            return {"error": f"policy {pol_id} not found"}

    # ------------------------------------------------------------- enforcement
    def apply(self) -> bool:
        """Pushes the compiled policy set into the OS firewall backend."""
        eng = self.engine
        if eng is None or getattr(eng, "backend", None) is None:
            return False
        try:
            ok = eng.backend.sync_policies(self.list())
            return bool(ok)
        except Exception as e:  # noqa: BLE001
            event("policy_apply_error", "high", error=str(e)[:300])
            return False

    # Linux-only hit counters read from nftables
    _hits_cache: dict = {}
    _hits_ts: float = 0.0

    def hits(self) -> dict:
        """Per-policy packet counters (Linux/nftables only, cached 5s)."""
        now = time.time()
        if now - self._hits_ts < 5:
            return self._hits_cache
        self._hits_ts = now
        hits = {}
        try:
            for chain in ("input", "output", "forward"):
                rc, out, _ = run(["nft", "list", "chain", "inet", "sentinelfw_pol", chain])
                if rc != 0:
                    continue
                for line in out.splitlines():
                    line = line.strip()
                    if "comment" not in line or "counter" not in line:
                        continue
                    try:
                        pkts = int(line.split("packets")[1].split()[0])
                        cid = line.split("comment")[1].strip().strip('"').split()[0]
                        pid = cid.split("-")[-1] if cid.startswith("pol-") else ""
                        hits[pid] = hits.get(pid, 0) + pkts
                    except (IndexError, ValueError):
                        continue
        except Exception:
            pass
        self._hits_cache = hits
        return hits


# ---------------------------------------------------------------------------
# Backend compilers
# ---------------------------------------------------------------------------

def _nft_rule(chains, pol, src_nets, dst_nets, service_flows):
    """Generates one nftables rule per (chain, family, service-flow) for a policy."""
    rules = []
    action = "accept" if pol["action"] == "accept" else "drop"
    comment = f'comment "pol-{pol["id"]}"'
    for chain in chains:
        for fam in ("ip", "ip6"):
            srcs = [str(n) for n in (src_nets or []) if (n.version == 6) == (fam == "ip6")]
            dsts = [str(n) for n in (dst_nets or []) if (n.version == 6) == (fam == "ip6")]
            if src_nets is not None and not srcs:
                continue  # source filtered to the other family
            if dst_nets is not None and not dsts:
                continue
            cond = ""
            if srcs:
                cond += f"{fam} saddr {{ {', '.join(srcs)} }} "
            if dsts:
                cond += f"{fam} daddr {{ {', '.join(dsts)} }} "
            for proto, pmin, pmax in service_flows:
                pcond = cond
                if proto == "icmp":
                    pcond += "meta l4proto icmp "
                else:
                    port = f"{pmin}" if pmin == pmax else f"range {pmin}-{pmax}"
                    pcond += f"{proto} dport {port} "
                rules.append(f"add rule inet sentinelfw_pol {chain} {pcond}counter {action} {comment}")
    return rules


def compile_nft(policies) -> str:
    """Compiles an ordered policy list into an nftables program."""
    L = ["add table inet sentinelfw_pol", "delete table inet sentinelfw_pol",
         "add table inet sentinelfw_pol"]
    for ch in ("input", "output", "forward"):
        L.append(f"add chain inet sentinelfw_pol {ch} {{ type filter hook {ch} priority -5; policy accept; }}")
    for pol in policies:
        if not pol.get("enabled", True):
            continue
        src_nets = _norm_addr_list(pol.get("src"))
        dst_nets = _norm_addr_list(pol.get("dst"))
        flows = []
        for svc in pol.get("services") or ["ANY"]:
            flows.extend(SERVICE_OBJECTS.get(str(svc).upper(), []))
        if not flows:  # ANY
            flows = [("tcp", 0, 65535), ("udp", 0, 65535), ("icmp", 0, 0)]
        chains = []
        d = pol.get("direction", "both")
        if d in ("in", "both"):
            chains.append("input")
        if d in ("out", "both"):
            chains.append("output")
        chains.append("forward")
        L.extend(_nft_rule(chains, pol, src_nets, dst_nets, flows))
    return "\n".join(L) + "\n"


def compile_windows(policies) -> dict:
    """Compiles policies into a {rule_name: spec} dict for WinBackend."""
    want = {}
    for pol in policies:
        if not pol.get("enabled", True):
            continue
        srcs = [str(v).strip() for v in (pol.get("src") or ["any"])
                if str(v).strip().lower() != "any"]
        dsts = [str(v).strip() for v in (pol.get("dst") or ["any"])
                if str(v).strip().lower() != "any"]
        flows = []
        for svc in pol.get("services") or ["ANY"]:
            flows.extend(SERVICE_OBJECTS.get(str(svc).upper(), []))
        if not flows:
            flows = [("tcp", 0, 65535), ("udp", 0, 65535), ("icmp", 0, 0)]
        # group ports per protocol
        by_proto = {}
        for proto, pmin, pmax in flows:
            if proto == "icmp":
                by_proto.setdefault("ICMPv4", []).append((0, 0))
            else:
                by_proto.setdefault(proto.upper(), []).append((pmin, pmax))
        d = pol.get("direction", "both")
        directions = []
        if d in ("in", "both"):
            directions.append("in")
        if d in ("out", "both"):
            directions.append("out")
        for dr in directions:
            remote = ",".join(srcs if dr == "in" else dsts)
            for proto, ports in by_proto.items():
                spec = {"dir": dr, "action": "allow" if pol["action"] == "accept" else "block",
                        "protocol": proto, "policy_id": pol["id"], "policy_name": pol.get("name", "")}
                if remote:
                    spec["remoteip"] = remote
                plist = sorted({p for pmin, pmax in ports for p in range(pmin, pmax + 1)} - {0})
                if proto != "ICMPv4" and plist:
                    if len(plist) > 60:  # netsh gets unwieldy; fall back to any-port
                        continue
                    spec["localport" if dr == "in" else "remoteport"] = ",".join(str(p) for p in plist)
                name = f"SentinelFW-POL-{pol['id']}-{proto}-{dr}"
                want[name] = spec
    return want


def service_catalog() -> list:
    return [{"name": k, "flows": [{"proto": f[0], "port_min": f[1], "port_max": f[2]} for f in v]}
            for k, v in SERVICE_OBJECTS.items()]
