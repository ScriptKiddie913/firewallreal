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
import re
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple
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
    "SENTINELFW-WEB": [("tcp", 9443, 9444)],
}

PROFILE_CATALOG = [
    {"id": "av", "name": "AntiVirus", "default": "g-default"},
    {"id": "web", "name": "Web Filter", "default": "g-default"},
    {"id": "dns", "name": "DNS Filter", "default": "default"},
    {"id": "app", "name": "Application Control", "default": "g-default"},
    {"id": "ips", "name": "IPS", "default": "g-default"},
    {"id": "ssl", "name": "SSL Inspection", "default": "certificate-inspection"},
]

VALID_ACTIONS = ("accept", "deny", "reject", "log", "rate_limit", "quarantine", "redirect", "inspect", "challenge", "tarpit", "decoy", "divert")
VALID_DIRECTIONS = ("in", "out", "both")


def is_schedule_active(schedule, at_time=None) -> bool:
    """Checks whether the policy rule is currently active according to its schedule."""
    if not schedule or schedule == "always":
        return True
    if at_time is not None:
        now = time.localtime(at_time) if isinstance(at_time, (int, float)) else at_time
    else:
        now = time.localtime()
    if isinstance(schedule, dict):
        days = schedule.get("days")
        if days:
            day_map = {0: "mon", 1: "tue", 2: "wed", 3: "thu", 4: "fri", 5: "sat", 6: "sun"}
            cur_day = day_map.get(now.tm_wday)
            clean_days = [d.lower()[:3] for d in days]
            if cur_day not in clean_days:
                return False
        start = schedule.get("start")
        end = schedule.get("end")
        if start and end:
            cur_time = f"{now.tm_hour:02d}:{now.tm_min:02d}"
            if not (start <= cur_time <= end):
                return False
    return True


_FQDN_CACHE = {}
_FQDN_LOCK = threading.Lock()


def resolve_fqdn(hostname: str, ttl: int = 60) -> list:
    """Resolves an FQDN to IP strings with TTL caching."""
    clean_host = hostname.strip().lower()
    now = time.time()
    with _FQDN_LOCK:
        if clean_host in _FQDN_CACHE:
            cached_ips, exp = _FQDN_CACHE[clean_host]
            if now < exp:
                return list(cached_ips)
    try:
        import socket
        res = socket.getaddrinfo(clean_host, None)
        ips = list({r[4][0] for r in res})
    except Exception:
        ips = []
    with _FQDN_LOCK:
        _FQDN_CACHE[clean_host] = (ips, now + ttl)
    return ips


def _norm_addr_list(items, address_groups=None):
    """Normalizes ['any'] / [] to None (no filter); expands address groups
    and FQDNs; validates and returns a list of ip_network objects for matching."""
    if not items:
        return None
    if any(str(i).strip().lower() == "any" for i in items):
        return None
    expanded = []
    groups = address_groups or {}
    for raw in items:
        raw_str = str(raw).strip()
        # Address group lookup (e.g. "DMZ" or "@DMZ")
        group_key = raw_str[1:] if raw_str.startswith("@") else raw_str
        if group_key in groups and isinstance(groups[group_key], list):
            expanded.extend(groups[group_key])
        elif any(c.isalpha() for c in raw_str) and not (":" in raw_str):
            # Potential FQDN
            resolved = resolve_fqdn(raw_str)
            if resolved:
                expanded.extend(resolved)
            else:
                expanded.append(raw_str)
        else:
            expanded.append(raw_str)

    nets = []
    for raw in expanded:
        try:
            val = str(raw).strip()
            if "/" in val:
                nets.append(ipaddress.ip_network(val, strict=False))
            else:
                nets.append(ipaddress.ip_network(val + "/32" if "." in val else val + "/128", strict=False))
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
    def cfg(self) -> dict:
        return self._cfg

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

    # -------------------------------------------------------- Address Groups
    def get_address_groups(self) -> dict:
        with self.lock:
            return dict(self._cfg.get("address_groups", {}))

    def set_address_group(self, name: str, members: list) -> dict:
        with self.lock:
            clean_name = str(name).strip()[:64]
            if not clean_name:
                return {"error": "Invalid group name"}
            groups = self._cfg.setdefault("address_groups", {})
            groups[clean_name] = [str(m).strip() for m in members if str(m).strip()]
            self._save()
            return {"name": clean_name, "members": groups[clean_name]}

    def delete_address_group(self, name: str) -> dict:
        with self.lock:
            groups = self._cfg.get("address_groups", {})
            if name in groups:
                del groups[name]
                self._save()
                return {"deleted": name}
            return {"error": f"group {name} not found"}

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
                q.setdefault("src_countries", [])
                q.setdefault("dst_countries", [])
                q.setdefault("schedule", "always")
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
        for ckey in ("src_countries", "dst_countries"):
            if not partial or ckey in data:
                cval = data.get(ckey) or []
                if isinstance(cval, str):
                    cval = [c.strip().upper() for c in cval.replace(";", ",").split(",") if c.strip()]
                clean[ckey] = [str(c).strip().upper()[:2] for c in cval if len(str(c).strip()) == 2]
        if not partial or "schedule" in data:
            sval = data.get("schedule") or "always"
            clean["schedule"] = sval if isinstance(sval, (str, dict)) else "always"
        for ikey in ("users", "groups", "apps"):
            if not partial or ikey in data:
                ival = data.get(ikey) or []
                if isinstance(ival, str):
                    ival = [x.strip() for x in ival.replace(";", ",").split(",") if x.strip()]
                clean[ikey] = [str(x).strip() for x in ival]
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

    # ------------------------------------------------------------- commit-confirm
    _staged_changes: list = []
    _rollback_timer = None
    _pending_rollback_snapshot = None

    def stage(self, action: str, data: dict = None, pol_id: int = None) -> dict:
        """Stages a policy modification without applying immediately."""
        with self.lock:
            if not hasattr(self, "_staged"):
                self._staged = []
            clean_item = {
                "action": str(action).lower(),
                "id": pol_id,
                "data": self._validate(data, partial=(action == "update")) if data else {},
                "staged_at": time.time(),
            }
            self._staged.append(clean_item)
            return {"status": "staged", "staged_count": len(self._staged)}

    def get_staged(self) -> list:
        with self.lock:
            return list(getattr(self, "_staged", []))

    def discard_staged(self) -> dict:
        with self.lock:
            count = len(getattr(self, "_staged", []))
            self._staged = []
            return {"discarded": count}

    def commit(self, timeout_seconds: int = 300, comment: str = "") -> dict:
        """Applies staged changes, creates version snapshot, and arms rollback timer."""
        with self.lock:
            staged = getattr(self, "_staged", [])
            if not staged:
                return {"error": "no staged changes to commit"}

            import copy
            self._pending_rollback_snapshot = copy.deepcopy(self.raw)

            for item in staged:
                act = item["action"]
                data = item.get("data", {})
                pid = item.get("id")
                if act == "add":
                    pol = dict(data)
                    pol["id"] = max([int(p.get("id", 0)) for p in self.raw], default=0) + 1
                    pol["created"] = time.time()
                    self.raw.append(pol)
                elif act == "update" and pid is not None:
                    for p in self.raw:
                        if int(p.get("id", -1)) == int(pid):
                            p.update(data)
                            break
                elif act == "delete" and pid is not None:
                    self.raw[:] = [p for p in self.raw if int(p.get("id", -1)) != int(pid)]

            self._staged = []
            self._save()
            self.apply()

            if getattr(self, "_rollback_timer", None):
                self._rollback_timer.cancel()
                self._rollback_timer = None

            if timeout_seconds > 0:
                self._rollback_timer = threading.Timer(timeout_seconds, self._auto_rollback)
                self._rollback_timer.daemon = True
                self._rollback_timer.start()

            event("policy_committed", "info", changes=len(staged), timeout=timeout_seconds, comment=comment)
            return {"status": "committed", "applied": len(staged), "confirm_timeout": timeout_seconds}

    def confirm(self) -> dict:
        """Confirms committed changes and cancels rollback timer."""
        with self.lock:
            if getattr(self, "_rollback_timer", None):
                self._rollback_timer.cancel()
                self._rollback_timer = None
            self._pending_rollback_snapshot = None
            event("policy_commit_confirmed", "info")
            return {"status": "confirmed"}

    def rollback(self) -> dict:
        """Rolls back to the pre-commit snapshot."""
        with self.lock:
            if getattr(self, "_rollback_timer", None):
                self._rollback_timer.cancel()
                self._rollback_timer = None
            if self._pending_rollback_snapshot is None:
                return {"error": "no pending rollback snapshot"}
            self._cfg["firewall_policies"] = self._pending_rollback_snapshot
            self._pending_rollback_snapshot = None
            self._save()
            self.apply()
            event("policy_rolled_back", "warning")
            return {"status": "rolled_back"}

    def _auto_rollback(self):
        with self.lock:
            if self._pending_rollback_snapshot is not None:
                event("policy_rollback_timeout", "warning", msg="Commit confirmation timed out; reverting")
                self.rollback()

    def diff(self) -> dict:
        """Returns comparison between active rules and staged changes."""
        with self.lock:
            return {
                "active_count": len(self.raw),
                "staged": list(getattr(self, "_staged", [])),
            }

    # ------------------------------------------------------------- Simulation & Diagnostics
    def simulate_packet(self, src_ip: str, dst_ip: str, proto: str, port: int,
                        direction: str = "in", src_country: str = None, dst_country: str = None,
                        user: str = None, groups: list = None, app: str = None,
                        device: str = None, posture: str = None, domain: str = None,
                        url_category: str = None, asn: int = None, threat_score: int = None,
                        ioc_match: bool = None, tenant_id: str = None,
                        timestamp: float = None, default_action: str = None) -> dict:
        """Simulates how the policy engine would evaluate an incoming or outgoing packet against canonical dimensions."""
        with self.lock:
            fallback_action = default_action or self.cfg.get("default_policy_action", "drop")
            addr_groups = self.get_address_groups()
            clean_proto = str(proto).lower()
            try:
                sip = ipaddress.ip_address(src_ip.strip())
            except ValueError:
                sip = None
            try:
                dip = ipaddress.ip_address(dst_ip.strip())
            except ValueError:
                dip = None

            now_ts = timestamp or time.time()
            for pol in self.raw:
                if not pol.get("enabled", True):
                    continue
                # 0. Expiration / TTL check
                ttl = pol.get("ttl")
                if ttl and now_ts > ttl:
                    continue
                # 0b. Tenant check
                if pol.get("tenant_id") and tenant_id and pol["tenant_id"] != tenant_id:
                    continue
                # 1. Schedule
                if not is_schedule_active(pol.get("schedule"), at_time=timestamp):
                    continue
                # 2. Direction
                pdir = pol.get("direction", "both")
                if pdir != "both" and pdir != direction:
                    continue
                # 3. Country checks
                sc_list = pol.get("src_countries") or []
                if sc_list and (not src_country or src_country.upper() not in sc_list):
                    continue
                dc_list = pol.get("dst_countries") or []
                if dc_list and (not dst_country or dst_country.upper() not in dc_list):
                    continue
                # 4. Source IP / Address Groups
                if sip:
                    snets = _norm_addr_list(pol.get("src"), address_groups=addr_groups)
                    if snets is not None and not any(sip in net for net in snets):
                        continue
                # 5. Destination IP / Address Groups
                if dip:
                    dnets = _norm_addr_list(pol.get("dst"), address_groups=addr_groups)
                    if dnets is not None and not any(dip in net for net in dnets):
                        continue
                # 6. Service / Port
                svcs = pol.get("services") or ["ANY"]
                if "ANY" not in svcs:
                    flows = []
                    for s in svcs:
                        flows.extend(SERVICE_OBJECTS.get(s, []))
                    matched_flow = False
                    for fproto, fmin, fmax in flows:
                        if fproto == clean_proto and (fmin == 0 and fmax == 0 or (fmin <= port <= fmax)):
                            matched_flow = True
                            break
                    if not matched_flow:
                        continue
                # 7. User / Group
                if pol.get("users") and user and user not in pol["users"]:
                    continue
                if pol.get("groups") and groups and not any(g in pol["groups"] for g in groups):
                    continue
                # 8. App
                if pol.get("apps") and app:
                    if app.upper() not in [a.upper() for a in pol["apps"]]:
                        continue
                # 9. Device & Posture
                if pol.get("devices"):
                    if not device or device not in pol["devices"]:
                        continue
                if pol.get("device_posture"):
                    if not posture or pol["device_posture"].upper() != posture.upper():
                        continue
                # 10. Domain & URL Category
                if pol.get("domains"):
                    if not domain or domain.lower() not in [d.lower() for d in pol["domains"]]:
                        continue
                if pol.get("url_categories"):
                    if not url_category or url_category.lower() not in [c.lower() for c in pol["url_categories"]]:
                        continue
                # 11. ASN
                if pol.get("asns"):
                    if asn is None or asn not in pol["asns"]:
                        continue
                # 12. Threat Score & IOC Match
                if pol.get("threat_score_min") is not None:
                    if threat_score is None or threat_score < pol["threat_score_min"]:
                        continue
                if pol.get("threat_score_max") is not None:
                    if threat_score is None or threat_score > pol["threat_score_max"]:
                        continue
                if pol.get("ioc_match") is True and not ioc_match:
                    continue

                return {
                    "matched": True,
                    "policy_id": pol.get("id"),
                    "policy_name": pol.get("name"),
                    "action": pol.get("action", "deny"),
                    "reason": f"Matched policy #{pol.get('id')} ({pol.get('name')})",
                    "policy": pol,
                }

            return {
                "matched": False,
                "policy_id": None,
                "policy_name": "Implicit Deny" if fallback_action in ("drop", "deny") else "Default Action",
                "action": fallback_action,
                "reason": f"Default policy: {fallback_action}",
            }

    def simulate(self, src_ip: str, dst_ip: str, port: int, proto: str = "tcp",
                 user: str = "", groups: list = None, app: str = "",
                 src_country: str = "", dst_country: str = "") -> dict:
        """FortiGate-grade policy simulation engine (Phase 46)."""
        res = self.simulate_packet(
            src_ip=src_ip, dst_ip=dst_ip, proto=proto, port=port,
            user=user, groups=groups, app=app,
            src_country=src_country, dst_country=dst_country
        )
        pol = res.get("policy") or {}
        nat_info = {
            "enabled": bool(pol.get("nat") or pol.get("nat_type")),
            "type": pol.get("nat_type", "masquerade") if (pol.get("nat") or pol.get("nat_type")) else "none",
            "target": pol.get("nat_target", "")
        }
        profiles = {
            "ips": bool(pol.get("ips") or pol.get("ips_profile")),
            "ips_profile": pol.get("ips_profile", "default") if (pol.get("ips") or pol.get("ips_profile")) else "disabled",
            "av": bool(pol.get("av") or pol.get("antivirus")),
            "web_filter": bool(pol.get("web_filter")),
            "dns_filter": bool(pol.get("dns_filter")),
            "tls_inspection": bool(pol.get("tls_inspection") or pol.get("ssl_inspection")),
            "dlp": bool(pol.get("dlp")),
            "logging": bool(pol.get("log") or pol.get("log_traffic")),
        }
        return {
            "matched": res["matched"],
            "policy_id": res["policy_id"],
            "policy_name": res["policy_name"],
            "action": res["action"].upper(),
            "reason": res["reason"],
            "packet": {
                "src_ip": src_ip, "dst_ip": dst_ip, "port": port, "proto": proto.upper(),
                "user": user or "anonymous", "app": app or "unknown",
            },
            "nat": nat_info,
            "security_profiles": profiles,
            "flow_path": "SLOW_PATH_INSPECTION" if any(profiles.values()) else ("FAST_PATH_OFFLOAD" if res["action"] == "accept" else "KERNEL_DROP"),
        }

    def find_shadowed_rules(self) -> list:
        """Detects policies that will never trigger because a previous broader rule supersedes them."""
        with self.lock:
            shadowed = []
            addr_groups = self.get_address_groups()
            active_pols = [p for p in self.raw if p.get("enabled", True)]
            for i, rule_b in enumerate(active_pols):
                b_src = _norm_addr_list(rule_b.get("src"), address_groups=addr_groups)
                b_dst = _norm_addr_list(rule_b.get("dst"), address_groups=addr_groups)
                b_svcs = set(rule_b.get("services") or ["ANY"])
                b_dir = rule_b.get("direction", "both")

                for rule_a in active_pols[:i]:
                    a_sched = rule_a.get("schedule", "always")
                    if a_sched != "always" and a_sched != rule_b.get("schedule"):
                        continue
                    a_dir = rule_a.get("direction", "both")
                    if a_dir != "both" and a_dir != b_dir:
                        continue
                    a_sc = set(rule_a.get("src_countries") or [])
                    b_sc = set(rule_b.get("src_countries") or [])
                    if a_sc and (not b_sc or not b_sc.issubset(a_sc)):
                        continue
                    a_dc = set(rule_a.get("dst_countries") or [])
                    b_dc = set(rule_b.get("dst_countries") or [])
                    if a_dc and (not b_dc or not b_dc.issubset(a_dc)):
                        continue
                    a_svcs = set(rule_a.get("services") or ["ANY"])
                    if "ANY" not in a_svcs and not b_svcs.issubset(a_svcs):
                        continue
                    a_src = _norm_addr_list(rule_a.get("src"), address_groups=addr_groups)
                    if a_src is not None:
                        if b_src is None:
                            continue
                        if not all(any(bn.subnet_of(an) for an in a_src) for bn in b_src):
                            continue
                    a_dst = _norm_addr_list(rule_a.get("dst"), address_groups=addr_groups)
                    if a_dst is not None:
                        if b_dst is None:
                            continue
                        if not all(any(bn.subnet_of(an) for an in a_dst) for bn in b_dst):
                            continue

                    shadowed.append({
                        "shadowed_id": rule_b.get("id"),
                        "shadowed_name": rule_b.get("name"),
                        "shadowed_by_id": rule_a.get("id"),
                        "shadowed_by_name": rule_a.get("name"),
                        "reason": f"Rule #{rule_a.get('id')} supersedes Rule #{rule_b.get('id')}",
                    })
                    break
            return shadowed

    def find_duplicate_rules(self) -> list:
        """Detects policies that have identical matching criteria and actions."""
        with self.lock:
            duplicates = []
            active_pols = [p for p in self.raw if p.get("enabled", True)]
            for i, a in enumerate(active_pols):
                for b in active_pols[i+1:]:
                    if (a.get("direction") == b.get("direction") and
                        set(a.get("src") or []) == set(b.get("src") or []) and
                        set(a.get("dst") or []) == set(b.get("dst") or []) and
                        set(a.get("services") or []) == set(b.get("services") or []) and
                        set(a.get("apps") or []) == set(b.get("apps") or []) and
                        a.get("action") == b.get("action")):
                        duplicates.append({
                            "rule_a_id": a.get("id"),
                            "rule_a_name": a.get("name"),
                            "rule_b_id": b.get("id"),
                            "rule_b_name": b.get("name"),
                            "reason": f"Rule #{b.get('id')} duplicates Rule #{a.get('id')}",
                        })
            return duplicates

    def find_conflicting_rules(self) -> list:
        """Detects policies that have identical matching criteria but contradictory actions."""
        with self.lock:
            conflicts = []
            active_pols = [p for p in self.raw if p.get("enabled", True)]
            for i, a in enumerate(active_pols):
                for b in active_pols[i+1:]:
                    if (a.get("direction") == b.get("direction") and
                        set(a.get("src") or []) == set(b.get("src") or []) and
                        set(a.get("dst") or []) == set(b.get("dst") or []) and
                        set(a.get("services") or []) == set(b.get("services") or []) and
                        set(a.get("apps") or []) == set(b.get("apps") or []) and
                        a.get("action") != b.get("action")):
                        conflicts.append({
                            "rule_a_id": a.get("id"),
                            "rule_a_name": a.get("name"),
                            "rule_a_action": a.get("action"),
                            "rule_b_id": b.get("id"),
                            "rule_b_name": b.get("name"),
                            "rule_b_action": b.get("action"),
                            "reason": f"Rule #{b.get('id')} ({b.get('action')}) conflicts with Rule #{a.get('id')} ({a.get('action')})",
                        })
            return conflicts


# ---------------------------------------------------------------------------
# Backend compilers
# ---------------------------------------------------------------------------

def _nft_rule(chains, pol, src_nets, dst_nets, service_flows):
    """Generates one nftables rule per (chain, family, service-flow) for a policy."""
    rules = []
    act = pol.get("action", "deny")
    action = "accept" if act == "accept" else ("reject" if act == "reject" else "drop")
    comment = f'comment "pol-{pol["id"]}"'
    in_itf = pol.get("in_interface") or pol.get("src_zone")
    out_itf = pol.get("out_interface") or pol.get("dst_zone")

    for chain in chains:
        for fam in ("ip", "ip6"):
            srcs = [str(n) for n in (src_nets or []) if (n.version == 6) == (fam == "ip6")]
            dsts = [str(n) for n in (dst_nets or []) if (n.version == 6) == (fam == "ip6")]
            if src_nets is not None and not srcs:
                continue  # source filtered to the other family
            if dst_nets is not None and not dsts:
                continue
            cond = ""
            if in_itf and in_itf != "any" and chain in ("input", "forward"):
                cond += f'iifname "{in_itf}" '
            if out_itf and out_itf != "any" and chain in ("output", "forward"):
                cond += f'oifname "{out_itf}" '
            if srcs:
                cond += f"{fam} saddr {{ {', '.join(srcs)} }} "
            elif pol.get("groups"):
                # Bind policy to dynamic identity group nft set
                clean_grps = [re.sub(r'[^a-zA-Z0-9_]', '_', g.lower()) for g in pol["groups"]]
                cond += f"{fam} saddr @identity_grp_{clean_grps[0]} "
            elif pol.get("users"):
                clean_usrs = [re.sub(r'[^a-zA-Z0-9_]', '_', u.lower()) for u in pol["users"]]
                cond += f"{fam} saddr @identity_usr_{clean_usrs[0]} "
            if dsts:
                cond += f"{fam} daddr {{ {', '.join(dsts)} }} "
            for proto, pmin, pmax in service_flows:
                pcond = cond
                if proto == "icmp":
                    pcond += "meta l4proto icmp "
                else:
                    port = f"{pmin}" if pmin == pmax else f"range {pmin}-{pmax}"
                    pcond += f"{proto} dport {port} "

                # Security Profile: NFQUEUE jump to Suricata inline IPS if enabled
                if pol.get("ips") or pol.get("ips_profile"):
                    pcond += "queue num 0-3 bypass "

                # Policy Logging
                if pol.get("log") or pol.get("log_traffic"):
                    pcond += f'log prefix "[SFW-POL-{pol["id"]}] " '

                rules.append(f"add rule inet sentinelfw_pol {chain} {pcond}counter {action} {comment}")
    return rules


def compile_nft(policies, address_groups=None) -> str:
    """Compiles an ordered policy list into an enterprise stateful nftables program with NAT and implicit deny."""
    L = ["add table inet sentinelfw_pol", "delete table inet sentinelfw_pol",
         "add table inet sentinelfw_pol"]

    # Dynamic identity sets for User-ID & FSSO Group enforcement (Phase 9/12)
    defined_id_sets = set()
    for pol in policies:
        if not pol.get("enabled", True):
            continue
        for grp in pol.get("groups", []):
            c_grp = re.sub(r'[^a-zA-Z0-9_]', '_', grp.lower())
            if c_grp not in defined_id_sets:
                defined_id_sets.add(c_grp)
                L.append(f"add set inet sentinelfw_pol identity_grp_{c_grp} {{ type ipv4_addr; flags timeout; }}")
        for usr in pol.get("users", []):
            c_usr = re.sub(r'[^a-zA-Z0-9_]', '_', usr.lower())
            if c_usr not in defined_id_sets:
                defined_id_sets.add(c_usr)
                L.append(f"add set inet sentinelfw_pol identity_usr_{c_usr} {{ type ipv4_addr; flags timeout; }}")

    # Base filter chains (Forward defaults to drop: FortiGate implicit deny)
    L.append("add chain inet sentinelfw_pol input { type filter hook input priority -5; policy accept; }")
    L.append("add chain inet sentinelfw_pol output { type filter hook output priority -5; policy accept; }")
    L.append("add chain inet sentinelfw_pol forward { type filter hook forward priority -5; policy drop; }")

    # Conntrack stateful rules: established/related accepted, invalid dropped
    for ch in ("input", "forward"):
        L.append(f"add rule inet sentinelfw_pol {ch} ct state established,related accept")
        L.append(f"add rule inet sentinelfw_pol {ch} ct state invalid drop")

    # Anti-lockout Priority-0 management rules on input
    L.append('add rule inet sentinelfw_pol input iifname "lo" accept')
    L.append("add rule inet sentinelfw_pol input tcp dport { 22, 443, 8443, 9443 } counter accept")
    L.append("add rule inet sentinelfw_pol input ip protocol icmp icmp type echo-request limit rate 10/second accept")

    # NAT table and chains
    has_nat = any(pol.get("nat") or pol.get("nat_type") for pol in policies if pol.get("enabled", True))
    if has_nat:
        L.extend([
            "add table inet sentinelfw_nat",
            "flush table inet sentinelfw_nat",
            "add chain inet sentinelfw_nat prerouting { type nat hook prerouting priority dstnat; policy accept; }",
            "add chain inet sentinelfw_nat postrouting { type nat hook postrouting priority srcnat; policy accept; }",
        ])

    for pol in policies:
        if not pol.get("enabled", True):
            continue
        src_nets = _norm_addr_list(pol.get("src"), address_groups=address_groups)
        dst_nets = _norm_addr_list(pol.get("dst"), address_groups=address_groups)
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

        # Real NAT compilation: Masquerade, SNAT, DNAT
        if pol.get("nat") or pol.get("nat_type"):
            ntype = pol.get("nat_type", "masquerade")
            out_itf = pol.get("out_interface") or pol.get("dst_zone") or ""
            itf_clause = f'oifname "{out_itf}" ' if out_itf and out_itf != "any" else ""
            if ntype == "masquerade":
                L.append(f"add rule inet sentinelfw_nat postrouting {itf_clause}masquerade comment \"nat-pol-{pol.get('id')}\"")
            elif ntype == "snat" and pol.get("nat_target"):
                L.append(f"add rule inet sentinelfw_nat postrouting {itf_clause}snat to {pol['nat_target']} comment \"snat-pol-{pol.get('id')}\"")
            elif ntype == "dnat" and pol.get("nat_target"):
                in_itf = pol.get("in_interface") or pol.get("src_zone") or ""
                in_clause = f'iifname "{in_itf}" ' if in_itf and in_itf != "any" else ""
                L.append(f"add rule inet sentinelfw_nat prerouting {in_clause}dnat to {pol['nat_target']} comment \"dnat-pol-{pol.get('id')}\"")

    # Terminal counter rule for implicit deny
    L.append('add rule inet sentinelfw_pol forward counter drop comment "implicit-deny"')

    return "\n".join(L) + "\n"


def compile_windows(policies, address_groups=None) -> dict:
    """Compiles policies into a {rule_name: spec} dict for WinBackend."""
    want = {}
    groups = address_groups or {}
    for pol in policies:
        if not pol.get("enabled", True):
            continue
        raw_srcs = pol.get("src") or ["any"]
        raw_dsts = pol.get("dst") or ["any"]
        srcs = []
        for v in raw_srcs:
            s_val = str(v).strip()
            if s_val.lower() == "any":
                continue
            grp_key = s_val[1:] if s_val.startswith("@") else s_val
            if grp_key in groups:
                srcs.extend(str(m).strip() for m in groups[grp_key])
            else:
                srcs.append(s_val)
        dsts = []
        for v in raw_dsts:
            d_val = str(v).strip()
            if d_val.lower() == "any":
                continue
            grp_key = d_val[1:] if d_val.startswith("@") else d_val
            if grp_key in groups:
                dsts.extend(str(m).strip() for m in groups[grp_key])
            else:
                dsts.append(d_val)
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


def find_shadowed_rules(rules: List[dict]) -> List[dict]:
    """Analyzes ordered firewall policies to detect shadowed/unreachable rules.

    A rule R2 is shadowed by a preceding rule R1 if R1 has broader or identical
    match predicates (action, direction, src, dst, services) making R2 unreachable.
    """
    shadowed = []
    active_rules = [r for r in rules if r.get("enabled", True)]

    for j in range(len(active_rules)):
        r2 = active_rules[j]
        r2_src = set(str(s).lower() for s in r2.get("src", ["any"]))
        r2_dst = set(str(d).lower() for d in r2.get("dst", ["any"]))
        r2_dir = r2.get("direction", "both")
        r2_svc = set(str(s).upper() for s in r2.get("services", ["ANY"]))

        for i in range(j):
            r1 = active_rules[i]
            r1_src = set(str(s).lower() for s in r1.get("src", ["any"]))
            r1_dst = set(str(d).lower() for d in r1.get("dst", ["any"]))
            r1_dir = r1.get("direction", "both")
            r1_svc = set(str(s).upper() for s in r1.get("services", ["ANY"]))

            # Direction match: r1 covers r2 if identical or r1 is "both"
            dir_matches = (r1_dir == "both") or (r1_dir == r2_dir)

            # Service match: ANY covers everything, or subset
            svc_matches = ("ANY" in r1_svc) or (r2_svc.issubset(r1_svc))

            # Address match: "any" covers everything, or subset
            src_matches = ("any" in r1_src) or (r2_src.issubset(r1_src))
            dst_matches = ("any" in r1_dst) or (r2_dst.issubset(r1_dst))

            if dir_matches and svc_matches and src_matches and dst_matches:
                shadowed.append({
                    "shadowed_rule_id": r2.get("id"),
                    "shadowed_rule_name": r2.get("name"),
                    "shadowing_rule_id": r1.get("id"),
                    "shadowing_rule_name": r1.get("name"),
                    "reason": f"Rule {r2.get('id')} is shadowed by broader preceding rule {r1.get('id')}",
                })
                break

    return shadowed


def get_unused_rules(rules: List[dict], min_idle_seconds: int = 86400) -> List[dict]:
    """Identifies policies with zero hit counts or long periods without matching traffic."""
    now = time.time()
    unused = []
    for r in rules:
        hits = int(r.get("hits", 0) or 0)
        created = float(r.get("created", now) or now)
        last_hit = float(r.get("last_hit", 0) or 0)

        # Unused if 0 hits and created at least min_idle_seconds ago, or no hits in idle window
        if hits == 0 and (now - created) >= min_idle_seconds:
            unused.append({
                "rule_id": r.get("id"),
                "name": r.get("name"),
                "hits": 0,
                "created": created,
                "idle_days": round((now - created) / 86400.0, 1),
            })
        elif hits > 0 and last_hit > 0 and (now - last_hit) >= min_idle_seconds:
            unused.append({
                "rule_id": r.get("id"),
                "name": r.get("name"),
                "hits": hits,
                "last_hit": last_hit,
                "idle_days": round((now - last_hit) / 86400.0, 1),
            })
    return unused

