"""SentinelFW management-plane security and SOC integrations.

Pure stdlib: scrypt credentials, cookie sessions with CSRF, login throttling,
RFC 6238 TOTP with recovery codes, a hash-chained tamper-evident audit log,
Prometheus metrics, RFC 5424 / CEF syslog forwarding, STIX 2.1 export and a
Sigma-style JSON rule engine with hot reload.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import struct
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional

from .common import DATA_DIR, HOME, LOGS, atomic_write, event

AUDIT_FILE = HOME / "audit.log"
API_TOKENS_FILE = HOME / "api_tokens.json"
SECRETS_FILE = DATA_DIR / "secrets.vault"
SECRETS_KEY_FILE = DATA_DIR / ".vault_master.key"
MASK_KEYS = ("password", "api_key", "bot_token", "secret", "token", "key")

# RBAC permission definitions
ROLES = {
    "SuperAdmin": [
        "*", "system:admin", "read:*",
        "policy:read", "policy:write", "policy:commit",
        "network:read", "network:write", "logs:read",
        "admin:tokens", "admin:secrets", "admin:auth",
        "policies:read", "policies:write", "rules:read", "rules:write",
        "blocklist:read", "blocklist:write", "appwall:read", "appwall:write",
        "forensics:read", "forensics:write", "decoy:read", "decoy:write",
    ],
    "SecurityAdmin": [
        "policy:read", "policy:write", "policy:commit", "logs:read",
        "read:*",
        "policies:read", "policies:write", "rules:read", "rules:write",
        "blocklist:read", "blocklist:write", "appwall:read", "appwall:write",
        "forensics:read", "forensics:write", "decoy:read", "decoy:write",
        "quarantine:read", "quarantine:write", "sigma:read", "sigma:write",
        "intelligence:read", "intelligence:write",
    ],
    "NetworkAdmin": [
        "network:read", "network:write", "policy:read", "logs:read",
        "read:*",
        "routes:read", "routes:write", "interfaces:read", "interfaces:write",
        "dns:read", "dns:write", "dhcp:read", "dhcp:write",
        "wireguard:read", "wireguard:write", "ipsec:read", "ipsec:write",
        "nat:read", "nat:write",
    ],
    "Auditor": [
        "read:*", "policy:read", "network:read", "logs:read",
        "policies:read", "rules:read", "blocklist:read", "appwall:read",
        "routes:read", "interfaces:read", "forensics:read", "sigma:read",
    ],
}

def has_permission(role: str, perm: str) -> bool:
    if role == "SuperAdmin":
        return True
    perms = ROLES.get(role, [])
    if "*" in perms or "system:admin" in perms:
        return True
    if perm in perms:
        return True
    if perm.endswith(":read") and "read:*" in perms:
        return True
    if perm.startswith("read:") and "read:*" in perms:
        return True
    if ":" in perm:
        cat = perm.split(":", 1)[0]
        if f"{cat}:*" in perms:
            return True
    return False


# =====================================================================
# credentials (scrypt) + sessions + throttling + TOTP
# =====================================================================
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=1, dklen=32)
    return "scrypt$16384$8$1$%s$%s" % (salt.hex(), h.hex())


def verify_password(password: str, stored: str) -> bool:
    try:
        parts = str(stored or "").split("$")
        if len(parts) == 6 and parts[0] == "scrypt":
            _, n, r, p, salt_hex, hash_hex = parts
            h = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt_hex),
                               n=int(n), r=int(r), p=int(p), dklen=32)
            return hmac.compare_digest(h.hex(), hash_hex)
        # legacy sha256 hex digest (pre-2.7 configs)
        digest = hashlib.sha256(password.encode("utf-8")).hexdigest()
        return hmac.compare_digest(digest, str(stored))
    except Exception:
        return False


def first_run_password() -> str:
    """Generate a one-time random password, print it once, return its scrypt hash."""
    otp = secrets.token_urlsafe(12)  # 16 chars
    print(f"\n{'='*60}")
    print(f"  SENTINELFW FIRST-RUN CREDENTIALS")
    print(f"  OTP PASSWORD: {otp}")
    print(f"  You MUST change this on first login.")
    print(f"{'='*60}\n")
    return hash_password(otp)


class AuthManager:
    """Sessions + login throttling + TOTP for the web console."""

    def __init__(self, cfg_get, session_ttl_minutes: int = 480):
        self._cfg_get = cfg_get                      # callable -> cfg dict
        self.ttl = session_ttl_minutes * 60
        self.sessions: Dict[str, dict] = {}
        self.attempts: Dict[str, List[float]] = {}   # "ip|user" -> timestamps
        self.lock = threading.Lock()

    # ------------------------------------------------------------ throttle
    def _locked_out(self, key: str) -> bool:
        with self.lock:
            ts = self.attempts.get(key, [])
            now = time.time()
            # 8 failures inside 10 minutes -> 10 minute lockout
            recent = [t for t in ts if now - t < 600]
            self.attempts[key] = recent
            if len(recent) >= 8:
                last = max(recent)
                if now - last < 600:
                    return True
        return False

    def _record_failure(self, key: str):
        with self.lock:
            self.attempts.setdefault(key, []).append(time.time())

    def _clear_failures(self, key: str):
        with self.lock:
            self.attempts.pop(key, None)

    # ------------------------------------------------------------ login
    def check_password(self, user: str, password: str) -> bool:
        w = self._cfg_get().get("webui", {})
        u, ph = str(w.get("username") or ""), str(w.get("password_hash") or "")
        if not (u and ph):
            return True  # auth disabled
        u_match = hmac.compare_digest(user.encode("utf-8"), u.encode("utf-8"))
        p_match = verify_password(password, ph)
        return u_match and p_match

    def totp_enabled(self) -> bool:
        m = self._cfg_get().get("management", {})
        return bool(m.get("totp_enabled") and m.get("totp_secret"))

    def login(self, user: str, password: str, totp: str, client_ip: str = "") -> dict:
        key = f"{client_ip}|{user}"
        if self._locked_out(key):
            return {"error": "too many failed attempts — locked out for 10 minutes"}
        if not self.check_password(user, password):
            self._record_failure(key)
            return {"error": "invalid credentials"}
        if self.totp_enabled():
            m = self._cfg_get().get("management", {})
            codes = m.get("recovery_codes") or []
            if totp and totp_verify(totp, m.get("totp_secret") or ""):
                pass  # valid time-based code
            elif totp and totp.strip() in codes:
                # single-use recovery code: consume it
                try:
                    codes.remove(totp.strip())
                    m["recovery_codes"] = codes
                except Exception:
                    pass
            else:
                self._record_failure(key)
                return {"error": "2FA code required", "totp_required": True}
        self._clear_failures(key)
        return self.new_session(user)

    def _use_recovery(self, code: str, codes: List[str]) -> bool:
        # empty code is not a recovery attempt; handled by caller flow
        if not code or not isinstance(codes, list):
            return False
        return code.strip() in codes

    # ------------------------------------------------------------ sessions
    def new_session(self, user: str, role: str = "SuperAdmin") -> dict:
        sid = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(24)
        with self.lock:
            now = time.time()
            self.sessions = {k: v for k, v in self.sessions.items() if v["expires"] > now}
            self.sessions[sid] = {"user": user, "role": role, "expires": now + self.ttl, "csrf": csrf}
        return {"session_id": sid, "csrf": csrf, "role": role, "expires_in": self.ttl}

    def validate_session(self, sid: str) -> Optional[dict]:
        with self.lock:
            s = self.sessions.get(sid)
            if not s:
                return None
            if s["expires"] < time.time():
                self.sessions.pop(sid, None)
                return None
            return s

    def drop_session(self, sid: str):
        with self.lock:
            self.sessions.pop(sid, None)

    def check_csrf(self, sid: str, token: str) -> bool:
        s = self.validate_session(sid)
        return bool(s and token and hmac.compare_digest(s["csrf"], token))


# =====================================================================
# API tokens (scoped, hashed at rest, expiration support)
# =====================================================================
def create_api_token(username: str, role: str = "SuperAdmin", expires_days: int = 90, note: str = "") -> dict:
    raw_token = "sfw_tok_" + secrets.token_hex(24)
    thash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    expires_at = time.time() + (expires_days * 86400)
    data = load_api_tokens()
    data[thash] = {
        "username": username,
        "role": role,
        "note": note,
        "created_at": time.time(),
        "expires_at": expires_at,
        "token_prefix": raw_token[:14] + "...",
    }
    save_api_tokens(data)
    audit_append("api_token_created", user=username, role=role, prefix=raw_token[:14])
    return {
        "token": raw_token,
        "token_hash": thash,
        "username": username,
        "role": role,
        "expires_at": expires_at,
    }


def load_api_tokens() -> dict:
    if not API_TOKENS_FILE.exists():
        return {}
    try:
        return json.loads(API_TOKENS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_api_tokens(tokens: dict):
    from .common import atomic_write
    atomic_write(API_TOKENS_FILE, json.dumps(tokens, indent=2))


def verify_api_token(raw_token: str) -> Optional[dict]:
    if not raw_token or not raw_token.startswith("sfw_"):
        return None
    thash = hashlib.sha256(raw_token.strip().encode("utf-8")).hexdigest()
    tokens = load_api_tokens()
    tok_info = tokens.get(thash)
    if not tok_info:
        return None
    if time.time() > tok_info.get("expires_at", 0):
        return None
    return tok_info


def revoke_api_token(token_or_prefix: str) -> bool:
    tokens = load_api_tokens()
    removed = False
    thash = hashlib.sha256(token_or_prefix.strip().encode("utf-8")).hexdigest() if token_or_prefix.startswith("sfw_") else token_or_prefix
    for h, info in list(tokens.items()):
        if h == thash or info.get("token_prefix", "").startswith(token_or_prefix):
            tokens.pop(h, None)
            removed = True
    if removed:
        save_api_tokens(tokens)
        audit_append("api_token_revoked", target=token_or_prefix[:14])
    return removed


# =====================================================================
# Secrets Vault (Zero-dependency Encrypt-then-MAC credential storage)
# =====================================================================
class SecretsVault:
    """Encrypted credential vault using HMAC-SHA256 CTR stream cipher + HMAC-SHA256 MAC.
    
    Operates strictly within Python stdlib with zero external dependencies.
    Protects 3rd-party API keys (Sarvam, VirusTotal, Telegram, etc.) at rest.
    """

    def __init__(self, key_path: Optional[Path] = None, data_path: Optional[Path] = None):
        self.key_path = key_path or SECRETS_KEY_FILE
        self.data_path = data_path or SECRETS_FILE
        self._lock = threading.RLock()
        self._master_key: Optional[bytes] = None

    def _get_master_key(self) -> bytes:
        if self._master_key is not None:
            return self._master_key
        with self._lock:
            if self._master_key is not None:
                return self._master_key
            if self.key_path.exists():
                try:
                    data = self.key_path.read_bytes()
                    if len(data) >= 32:
                        self._master_key = data[:32]
                        return self._master_key
                except Exception:
                    pass
            k = secrets.token_bytes(32)
            try:
                self.key_path.parent.mkdir(parents=True, exist_ok=True)
                atomic_write(self.key_path, k, binary=True)
                try:
                    os.chmod(self.key_path, 0o600)
                except Exception:
                    pass
            except Exception:
                pass
            self._master_key = k
            return self._master_key

    def _derive_keys(self, salt: bytes) -> tuple:
        master = self._get_master_key()
        k_enc = hmac.digest(master, salt + b":enc", "sha256")
        k_mac = hmac.digest(master, salt + b":mac", "sha256")
        return k_enc, k_mac

    def _encrypt(self, plaintext: bytes) -> bytes:
        salt = secrets.token_bytes(16)
        iv = secrets.token_bytes(16)
        k_enc, k_mac = self._derive_keys(salt)
        
        # Keystream via HMAC-SHA256 counter mode
        ciphertext = bytearray(len(plaintext))
        block_count = (len(plaintext) + 31) // 32
        for i in range(block_count):
            counter = iv + i.to_bytes(4, "big")
            ks = hmac.digest(k_enc, counter, "sha256")
            chunk_len = min(32, len(plaintext) - i * 32)
            for j in range(chunk_len):
                ciphertext[i * 32 + j] = plaintext[i * 32 + j] ^ ks[j]
                
        # Authenticate over salt + iv + ciphertext
        tag = hmac.digest(k_mac, salt + iv + bytes(ciphertext), "sha256")
        return b"SFWV" + salt + iv + tag + bytes(ciphertext)

    def _decrypt(self, payload: bytes) -> bytes:
        if not payload.startswith(b"SFWV") or len(payload) < 68:
            raise ValueError("Invalid secrets vault format")
        salt = payload[4:20]
        iv = payload[20:36]
        tag = payload[36:68]
        ciphertext = payload[68:]
        
        k_enc, k_mac = self._derive_keys(salt)
        expected_tag = hmac.digest(k_mac, salt + iv + ciphertext, "sha256")
        if not hmac.compare_digest(tag, expected_tag):
            raise ValueError("Vault authentication tag verification failed (tampered data)")
            
        plaintext = bytearray(len(ciphertext))
        block_count = (len(ciphertext) + 31) // 32
        for i in range(block_count):
            counter = iv + i.to_bytes(4, "big")
            ks = hmac.digest(k_enc, counter, "sha256")
            chunk_len = min(32, len(ciphertext) - i * 32)
            for j in range(chunk_len):
                plaintext[i * 32 + j] = ciphertext[i * 32 + j] ^ ks[j]
        return bytes(plaintext)

    def load(self) -> dict:
        if not self.data_path.exists():
            return {}
        try:
            payload = self.data_path.read_bytes()
            dec = self._decrypt(payload)
            return json.loads(dec.decode("utf-8"))
        except Exception:
            return {}

    def save(self, secrets_dict: dict):
        raw = json.dumps(secrets_dict, indent=2).encode("utf-8")
        enc = self._encrypt(raw)
        self.data_path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(self.data_path, enc, binary=True)
        try:
            os.chmod(self.data_path, 0o600)
        except Exception:
            pass

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        return self.load().get(key, default)

    def set(self, key: str, value: str):
        with self._lock:
            data = self.load()
            data[key] = value
            self.save(data)
            audit_append("secret_stored", key=key)

    def delete(self, key: str) -> bool:
        with self._lock:
            data = self.load()
            if key in data:
                del data[key]
                self.save(data)
                audit_append("secret_deleted", key=key)
                return True
            return False

    def list_keys(self) -> list:
        return sorted(list(self.load().keys()))


secrets_vault = SecretsVault()


# =====================================================================
# TOTP (RFC 6238) — hmac/hashlib only
# =====================================================================
_B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def totp_secret_new() -> str:
    raw = secrets.token_bytes(20)
    bits = "".join(f"{b:08b}" for b in raw)
    out = ""
    for i in range(0, len(bits) - 4, 5):
        out += _B32[int(bits[i:i + 5], 2)]
    return out


def _b32decode(s: str) -> bytes:
    s = re.sub(r"[^A-Z2-7]", "", (s or "").upper())
    bits = "".join(f"{_B32.index(c):05b}" for c in s)
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - 7, 8))


def totp_now(secret: str, step: int = 30, digits: int = 6, t: Optional[float] = None) -> str:
    key = _b32decode(secret)
    counter = int((t if t is not None else time.time()) // step)
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[-1] & 0x0F
    code = (struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp_verify(code: str, secret: str, window: int = 1) -> bool:
    code = (code or "").strip()
    if not re.fullmatch(r"\d{6,8}", code) or not secret:
        return False
    now = time.time()
    for drift in range(-window, window + 1):
        if hmac.compare_digest(code, totp_now(secret, t=now + drift * 30)):
            return True
    return False


def totp_uri(secret: str, user: str, issuer: str = "SentinelFW") -> str:
    from urllib.parse import quote
    return f"otpauth://totp/{quote(issuer)}:{quote(user)}?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"


def recovery_codes_new(n: int = 8) -> List[str]:
    return [f"{secrets.randbelow(10**5):05d}-{secrets.randbelow(10**5):05d}" for _ in range(n)]


# =====================================================================
# hash-chained audit log
# =====================================================================
def audit_append(action: str, user: str = "system", **fields) -> dict:
    """Appends one tamper-evident record to HOME/audit.log.

    Every record carries the SHA-256 of the previous line, so any edit,
    deletion or insertion breaks the chain and `audit_verify` reports it.
    """
    prev = ""
    try:
        if AUDIT_FILE.exists():
            with open(AUDIT_FILE, "rb") as f:
                f.seek(max(0, AUDIT_FILE.stat().st_size - 4096), 0)
                lines = [l for l in f.read().decode("utf-8", "replace").splitlines() if l.strip()]
                if lines:
                    prev = json.loads(lines[-1]).get("hash", "")
    except Exception:
        prev = ""
    rec = {"ts": time.time(), "user": user, "action": action}
    rec.update(fields)
    rec["prev"] = prev
    payload = json.dumps(rec, sort_keys=True, default=str)
    rec["hash"] = hashlib.sha256((prev + payload).encode("utf-8")).hexdigest()
    try:
        HOME.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, sort_keys=True, default=str) + "\n")
    except Exception:
        pass
    return rec


def audit_verify(path: Optional[Path] = None) -> dict:
    """Walks the chain; returns {ok, records, first_bad}."""
    p = Path(path or AUDIT_FILE)
    if not p.exists():
        return {"ok": True, "records": 0, "note": "no audit log yet"}
    prev = ""
    n = bad = 0
    with open(p, encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            n += 1
            try:
                rec = json.loads(line)
                body = {k: v for k, v in rec.items() if k != "hash"}
                expect = hashlib.sha256((prev + json.dumps(body, sort_keys=True,
                                                            default=str)).encode()).hexdigest()
                if not hmac.compare_digest(expect, rec.get("hash", "")) or \
                        rec.get("prev", "") != prev:
                    bad = bad or i  # edited content, or broken chain linkage
                prev = rec.get("hash", "")
            except Exception:
                bad = bad or i
    return {"ok": bad == 0 and n > 0, "records": n, "first_bad": bad or None}


def audit_last(limit: int = 100) -> List[dict]:
    try:
        lines = open(AUDIT_FILE, encoding="utf-8", errors="replace").read().splitlines()
        return [json.loads(l) for l in lines[-limit:] if l.strip()]
    except Exception:
        return []


def mask_body(data) -> str:
    """Secret-free one-line rendering of a request body for the audit log.

    Copies first: the request body is the live object the API handler is
    about to consume, so masking must never mutate it (a key named e.g.
    `shared_key` would otherwise be replaced with '***' in the actual
    config write).
    """
    try:
        d = dict(data) if isinstance(data, dict) else {}
        for k in list(d):
            if any(m in k.lower() for m in MASK_KEYS):
                d[k] = "***"
        return json.dumps(d, default=str)[:400]
    except Exception:
        return "(unprintable)"


# =====================================================================
# Prometheus metrics
# =====================================================================
def prometheus_metrics(engine, webui) -> str:
    lines = []
    def metric(name, kind, help_, value, labels=""):
        lines.append(f"# HELP {name} {help_}")
        lines.append(f"# TYPE {name} {kind}")
        lines.append(f"{name}{labels} {value}")

    if engine is not None:
        try:
            metric("sentinelfw_bans_active", "gauge", "Currently enforced IP bans",
                   len(engine.store.bans))
            metric("sentinelfw_blocklist_ranges", "gauge", "Blocklisted IP ranges",
                   len(engine.lists.ipset))
            metric("sentinelfw_offenses_total", "gauge", "Total recorded offenses",
                   len(engine.store.offenses))
            metric("sentinelfw_trusted_ips", "gauge", "Protected management entries",
                   len(engine.cfg.get("trusted_ips", [])))
            t = getattr(engine.intel, "status", lambda: {})() or {}
            metric("sentinelfw_vt_cached_ips", "gauge", "Cached VirusTotal verdicts",
                   t.get("cached_ips", 0))
            metric("sentinelfw_vt_malicious", "gauge", "VirusTotal-malicious IPs seen",
                   t.get("detected_malicious", 0))
        except Exception:
            pass
    if webui is not None:
        try:
            r = webui._traffic_rates() if hasattr(webui, "_traffic_rates") else {}
            metric("sentinelfw_traffic_bps_in", "gauge", "Inbound bits per second", r.get("bps_in", 0))
            metric("sentinelfw_traffic_bps_out", "gauge", "Outbound bits per second", r.get("bps_out", 0))
            metric("sentinelfw_traffic_pps_in", "gauge", "Inbound packets per second", r.get("pps_in", 0))
            metric("sentinelfw_traffic_pps_out", "gauge", "Outbound packets per second", r.get("pps_out", 0))
            c = webui.get_applications() if hasattr(webui, "get_applications") else {}
            metric("sentinelfw_applications_indexed", "gauge", "Applications indexed",
                   c.get("total", 0) if isinstance(c, dict) else 0)
            con = webui.conntrack.get_active() if webui.conntrack else []
            est = sum(1 for x in con if str(x.get("state", "")).startswith("ESTABLISHED"))
            metric("sentinelfw_sessions_active", "gauge", "Active sockets", len(con))
            metric("sentinelfw_sessions_established", "gauge", "Established sessions", est)
        except Exception:
            pass
    # event counters by severity (scan recent log tail)
    try:
        sev = {}
        p = LOGS / "events.jsonl"
        if p.exists():
            with open(p, encoding="utf-8", errors="ignore") as f:
                f.seek(max(0, p.stat().st_size - 400_000), 0)
                f.readline()  # skip partial
                for line in f:
                    try:
                        s = json.loads(line).get("severity", "")
                        if s:
                            sev[s] = sev.get(s, 0) + 1
                    except Exception:
                        pass
        for s, v in sorted(sev.items()):
            lines.append(f'sentinelfw_events{{severity="{s}"}} {v}')
    except Exception:
        pass
    uptime = time.time() - (getattr(webui, "start_time", None) or time.time())
    metric("sentinelfw_uptime_seconds", "gauge", "Console uptime", int(uptime))
    return "\n".join(lines) + "\n"


# =====================================================================
# STIX 2.1 export
# =====================================================================
def stix_export(engine) -> dict:
    """Bans + VirusTotal-malicious IPs as a STIX 2.1 bundle of indicators."""
    from . import vtdb
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    objs = []

    def iid(t, n):
        return f"{t}--{hashlib.sha256((t + n).encode()).hexdigest()[:32]}"

    objs.append({"type": "identity", "spec_version": "2.1", "id": iid("identity", "sentinelfw"),
                 "created": now, "modified": now, "name": "SentinelFW",
                 "identity_class": "system"})
    if engine is not None:
        with engine.store.lock:
            bans = dict(engine.store.bans)
            offenses = dict(engine.store.offenses)
        for ip, meta in bans.items():
            reason = str(meta.get("reason", "Autonomous Threat Response"))[:300]
            objs.append({
                "type": "indicator", "spec_version": "2.1",
                "id": iid("indicator", f"ban-{ip}"),
                "created_by_ref": iid("identity", "sentinelfw"),
                "created": now, "modified": now,
                "name": f"Banned host {ip}",
                "description": reason,
                "indicator_types": ["malicious-activity"],
                "pattern": f"[ipv4-addr:value = '{ip}']",
                "pattern_type": "stix", "valid_from": now,
                "labels": [f"offenses:{offenses.get(ip, 0)}"],
            })
        try:
            for row in _vt_malicious(vtdb):
                ip = row.get("ip")
                if ip and ip not in bans:
                    objs.append({
                        "type": "indicator", "spec_version": "2.1",
                        "id": iid("indicator", f"vt-{ip}"),
                        "created_by_ref": iid("identity", "sentinelfw"),
                        "created": now, "modified": now,
                        "name": f"VirusTotal-malicious {ip}",
                        "description": f"{row.get('malicious', 0)} detection engines",
                        "indicator_types": ["malicious-activity"],
                        "pattern": f"[ipv4-addr:value = '{ip}']",
                        "pattern_type": "stix", "valid_from": now,
                    })
        except Exception:
            pass
    return {"type": "bundle", "id": iid("bundle", str(time.time())),
            "objects": objs}


def _vt_malicious(vtdb) -> List[dict]:
    try:
        import sqlite3
        c = sqlite3.connect(str(HOME / "intel.db"))
        c.row_factory = sqlite3.Row
        rows = c.execute("SELECT ip, malicious FROM vt_reports WHERE verdict = 'MALICIOUS'").fetchall()
        c.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


# =====================================================================
# Syslog forwarding (RFC 5424 / CEF)
# =====================================================================
class SyslogForwarder:
    """Ships every engine event to a remote collector over UDP/TCP."""

    def __init__(self, cfg_get):
        self._cfg_get = cfg_get
        self._lock = threading.Lock()
        self._sock = None

    def _cfg(self) -> dict:
        try:
            return self._cfg_get().get("syslog", {}) or {}
        except Exception:
            return {}

    def enabled(self) -> bool:
        c = self._cfg()
        return bool(c.get("enabled") and c.get("host"))

    def _send(self, data: bytes):
        c = self._cfg()
        host, port = str(c.get("host")), int(c.get("port") or 514)
        proto = str(c.get("proto") or "udp").lower()
        try:
            if proto == "tcp":
                with socket.create_connection((host, port), timeout=2) as s:
                    s.sendall(data)
            else:
                with self._lock:
                    if self._sock is None:
                        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    self._sock.sendto(data, (host, port))
        except Exception:
            pass

    def handle_event(self, rec: dict):
        if not self.enabled():
            return
        host = socket.gethostname()
        ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(rec.get("_ts") or time.time()))
        if str(self._cfg().get("format") or "rfc5424").lower() == "cef":
            sev_map = {"info": 3, "low": 4, "medium": 6, "warning": 6, "high": 7,
                       "critical": 8, "crit": 8}
            ext = "".join(f" {k}={str(v)[:180]}" for k, v in rec.items()
                          if k not in ("kind", "severity", "_ts", "ts"))
            msg = (f"CEF:0|SentinelFW|SentinelFW|3.0|{rec.get('kind', 'event')}|"
                   f"{rec.get('kind', 'event')}|{sev_map.get(str(rec.get('severity', 'info')).lower(), 3)}|{ext}")
            self._send((msg + "\n").encode("utf-8", "replace"))
        else:
            # RFC 5424: <PRI>VERSION TIMESTAMP HOST APP PROCID MSGID STRUCTURED MSG
            pri = 8 * 3 + 6  # facility daemon(3) * 8 + severity informational(6)
            sev = str(rec.get("severity", "info")).lower()
            if sev in ("warning", "medium", "low"):
                pri = 8 * 3 + 4
            elif sev in ("high", "crit", "critical"):
                pri = 8 * 3 + 2
            sd = '[sentinelfw event_id="%s" severity="%s"]' % (
                rec.get("kind", "event"), rec.get("severity", "info"))
            msg = " ".join(f"{k}={str(v)[:180]}" for k, v in rec.items()
                           if k not in ("kind", "severity", "ts", "_ts"))
            line = f"<{pri}>1 {ts} {host} SentinelFW - {rec.get('kind', 'event')} {sd} {msg}\n"
            self._send(line.encode("utf-8", "replace"))


# =====================================================================
# Sigma-style JSON rule engine
# =====================================================================
class SigmaEngine:
    """Loads JSON rules from lists/sigma/*.json, matches engine events.

    Rule format (Sigma-inspired, JSON so the stdlib can read it):
      {"id": "unique", "name": "human", "severity": "high",
       "description": "...",
       "action": "monitor" | "block",      # block = ban event's src/remote IP
       "selection": {"kind": "honeypot_credentials",
                     "user": ["root", "admin"],
                     "src": "*185.*"}}
    Values: exact string, glob with *?[], or a list of either.
    """

    def __init__(self, rules_dir: Path, cfg_get=None):
        self.dir = Path(rules_dir)
        self.cfg_get = cfg_get
        self.rules: List[dict] = []
        self.stats: Dict[str, int] = {}
        self._mtime = 0
        self._lock = threading.Lock()
        self._seed_bundled()
        self.reload()

    def _seed_bundled(self):
        """First run: install the bundled starter ruleset into the data dir."""
        try:
            if not self.dir.is_dir() or not any(self.dir.glob("*.json")):
                bundled = Path(__file__).resolve().parent / "bundled" / "sigma"
                if bundled.is_dir():
                    import shutil
                    self.dir.mkdir(parents=True, exist_ok=True)
                    for f in bundled.glob("*.json"):
                        dst = self.dir / f.name
                        if not dst.exists():
                            shutil.copy2(f, dst)
        except Exception:
            pass

    def enabled(self) -> bool:
        try:
            return bool((self.cfg_get() or {}).get("sigma", {}).get("enabled", True))
        except Exception:
            return True

    def reload(self) -> int:
        with self._lock:
            rules = []
            if self.dir.is_dir():
                m = max((p.stat().st_mtime for p in self.dir.glob("*.json")), default=0)
                for p in sorted(self.dir.glob("*.json")):
                    try:
                        r = json.loads(p.read_text(encoding="utf-8"))
                        if r.get("id") and r.get("selection"):
                            rules.append(r)
                    except Exception:
                        pass
                self._mtime = m
            self.rules = rules
            return len(rules)

    def maybe_reload(self):
        try:
            m = max((p.stat().st_mtime for p in self.dir.glob("*.json")), default=0)
            if m != self._mtime:
                self.reload()
        except Exception:
            pass

    @staticmethod
    def _match_value(value, pattern) -> bool:
        if isinstance(pattern, list):
            return any(SigmaEngine._match_value(value, p) for p in pattern)
        value = str(value if value is not None else "")
        pattern = str(pattern)
        if "*" in pattern or "?" in pattern or "[" in pattern:
            import fnmatch
            return fnmatch.fnmatch(value.lower(), pattern.lower())
        return value.lower() == pattern.lower()

    def match(self, rec: dict) -> List[dict]:
        if not self.enabled():
            return []
        self.maybe_reload()
        hits = []
        with self._lock:
            rules = list(self.rules)
        for r in rules:
            sel = r.get("selection") or {}
            if all(self._match_value(rec.get(k), v) for k, v in sel.items()):
                hits.append(r)
        return hits

    def record_hit(self, rule: dict):
        with self._lock:
            self.stats[rule["id"]] = self.stats.get(rule["id"], 0) + 1
