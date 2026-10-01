"""SentinelFW Identity Engine — User, Group, and Authentication Directory.

Provides zero-dependency identity resolution and authentication support:
* Thread-safe IP-to-User/Group mapping directory (IdentityDirectory)
* RFC 4511 Simple LDAP / Active Directory bind authenticator (pure socket + ssl)
* RFC 2865 RADIUS Access-Request authenticator (pure socket + hashlib)
* Zero-dependency JWT / OIDC token validator (HMAC-SHA256, claims validation)
"""
import base64
import collections
import hashlib
import hmac
import json
import secrets
import socket
import ssl
import struct
import threading
import time
from typing import Dict, List, Optional, Set, Tuple, Union
from .common import event


# ---------------------------------------------------------------------------
# Identity Directory (IP -> User / Group Mapping)
# ---------------------------------------------------------------------------
class IdentityDirectory:
    """Thread-safe IP-to-Identity directory with TTL expiration."""

    def __init__(self, config: Optional[dict] = None):
        self._lock = threading.RLock()
        self._map: Dict[str, dict] = {}
        if config and isinstance(config, dict):
            for item in config.get("identities", []):
                if isinstance(item, dict) and "ip" in item and "username" in item:
                    self.map_ip(item["ip"], item["username"], groups=item.get("groups", []),
                                domain=item.get("domain", ""), method=item.get("method", "config"),
                                ttl=item.get("ttl", 0))

    def map_ip(self, ip: str, username: str, groups: Optional[List[str]] = None,
               domain: str = "", method: str = "manual", ttl: int = 3600,
               device_id: str = "", device_name: str = "", mac_address: str = "",
               posture: str = "COMPLIANT", session_id: str = "") -> dict:
        """Binds an IP address to a full user, device, and session identity context."""
        clean_ip = str(ip).strip()
        clean_user = str(username).strip()
        now = time.time()
        record = {
            "ip": clean_ip,
            "username": clean_user,
            "groups": [str(g).strip() for g in (groups or [])],
            "domain": str(domain).strip(),
            "method": str(method).strip(),
            "device_id": str(device_id).strip(),
            "device_name": str(device_name).strip(),
            "mac_address": str(mac_address).strip().upper(),
            "posture": str(posture).strip().upper(),
            "session_id": str(session_id).strip(),
            "authenticated_at": now,
            "expires_at": now + ttl if ttl > 0 else 0,
        }
        with self._lock:
            self._map[clean_ip] = record
            event("identity_mapped", "info", ip=clean_ip, user=clean_user, method=method, device=device_id)
            return dict(record)

    def get_identity(self, ip: str) -> Optional[dict]:
        """Looks up the identity for an IP, returning None if not found or expired."""
        clean_ip = str(ip).strip()
        now = time.time()
        with self._lock:
            rec = self._map.get(clean_ip)
            if not rec:
                return None
            if rec["expires_at"] > 0 and now > rec["expires_at"]:
                del self._map[clean_ip]
                return None
            return dict(rec)

    def lookup_by_user(self, username: str) -> List[dict]:
        """Returns all active IP and device bindings for a given username."""
        clean_user = str(username).strip().lower()
        now = time.time()
        with self._lock:
            results = []
            for rec in list(self._map.values()):
                if rec["expires_at"] > 0 and now > rec["expires_at"]:
                    continue
                if rec["username"].lower() == clean_user:
                    results.append(dict(rec))
            return results

    def lookup_by_device(self, device_id: str) -> List[dict]:
        """Returns all active IP and user bindings for a given device ID."""
        clean_dev = str(device_id).strip().lower()
        now = time.time()
        with self._lock:
            results = []
            for rec in list(self._map.values()):
                if rec["expires_at"] > 0 and now > rec["expires_at"]:
                    continue
                if rec.get("device_id", "").lower() == clean_dev:
                    results.append(dict(rec))
            return results

    def revoke_ip(self, ip: str) -> bool:
        """Revokes an IP identity binding."""
        clean_ip = str(ip).strip()
        with self._lock:
            if clean_ip in self._map:
                user = self._map[clean_ip].get("username")
                del self._map[clean_ip]
                event("identity_revoked", "info", ip=clean_ip, user=user)
                return True
            return False

    def list_identities(self) -> List[dict]:
        """Returns all non-expired identity bindings."""
        now = time.time()
        with self._lock:
            active = []
            expired = []
            for ip, rec in self._map.items():
                if rec["expires_at"] > 0 and now > rec["expires_at"]:
                    expired.append(ip)
                else:
                    active.append(dict(rec))
            for ip in expired:
                del self._map[ip]
            return active

    def clear(self):
        with self._lock:
            self._map.clear()


# Global directory singleton
directory = IdentityDirectory()


# ---------------------------------------------------------------------------
# Lightweight Zero-Dependency LDAP Simple Bind (RFC 4511)
# ---------------------------------------------------------------------------
def _ber_len(length: int) -> bytes:
    if length < 128:
        return bytes([length])
    len_bytes = []
    while length > 0:
        len_bytes.append(length & 0xFF)
        length >>= 8
    len_bytes.reverse()
    return bytes([0x80 | len(len_bytes)]) + bytes(len_bytes)


def _ber_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(value)) + value


def _ber_integer(val: int) -> bytes:
    # 0x02 = INTEGER
    if val == 0:
        return bytes([0x02, 0x01, 0x00])
    b = []
    temp = val
    while temp > 0:
        b.append(temp & 0xFF)
        temp >>= 8
    b.reverse()
    if b[0] & 0x80:
        b.insert(0, 0x00)
    return bytes([0x02, len(b)]) + bytes(b)


def _ber_octet_string(val: Union[str, bytes]) -> bytes:
    # 0x04 = OCTET STRING
    raw = val.encode("utf-8") if isinstance(val, str) else val
    return _ber_tlv(0x04, raw)


def ldap_authenticate(server: str, bind_dn: str, password: str, port: int = 389,
                      use_tls: bool = False, ca_file: Optional[str] = None,
                      timeout: float = 5.0) -> Tuple[bool, str]:
    """Authenticates against an LDAP / Active Directory server via Simple Bind (RFC 4511)."""
    try:
        raw_sock = socket.create_connection((server, port), timeout=timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            if ca_file and os.path.exists(ca_file):
                ctx.load_verify_locations(ca_file)
            sock = ctx.wrap_socket(raw_sock, server_hostname=server)
        else:
            sock = raw_sock

        with sock:
            # Construct LDAP Simple Bind Request:
            # MessageID: 1 (INTEGER)
            # BindRequest: [APPLICATION 0] SEQUENCE {
            #     version: 3 (INTEGER),
            #     name: bind_dn (OCTET STRING),
            #     authentication: [CONTEXT 0] password (OCTET STRING)
            # }
            msg_id = _ber_integer(1)
            version = _ber_integer(3)
            dn = _ber_octet_string(bind_dn)
            auth = _ber_tlv(0x80, password.encode("utf-8"))  # Context tag 0: simple auth
            bind_req_body = version + dn + auth
            bind_req = _ber_tlv(0x60, bind_req_body)  # 0x60 = Application 0 constructed
            msg_seq = _ber_tlv(0x30, msg_id + bind_req)  # 0x30 = SEQUENCE

            sock.sendall(msg_seq)
            resp = sock.recv(4096)
            if not resp or len(resp) < 7:
                return False, "Empty or truncated response from LDAP server"

            # Parse BindResponse (Application 1: 0x61)
            # ResultCode is an ENUMERATED (0x0a) inside BindResponse: 0 = success
            idx = resp.find(b"\x0a\x01")
            if idx != -1 and idx + 2 < len(resp):
                result_code = resp[idx + 2]
                if result_code == 0:
                    return True, "LDAP bind successful"
                elif result_code == 49:
                    return False, "Invalid credentials"
                else:
                    return False, f"LDAP error result code: {result_code}"
            return False, "Malformed LDAP bind response"
    except Exception as e:
        return False, f"LDAP connection error: {str(e)}"


# ---------------------------------------------------------------------------
# Lightweight Zero-Dependency RADIUS Authenticator (RFC 2865)
# ---------------------------------------------------------------------------
def radius_authenticate(server: str, secret: str, username: str, password: str,
                        port: int = 1812, timeout: float = 5.0) -> Tuple[bool, str]:
    """Authenticates a user against a RADIUS server via RFC 2865 Access-Request."""
    try:
        import os
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        with sock:
            packet_id = os.urandom(1)[0]
            request_authenticator = os.urandom(16)

            # Attribute 1: User-Name
            user_bytes = username.encode("utf-8")
            attr_user = bytes([1, len(user_bytes) + 2]) + user_bytes

            # Attribute 2: User-Password (RFC 2865 section 5.2: 16-byte padded, XOR with MD5(secret + auth))
            pw_bytes = password.encode("utf-8")
            pad_len = 16 - (len(pw_bytes) % 16) if (len(pw_bytes) % 16) != 0 else 0
            if len(pw_bytes) == 0:
                pad_len = 16
            padded_pw = pw_bytes + (b"\x00" * pad_len)
            secret_bytes = secret.encode("utf-8") if isinstance(secret, str) else secret

            encrypted_pw = b""
            last_block = request_authenticator
            for i in range(0, len(padded_pw), 16):
                chunk = padded_pw[i:i + 16]
                b_hash = hashlib.md5(secret_bytes + last_block).digest()
                c_block = bytes(x ^ y for x, y in zip(chunk, b_hash))
                encrypted_pw += c_block
                last_block = c_block

            attr_pw = bytes([2, len(encrypted_pw) + 2]) + encrypted_pw

            # Build Packet: Code(1=Access-Request) + ID(1) + Length(2) + Authenticator(16) + Attributes
            attrs = attr_user + attr_pw
            length = 20 + len(attrs)
            pkt = struct.pack("!BBH", 1, packet_id, length) + request_authenticator + attrs

            sock.sendto(pkt, (server, port))
            resp, _ = sock.recvfrom(4096)
            if len(resp) < 20:
                return False, "Truncated RADIUS response"

            code, resp_id, resp_len = struct.unpack("!BBH", resp[:4])
            if resp_id != packet_id:
                return False, "RADIUS response ID mismatch"

            # Check Response Authenticator: MD5(Code + ID + Length + RequestAuth + Attributes + Secret)
            calc_auth = hashlib.md5(resp[:4] + request_authenticator + resp[20:resp_len] + secret_bytes).digest()
            if calc_auth != resp[4:20]:
                return False, "Invalid RADIUS response authenticator"

            if code == 2:  # Access-Accept
                return True, "RADIUS Access-Accept"
            elif code == 3:  # Access-Reject
                return False, "RADIUS Access-Reject"
            elif code == 11:  # Access-Challenge
                return False, "RADIUS Access-Challenge not supported"
            else:
                return False, f"Unexpected RADIUS code: {code}"
    except socket.timeout:
        return False, "RADIUS server timeout"
    except Exception as e:
        return False, f"RADIUS authentication error: {str(e)}"


# ---------------------------------------------------------------------------
# Lightweight Zero-Dependency JWT / OIDC Validator
# ---------------------------------------------------------------------------
def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def create_jwt(payload: dict, secret: str, header: Optional[dict] = None) -> str:
    """Creates a signed JSON Web Token (HS256) using Python standard library."""
    h = header or {"alg": "HS256", "typ": "JWT"}
    h_b64 = _b64url_encode(json.dumps(h, separators=(',', ':')).encode("utf-8"))
    p_b64 = _b64url_encode(json.dumps(payload, separators=(',', ':')).encode("utf-8"))
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_b64 = _b64url_encode(sig)
    return f"{h_b64}.{p_b64}.{sig_b64}"


class JWTValidator:
    """Zero-dependency JWT creation and verification helper."""

    @staticmethod
    def create_token(payload: dict, secret: str) -> str:
        return create_jwt(payload, secret)

    @staticmethod
    def validate_token(token: str, secret: str, expected_audience: Optional[str] = None) -> Tuple[bool, str, dict]:
        valid, claims, msg = verify_jwt(token, secret=secret, expected_audience=expected_audience)
        return valid, msg, claims


def _b64url_decode(s: str) -> bytes:
    padding = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + padding)


def verify_jwt(token: str, secret: Optional[str] = None, expected_issuer: Optional[str] = None,
               expected_audience: Optional[str] = None, leeway: int = 60,
               allow_unverified: bool = False) -> Tuple[bool, dict, str]:
    """Validates a JSON Web Token (HMAC-SHA256).

    Rejects unverified tokens by default unless allow_unverified=True is explicitly set.
    Returns (valid: bool, claims: dict, message: str).
    """
    if not token or not isinstance(token, str):
        return False, {}, "Missing or invalid token string"

    if not secret and not allow_unverified:
        return False, {}, "JWT verification failed: Cryptographic signature secret is required"

    parts = token.strip().split(".")
    if len(parts) != 3:
        return False, {}, "Invalid JWT structure (must have 3 parts)"

    header_b64, payload_b64, sig_b64 = parts
    try:
        header = json.loads(_b64url_decode(header_b64).decode("utf-8"))
        claims = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    except Exception as e:
        return False, {}, f"Failed to parse JWT payload: {str(e)}"

    # Signature verification
    if secret:
        alg = header.get("alg", "")
        if alg != "HS256":
            return False, claims, f"Unsupported JWT algorithm: {alg} (only HS256 supported in stdlib)"
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        expected_sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
        actual_sig = _b64url_decode(sig_b64)
        if not hmac.compare_digest(expected_sig, actual_sig):
            return False, claims, "JWT signature verification failed"

    # Validate standard claims
    now = time.time()
    if "exp" in claims:
        try:
            exp = float(claims["exp"])
            if now > (exp + leeway):
                return False, claims, "JWT token has expired"
        except (ValueError, TypeError):
            return False, claims, "Invalid exp claim format"

    if "nbf" in claims:
        try:
            nbf = float(claims["nbf"])
            if now < (nbf - leeway):
                return False, claims, "JWT token is not yet valid (nbf)"
        except (ValueError, TypeError):
            return False, claims, "Invalid nbf claim format"

    if expected_issuer and claims.get("iss") != expected_issuer:
        return False, claims, f"Issuer mismatch (expected {expected_issuer}, got {claims.get('iss')})"

    if expected_audience:
        aud = claims.get("aud")
        if isinstance(aud, list):
            if expected_audience not in aud:
                return False, claims, f"Audience mismatch (not in {aud})"
        elif aud != expected_audience:
            return False, claims, f"Audience mismatch (expected {expected_audience}, got {aud})"

    return True, claims, "Token valid"


# ---------------------------------------------------------------------------
# Device Posture Evaluator
# ---------------------------------------------------------------------------
class DevicePostureEvaluator:
    """Evaluates client endpoint health, security posture, and compliance checks."""

    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    UNKNOWN = "UNKNOWN"
    COMPROMISED = "COMPROMISED"

    @classmethod
    def assess_posture(cls, posture_data: Optional[dict], policy: Optional[dict] = None) -> dict:
        """Evaluates posture metrics returning full structured assessment and 4-state classification."""
        pol = policy or {
            "require_disk_encryption": True,
            "require_firewall": True,
            "require_edr": True,
            "min_os_build": 19041,
            "max_risk_score": 75,
        }
        now = time.time()
        if not posture_data or not isinstance(posture_data, dict):
            return {
                "state": cls.UNKNOWN,
                "compliant": False,
                "score": 0,
                "violations": ["No posture telemetry provided by endpoint"],
                "metrics": {},
                "evaluated_at": now,
            }

        violations = []
        score = 100

        # Check compromise indicators
        if posture_data.get("compromised", False) or posture_data.get("tamper_status") == "tampered":
            violations.append("Active endpoint compromise or tampering detected")
            return {
                "state": cls.COMPROMISED,
                "compliant": False,
                "score": 0,
                "violations": violations,
                "metrics": dict(posture_data),
                "evaluated_at": now,
            }

        # 1. Disk encryption
        if pol.get("require_disk_encryption") and not posture_data.get("disk_encrypted", True):
            violations.append("Full disk encryption (BitLocker/LUKS) is disabled")
            score -= 30

        # 2. Host firewall active
        if pol.get("require_firewall") and not posture_data.get("firewall_active", True):
            violations.append("Host firewall is disabled or not running")
            score -= 25

        # 3. EDR / Anti-malware presence
        if pol.get("require_edr"):
            edr = posture_data.get("edr_present", True) or posture_data.get("antivirus_active", True)
            if not edr:
                violations.append("No active EDR / Anti-malware agent detected")
                score -= 30

        # 4. OS Build / Patch freshness
        build_raw = posture_data.get("os_build", 22000)
        try:
            build = int(build_raw or 0)
        except (ValueError, TypeError):
            build = 0
        min_build = int(pol.get("min_os_build", 19041))
        if build > 0 and build < min_build:
            violations.append(f"Operating system build {build} is older than required minimum {min_build}")
            score -= 15

        # 5. Risk score ceiling
        endpoint_risk = int(posture_data.get("risk_score", 0) or 0)
        if endpoint_risk > pol.get("max_risk_score", 75):
            violations.append(f"Endpoint risk score {endpoint_risk} exceeds maximum acceptable threshold")
            score -= 30

        final_score = max(0, score)
        compliant = len(violations) == 0 and final_score >= 70
        state = cls.COMPLIANT if compliant else cls.NON_COMPLIANT

        return {
            "state": state,
            "compliant": compliant,
            "score": final_score,
            "violations": violations,
            "metrics": dict(posture_data),
            "evaluated_at": now,
        }

    @classmethod
    def evaluate_posture(cls, posture_data: dict, policy: Optional[dict] = None) -> Tuple[bool, List[str], int]:
        """Evaluates posture metrics against organizational zero-trust requirements.

        Returns (compliant: bool, violations: List[str], posture_score: int).
        """
        res = cls.assess_posture(posture_data, policy=policy)
        return res["compliant"], res["violations"], res["score"]

    @classmethod
    def generate_signed_report(cls, posture_data: dict, secret_key: str) -> dict:
        """Generates a cryptographically signed posture report payload."""
        now = time.time()
        payload = {
            "data": posture_data,
            "timestamp": now,
            "nonce": secrets.token_hex(8),
        }
        serialized = json.dumps(payload, sort_keys=True).encode("utf-8")
        sig = hmac.new(secret_key.encode("utf-8"), serialized, hashlib.sha256).hexdigest()
        return {
            "payload": payload,
            "signature": sig,
        }

    @classmethod
    def verify_signed_report(cls, report: dict, secret_key: str, max_age_seconds: int = 300) -> Tuple[bool, str, dict]:
        """Validates HMAC signature and freshness of a posture report."""
        if not isinstance(report, dict) or "payload" not in report or "signature" not in report:
            return False, "Malformed posture report structure", {}

        payload = report["payload"]
        sig = report["signature"]
        serialized = json.dumps(payload, sort_keys=True).encode("utf-8")
        expected_sig = hmac.new(secret_key.encode("utf-8"), serialized, hashlib.sha256).hexdigest()

        if not hmac.compare_digest(sig, expected_sig):
            return False, "Invalid cryptographic signature", {}

        timestamp = float(payload.get("timestamp", 0))
        if time.time() - timestamp > max_age_seconds:
            return False, "Posture report expired", {}

        return True, "Valid", payload.get("data", {})


# ---------------------------------------------------------------------------
# Micro-segmentation Engine (East-West traffic policy)
# ---------------------------------------------------------------------------
class MicrosegmentationManager:
    """Manages internal east-west traffic learning and zero-trust segmentation enforcement."""

    def __init__(self, mode: str = "learning"):
        self.mode = mode  # "learning" or "enforcing"
        self._observed_flows: Dict[Tuple[str, str, int, str], int] = collections.defaultdict(int)
        self._enforced_rules: Set[Tuple[str, str, int, str]] = set()
        self._lock = threading.RLock()

    def record_traffic(self, src_ip: str, dst_ip: str, dport: int, proto: str = "tcp"):
        """Records an observed east-west traffic flow during learning mode."""
        key = (str(src_ip).strip(), str(dst_ip).strip(), int(dport), str(proto).lower())
        with self._lock:
            self._observed_flows[key] += 1

    def generate_least_privilege_policies(self) -> List[dict]:
        """Compiles observed traffic into minimal-privilege allowlist policies."""
        policies = []
        with self._lock:
            for idx, ((src, dst, port, proto), hits) in enumerate(self._observed_flows.items(), start=1):
                policies.append({
                    "id": f"microseg-{idx}",
                    "name": f"EastWest-{src}-to-{dst}:{port}",
                    "src": src,
                    "dst": dst,
                    "dport": port,
                    "proto": proto,
                    "action": "accept",
                    "observed_hits": hits,
                })
        return policies

    def promote_to_enforcement(self) -> int:
        """Locks in learned flows and switches mode to enforcing."""
        with self._lock:
            self._enforced_rules = set(self._observed_flows.keys())
            self.mode = "enforcing"
            event("microsegmentation_enforcing", "info", rule_count=len(self._enforced_rules))
            return len(self._enforced_rules)

    def check_verdict(self, src_ip: str, dst_ip: str, dport: int, proto: str = "tcp") -> Tuple[str, str]:
        """Evaluates whether an internal flow is permitted under micro-segmentation."""
        if self.mode == "learning":
            self.record_traffic(src_ip, dst_ip, dport, proto)
            return "accept", "learning_mode"

        key = (str(src_ip).strip(), str(dst_ip).strip(), int(dport), str(proto).lower())
        with self._lock:
            if key in self._enforced_rules:
                return "accept", "explicit_east_west_allowlist"
            return "deny", "microsegmentation_isolation_violation"


# ---------------------------------------------------------------------------
# ZTNA Access Evaluator
# ---------------------------------------------------------------------------
class ZTNAEvaluator:
    """Evaluates contextual zero-trust application access based on identity, device posture, and tokens."""

    def __init__(self, directory: Optional[IdentityDirectory] = None, default_secret: str = ""):
        self.directory = directory or IdentityDirectory()
        self._default_secret = default_secret or secrets.token_hex(16)
        self._app_entitlements: Dict[str, dict] = {}
        self._revoked_sessions: Set[str] = set()
        self._revoked_devices: Set[str] = set()
        self._lock = threading.RLock()

    def register_app(self, app_name: str, allowed_groups: List[str],
                     min_posture_score: int = 70, require_mfa: bool = False,
                     max_risk_score: int = 75):
        clean_name = str(app_name).strip().lower()
        with self._lock:
            self._app_entitlements[clean_name] = {
                "allowed_groups": [g.lower() for g in allowed_groups],
                "min_posture_score": min_posture_score,
                "require_mfa": require_mfa,
                "max_risk_score": max_risk_score,
            }

    def issue_session(self, username: str, device_id: str, app_name: str,
                      groups: Optional[List[str]] = None, posture_state: str = "COMPLIANT",
                      ttl_seconds: int = 300, secret: str = "") -> str:
        """Issues a short-lived cryptographically signed ZTNA session token."""
        now = time.time()
        session_id = f"ztna-{secrets.token_hex(8)}"
        payload = {
            "sub": str(username).strip(),
            "device_id": str(device_id).strip(),
            "app": str(app_name).strip().lower(),
            "groups": groups or [],
            "posture": str(posture_state).upper(),
            "jti": session_id,
            "iat": int(now),
            "exp": int(now + ttl_seconds),
        }
        signing_key = secret or self._default_secret
        token = JWTValidator.create_token(payload, signing_key)
        event("ztna_session_issued", "info", user=username, app=app_name, session_id=session_id)
        return token

    def verify_session(self, token: str, app_name: str, secret: str = "") -> Tuple[bool, str, Optional[dict]]:
        """Verifies a ZTNA session token, checking signature, expiry, app scope, and revocation."""
        signing_key = secret or self._default_secret
        valid, msg, claims = JWTValidator.validate_token(token, signing_key, expected_audience=None)
        if not valid or not claims:
            return False, f"Token validation failed: {msg}", None

        session_id = claims.get("jti", "")
        device_id = claims.get("device_id", "")
        with self._lock:
            if session_id and session_id in self._revoked_sessions:
                return False, "Session has been revoked", None
            if device_id and device_id in self._revoked_devices:
                return False, "Device access has been revoked", None

        # Verify application scope
        token_app = str(claims.get("app", "")).lower()
        clean_app = str(app_name).strip().lower()
        if token_app and clean_app and token_app != clean_app and token_app != "*":
            return False, f"Token scoped for '{token_app}', not '{clean_app}'", None

        # Verify posture claim in token
        token_posture = claims.get("posture", "COMPLIANT")
        if token_posture in ("NON_COMPLIANT", "COMPROMISED"):
            return False, f"Token posture state is {token_posture}", None

        return True, "Valid", claims

    def revoke_session(self, session_id: str) -> bool:
        """Revokes an individual ZTNA session token by session ID."""
        with self._lock:
            self._revoked_sessions.add(session_id)
            event("ztna_session_revoked", "warning", session_id=session_id)
            return True

    def revoke_device(self, device_id: str) -> bool:
        """Revokes all access for a compromised or non-compliant device ID."""
        with self._lock:
            self._revoked_devices.add(device_id)
            event("ztna_device_revoked", "warning", device_id=device_id)
            return True

    def evaluate_access(self, client_ip: str, app_name: str,
                        posture_data: Optional[dict] = None,
                        token: Optional[str] = None,
                        risk_score: int = 0) -> Tuple[bool, str]:
        """Evaluates whether access is authorized based on identity, token, groups, and device posture."""
        clean_app = str(app_name).strip().lower()

        # Check if device was revoked
        with self._lock:
            entitlement = self._app_entitlements.get(clean_app)

        # 1. If token provided, validate token first
        user_identity = None
        if token:
            valid, msg, claims = self.verify_session(token, app_name=clean_app)
            if not valid:
                return False, f"ZTNA token invalid: {msg}"
            user_identity = {
                "username": claims.get("sub", ""),
                "groups": claims.get("groups", []),
                "device_id": claims.get("device_id", ""),
            }

        # 2. If no token, check IP identity binding
        if not user_identity:
            user_identity = self.directory.get_identity(client_ip)
            if not user_identity and entitlement:
                return False, "Unauthenticated client: no active identity binding or token provided"

        # Check device revocation
        if user_identity and user_identity.get("device_id"):
            with self._lock:
                if user_identity["device_id"] in self._revoked_devices:
                    return False, f"Device {user_identity['device_id']} is revoked"

        # 3. Role / Group check
        if entitlement and user_identity:
            allowed = entitlement.get("allowed_groups", [])
            user_groups = [str(g).lower() for g in user_identity.get("groups", [])]
            if allowed and not any(g in allowed for g in user_groups):
                return False, f"User {user_identity.get('username')} not in authorized groups for {app_name}"

            max_risk = entitlement.get("max_risk_score", 75)
            if risk_score > max_risk:
                return False, f"Continuous risk score {risk_score} exceeds threshold {max_risk}"

        # 4. Posture check
        if posture_data is not None:
            assessment = DevicePostureEvaluator.assess_posture(
                posture_data,
                policy={"min_posture_score": entitlement.get("min_posture_score", 70) if entitlement else 70}
            )
            if assessment["state"] == DevicePostureEvaluator.COMPROMISED:
                if user_identity and user_identity.get("device_id"):
                    self.revoke_device(user_identity["device_id"])
                return False, "Device is compromised; access blocked and device revoked"

            if not assessment["compliant"]:
                return False, f"Device posture failed: {'; '.join(assessment['violations'])}"

        return True, "Access granted"


class JITRuleManager:
    """Manages temporary firewall access rules that automatically expire."""

    def __init__(self, engine=None):
        self.engine = engine
        self._rules: Dict[str, dict] = {}
        self._lock = threading.RLock()

    def grant_access(self, user: str, src_ip: str, dst_ip: str, port: int,
                     proto: str = "tcp", duration_seconds: int = 3600,
                     justification: str = "") -> dict:
        """Issues a temporary JIT access rule."""
        rule_id = f"jit-{secrets.token_hex(4)}"
        now = time.time()
        record = {
            "id": rule_id,
            "user": user,
            "src": src_ip,
            "dst": dst_ip,
            "port": port,
            "proto": proto.lower(),
            "created_at": now,
            "expires_at": now + duration_seconds,
            "duration": duration_seconds,
            "justification": justification,
        }
        with self._lock:
            self._rules[rule_id] = record
            event("jit_rule_granted", "info", user=user, rule_id=rule_id,
                  src=src_ip, dst=dst_ip, port=port, duration=duration_seconds)
            return dict(record)

    def tick(self) -> List[str]:
        """Purges expired JIT rules."""
        now = time.time()
        expired = []
        with self._lock:
            for rid, r in list(self._rules.items()):
                if now >= r["expires_at"]:
                    expired.append(rid)
                    del self._rules[rid]

        for rid in expired:
            event("jit_rule_expired", "info", rule_id=rid)
        return expired

    def list_active(self) -> List[dict]:
        now = time.time()
        with self._lock:
            return [
                {**r, "remaining_seconds": max(0, int(r["expires_at"] - now))}
                for r in self._rules.values() if now < r["expires_at"]
            ]

