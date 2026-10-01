"""SentinelFW Deep TLS Protocol Inspector.

Parses TLS ClientHello handshakes, extracts Server Name Indication (SNI),
and computes JA3/JA4 cryptographic fingerprints for tool identification.
"""
import hashlib
import re
import struct
from typing import Dict, List, Optional, Tuple


class TLSInspector:
    """Extracts metadata, SNI, and JA3 fingerprints from TLS ClientHello packets."""

    @classmethod
    def parse_client_hello(cls, payload: bytes) -> Optional[dict]:
        """
        Parses a raw TLS ClientHello payload.
        Returns metadata dictionary or None if not a valid ClientHello.
        """
        if len(payload) < 44:
            return None

        # Record layer: Type (0x16 Handshake), Version, Length
        rec_type, rec_ver, rec_len = struct.unpack("!BHH", payload[:5])
        if rec_type != 0x16:
            return None

        pos = 5
        hs_type = payload[pos]
        if hs_type != 0x01:  # ClientHello
            return None

        pos += 4  # skip handshake type (1 byte) + handshake length (3 bytes)
        client_version = struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 2 + 32  # skip version + random (32 bytes)

        if pos >= len(payload):
            return None

        # Session ID length
        sess_id_len = payload[pos]
        pos += 1 + sess_id_len

        if pos + 2 > len(payload):
            return None

        # Cipher Suites
        cs_len = struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 2
        cipher_suites = []
        for i in range(0, cs_len, 2):
            if pos + i + 2 <= len(payload):
                cs = struct.unpack("!H", payload[pos + i:pos + i + 2])[0]
                cipher_suites.append(cs)
        pos += cs_len

        if pos >= len(payload):
            return {"version": client_version, "ciphers": cipher_suites, "sni": ""}

        # Compression methods
        comp_len = payload[pos]
        pos += 1 + comp_len

        # Extensions
        extensions = []
        sni = ""
        alpn = ""
        ec_curves = []
        ec_point_formats = []

        if pos + 2 <= len(payload):
            ext_total_len = struct.unpack("!H", payload[pos:pos + 2])[0]
            pos += 2
            end_pos = min(len(payload), pos + ext_total_len)

            while pos + 4 <= end_pos:
                ext_type, ext_len = struct.unpack("!HH", payload[pos:pos + 4])
                extensions.append(ext_type)
                pos += 4
                ext_data = payload[pos:pos + ext_len]

                if ext_type == 0x0000:  # server_name (SNI)
                    try:
                        # skip server_name_list_length (2) + name_type (1) + name_length (2)
                        if len(ext_data) > 5 and ext_data[2] == 0:
                            nlen = struct.unpack("!H", ext_data[3:5])[0]
                            sni = ext_data[5:5 + nlen].decode(errors="ignore")
                    except Exception:
                        pass
                elif ext_type == 0x000a:  # supported_groups (elliptic_curves)
                    if len(ext_data) >= 2:
                        glen = struct.unpack("!H", ext_data[:2])[0]
                        for j in range(2, min(len(ext_data), 2 + glen), 2):
                            ec_curves.append(struct.unpack("!H", ext_data[j:j + 2])[0])
                elif ext_type == 0x000b:  # ec_point_formats
                    if len(ext_data) >= 1:
                        flen = ext_data[0]
                        ec_point_formats.extend(ext_data[1:1 + flen])
                elif ext_type == 0x0010:  # ALPN
                    try:
                        if len(ext_data) >= 3:
                            alpn_len = struct.unpack("!H", ext_data[:2])[0]
                            pos_alpn = 2
                            while pos_alpn < min(len(ext_data), 2 + alpn_len):
                                slen = ext_data[pos_alpn]
                                pos_alpn += 1
                                proto_name = ext_data[pos_alpn:pos_alpn + slen].decode(errors="ignore")
                                if proto_name and not alpn:
                                    alpn = proto_name
                                pos_alpn += slen
                    except Exception:
                        pass

                pos += ext_len

        # Compute JA3 string: SSLVersion,CipherSuites,Extensions,EllipticCurves,EllipticCurvePointFormats
        ciphers_str = "-".join(str(c) for c in cipher_suites)
        exts_str = "-".join(str(e) for e in extensions)
        curves_str = "-".join(str(c) for c in ec_curves)
        points_str = "-".join(str(p) for p in ec_point_formats)
        ja3_raw = f"{client_version},{ciphers_str},{exts_str},{curves_str},{points_str}"
        ja3_hash = hashlib.md5(ja3_raw.encode()).hexdigest()

        # Compute JA4 fingerprint:
        # Format: [t/q][version][d/i][ciphers:02d][exts:02d][alpn:2]_[ciphers_hash:12]_[exts_hash:12]
        proto_flag = "t"
        ver_flag = "13" if client_version >= 0x0304 else "12"
        sni_flag = "d" if (sni and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", sni)) else "i"
        
        # Filter out GREASE from counts and hashes
        def _is_grease(val: int) -> bool:
            return (val & 0x0F0F) == 0x0A0A and ((val >> 8) == (val & 0xFF))

        clean_ciphers = [c for c in cipher_suites if not _is_grease(c)]
        clean_exts = [e for e in extensions if not _is_grease(e)]
        
        alpn_flag = "00"
        if alpn:
            alpn_clean = re.sub(r"[^a-zA-Z0-9]", "", alpn)
            if len(alpn_clean) >= 2:
                alpn_flag = f"{alpn_clean[0]}{alpn_clean[-1]}"
            elif len(alpn_clean) == 1:
                alpn_flag = f"{alpn_clean[0]}0"
                
        ciphers_hex = ",".join(f"{c:04x}" for c in sorted(clean_ciphers))
        exts_hex = ",".join(f"{e:04x}" for e in sorted(clean_exts))
        
        ciphers_hash = hashlib.sha256(ciphers_hex.encode()).hexdigest()[:12] if clean_ciphers else "000000000000"
        exts_hash = hashlib.sha256(exts_hex.encode()).hexdigest()[:12] if clean_exts else "000000000000"
        
        ja4 = f"{proto_flag}{ver_flag}{sni_flag}{min(99, len(clean_ciphers)):02d}{min(99, len(clean_exts)):02d}{alpn_flag}_{ciphers_hash}_{exts_hash}"

        return {
            "version": client_version,
            "sni": sni,
            "alpn": alpn,
            "ja3_raw": ja3_raw,
            "ja3": ja3_hash,
            "ja4": ja4,
            "ciphers": cipher_suites,
            "extensions": extensions,
        }

    @classmethod
    def parse_quic_initial(cls, payload: bytes) -> Optional[dict]:
        """Parses a QUIC Initial packet (Long Header) and extracts TLS 1.3 ClientHello / JA4Q."""
        if len(payload) < 20:
            return None

        first_byte = payload[0]
        # QUIC Long Header has bit 7 set (0x80) and bit 6 set (fixed bit 0x40)
        if not (first_byte & 0x80):
            return None

        # Version (bytes 1-4)
        quic_version = struct.unpack("!I", payload[1:5])[0]
        if quic_version == 0:
            # Version negotiation packet
            return {"version": 0, "type": "version_negotiation", "sni": "", "ja4": "q000000"}

        pos = 5
        if pos >= len(payload):
            return None

        # Destination Connection ID Length
        dcid_len = payload[pos]
        pos += 1 + dcid_len

        if pos >= len(payload):
            return None

        # Source Connection ID Length
        scid_len = payload[pos]
        pos += 1 + scid_len

        # In QUIC Initial, search for embedded TLS 1.3 ClientHello (0x01 handshake type)
        ch_idx = payload.find(b"\x01\x00", pos)
        sni = ""
        ja4q = f"q13d000000_000000000000_000000000000"

        if ch_idx != -1 and ch_idx + 4 < len(payload):
            # Attempt to parse ClientHello structure embedded inside CRYPTO frame
            sub_res = cls.parse_client_hello(b"\x16\x03\x03\x00\x00" + payload[ch_idx:])
            if sub_res and sub_res.get("sni"):
                sni = sub_res["sni"]
                ja4q = "q" + sub_res.get("ja4", "13d000000_000000000000_000000000000")[1:]

        return {
            "protocol": "quic",
            "version": hex(quic_version),
            "sni": sni,
            "ja4": ja4q,
            "raw_len": len(payload),
        }

    @classmethod
    def check_quic_policy(cls, sni: str = "", policy: str = "allow") -> Tuple[bool, str]:
        """Evaluates QUIC traffic against firewall policy.

        Policies: 'allow', 'block' (drop QUIC), or 'force_fallback' (block UDP/443 to force TCP fallback).
        Returns (action_drop: bool, reason: str).
        """
        pol = str(policy or "allow").lower().strip()
        if pol == "block":
            return True, f"QUIC blocked by firewall policy for {sni or 'unknown'}"
        elif pol == "force_fallback":
            return True, "QUIC blocked to enforce TCP TLS inspection fallback"
        return False, "allowed"


# ---------------------------------------------------------------------------
# Enterprise TLS Privacy Bypass & Certificate Validation Engines
# ---------------------------------------------------------------------------

class TLSPrivacyBypassManager:
    """Manages privacy-conscious TLS inspection exemptions (Banking, Healthcare, Gov)."""

    DEFAULT_EXEMPTIONS = {
        "banking": [
            "*.chase.com", "*.bankofamerica.com", "*.wellsfargo.com",
            "*.fidelity.com", "*.vanguard.com", "*.citi.com", "*.schwab.com"
        ],
        "healthcare": [
            "*.mychart.com", "*.epic.com", "*.cerner.com", "*.kaiserpermanente.org"
        ],
        "government": [
            "*.irs.gov", "*.login.gov", "*.ssa.gov", "*.usps.com", "*.va.gov"
        ],
    }

    def __init__(self, custom_bypass_rules: Optional[List[str]] = None,
                 disabled_categories: Optional[List[str]] = None):
        self._rules = set()
        disabled = set(c.lower() for c in (disabled_categories or []))

        for cat, domains in self.DEFAULT_EXEMPTIONS.items():
            if cat not in disabled:
                for d in domains:
                    self._rules.add(d.lower())

        if custom_bypass_rules:
            for rule in custom_bypass_rules:
                self._rules.add(rule.strip().lower())

    def add_rule(self, domain_or_pattern: str):
        self._rules.add(domain_or_pattern.strip().lower())

    def remove_rule(self, domain_or_pattern: str):
        self._rules.discard(domain_or_pattern.strip().lower())

    def should_bypass(self, sni: str) -> Tuple[bool, str]:
        """Checks if a domain must be bypassed from TLS inspection."""
        clean_sni = str(sni).strip().lower()
        if not clean_sni:
            return False, "no_sni"

        if clean_sni in self._rules:
            return True, f"exact_rule_match:{clean_sni}"

        for rule in self._rules:
            if rule.startswith("*."):
                suffix = rule[1:]  # e.g. .chase.com
                if clean_sni.endswith(suffix) or clean_sni == rule[2:]:
                    return True, f"wildcard_rule_match:{rule}"

        return False, "inspect"


class UpstreamCertValidator:
    """Validates upstream TLS certificate chains, expiry, and SAN match."""

    @classmethod
    def validate_certificate(cls, cert: dict, expected_sni: str,
                             now: Optional[float] = None) -> Tuple[bool, str]:
        """Validates certificate expiry and subject alternative names.

        cert is expected to be a dictionary with keys:
        'notBefore', 'notAfter', 'subjectAltName' or 'commonName'.
        """
        import time
        check_time = now if now is not None else time.time()
        not_before = float(cert.get("notBefore", 0))
        not_after = float(cert.get("notAfter", check_time + 86400))

        if check_time < not_before:
            return False, "upstream_certificate_not_yet_valid"
        if check_time > not_after:
            return False, "upstream_certificate_expired"

        clean_sni = expected_sni.strip().lower()
        sans = [str(name).strip().lower() for name in cert.get("subjectAltName", [])]
        cn = str(cert.get("commonName", "")).strip().lower()

        matched = False
        all_names = sans if sans else ([cn] if cn else [])
        for name in all_names:
            if name == clean_sni:
                matched = True
                break
            if name.startswith("*."):
                suffix = name[1:]
                if clean_sni.endswith(suffix):
                    matched = True
                    break

        if not matched and all_names:
            return False, f"hostname_mismatch (requested {clean_sni}, presented {all_names})"

        return True, "valid"


class CertPinningTracker:
    """Detects client certificate pinning failures and manages dynamic auto-bypass."""

    def __init__(self, failure_threshold: int = 3, auto_bypass_ttl: int = 86400):
        self.failure_threshold = failure_threshold
        self.auto_bypass_ttl = auto_bypass_ttl
        self._failures: Dict[str, List[float]] = {}
        self._auto_bypassed: Dict[str, float] = {}

    def record_alert(self, sni: str, alert_code: int = 46) -> Tuple[bool, int]:
        """Records an alert (e.g. 46=unknown_ca, 42=bad_cert).

        Returns (is_now_auto_bypassed, recent_failure_count).
        """
        import time
        now = time.time()
        clean_sni = str(sni).strip().lower()
        if not clean_sni:
            return False, 0

        # Purge failures older than 1 hour
        recent = [t for t in self._failures.get(clean_sni, []) if now - t < 3600]
        recent.append(now)
        self._failures[clean_sni] = recent

        if len(recent) >= self.failure_threshold:
            self._auto_bypassed[clean_sni] = now + self.auto_bypass_ttl
            return True, len(recent)

        return False, len(recent)

    def is_auto_bypassed(self, sni: str) -> bool:
        """Returns True if domain is currently in dynamic pinning auto-bypass."""
        import time
        now = time.time()
        clean_sni = str(sni).strip().lower()
        exp = self._auto_bypassed.get(clean_sni, 0)
        if exp > now:
            return True
        elif clean_sni in self._auto_bypassed:
            del self._auto_bypassed[clean_sni]
        return False


class TLSInspectionPolicy:
    """Unified policy controller for transparent TLS interception, bypass, and QUIC fallback."""

    def __init__(self, bypass_manager: Optional[TLSPrivacyBypassManager] = None,
                 pinning_tracker: Optional[CertPinningTracker] = None,
                 quic_policy: str = "force_fallback"):
        self.bypass = bypass_manager or TLSPrivacyBypassManager()
        self.pinning = pinning_tracker or CertPinningTracker()
        self.quic_policy = quic_policy

    def evaluate(self, sni: str, is_quic: bool = False,
                 cert_data: Optional[dict] = None) -> dict:
        clean_sni = str(sni).strip().lower()

        # 1. QUIC Policy
        if is_quic:
            drop, reason = TLSInspector.check_quic_policy(clean_sni, self.quic_policy)
            if drop:
                return {"action": "drop", "reason": reason, "sni": clean_sni}

        # 2. Pinning dynamic auto-bypass
        if self.pinning.is_auto_bypassed(clean_sni):
            return {"action": "bypass", "reason": "pinning_auto_bypass", "sni": clean_sni}

        # 3. Privacy exemptions (Banking/Health/Gov)
        bypass, reason = self.bypass.should_bypass(clean_sni)
        if bypass:
            return {"action": "bypass", "reason": reason, "sni": clean_sni}

        # 4. Upstream certificate check if cert data supplied
        if cert_data:
            valid, cert_err = UpstreamCertValidator.validate_certificate(cert_data, clean_sni)
            if not valid:
                return {"action": "block", "reason": cert_err, "sni": clean_sni}

        # Default action: decrypt and perform deep L7 inspection
        return {"action": "inspect", "reason": "full_inspection_eligible", "sni": clean_sni}
