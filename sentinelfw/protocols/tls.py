"""SentinelFW Deep TLS Protocol Inspector.

Parses TLS ClientHello handshakes, extracts Server Name Indication (SNI),
and computes JA3/JA4 cryptographic fingerprints for tool identification.
"""
import hashlib
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

                pos += ext_len

        # Compute JA3 string: SSLVersion,CipherSuites,Extensions,EllipticCurves,EllipticCurvePointFormats
        ciphers_str = "-".join(str(c) for c in cipher_suites)
        exts_str = "-".join(str(e) for e in extensions)
        curves_str = "-".join(str(c) for c in ec_curves)
        points_str = "-".join(str(p) for p in ec_point_formats)
        ja3_raw = f"{client_version},{ciphers_str},{exts_str},{curves_str},{points_str}"
        ja3_hash = hashlib.md5(ja3_raw.encode()).hexdigest()

        return {
            "version": client_version,
            "sni": sni,
            "ja3_raw": ja3_raw,
            "ja3": ja3_hash,
            "ciphers": cipher_suites,
            "extensions": extensions,
        }
