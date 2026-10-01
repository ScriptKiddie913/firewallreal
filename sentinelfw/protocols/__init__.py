"""SentinelFW Deep Protocol Inspection Suite."""

from .dns import DNSInspector
from .ftp import FTPInspector
from .http import HTTPInspector
from .smb import SMBInspector
from .smtp import SMTPInspector
from .ssh import SSHInspector
from .tls import TLSInspector


class ProtocolAnalyzer:
    """Unified L7 protocol analysis engine combining specialized protocol decoders."""

    def __init__(self, cfg=None):
        self.cfg = cfg or {}
        self.dns = DNSInspector
        self.http = HTTPInspector
        self.tls = TLSInspector
        self.ssh = SSHInspector
        self.ftp = FTPInspector
        self.smb = SMBInspector
        self.smtp = SMTPInspector

    def analyze_payload(self, proto_or_payload, port: int = 0, payload: bytes = b"", **kw) -> dict:
        """Inspects payload bytes according to protocol type and port."""
        if isinstance(proto_or_payload, (bytes, bytearray)):
            raw = bytes(proto_or_payload)
            proto = str(kw.get("proto", "tcp")).lower()
            dport = port or int(kw.get("dport", 0))
        else:
            proto = str(proto_or_payload).lower()
            dport = port or int(kw.get("dport", 0))
            raw = payload or kw.get("payload", b"")

        if not raw:
            return {"protocol": proto, "inspected": False}

        if proto == "tcp":
            if dport in (80, 8080, 8000, 8888) or raw.startswith((b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ")):
                atk, details = self.http.inspect_request(raw)
                return {"protocol": "http", "inspected": True, "attack": atk, "details": details}
            elif dport in (443, 8443, 9443) or raw.startswith(b"\x16\x03"):
                ch = self.tls.parse_client_hello(raw)
                return {"protocol": "tls", "inspected": True, "client_hello": ch}
            elif dport == 22 or raw.startswith(b"SSH-"):
                banner = self.ssh.parse_banner(raw) if hasattr(self.ssh, "parse_banner") else str(raw[:50])
                return {"protocol": "ssh", "inspected": True, "banner": banner}
        elif proto == "udp":
            if dport == 53:
                return {"protocol": "dns", "inspected": True}
        return {"protocol": proto, "inspected": False}

    analyze_packet = analyze_payload


__all__ = [
    "DNSInspector",
    "FTPInspector",
    "HTTPInspector",
    "SMBInspector",
    "SMTPInspector",
    "SSHInspector",
    "TLSInspector",
    "ProtocolAnalyzer",
]
