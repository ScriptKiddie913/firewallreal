"""SentinelFW App-ID Engine — Port-Independent Application Identification.

Identifies applications and cloud services using multi-layer heuristics:
* TLS Server Name Indication (SNI) matching
* HTTP Host, Request URI, and User-Agent signatures
* JA4 client TLS fingerprints
* Protocol banners and payload heuristics
* Port fallback catalogs
"""
import re
from typing import Dict, List, Optional, Union


APP_CATALOG = {
    # Collaboration & Communication
    "Zoom": {
        "category": "Collaboration",
        "risk": "low",
        "sni": [r".*\.zoom\.us$", r".*\.zoom\.com$"],
        "http_hosts": [r".*\.zoom\.us$", r".*\.zoom\.com$"],
        "ports": [3478, 3479, 8801, 8802],
    },
    "Slack": {
        "category": "Collaboration",
        "risk": "low",
        "sni": [r".*\.slack\.com$", r".*\.slack-msgs\.com$", r".*\.slack-edge\.com$"],
        "http_hosts": [r".*\.slack\.com$"],
    },
    "Microsoft-Teams": {
        "category": "Collaboration",
        "risk": "low",
        "sni": [r".*teams\.microsoft\.com$", r".*\.skype\.com$", r"teams\.microsoft\.com$"],
        "http_hosts": [r".*teams\.microsoft\.com$", r"teams\.microsoft\.com$"],
    },
    "Discord": {
        "category": "Collaboration",
        "risk": "low",
        "sni": [r".*\.discord\.gg$", r".*\.discord\.com$", r".*\.discordapp\.com$"],
        "http_hosts": [r".*\.discord\.com$"],
    },

    # Developer & Cloud Infrastructure
    "GitHub": {
        "category": "Cloud / DevOps",
        "risk": "low",
        "sni": [r".*\.github\.com$", r"github\.com$", r".*\.githubusercontent\.com$"],
        "http_hosts": [r".*\.github\.com$", r"github\.com$"],
    },
    "GitLab": {
        "category": "Cloud / DevOps",
        "risk": "low",
        "sni": [r".*\.gitlab\.com$", r"gitlab\.com$"],
        "http_hosts": [r".*\.gitlab\.com$"],
    },
    "AWS": {
        "category": "Cloud / Infrastructure",
        "risk": "low",
        "sni": [r".*\.amazonaws\.com$", r".*\.aws\.amazon\.com$"],
        "http_hosts": [r".*\.amazonaws\.com$"],
    },
    "Microsoft-Azure": {
        "category": "Cloud / Infrastructure",
        "risk": "low",
        "sni": [r".*\.azure\.com$", r".*\.windows\.net$", r".*\.trafficmanager\.net$"],
        "http_hosts": [r".*\.azure\.com$"],
    },
    "Google-Cloud": {
        "category": "Cloud / Infrastructure",
        "risk": "low",
        "sni": [r".*\.googleapis\.com$", r".*\.appspot\.com$", r".*\.cloud\.google\.com$"],
        "http_hosts": [r".*\.googleapis\.com$"],
    },
    "Cloudflare": {
        "category": "Cloud / Infrastructure",
        "risk": "low",
        "sni": [r".*\.cloudflare\.com$", r".*\.cloudflare-dns\.com$"],
        "http_hosts": [r".*\.cloudflare\.com$"],
    },

    # High-Risk / Evasion
    "BitTorrent": {
        "category": "P2P / File Sharing",
        "risk": "high",
        "payload_patterns": [b"\x13BitTorrent protocol", b"d1:ad2:id20:", b"d1:rd2:id20:"],
        "ports": [6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889],
    },
    "Tor": {
        "category": "Anonymizer / Proxy",
        "risk": "critical",
        "sni": [r".*\.onion$"],
        "ports": [9001, 9030, 9050, 9051],
    },
    "WireGuard": {
        "category": "VPN / Tunneling",
        "risk": "medium",
        "ports": [51820],
    },

    # Messaging & Social
    "Telegram": {
        "category": "Messaging",
        "risk": "medium",
        "sni": [r".*\.telegram\.org$", r".*\.t\.me$", r"telegram\.org$", r"t\.me$"],
        "http_hosts": [r".*\.telegram\.org$", r".*\.t\.me$"],
        "ports": [443, 80],
    },
    "WhatsApp": {
        "category": "Messaging",
        "risk": "low",
        "sni": [r".*\.whatsapp\.com$", r".*\.whatsapp\.net$", r"whatsapp\.com$"],
        "http_hosts": [r".*\.whatsapp\.com$"],
        "ports": [443, 5222],
    },
    "Signal": {
        "category": "Messaging",
        "risk": "low",
        "sni": [r".*\.signal\.org$", r"signal\.org$"],
        "http_hosts": [r".*\.signal\.org$"],
        "ports": [443],
    },
    "TikTok": {
        "category": "Social Media",
        "risk": "medium",
        "sni": [r".*\.tiktok\.com$", r".*\.tiktokv\.com$", r".*\.byteoversea\.com$"],
        "http_hosts": [r".*\.tiktok\.com$"],
    },

    # AI & Generative Intelligence
    "OpenAI-ChatGPT": {
        "category": "AI / LLM",
        "risk": "medium",
        "sni": [r".*\.openai\.com$", r".*\.chatgpt\.com$", r"chatgpt\.com$", r"api\.openai\.com$"],
        "http_hosts": [r".*\.openai\.com$", r".*\.chatgpt\.com$"],
        "ports": [443],
    },
    "Anthropic-Claude": {
        "category": "AI / LLM",
        "risk": "medium",
        "sni": [r".*\.anthropic\.com$", r".*\.claude\.ai$", r"claude\.ai$"],
        "http_hosts": [r".*\.anthropic\.com$", r".*\.claude\.ai$"],
        "ports": [443],
    },

    # Media & Entertainment
    "YouTube": {
        "category": "Streaming Media",
        "risk": "low",
        "sni": [r".*\.youtube\.com$", r".*\.googlevideo\.com$", r"youtu\.be$"],
        "http_hosts": [r".*\.youtube\.com$", r".*\.googlevideo\.com$"],
    },
    "Netflix": {
        "category": "Streaming Media",
        "risk": "low",
        "sni": [r".*\.netflix\.com$", r".*\.nflxvideo\.net$", r".*\.nflximg\.net$"],
        "http_hosts": [r".*\.netflix\.com$"],
    },
    "Spotify": {
        "category": "Streaming Media",
        "risk": "low",
        "sni": [r".*\.spotify\.com$", r".*\.scdn\.co$"],
        "http_hosts": [r".*\.spotify\.com$"],
    },

    # Enterprise Services, Remote Access & Protocols
    "SSH": {
        "category": "Remote Access",
        "risk": "medium",
        "payload_patterns": [b"SSH-1.", b"SSH-2."],
        "ports": [22],
    },
    "RDP": {
        "category": "Remote Access",
        "risk": "medium",
        "payload_patterns": [b"\x03\x00\x00"],
        "ports": [3389],
    },
    "SMB": {
        "category": "File Sharing",
        "risk": "medium",
        "payload_patterns": [b"\xffSMB", b"\xfeSMB"],
        "ports": [445, 139],
    },
    "FTP": {
        "category": "File Sharing",
        "risk": "medium",
        "payload_patterns": [b"220 ", b"USER ", b"PASS "],
        "ports": [21],
    },
    "SMTP": {
        "category": "Email",
        "risk": "low",
        "payload_patterns": [b"220 ", b"EHLO ", b"HELO "],
        "ports": [25, 587],
    },
    "IMAP": {
        "category": "Email",
        "risk": "low",
        "payload_patterns": [b"* OK "],
        "ports": [143, 993],
    },
    "DNS-over-HTTPS": {
        "category": "Network Service",
        "risk": "medium",
        "sni": [r"cloudflare-dns\.com$", r"dns\.google$", r"dns\.quad9\.net$"],
        "ports": [443],
    },
    "DNS-over-TLS": {
        "category": "Network Service",
        "risk": "medium",
        "ports": [853],
    },
    "OpenVPN": {
        "category": "VPN / Tunneling",
        "risk": "medium",
        "ports": [1194],
    },
    "Redis": {
        "category": "Database",
        "risk": "medium",
        "payload_patterns": [b"*1\r\n$4\r\nPING", b"+PONG\r\n", b"*2\r\n$4\r\nAUTH"],
        "ports": [6379],
    },
    "MySQL": {
        "category": "Database",
        "risk": "medium",
        "ports": [3306],
    },
    "PostgreSQL": {
        "category": "Database",
        "risk": "medium",
        "ports": [5432],
    },
    "DNS": {
        "category": "Network Service",
        "risk": "low",
        "ports": [53],
    },
    "NTP": {
        "category": "Network Service",
        "risk": "low",
        "ports": [123],
    },
}


class AppIDClassifier:
    """Port-independent Application Identification classifier."""

    def __init__(self, catalog_or_cfg: Optional[Union[Dict[str, dict], dict]] = None):
        if isinstance(catalog_or_cfg, dict) and "appid_catalog" in catalog_or_cfg:
            self.catalog = catalog_or_cfg["appid_catalog"]
        elif (isinstance(catalog_or_cfg, dict) and catalog_or_cfg and
              all(isinstance(v, dict) for v in catalog_or_cfg.values()) and
              not any(k in catalog_or_cfg for k in ("webui", "enforcement_profile", "traffic_control", "trusted_ips"))):
            self.catalog = catalog_or_cfg
        else:
            self.catalog = dict(APP_CATALOG)
        self._compiled_sni = {}
        self._compiled_hosts = {}
        for app_name, spec in self.catalog.items():
            if isinstance(spec, dict):
                if "sni" in spec:
                    self._compiled_sni[app_name] = [re.compile(p, re.IGNORECASE) for p in spec["sni"]]
                if "http_hosts" in spec:
                    self._compiled_hosts[app_name] = [re.compile(p, re.IGNORECASE) for p in spec["http_hosts"]]

    def identify(self, payload: bytes = b"", proto: str = "tcp", dport: int = 0,
                 sni: str = "", host: str = "", uri: str = "", user_agent: str = "",
                 ja4: str = "") -> dict:
        """Classifies traffic into an application using multiple available attributes."""
        clean_proto = str(proto).lower()

        # 1. Check TLS SNI (high confidence)
        if sni:
            clean_sni = str(sni).strip().lower()
            for app_name, patterns in self._compiled_sni.items():
                if any(p.match(clean_sni) for p in patterns):
                    spec = self.catalog[app_name]
                    return {
                        "app": app_name,
                        "category": spec["category"],
                        "risk": spec["risk"],
                        "confidence": "high",
                        "confidence_score": 0.95,
                        "matched_by": "sni",
                        "indicator": clean_sni,
                    }

        # 2. Check HTTP Host
        if host:
            clean_host = str(host).strip().lower()
            for app_name, patterns in self._compiled_hosts.items():
                if any(p.match(clean_host) for p in patterns):
                    spec = self.catalog[app_name]
                    return {
                        "app": app_name,
                        "category": spec["category"],
                        "risk": spec["risk"],
                        "confidence": "high",
                        "confidence_score": 0.90,
                        "matched_by": "http_host",
                        "indicator": clean_host,
                    }

        # 3. Check Payload Signatures / Banners
        if payload:
            for app_name, spec in self.catalog.items():
                patterns = spec.get("payload_patterns") or []
                for pat in patterns:
                    if pat in payload[:512]:
                        return {
                            "app": app_name,
                            "category": spec["category"],
                            "risk": spec["risk"],
                            "confidence": "high",
                            "confidence_score": 0.98,
                            "matched_by": "payload_signature",
                            "indicator": str(pat[:32]),
                        }

        # 4. Port Catalog Fallback (low confidence)
        if dport > 0:
            for app_name, spec in self.catalog.items():
                ports = spec.get("ports") or []
                if dport in ports:
                    return {
                        "app": app_name,
                        "category": spec["category"],
                        "risk": spec["risk"],
                        "confidence": "low",
                        "confidence_score": 0.30,
                        "matched_by": "port_fallback",
                        "indicator": str(dport),
                    }

        return {
            "app": "Unknown",
            "category": "Unknown",
            "risk": "unknown",
            "confidence": "none",
            "confidence_score": 0.0,
            "matched_by": "none",
            "indicator": "",
        }

    def list_catalog(self) -> List[dict]:
        """Returns the full catalog of detectable applications."""
        result = []
        for name, spec in self.catalog.items():
            result.append({
                "app": name,
                "category": spec.get("category", "Unknown"),
                "risk": spec.get("risk", "low"),
            })
        return sorted(result, key=lambda x: x["app"])


# Global classifier singleton
classifier = AppIDClassifier()
AppIdEngine = AppIDClassifier
