"""SentinelFW Web Application Firewall (WAF) Engine.

Provides OWASP Core Rule Set-style rule evaluation, paranoia levels 1–4,
per-request anomaly scoring, virtual hosts, bot mitigation, API protection,
upload inspection, credential-stuffing prevention, and reverse-proxy load balancing.
"""
from .rules import WAFRule, WAFRuleEngine
from .middleware import WAFMiddleware
from .vhosts import VHostManager
from .bot import BotMitigator
from .api_protect import APIProtector
from .upload import UploadScanner
from .credential import CredentialShield
from .loadbalancer import LoadBalancer
from .proxy import WAFProxyServer

__all__ = [
    "WAFRule",
    "WAFRuleEngine",
    "WAFMiddleware",
    "VHostManager",
    "BotMitigator",
    "APIProtector",
    "UploadScanner",
    "CredentialShield",
    "LoadBalancer",
    "WAFProxyServer",
]
