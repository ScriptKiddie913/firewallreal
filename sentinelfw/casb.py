"""SentinelFW Cloud Access Security Broker (CASB) & Shadow IT Subsystem.

Provides enterprise SaaS visibility, tenant restriction header injection,
unsanctioned SaaS discovery, and bandwidth accounting.
"""
import collections
import threading
import time
from typing import Dict, List, Optional, Set, Tuple


class CASBAction:
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    RESTRICT_TENANT = "RESTRICT_TENANT"


class TenantRestrictionEngine:
    """Manages tenant restriction headers for Microsoft 365, Google Workspace, and Slack."""

    def __init__(self, m365_tenants: Optional[List[str]] = None,
                 m365_context_id: str = "",
                 google_domains: Optional[List[str]] = None,
                 slack_workspaces: Optional[List[str]] = None):
        self.m365_tenants = m365_tenants or []
        self.m365_context_id = m365_context_id
        self.google_domains = google_domains or []
        self.slack_workspaces = slack_workspaces or []

    def get_headers_for_host(self, host: str) -> Dict[str, str]:
        """Returns HTTP headers to inject for authorized enterprise tenant access."""
        clean_host = host.split(":")[0].strip().lower()
        headers = {}

        # Microsoft 365 endpoints (login.microsoftonline.com, login.windows.net, etc.)
        if self.m365_tenants and any(clean_host.endswith(dom) for dom in ("microsoftonline.com", "windows.net", "office.com", "microsoft.com")):
            headers["Restrict-Access-To-Tenants"] = ", ".join(self.m365_tenants)
            if self.m365_context_id:
                headers["Restrict-Access-Context"] = self.m365_context_id

        # Google Workspace endpoints (accounts.google.com, etc.)
        if self.google_domains and any(clean_host.endswith(dom) for dom in ("google.com", "googleapis.com")):
            headers["X-GoogApps-Allowed-Domains"] = ", ".join(self.google_domains)

        # Slack endpoints
        if self.slack_workspaces and clean_host.endswith("slack.com"):
            headers["X-Slack-Allowed-Workspaces-Requester"] = ", ".join(self.slack_workspaces)

        return headers


class ShadowITEngine:
    """Discovers unsanctioned SaaS applications and tracks data transfer accounting."""

    DEFAULT_SAAS_CATALOG = {
        "Microsoft 365": {"domains": ["*.office.com", "*.microsoft.com", "*.sharepoint.com"], "sanctioned": True, "category": "Productivity"},
        "Google Workspace": {"domains": ["*.google.com", "*.drive.google.com"], "sanctioned": True, "category": "Productivity"},
        "Salesforce": {"domains": ["*.salesforce.com", "*.force.com"], "sanctioned": True, "category": "CRM"},
        "GitHub": {"domains": ["*.github.com"], "sanctioned": True, "category": "DevTools"},
        "WeTransfer": {"domains": ["*.wetransfer.com"], "sanctioned": False, "category": "CloudStorage"},
        "Mega": {"domains": ["*.mega.nz", "*.mega.io"], "sanctioned": False, "category": "CloudStorage"},
        "Personal Dropbox": {"domains": ["*.dropbox.com"], "sanctioned": False, "category": "CloudStorage"},
        "TikTok": {"domains": ["*.tiktok.com"], "sanctioned": False, "category": "SocialMedia"},
        "Telegram Web": {"domains": ["*.telegram.org", "*.web.telegram.org"], "sanctioned": False, "category": "Messaging"},
    }

    def __init__(self, catalog: Optional[dict] = None):
        self._catalog = catalog or self.DEFAULT_SAAS_CATALOG
        self._lock = threading.RLock()
        # Accounting: (user_or_ip, app_name) -> {requests, upload_bytes, download_bytes, first_seen, last_seen}
        self._accounting: Dict[Tuple[str, str], dict] = collections.defaultdict(
            lambda: {"requests": 0, "upload_bytes": 0, "download_bytes": 0, "first_seen": time.time(), "last_seen": time.time()}
        )

    def identify_app(self, host: str) -> Optional[Tuple[str, dict]]:
        clean_host = host.split(":")[0].strip().lower()
        for app_name, info in self._catalog.items():
            for dom in info["domains"]:
                if dom.startswith("*."):
                    suffix = dom[1:]
                    if clean_host.endswith(suffix) or clean_host == dom[2:]:
                        return app_name, info
                elif clean_host == dom:
                    return app_name, info
        return None

    def record_traffic(self, user_or_ip: str, host: str, upload_bytes: int = 0, download_bytes: int = 0) -> Optional[dict]:
        """Records bandwidth accounting and returns SaaS metadata if application recognized."""
        identified = self.identify_app(host)
        if not identified:
            return None

        app_name, info = identified
        key = (user_or_ip.strip(), app_name)
        now = time.time()

        with self._lock:
            rec = self._accounting[key]
            rec["requests"] += 1
            rec["upload_bytes"] += upload_bytes
            rec["download_bytes"] += download_bytes
            rec["last_seen"] = now

        return {
            "app_name": app_name,
            "category": info["category"],
            "sanctioned": info["sanctioned"],
            "upload_bytes": upload_bytes,
            "download_bytes": download_bytes,
        }

    def get_unsanctioned_summary(self) -> List[dict]:
        """Returns summary of all shadow IT data flows to unsanctioned applications."""
        summary = []
        with self._lock:
            for (user_or_ip, app_name), stats in self._accounting.items():
                app_info = self._catalog.get(app_name, {})
                if not app_info.get("sanctioned", False):
                    summary.append({
                        "user_or_ip": user_or_ip,
                        "app_name": app_name,
                        "category": app_info.get("category", "Unknown"),
                        "requests": stats["requests"],
                        "upload_bytes": stats["upload_bytes"],
                        "download_bytes": stats["download_bytes"],
                        "first_seen": stats["first_seen"],
                        "last_seen": stats["last_seen"],
                    })
        return summary
