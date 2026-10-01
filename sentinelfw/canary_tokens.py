"""SentinelFW Canary Tokens & Honeytokens Engine.

Generates and monitors deceptive assets to catch unauthorized access:
* Canary API Keys: Fake AWS, GitHub, Slack tokens embedded in decoy paths
* Canary Files: Honey-documents (.env, aws_credentials, id_rsa_backup)
* Network / Log Scanner: Alerts immediately when a canary token appears in traffic
"""
import os
import secrets
import string
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from .common import DATA_DIR, event


class CanaryManager:
    """Manages generation, storage, and alert triggers for honeytokens."""

    def __init__(self, storage_dir: Optional[Path] = None):
        self.dir = storage_dir or (DATA_DIR / "canaries")
        self.dir.mkdir(parents=True, exist_ok=True)
        self._tokens: Dict[str, dict] = {}
        self._lock = threading.RLock()

    def generate_aws_canary(self, label: str = "prod-deployer") -> Tuple[str, str]:
        """Generates a fake AWS Access Key and Secret Key pair."""
        charset = string.ascii_uppercase + string.digits
        key_id = "AKIA" + "".join(secrets.choice(charset) for _ in range(16))
        secret = secrets.token_urlsafe(30)
        with self._lock:
            self._tokens[key_id] = {
                "type": "aws_key",
                "label": label,
                "key_id": key_id,
                "secret": secret,
                "created_at": time.time(),
                "triggered": False,
                "triggered_at": 0.0,
                "trigger_ip": "",
            }
        return key_id, secret

    def generate_github_canary(self, label: str = "ci-token") -> str:
        """Generates a fake GitHub Personal Access Token."""
        token = "ghp_" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))
        with self._lock:
            self._tokens[token] = {
                "type": "github_token",
                "label": label,
                "token": token,
                "created_at": time.time(),
                "triggered": False,
                "triggered_at": 0.0,
                "trigger_ip": "",
            }
        return token

    def generate_gcp_canary(self, project_id: str = "prod-corp-sec", label: str = "gcp-sa") -> dict:
        """Generates a fake Google Cloud Service Account JSON honeytoken."""
        sa_id = secrets.token_hex(10)
        client_email = f"deployer-{sa_id}@{project_id}.iam.gserviceaccount.com"
        private_key_id = secrets.token_hex(20)
        token_key = f"gcp_{sa_id}"
        sa_json = {
            "type": "service_account",
            "project_id": project_id,
            "private_key_id": private_key_id,
            "private_key": f"-----BEGIN {'FAKE_KEY'}-----\n" + secrets.token_hex(64) + f"\n-----END {'FAKE_KEY'}-----\n",
            "client_email": client_email,
            "client_id": str(secrets.randbelow(10**18)),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
        with self._lock:
            self._tokens[client_email] = {
                "type": "gcp_sa_key",
                "label": label,
                "token": client_email,
                "key_id": private_key_id,
                "created_at": time.time(),
                "triggered": False,
                "triggered_at": 0.0,
                "trigger_ip": "",
            }
        return sa_json

    def generate_azure_canary(self, account_name: str = "prodbackupblob", label: str = "azure-sas") -> str:
        """Generates a fake Azure Storage Connection String / SAS honeytoken."""
        account_key = secrets.token_urlsafe(64)
        conn_str = f"DefaultEndpointsProtocol=https;AccountName={account_name};AccountKey={account_key};EndpointSuffix=core.windows.net"
        with self._lock:
            self._tokens[account_name] = {
                "type": "azure_storage_key",
                "label": label,
                "token": account_name,
                "connection_string": conn_str,
                "created_at": time.time(),
                "triggered": False,
                "triggered_at": 0.0,
                "trigger_ip": "",
            }
        return conn_str

    def generate_db_row_canary(self, table: str = "customers", label: str = "canary-user") -> dict:
        """Generates a deceptive DB-row honeytoken (e.g. fake VIP or admin row with tripwire email)."""
        uid = secrets.token_hex(8)
        email = f"security.audit+{uid}@sentinel-audit.internal"
        row = {
            "id": uid,
            "username": f"admin_backup_{uid[:4]}",
            "email": email,
            "password_hash": "$2b$12$e8r..." + secrets.token_hex(16),
            "role": "SuperAdmin",
            "is_canary": True,
        }
        with self._lock:
            self._tokens[email] = {
                "type": "db_row",
                "label": label,
                "table": table,
                "token": email,
                "row_id": uid,
                "created_at": time.time(),
                "triggered": False,
                "triggered_at": 0.0,
                "trigger_ip": "",
            }
        return row

    def deploy_canary_file(self, target_path: Union[str, Path], file_type: str = "env") -> dict:
        """Deploys a deceptive file (such as .env.production or credentials) with honeytokens."""
        p = Path(target_path)
        p.parent.mkdir(parents=True, exist_ok=True)

        if file_type == "aws":
            key_id, secret = self.generate_aws_canary(label=f"file:{p.name}")
            content = f"[default]\naws_access_key_id = {key_id}\naws_secret_access_key = {secret}\nregion = us-east-1\n"
        else:  # env file default
            gh_token = self.generate_github_canary(label=f"file:{p.name}")
            content = (
                f"# Production Environment Configuration\n"
                f"NODE_ENV=production\n"
                f"DATABASE_URL=postgres://app_admin:SecretPass2026@10.0.0.54:5432/app_prod\n"
                f"GITHUB_API_TOKEN={gh_token}\n"
                f"ENCRYPTION_KEY={secrets.token_hex(16)}\n"
            )

        p.write_text(content, encoding="utf-8")
        return {"path": str(p), "type": file_type, "deployed_at": time.time()}

    def check_traffic_for_canaries(self, text_or_bytes: Union[str, bytes], source_ip: str = "") -> Optional[dict]:
        """Scans payload text or traffic for known canary tokens."""
        if not text_or_bytes:
            return None
        payload = text_or_bytes if isinstance(text_or_bytes, str) else text_or_bytes.decode("utf-8", "ignore")

        with self._lock:
            for token, meta in self._tokens.items():
                if token in payload:
                    if not meta["triggered"]:
                        meta["triggered"] = True
                        meta["triggered_at"] = time.time()
                        meta["trigger_ip"] = source_ip
                        event("canary_token_tripped", "critical",
                              token_type=meta["type"], label=meta["label"], ip=source_ip)
                    return dict(meta)
        return None

    def list_canaries(self) -> List[dict]:
        with self._lock:
            return list(self._tokens.values())


# Global singleton
canary_mgr = CanaryManager()
