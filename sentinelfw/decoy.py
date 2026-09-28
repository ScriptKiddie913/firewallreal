"""SentinelFW Decoy and Canary Token System.

Plants realistic decoy credential files, canary tokens, and fake keys across the
filesystem, alerting with high priority whenever an attacker or malware touches them.
"""
import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Dict, List
from .common import DATA_DIR, IS_WIN, STOP, event

SAMPLE_AWS_DECOY = """[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-east-1
"""

SAMPLE_ENV_DECOY = """# Production API Secrets
DATABASE_URL=postgres://admin:SuperSecretPass2024@127.0.0.1:5432/proddb
OPENAI_API_KEY=sk-proj-999999999999999999999999999999999999999999999999
STRIPE_SECRET_KEY=sk_live_51HzXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""


class CanarySystem(threading.Thread):
    """Plants and watches decoy canary tokens for unauthorized read/write access."""

    def __init__(self, cfg=None, base_dir: Path = None):
        super().__init__(name="canary_system", daemon=True)
        self.cfg = cfg or {}
        c_cfg = self.cfg.get("canary", {})
        self.enabled = c_cfg.get("enabled", True)
        self.plant_aws = c_cfg.get("plant_fake_credentials", True)
        self.plant_env = c_cfg.get("plant_fake_env_files", True)
        self.base_dir = base_dir or (DATA_DIR / "canary")
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._tokens: Dict[str, dict] = {}
        self._lock = threading.RLock()
        self.setup_decoys()

    def setup_decoys(self):
        """Plants decoy files on the filesystem."""
        if not self.enabled:
            return

        if self.plant_aws:
            aws_file = self.base_dir / "aws_credentials.bak"
            if not aws_file.exists():
                aws_file.write_text(SAMPLE_AWS_DECOY, encoding="utf-8")
            self._register_token(aws_file, "aws_credentials")

        if self.plant_env:
            env_file = self.base_dir / ".env.production"
            if not env_file.exists():
                env_file.write_text(SAMPLE_ENV_DECOY, encoding="utf-8")
            self._register_token(env_file, "production_env_secrets")

    def _register_token(self, path: Path, token_type: str):
        try:
            st = path.stat()
            self._tokens[str(path)] = {
                "path": str(path),
                "type": token_type,
                "size": st.st_size,
                "mtime": st.st_mtime,
                "hash": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        except OSError:
            pass

    def run(self):
        """Monitors decoy tokens for unauthorized modification or access."""
        while not STOP.wait(2.0):
            if not self.enabled:
                continue
            self.check_decoys()

    def check_decoys(self) -> List[dict]:
        alerts = []
        with self._lock:
            for path_str, meta in list(self._tokens.items()):
                p = Path(path_str)
                if not p.exists():
                    event("canary_file_deleted", "critical", path=path_str, token_type=meta["type"])
                    alerts.append({"event": "deleted", "path": path_str})
                    del self._tokens[path_str]
                    continue

                try:
                    st = p.stat()
                    # Check if file was modified
                    if st.st_mtime != meta["mtime"] or st.st_size != meta["size"]:
                        new_hash = hashlib.sha256(p.read_bytes()).hexdigest()
                        if new_hash != meta["hash"]:
                            event(
                                "canary_token_tampered",
                                "critical",
                                path=path_str,
                                token_type=meta["type"],
                                old_hash=meta["hash"],
                                new_hash=new_hash,
                            )
                            alerts.append({"event": "tampered", "path": path_str})
                            meta["mtime"] = st.st_mtime
                            meta["size"] = st.st_size
                            meta["hash"] = new_hash
                except OSError:
                    pass
        return alerts

    def get_planted_decoys(self) -> List[dict]:
        with self._lock:
            return list(self._tokens.values())
