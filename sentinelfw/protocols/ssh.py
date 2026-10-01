import collections
import hashlib
import threading
import time
from typing import Dict, List, Optional, Tuple


class SSHInspector:
    """Inspects SSH initial banners, brute-force frequency, and version identification exchanges."""

    _auth_lock = threading.Lock()
    _auth_attempts: Dict[str, List[float]] = collections.defaultdict(list)

    @classmethod
    def record_auth_attempt(cls, client_ip: str, window_seconds: float = 60.0,
                            threshold: int = 5) -> Optional[dict]:
        """Tracks SSH connection / authentication frequency and flags brute force spikes."""
        now = time.time()
        with cls._auth_lock:
            attempts = [t for t in cls._auth_attempts[client_ip] if now - t <= window_seconds]
            attempts.append(now)
            cls._auth_attempts[client_ip] = attempts
            if len(attempts) >= threshold:
                return {
                    "client_ip": client_ip,
                    "attempts": len(attempts),
                    "window_seconds": window_seconds,
                    "threat": "ssh_brute_force"
                }
        return None

    @classmethod
    def compute_hassh(cls, kex_algs: str, enc_algs: str, mac_algs: str, comp_algs: str) -> str:
        """Computes standard HASSH md5 fingerprint from SSH_MSG_KEXINIT parameters."""
        raw = f"{kex_algs};{enc_algs};{mac_algs};{comp_algs}"
        return hashlib.md5(raw.encode()).hexdigest()

    @classmethod
    def inspect_banner(cls, banner_bytes: bytes) -> Tuple[Optional[str], dict]:
        try:
            line = banner_bytes.decode("latin-1").strip()
        except Exception:
            return None, {}

        if not line.startswith("SSH-"):
            return None, {}

        parts = line.split("-", 2)
        proto_ver = parts[1] if len(parts) > 1 else ""
        software_ver = parts[2] if len(parts) > 2 else ""

        # Flag obsolete SSHv1
        if proto_ver == "1.5" or proto_ver == "1.33":
            return "ssh_obsolete_version", {"banner": line, "proto": proto_ver}

        # Check for known scanning or automated bot versions
        low = software_ver.lower()
        if any(bot in low for bot in ("libssh", "paramiko", "putty", "dropbear", "gobot")):
            return "service_fingerprint", {"banner": line, "client": software_ver}

        return None, {"banner": line, "client": software_ver}
