import collections
import re
import threading
import time
from typing import Dict, List, Optional, Tuple

PORT_CMD_REGEX = re.compile(r"^PORT\s+(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)", re.IGNORECASE)
SENSITIVE_FILES = re.compile(r"(?i)\b(?:passwd|shadow|\.env|id_rsa|id_dsa|id_ecdsa|web\.config|config\.php|\.git|wp-config\.php)\b")


class FTPInspector:
    """Inspects FTP client and server communications."""

    _login_lock = threading.Lock()
    _login_attempts: Dict[str, List[float]] = collections.defaultdict(list)

    @classmethod
    def record_login_attempt(cls, client_ip: str, window_seconds: float = 60.0,
                             threshold: int = 5) -> Optional[dict]:
        """Tracks FTP authentication frequency and flags brute force spikes."""
        now = time.time()
        with cls._login_lock:
            attempts = [t for t in cls._login_attempts[client_ip] if now - t <= window_seconds]
            attempts.append(now)
            cls._login_attempts[client_ip] = attempts
            if len(attempts) >= threshold:
                return {
                    "client_ip": client_ip,
                    "attempts": len(attempts),
                    "window_seconds": window_seconds,
                    "threat": "ftp_brute_force"
                }
        return None

    @classmethod
    def inspect_command(cls, line: str, client_ip: str = "") -> Tuple[Optional[str], dict]:
        """
        Parses an FTP command line and checks for malicious patterns.
        Returns: (attack_type or None, details_dict)
        """
        line = line.strip()
        if not line:
            return None, {}

        parts = line.split(" ", 1)
        verb = parts[0].upper()
        arg = parts[1] if len(parts) > 1 else ""

        # 1. FTP Bounce Attack Check (PORT to third-party IP)
        if verb == "PORT":
            m = PORT_CMD_REGEX.match(line)
            if m:
                target_ip = f"{m.group(1)}.{m.group(2)}.{m.group(3)}.{m.group(4)}"
                port = (int(m.group(5)) << 8) + int(m.group(6))
                if client_ip and target_ip != client_ip and not target_ip.startswith("127."):
                    return "ftp_bounce", {"target_ip": target_ip, "target_port": port, "client_ip": client_ip}

        # 2. Directory Traversal Check
        if verb in ("CWD", "CDUP", "RETR", "STOR", "DELE", "RMD"):
            if "../" in arg or "..\\" in arg or "%2e%2e" in arg.lower():
                return "ftp_traversal", {"verb": verb, "path": arg}

        # 3. Sensitive File Exfiltration Check
        if verb in ("RETR", "STOR"):
            if SENSITIVE_FILES.search(arg):
                return "ftp_sensitive_file", {"verb": verb, "path": arg}

        # 4. Command Injection in Filename
        if verb in ("RETR", "STOR", "APPE"):
            if any(ch in arg for ch in (";", "|", "&", "`", "$")):
                return "ftp_command_injection", {"verb": verb, "filename": arg}

        return None, {"verb": verb, "arg": arg}
