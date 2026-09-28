"""SentinelFW Deep FTP Protocol Inspector.

Analyzes cleartext FTP command streams, identifies bounce attacks, traversal attempts,
command injection, and harvests credentials for threat correlation.
"""
import re
from typing import Dict, List, Optional, Tuple

PORT_CMD_REGEX = re.compile(r"^PORT\s+(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)", re.IGNORECASE)


class FTPInspector:
    """Inspects FTP client and server communications."""

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

        # 3. Command Injection in Filename
        if verb in ("RETR", "STOR", "APPE"):
            if any(ch in arg for ch in (";", "|", "&", "`", "$")):
                return "ftp_command_injection", {"verb": verb, "filename": arg}

        return None, {"verb": verb, "arg": arg}
