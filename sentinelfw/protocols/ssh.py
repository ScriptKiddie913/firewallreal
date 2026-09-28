"""SentinelFW Deep SSH Protocol Inspector.

Analyzes SSH protocol banners, client identification strings, and HASSH fingerprints.
"""
from typing import Dict, Optional, Tuple


class SSHInspector:
    """Inspects SSH initial banners and version identification exchanges."""

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
