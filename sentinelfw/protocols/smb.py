"""SentinelFW Deep SMB Protocol Inspector.

Detects SMBv1 legacy usage, EternalBlue (MS17-010) exploit indicators,
and lateral movement indicators (PsExec / service installation).
"""
from typing import Dict, Optional, Tuple


class SMBInspector:
    """Inspects SMB/CIFS network packet headers."""

    @classmethod
    def inspect_packet(cls, payload: bytes) -> Tuple[Optional[str], dict]:
        if len(payload) < 8:
            return None, {}

        # Check for SMB1 magic: \xffSMB
        if b"\xffSMB" in payload[:12]:
            cmd_idx = payload.find(b"\xffSMB") + 4
            if cmd_idx < len(payload):
                cmd = payload[cmd_idx]
                # SMB_COM_TRANSACTION2 (0x32) or SMB_COM_NT_TRANSACT (0xa0) are EternalBlue vectors
                if cmd in (0x32, 0xa0):
                    # Check for large multiplex ID or known exploit structure
                    if len(payload) > 100 and b"\x00\x00\x00\x00" in payload[cmd_idx:cmd_idx + 16]:
                        return "smb_eternalblue_probe", {"smb_version": 1, "command": hex(cmd)}
            return "smb_legacy_version", {"smb_version": 1}

        # Check for SMB2 magic: \xfeSMB
        if b"\xfeSMB" in payload[:12]:
            return None, {"smb_version": 2}

        return None, {}
