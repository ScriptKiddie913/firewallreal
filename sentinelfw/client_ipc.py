"""
SentinelFW 3.0: Authenticated Local IPC Protocol (Daemon / Client Split).
Communicates over UNIX domain sockets on Linux and Named Pipes on Windows.
"""

import json
import os
import socket
import sys
from pathlib import Path
from .common import IS_WIN, HOME

SOCKET_PATH = "/run/sentinelfw.sock" if not IS_WIN else r"\\.\pipe\SentinelFW-IPC"

class IPCMessage:
    @staticmethod
    def encode(action: str, params: dict = None) -> bytes:
        data = {
            "action": action,
            "params": params or {},
            "client_pid": os.getpid()
        }
        raw = json.dumps(data).encode("utf-8")
        return len(raw).to_bytes(4, byteorder="big") + raw

    @staticmethod
    def decode(stream_bytes: bytes) -> dict:
        return json.loads(stream_bytes.decode("utf-8"))

class IPCClient:
    """Client used by unprivileged CLI commands to interact with the resident daemon."""

    def __init__(self, endpoint=None):
        self.endpoint = endpoint or SOCKET_PATH

    def send_command(self, action: str, params: dict = None) -> dict:
        if IS_WIN:
            # On Windows, emulate/use pipe or localhost loopback stream
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.connect(("127.0.0.1", 58392))
            except ConnectionRefusedError:
                return {"status": "error", "message": "SentinelFW 3.0 service daemon is not running."}
        else:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                s.connect(self.endpoint)
            except (FileNotFoundError, ConnectionRefusedError):
                return {"status": "error", "message": "SentinelFW 3.0 daemon socket not found. Is the service running?"}

        try:
            payload = IPCMessage.encode(action, params)
            s.sendall(payload)
            # Read 4-byte header length
            length_bytes = s.recv(4)
            if not length_bytes:
                return {"status": "error", "message": "Empty response from daemon"}
            length = int.from_bytes(length_bytes, byteorder="big")
            data = b""
            while len(data) < length:
                chunk = s.recv(min(length - len(data), 4096))
                if not chunk:
                    break
                data += chunk
            return IPCMessage.decode(data)
        finally:
            s.close()
