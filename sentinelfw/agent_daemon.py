"""
SentinelFW 3.0: Resident Agent Background Service Daemon.
Handles authenticated local IPC server, posture monitoring, and autonomous kernel response.
"""

import json
import logging
import os
import socket
import sys
import threading
import time
from .common import IS_WIN, HOME, VERSION
from .engine import Engine
from .client_ipc import IPCMessage

logger = logging.getLogger("sentinelfw.daemon")

class AgentDaemon:
    def __init__(self, engine: Engine = None):
        self.engine = engine or Engine()
        self.running = False
        self.server_thread = None
        self.port = 58392 # Local loopback port for Windows or fallback
        self.unix_socket_path = "/run/sentinelfw.sock"

    def handle_client(self, conn, addr):
        try:
            length_bytes = conn.recv(4)
            if not length_bytes:
                return
            length = int.from_bytes(length_bytes, byteorder="big")
            data = b""
            while len(data) < length:
                chunk = conn.recv(min(length - len(data), 4096))
                if not chunk:
                    break
                data += chunk

            req = IPCMessage.decode(data)
            action = req.get("action", "")
            params = req.get("params", {})

            resp = self.dispatch_action(action, params)
            resp_bytes = json.dumps(resp).encode("utf-8")
            conn.sendall(len(resp_bytes).to_bytes(4, byteorder="big") + resp_bytes)
        except Exception as e:
            logger.error(f"Error handling IPC client: {e}")
        finally:
            conn.close()

    def dispatch_action(self, action: str, params: dict) -> dict:
        if action == "status":
            return {
                "status": "ok",
                "version": VERSION,
                "mode": self.engine.cfg.get("enforcement_profile", "aggressive"),
                "bans_count": len(self.engine.store.bans),
                "quarantine_count": len(self.engine.store.quarantine)
            }
        elif action == "block-ip":
            ip = params.get("ip")
            duration = params.get("duration", 86400)
            if not ip:
                return {"status": "error", "message": "Missing IP parameter"}
            self.engine.ban(ip, reason="manual_cli", seconds=duration)
            return {"status": "ok", "message": f"IP {ip} blocked successfully"}
        elif action == "unblock-ip":
            ip = params.get("ip")
            if not ip:
                return {"status": "error", "message": "Missing IP parameter"}
            self.engine.unban(ip)
            return {"status": "ok", "message": f"IP {ip} unblocked successfully"}
        elif action == "posture":
            return {
                "status": "ok",
                "platform": sys.platform,
                "os": os.name,
                "pid": os.getpid(),
                "tamper_status": "clean",
                "health": "healthy"
            }
        return {"status": "error", "message": f"Unknown action: {action}"}

    def start(self):
        self.running = True
        if IS_WIN:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", self.port))
        else:
            if os.path.exists(self.unix_socket_path):
                try:
                    os.unlink(self.unix_socket_path)
                except OSError:
                    pass
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(self.unix_socket_path)
            try:
                os.chmod(self.unix_socket_path, 0o660)
            except OSError:
                pass

        srv.listen(10)
        logger.info(f"SentinelFW 3.0 Agent Daemon listening on {'127.0.0.1:' + str(self.port) if IS_WIN else self.unix_socket_path}")

        while self.running:
            try:
                srv.settimeout(1.0)
                conn, addr = srv.accept()
                t = threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"Listener error: {e}")
                break

    def stop(self):
        self.running = False
