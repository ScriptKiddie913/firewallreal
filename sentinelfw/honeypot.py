"""SentinelFW Honeypot and Deception Services.

Provides lightweight, fully pure-Python service emulators (SSH, HTTP, FTP,
Telnet, MySQL, SMB, RDP, SMTP) designed to attract, engage, and record
attacker tools, credentials, and payloads.

Every service can be spawned / stopped individually at runtime through the
Web UI or REST API; ports are configurable and binds are idempotent.
"""
import os
import socket
import threading
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional
from .common import DATA_DIR, STOP, event


class HoneypotSession:
    """Records an interaction session between an external IP and a honeypot service."""

    def __init__(self, service: str, src_ip: str, src_port: int):
        self.service = service
        self.src_ip = src_ip
        self.src_port = src_port
        self.start_time = time.time()
        self.end_time = self.start_time
        self.commands: List[str] = []
        self.credentials: List[Dict[str, str]] = []
        self.payloads: List[bytes] = []

    def to_dict(self) -> dict:
        return {
            "service": self.service,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "start_time": self.start_time,
            "duration": round(self.end_time - self.start_time, 2),
            "commands": self.commands,
            "credentials": self.credentials,
            "payload_count": len(self.payloads),
        }


class HoneypotService(threading.Thread):
    """Base class for lightweight honeypot service emulators."""

    def __init__(self, name: str, port: int, on_session: Optional[Callable] = None):
        super().__init__(name=f"honeypot_{name}", daemon=True)
        self.service_name = name
        self.port = port
        self.on_session = on_session
        self.sock: Optional[socket.socket] = None
        self.running = False
        self.bind_error = ""
        self.started_at = 0.0
        self.hit_count = 0
        self.upload_dir = DATA_DIR / "honeypot_uploads"
        self.upload_dir.mkdir(parents=True, exist_ok=True)

    def bind_and_listen(self) -> bool:
        if self.sock is not None:
            return True  # already bound
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", self.port))
            s.listen(16)
            s.settimeout(1.0)
            self.sock = s
            self.bind_error = ""
            return True
        except Exception as e:
            event("honeypot_bind_failed", "low", service=self.service_name, port=self.port, error=str(e))
            self.bind_error = str(e)
            self.sock = None
            return False

    def run(self):
        if not self.bind_and_listen():
            return
        self.running = True
        self.started_at = time.time()
        event("honeypot_service_started", "info", service=self.service_name, port=self.port)
        while not STOP.is_set() and self.running:
            try:
                client, addr = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                if STOP.is_set() or not self.running:
                    break
                # Listening socket died (e.g. closed by stop()) — try rebind once
                self.sock = None
                if not self.running or not self.bind_and_listen():
                    break
                continue
            self.hit_count += 1
            threading.Thread(target=self._handle_client, args=(client, addr), daemon=True).start()

        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def shutdown(self):
        """Stops the accept loop and closes the listener socket."""
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def status(self) -> dict:
        return {
            "service": self.service_name,
            "port": self.port,
            "running": bool(self.running and self.is_alive()),
            "bind_error": self.bind_error,
            "hits": self.hit_count,
            "uptime_seconds": int(time.time() - self.started_at) if self.started_at else 0,
        }

    def _handle_client(self, client: socket.socket, addr: tuple):
        pass


class HTTPHoneypot(HoneypotService):
    """Emulates a web server with deliberately appealing vulnerable endpoints."""

    def __init__(self, port: int = 8080, on_session=None):
        super().__init__("http", port, on_session)

    def _handle_client(self, client: socket.socket, addr: tuple):
        src_ip, src_port = addr[0], addr[1]
        session = HoneypotSession("http", src_ip, src_port)
        client.settimeout(5.0)
        try:
            data = client.recv(8192)
            if data:
                session.payloads.append(data)
                req_line = data.split(b"\r\n")[0].decode(errors="ignore")
                session.commands.append(req_line)

                event("honeypot_http_hit", "high", src=src_ip, sport=src_port, request=req_line)

                body = "<html><body><h1>403 Forbidden</h1><p>Access Denied.</p></body></html>"
                resp = (
                    f"HTTP/1.1 403 Forbidden\r\n"
                    f"Server: Apache/2.4.52 (Ubuntu)\r\n"
                    f"Content-Type: text/html\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    f"Connection: close\r\n\r\n"
                    f"{body}"
                )
                client.sendall(resp.encode())
        except Exception:
            pass
        finally:
            client.close()
            session.end_time = time.time()
            if self.on_session:
                self.on_session(session)


class SSHHoneypot(HoneypotService):
    """Emulates an SSH banner, captures authentication attempts, and records probes."""

    def __init__(self, port: int = 2222, on_session=None):
        super().__init__("ssh", port, on_session)

    def _handle_client(self, client: socket.socket, addr: tuple):
        src_ip, src_port = addr[0], addr[1]
        session = HoneypotSession("ssh", src_ip, src_port)
        client.settimeout(5.0)
        try:
            client.sendall(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
            client_banner = client.recv(1024)
            if client_banner:
                session.commands.append(client_banner.decode(errors="ignore").strip())
                event("honeypot_ssh_hit", "high", src=src_ip, client_banner=session.commands[0])
            time.sleep(0.5)
        except Exception:
            pass
        finally:
            client.close()
            session.end_time = time.time()
            if self.on_session:
                self.on_session(session)


class FTPHoneypot(HoneypotService):
    """Emulates a vsftpd server and captures cleartext authentication credentials."""

    def __init__(self, port: int = 2121, on_session=None):
        super().__init__("ftp", port, on_session)

    def _handle_client(self, client: socket.socket, addr: tuple):
        src_ip, src_port = addr[0], addr[1]
        session = HoneypotSession("ftp", src_ip, src_port)
        client.settimeout(10.0)
        user = ""
        try:
            client.sendall(b"220 (vsFTPd 3.0.5)\r\n")
            while True:
                line = client.recv(1024)
                if not line:
                    break
                cmd = line.decode(errors="ignore").strip()
                session.commands.append(cmd)
                parts = cmd.split(" ", 1)
                verb = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ""

                if verb == "USER":
                    user = arg
                    client.sendall(b"331 Please specify the password.\r\n")
                elif verb == "PASS":
                    session.credentials.append({"user": user, "password": arg})
                    event("honeypot_ftp_creds", "high", src=src_ip, user=user, password=arg)
                    client.sendall(b"530 Login incorrect.\r\n")
                    break
                elif verb == "QUIT":
                    client.sendall(b"221 Goodbye.\r\n")
                    break
                else:
                    client.sendall(b"500 Unknown command.\r\n")
        except Exception:
            pass
        finally:
            client.close()
            session.end_time = time.time()
            if self.on_session:
                self.on_session(session)


class TelnetHoneypot(HoneypotService):
    """Emulates a generic router/IoT device login to trap automated botnet credentials."""

    def __init__(self, port: int = 2323, on_session=None):
        super().__init__("telnet", port, on_session)

    def _handle_client(self, client: socket.socket, addr: tuple):
        src_ip, src_port = addr[0], addr[1]
        session = HoneypotSession("telnet", src_ip, src_port)
        client.settimeout(8.0)
        try:
            client.sendall(b"\r\nLogin: ")
            user = client.recv(256).decode(errors="ignore").strip()
            client.sendall(b"Password: ")
            pwd = client.recv(256).decode(errors="ignore").strip()
            session.credentials.append({"user": user, "password": pwd})
            event("honeypot_telnet_creds", "high", src=src_ip, user=user, password=pwd)
            client.sendall(b"\r\nLogin Failed\r\n")
        except Exception:
            pass
        finally:
            client.close()
            session.end_time = time.time()
            if self.on_session:
                self.on_session(session)


class MySQLHoneypot(HoneypotService):
    """Emulates a MySQL 8 server handshake and captures login attempts."""

    def __init__(self, port: int = 3307, on_session=None):
        super().__init__("mysql", port, on_session)

    def _handle_client(self, client: socket.socket, addr: tuple):
        src_ip, src_port = addr[0], addr[1]
        session = HoneypotSession("mysql", src_ip, src_port)
        client.settimeout(6.0)
        try:
            # Greeting packet: protocol 10, server version, auth plugin
            greeting = (
                b"\x4f\x00\x00\x00"  # payload len 79 + seq 0
                b"\x0a"  # protocol v10
                b"8.0.32-0ubuntu0.22.04.2\x00"
                b"\x01\x00\x00\x00"  # conn id
                b"ABCDEFGH"  # auth data part 1
                b"\x00"  # filler
                b"\x21\x00"  # capabilities lower
                b"\x21"  # charset
                b"\x02\x00"  # status
                b"\x0a\x00"  # capabilities upper
                b"\x15"  # auth plugin data len
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"mysql_native_password\x00"
            )
            client.sendall(greeting)
            data = client.recv(512)
            if data and len(data) > 32:
                session.payloads.append(data[:128])
                session.commands.append("MySQL login handshake (native password)")
                event("honeypot_mysql_hit", "high", src=src_ip,
                      note="MySQL authentication probe captured")
                # auth fail error packet
                client.sendall(b"\x17\x00\x00\x02\xff\x15\x04"
                                b"Access denied for user (using password: YES)")
        except Exception:
            pass
        finally:
            client.close()
            session.end_time = time.time()
            if self.on_session:
                self.on_session(session)


class SMBHoneypot(HoneypotService):
    """Emulates an SMBv1/SMBv2 endpoint that records negotiation probes."""

    def __init__(self, port: int = 4450, on_session=None):
        super().__init__("smb", port, on_session)

    def _handle_client(self, client: socket.socket, addr: tuple):
        src_ip, src_port = addr[0], addr[1]
        session = HoneypotSession("smb", src_ip, src_port)
        client.settimeout(6.0)
        try:
            data = client.recv(512)
            if data:
                session.payloads.append(data[:256])
                is_smb1 = data[:4] == b"\xffSMB"
                session.commands.append(f"SMB {'v1 (EternalBlue-era)' if is_smb1 else 'v2'} negotiate request")
                event("honeypot_smb_hit", "high", src=src_ip,
                      proto="SMB1" if is_smb1 else "SMB2", note="negotiate probe")
                if is_smb1:
                    client.sendall(b"\xffSMB\x72\x00\x00\x00\x00")
        except Exception:
            pass
        finally:
            client.close()
            session.end_time = time.time()
            if self.on_session:
                self.on_session(session)


class RDPHoneypot(HoneypotService):
    """Emulates an RDP endpoint recording X.224 connection requests."""

    def __init__(self, port: int = 3390, on_session=None):
        super().__init__("rdp", port, on_session)

    def _handle_client(self, client: socket.socket, addr: tuple):
        src_ip, src_port = addr[0], addr[1]
        session = HoneypotSession("rdp", src_ip, src_port)
        client.settimeout(6.0)
        try:
            data = client.recv(512)
            if data:
                session.payloads.append(data[:256])
                session.commands.append("RDP X.224 connection request")
                event("honeypot_rdp_hit", "high", src=src_ip, note="RDP connection probe")
                # X.224 connection confirm with RDP negotiation failure
                client.sendall(bytes.fromhex("03000013000e0000000000000200080000000000"))
        except Exception:
            pass
        finally:
            client.close()
            session.end_time = time.time()
            if self.on_session:
                self.on_session(session)


class SMTPHoneypot(HoneypotService):
    """Emulates an open relay bait and captures sender/recipient/command sequences."""

    def __init__(self, port: int = 2525, on_session=None):
        super().__init__("smtp", port, on_session)

    def _handle_client(self, client: socket.socket, addr: tuple):
        src_ip, src_port = addr[0], addr[1]
        session = HoneypotSession("smtp", src_ip, src_port)
        client.settimeout(10.0)
        mail_from = rcpt_to = ""
        try:
            client.sendall(b"220 mail.example.com ESMTP Postfix (Ubuntu)\r\n")
            while True:
                line = client.recv(1024)
                if not line:
                    break
                cmd = line.decode(errors="ignore").strip()
                session.commands.append(cmd)
                verb = cmd.split(" ", 1)[0].upper() if cmd else ""
                if verb == "HELO" or verb == "EHLO":
                    client.sendall(b"250 mail.example.com\r\n")
                elif verb == "MAIL":
                    mail_from = cmd
                    client.sendall(b"250 2.1.0 Ok\r\n")
                elif verb == "RCPT":
                    rcpt_to = cmd
                    client.sendall(b"250 2.1.5 Ok\r\n")
                elif verb == "DATA":
                    client.sendall(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    client.recv(4096)  # swallow message body
                    session.commands.append("<message body>")
                    client.sendall(b"250 2.0.0 Ok: queued\r\n")
                elif verb == "QUIT":
                    client.sendall(b"221 Bye\r\n")
                    break
                else:
                    client.sendall(b"502 5.5.2 Error: command not recognized\r\n")
            if mail_from or rcpt_to:
                event("honeypot_smtp_relay", "high", src=src_ip, mail_from=mail_from, rcpt_to=rcpt_to)
        except Exception:
            pass
        finally:
            client.close()
            session.end_time = time.time()
            if self.on_session:
                self.on_session(session)


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------

SERVICE_CLASSES = {
    "http": (HTTPHoneypot, 8080),
    "ssh": (SSHHoneypot, 2222),
    "ftp": (FTPHoneypot, 2121),
    "mysql": (MySQLHoneypot, 3307),
    "smb": (SMBHoneypot, 4450),
    "rdp": (RDPHoneypot, 3390),
    "telnet": (TelnetHoneypot, 2323),
    "smtp": (SMTPHoneypot, 2525),
}


class HoneypotManager:
    """Manages the full suite of honeypot emulators and retains interaction history.

    Services can be spawned / stopped at any time via start_service() /
    stop_service(); configuration changes persist into the engine config dict.
    """

    def __init__(self, cfg=None, config_persist=None):
        self.cfg = cfg or {}
        self._persist = config_persist  # callable(cfg) to save config, optional
        h_cfg = self.cfg.get("honeypot", {})
        self.enabled = h_cfg.get("enabled", True)
        self.services_cfg = h_cfg.get("services", {})
        self.services: Dict[str, HoneypotService] = {}
        self.sessions: List[dict] = []
        self._lock = threading.RLock()

    def _on_session(self, sess: HoneypotSession):
        with self._lock:
            self.sessions.append(sess.to_dict())
            if len(self.sessions) > 1000:
                self.sessions.pop(0)

    # -- service lifecycle ---------------------------------------------------
    def _service_cfg(self, name: str) -> dict:
        defaults = {"enabled": name in ("ssh", "http", "ftp", "telnet")}
        defaults.update(self.services_cfg.get(name, {}))
        return defaults

    @staticmethod
    def _port_blocked_hint(err: str) -> str:
        e = (err or "").lower()
        if "10013" in e or "access" in e or "permission" in e or "eacces" in e or "eperm" in e:
            return ("Port forbidden by the OS (WinError 10013 / EACCES): the port is in a reserved or "
                    "excluded range (e.g. Hyper-V/WinNAT exclusions), already bound, or needs elevation. "
                    "SentinelFW will try nearby ports automatically; pick another port or run as Administrator.")
        if "10048" in e or "in use" in e or "eaddrinuse" in e:
            return "Port is already in use by another process — SentinelFW will try nearby ports automatically."
        return ""

    def start_service(self, name: str, port: Optional[int] = None) -> dict:
        """Spawns a single honeypot service by name. Returns its status.

        If the requested port cannot be bound (in use, OS-reserved, WinError 10013),
        up to 12 nearby alternate ports are tried automatically so the decoy still
        spawns; the actually-bound port is reported and persisted.
        """
        if name not in SERVICE_CLASSES:
            return {"error": f"unknown service '{name}'"}
        with self._lock:
            existing = self.services.get(name)
            if existing and existing.is_alive() and existing.running:
                if port and port != existing.port:
                    self.stop_service(name)
                else:
                    return existing.status()
            cls, default_port = SERVICE_CLASSES[name]
            scfg = self._service_cfg(name)
            requested_port = int(port or scfg.get("port", default_port))

            candidates = [requested_port]
            for delta in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 100, 1000):
                p = requested_port + delta
                if 1 <= p <= 65535:
                    candidates.append(p)

            srv = None
            last_err = ""
            for idx, use_port in enumerate(candidates):
                srv = cls(port=use_port, on_session=self._on_session)
                srv.start()
                # wait until the bind either succeeds (running) or fails (bind_error / thread death)
                deadline = time.time() + 1.5
                while time.time() < deadline:
                    if srv.bind_error or srv.running or not srv.is_alive():
                        break
                    time.sleep(0.02)
                if not srv.bind_error and srv.running:
                    break
                # bind failed — try the next candidate port
                last_err = srv.bind_error or f"port {use_port} unavailable"
                srv.shutdown()
                srv = None
                if idx == 0:
                    event("honeypot_bind_failed", "low", service=name, port=requested_port,
                          error=last_err, hint=self._port_blocked_hint(last_err))

            if srv is None:
                return {"service": name, "port": requested_port, "running": False,
                        "bind_error": last_err, "hint": self._port_blocked_hint(last_err) or last_err,
                        "started": False}

            self.services[name] = srv
            # persist desired state (with the actually-bound port so restarts are stable)
            self.services_cfg.setdefault(name, {})
            self.services_cfg[name]["enabled"] = True
            self.services_cfg[name]["port"] = srv.port
            if self._persist:
                try:
                    self._persist(self.cfg)
                except Exception:
                    pass
            status = srv.status()
            status["started"] = True
            if srv.port != requested_port:
                status["fallback_from"] = requested_port
                event("honeypot_port_fallback", "info", service=name,
                      requested=requested_port, bound=srv.port,
                      reason=self._port_blocked_hint(last_err) or last_err)
            return status

    def stop_service(self, name: str) -> dict:
        with self._lock:
            srv = self.services.get(name)
            if not srv:
                return {"error": f"service '{name}' is not running"}
            srv.shutdown()
            self.services.pop(name, None)
            self.services_cfg.setdefault(name, {})["enabled"] = False
            if self._persist:
                try:
                    self._persist(self.cfg)
                except Exception:
                    pass
            event("honeypot_service_stopped", "info", service=name)
            return {"service": name, "stopped": True}

    def start(self):
        """Spawns all configured-and-enabled honeypot services."""
        if not self.enabled:
            event("honeypot_disabled", "info")
            return
        for name in SERVICE_CLASSES:
            scfg = self._service_cfg(name)
            if scfg.get("enabled", False):
                self.start_service(name, port=int(scfg.get("port", SERVICE_CLASSES[name][1])))

    def stop(self):
        """Shuts down all active honeypot threads."""
        with self._lock:
            for s in self.services.values():
                s.shutdown()
            self.services.clear()

    # -- status / history -----------------------------------------------------
    def service_status(self) -> List[dict]:
        with self._lock:
            out = []
            for name, (cls, default_port) in SERVICE_CLASSES.items():
                srv = self.services.get(name)
                if srv:
                    out.append(srv.status())
                else:
                    scfg = self._service_cfg(name)
                    out.append({
                        "service": name,
                        "port": int(scfg.get("port", default_port)),
                        "running": False,
                        "configured": bool(scfg.get("enabled", False)),
                        "bind_error": "",
                        "hits": 0,
                        "uptime_seconds": 0,
                    })
            return out

    def get_sessions(self, limit: int = 50) -> List[dict]:
        with self._lock:
            return list(self.sessions)[-limit:]
