"""SentinelFW Tarpit Engine — Endless SSH and Slow HTTP Attacker Traps.

Drains attacker resources, threads, and time by holding connections open:
* Endless SSH tarpit: Sends infinite, randomized RFC 4253 banner lines at slow intervals
* Slow HTTP tarpit: Drip-feeds HTTP response headers or chunks (1 byte every few seconds)
* Strict concurrency & memory caps (prevents honeypot resource exhaustion)
"""
import random
import socket
import string
import threading
import time
from typing import Dict, List, Optional
from .common import event


class TarpitConnection(threading.Thread):
    """Handles a single trapped client connection."""

    def __init__(self, client_sock: socket.socket, client_ip: str, client_port: int,
                 proto: str = "ssh", delay_seconds: float = 10.0):
        super().__init__(name=f"tarpit_{proto}_{client_ip}_{client_port}", daemon=True)
        self.sock = client_sock
        self.client_ip = client_ip
        self.client_port = client_port
        self.proto = proto.lower()
        self.delay = delay_seconds
        self.running = True
        self.bytes_sent = 0
        self.started_at = time.time()

    def run(self):
        try:
            self.sock.settimeout(30.0)
            if self.proto == "ssh":
                self._run_ssh()
            elif self.proto == "http":
                self._run_http()
        except Exception:
            pass
        finally:
            self.close()

    def _run_ssh(self):
        # Endless RFC 4253 pre-banner lines (RFC 4253 section 4.2 permits arbitrary lines before SSH-2.0-)
        while self.running:
            line_len = random.randint(30, 70)
            random_line = "".join(random.choices(string.ascii_letters + string.digits + " -_/", k=line_len))
            payload = (random_line + "\r\n").encode("ascii")
            self.sock.sendall(payload)
            self.bytes_sent += len(payload)
            time.sleep(self.delay)

    def _run_http(self):
        # Initial status line
        self.sock.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
        while self.running:
            # Send 1 byte chunk every self.delay seconds
            chunk = b"1\r\nX\r\n"
            self.sock.sendall(chunk)
            self.bytes_sent += len(chunk)
            time.sleep(self.delay)

    def close(self):
        self.running = False
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass


class TarpitServer(threading.Thread):
    """Multi-threaded tarpit listener with hard concurrency caps."""

    def __init__(self, port: int, proto: str = "ssh", max_conns: int = 200, delay_seconds: float = 10.0):
        super().__init__(name=f"tarpit_server_{proto}_{port}", daemon=True)
        self.port = int(port)
        self.proto = proto.lower()
        self.max_conns = max(1, int(max_conns))
        self.delay = float(delay_seconds)
        self.running = False
        self.sock: Optional[socket.socket] = None
        self._conns: List[TarpitConnection] = []
        self._lock = threading.RLock()

    def run(self):
        self.running = True
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(("0.0.0.0", self.port))
            self.sock.listen(128)
            self.sock.settimeout(2.0)
            event("tarpit_started", "info", proto=self.proto, port=self.port, max_conns=self.max_conns)
        except Exception as e:
            event("tarpit_bind_error", "high", proto=self.proto, port=self.port, error=str(e))
            self.running = False
            return

        while self.running:
            try:
                csock, (cip, cport) = self.sock.accept()
                with self._lock:
                    # Clean dead connections
                    self._conns = [c for c in self._conns if c.is_alive()]
                    if len(self._conns) >= self.max_conns:
                        # Drop excess connection
                        try:
                            csock.close()
                        except Exception:
                            pass
                        continue

                    conn = TarpitConnection(csock, cip, cport, proto=self.proto, delay_seconds=self.delay)
                    self._conns.append(conn)
                    conn.start()
                    event("tarpit_trapped", "medium", ip=cip, proto=self.proto, active=len(self._conns))
            except socket.timeout:
                continue
            except Exception:
                if not self.running:
                    break

        self._cleanup()

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        self._cleanup()

    def _cleanup(self):
        with self._lock:
            for c in self._conns:
                c.close()
            self._conns.clear()

    def status(self) -> dict:
        with self._lock:
            active = sum(1 for c in self._conns if c.is_alive())
            return {
                "proto": self.proto,
                "port": self.port,
                "running": self.running,
                "active_trapped": active,
                "max_conns": self.max_conns,
            }


class TarpitManager:
    """Coordinates TCP/SSH/HTTP tarpits for slowing down automated scanner bots."""

    def __init__(self, cfg=None, engine=None):
        self.cfg = cfg or {}
        self.engine = engine
        self._servers: Dict[str, TarpitServer] = {}
        self._lock = threading.RLock()

    def start_server(self, name: str, port: int, proto: str = "ssh", max_conns: int = 200, delay: float = 10.0) -> bool:
        with self._lock:
            if name in self._servers and self._servers[name].running:
                return True
            srv = TarpitServer(port=port, proto=proto, max_conns=max_conns, delay_seconds=delay)
            srv.start()
            self._servers[name] = srv
            return True

    def stop_server(self, name: str):
        with self._lock:
            if name in self._servers:
                self._servers[name].stop()
                del self._servers[name]

    def stop_all(self):
        with self._lock:
            for srv in self._servers.values():
                srv.stop()
            self._servers.clear()

    def status(self) -> dict:
        with self._lock:
            return {name: srv.status() for name, srv in self._servers.items()}

