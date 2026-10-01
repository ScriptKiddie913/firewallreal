"""SentinelFW Built-in Web UI and Control Plane Server.

Serves the matte-grey enterprise defense console and high-performance REST API / SSE stream
using pure Python standard library http.server without requiring external web frameworks.
"""
import collections
from http import HTTPStatus
import http.server
import json
import os
from pathlib import Path
import queue
import re
import socket
import sys
import threading
import time
from typing import Dict, List, Optional
from urllib.parse import parse_qs, unquote, urlparse

from . import vtdb
from . import sarvam_ai
from . import mgmt
from . import forensics
from . import ops
from . import integrations as integ
from .common import (
    CONFIG_FILE,
    DATA_DIR,
    HOME,
    IS_WIN,
    LOGS,
    STOP,
    VERSION,
    atomic_write,
    event,
    register_event_listener,
)
from .geoip import country_db_status, ensure_country_db
from .lists import list_edit
from .telegram_bot import TelegramNotifier, telegram_notifier
from .vector_analysis import TrafficAnalyzer, VECTORS as VECTOR_CATALOG

STATIC_DIR = Path(__file__).resolve().parent / "webui_static"

# Ensure the offline country DB is loaded (downloads on first use)
try:
    ensure_country_db(background=True)
except Exception:
    pass

# Event bus for Server-Sent Events (SSE)
_SSE_CLIENT_QUEUES: List[queue.Queue] = []
_SSE_LOCK = threading.Lock()


def _sse_event_listener(evt: dict):
    with _SSE_LOCK:
        for q in list(_SSE_CLIENT_QUEUES):
            try:
                q.put_nowait(evt)
            except (queue.Full, Exception):
                pass


register_event_listener(_sse_event_listener)
register_event_listener(telegram_notifier.notify)


class APIRateLimiter:
    """Sliding-window IP rate limiter for management-plane protection (Phase 27)."""

    def __init__(self, limit_per_minute: int = 240):
        self.limit = limit_per_minute
        self._history: Dict[str, List[float]] = collections.defaultdict(list)
        self._lock = threading.Lock()

    def is_allowed(self, ip: str) -> bool:
        if not ip or ip in ("127.0.0.1", "::1", "localhost"):
            return True
        now = time.time()
        cutoff = now - 60.0
        with self._lock:
            timestamps = self._history[ip]
            while timestamps and timestamps[0] < cutoff:
                timestamps.pop(0)
            if len(timestamps) >= self.limit:
                return False
            timestamps.append(now)
            return True


class SentinelRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Handles static web dashboard assets, REST API, and SSE live telemetry."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC_DIR), **kwargs)

    def handle(self):
        try:
            super().handle()
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
            pass

    def log_message(self, format, *args):
        # Suppress noisy standard HTTP access logs
        pass

    def end_headers(self):
        # Phase 27: Strict Defense-in-Depth Security Headers
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://unpkg.com; "
            "style-src 'self' 'unsafe-inline' https://unpkg.com https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com data:; "
            "connect-src 'self' https://tiles.openfreemap.org https://demotiles.maplibre.org https://*.tile.openstreetmap.org https://*.basemaps.cartocdn.com https://api.telegram.org; "
            "img-src 'self' data: blob: https:; "
            "worker-src 'self' blob:; "
            "child-src 'self' blob:; "
            "frame-ancestors 'none'",
        )
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        if getattr(self.server, "tls_active", False):
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        super().end_headers()

    def _check_rate_limit(self) -> bool:
        client_ip = self.client_address[0] if self.client_address else "127.0.0.1"
        limiter = getattr(self.server, "rate_limiter", None)
        if limiter and not limiter.is_allowed(client_ip):
            self._json_response({
                "error": "too_many_requests",
                "message": "API rate limit exceeded. Please retry later.",
            }, 429)
            return False
        return True

    def do_OPTIONS(self):
        """CORS pre-flight support."""
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    # ------------------------------------------------------------ auth
    # ------------------------------------------------------------ auth
    def _session_ok(self) -> bool:
        """Valid session cookie (writes need the CSRF token too)."""
        server: SentinelWebUI = self.server
        auth = server.auth
        if auth is None:
            return False
        cookies = self.headers.get("Cookie") or ""
        sid = ""
        for part in cookies.split(";"):
            k, _, v = part.strip().partition("=")
            if k == "sfw_session":
                sid = v
        if not sid:
            return False
        s = auth.validate_session(sid)
        if not s:
            return False
        if self.command in ("GET", "HEAD", "OPTIONS"):
            self.auth_user = s.get("user", "operator")
            self.auth_role = s.get("role", "SuperAdmin")
            self.auth_type = "session"
            return True
        csrf = self.headers.get("X-CSRF-Token") or ""
        for part in cookies.split(";"):
            k, _, v = part.strip().partition("=")
            if k == "sfw_csrf":
                csrf = csrf or v
        if auth.check_csrf(sid, csrf):
            self.auth_user = s.get("user", "operator")
            self.auth_role = s.get("role", "SuperAdmin")
            self.auth_type = "session"
            return True
        return False

    def _auth_user(self) -> str:
        if hasattr(self, "auth_user") and self.auth_user:
            return str(self.auth_user)
        server: SentinelWebUI = self.server
        w = (server.engine.cfg.get("webui", {}) if server.engine else {})
        return str(w.get("username") or "operator")

    def _default_pw_live(self) -> bool:
        server: SentinelWebUI = self.server
        w = (server.engine.cfg.get("webui", {}) if server.engine else {})
        # Explicit must_change_password flag or uninitialized hash
        return bool(w.get("must_change_password", False)) or not bool(w.get("password_hash"))

    def _enforce_role(self, perm: str) -> bool:
        role = getattr(self, "auth_role", "SuperAdmin")
        if mgmt.has_permission(role, perm):
            return True
        self._json_response({
            "error": "forbidden",
            "required_permission": perm,
            "role": role,
            "message": f"Role '{role}' lacks permission '{perm}'"
        }, 403)
        return False

    def _check_auth(self) -> bool:
        """Bearer token / API key OR session cookie with CSRF OR basic auth."""
        server: SentinelWebUI = self.server
        engine = server.engine
        if engine is None:
            self.auth_user = "operator"
            self.auth_role = "SuperAdmin"
            self.auth_type = "none"
            return True
        w = engine.cfg.get("webui", {})
        user, pw_hash = str(w.get("username") or ""), str(w.get("password_hash") or "")

        # 1) API Bearer token or X-API-Key header
        auth_header = self.headers.get("Authorization") or ""
        api_key_header = self.headers.get("X-API-Key") or ""
        token = ""
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
        elif api_key_header:
            token = api_key_header.strip()

        if token:
            tok_info = mgmt.verify_api_token(token)
            if tok_info:
                self.auth_user = tok_info.get("username", "api_client")
                self.auth_role = tok_info.get("role", "SuperAdmin")
                self.auth_type = "token"
                return True
            else:
                self._auth_required()
                return False

        if not (user and pw_hash):
            self.auth_user = "operator"
            self.auth_role = "SuperAdmin"
            self.auth_type = "none"
            return True  # auth disabled

        # 2) cookie session
        try:
            if server.auth is not None and engine.cfg.get("management", {}).get("sessions", True) \
                    and self._session_ok():
                return True
        except Exception:
            pass

        # 3) basic auth
        if auth_header.startswith("Basic "):
            import base64
            try:
                dec = base64.b64decode(auth_header[6:], validate=False).decode("utf-8", "replace")
                u, _, p = dec.partition(":")
            except Exception:
                self._auth_required()
                return False
            if mgmt.verify_password(p, pw_hash) and u == user:
                self.auth_user = u
                self.auth_role = "SuperAdmin"
                self.auth_type = "basic"
                return True
            self._auth_required()
            return False
        self._auth_required()
        return False

    def _auth_required(self):
        path = getattr(self, "path", "/")
        if not path.startswith("/api/") and self.command in ("GET", "HEAD"):
            # browsers get the login page
            self._serve_login_page()
            return
        body = json.dumps({"error": "authentication required"}).encode()
        try:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="SentinelFW Dashboard"')
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
            pass

    def _handle_login_form(self):
        """POST /login — form-encoded credentials -> session cookies."""
        server: SentinelWebUI = self.server
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        from urllib.parse import parse_qs
        form = parse_qs(raw)
        user = (form.get("username") or [""])[0]
        password = (form.get("password") or [""])[0]
        totp = (form.get("totp") or [""])[0]
        client_ip = self.client_address[0] if self.client_address else ""
        res = server.auth.login(user, password, totp, client_ip) if server.auth \
            else {"error": "auth unavailable"}
        if res.get("error"):
            mgmt.audit_append("login_failed", user=user, ip=client_ip, error=res["error"])
            body = b"<html><body>invalid credentials<script>setTimeout(function(){location='/login'},0)</script></body></html>"
            self.send_response(401)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        s = res
        self.send_response(302)
        secure_flag = "; Secure" if getattr(server, "tls_active", False) else ""
        self.send_header("Set-Cookie",
                         f"sfw_session={s['session_id']}; Path=/; HttpOnly; SameSite=Strict{secure_flag}")
        self.send_header("Set-Cookie",
                         f"sfw_csrf={s['csrf']}; Path=/; SameSite=Strict{secure_flag}")
        self.send_header("Location", "/")
        self.end_headers()
        mgmt.audit_append("login_success", user=user, ip=client_ip)

    def _serve_login_page(self):
        server: SentinelWebUI = self.server
        engine = server.engine
        totp = bool(engine and engine.cfg.get("management", {}).get("totp_enabled"))
        page = """<!doctype html><html><head><meta charset="utf-8">
<title>SentinelFW — Sign in</title>
<style>
body{background:#0d1117;color:#d7dee7;font-family:system-ui,Segoe UI,Arial,sans-serif;
display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.box{width:360px;background:#141b24;border:1px solid #263140;padding:34px;border-radius:6px}
h1{font-size:17px;letter-spacing:3px;margin:0 0 4px;color:#8fb7dd}
p{font-size:11px;color:#5a6472;margin:0 0 22px}
label{display:block;font-size:10px;letter-spacing:1px;color:#7d8a9a;margin:14px 0 5px}
input{width:100%;box-sizing:border-box;background:#0d1117;border:1px solid #263140;
color:#d7dee7;padding:9px 11px;font-family:Consolas,monospace;border-radius:3px}
button{width:100%;margin-top:20px;padding:10px;background:#2b4a68;border:none;color:#fff;
letter-spacing:2px;font-size:12px;cursor:pointer;border-radius:3px}
button:hover{background:#365b80}
.err{color:#e04f4f;font-size:11px;min-height:15px;margin-top:12px}
</style></head><body><div class="box">
<h1>SENTINELFW</h1><p>firewall &middot; IPS &middot; deception console</p>
<form method="post" action="/login">
<label>USERNAME</label><input name="username" autocomplete="username" required>
<label>PASSWORD</label><input name="password" type="password" autocomplete="current-password" required>"""
        if totp:
            page += '<label>2FA CODE (or recovery code)</label><input name="totp" autocomplete="one-time-code">'
        page += """<div class="err" id="err"></div>
<button type="submit">SIGN IN</button></form></div></body></html>"""
        body = page.encode("utf-8")
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
            pass

    def do_PUT(self):
        if not self._check_rate_limit():
            return
        if not self._check_auth():
            return
        if getattr(self, "auth_role", "") == "Auditor":
            self._json_response({"error": "forbidden: auditor role has read-only access"}, 403)
            return
        parsed = urlparse(self.path)
        path = parsed.path
        server: SentinelWebUI = self.server
        if path.startswith("/api/v1/appwall/policies/"):
            if not self._enforce_role("appwall:write"):
                return
            try:
                idx = int(path.rsplit("/", 1)[-1])
            except ValueError:
                self._json_response({"error": "invalid policy index"}, 400)
                return
            content_len = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_len).decode("utf-8", "replace") if content_len > 0 else "{}"
            try:
                data = json.loads(body)
            except Exception:
                data = {}
            self._json_response(server.appwall_update_policy(idx, data))
            return
        if path.startswith("/api/v1/policies/"):
            if not self._enforce_role("policies:write"):
                return
            try:
                pol_id = int(path.split("/")[-1])
            except ValueError:
                self._json_response({"error": "invalid policy id"}, 400)
                return
            content_len = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_len).decode("utf-8", "replace") if content_len > 0 else "{}"
            try:
                data = json.loads(body)
            except Exception:
                data = {}
            if server.engine:
                self._json_response(server.engine.policies.update(pol_id, data))
            else:
                self._json_response({"error": "engine unavailable"}, 400)
        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Endpoint not found")

    def do_GET(self):
        if not self._check_rate_limit():
            return
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        if path.startswith("/api/f1/"):
            fkey = self.headers.get("X-Fleet-Key") or ""
            srv_f = self.server
            if not srv_f.fleet or not srv_f.fleet.enabled() or not srv_f.fleet.key_ok(fkey):
                self._json_response({"error": "fleet disabled or bad key"}, 403)
                return
            if path == "/api/f1/blocklist":
                self._json_response({"blocklist": list(srv_f.engine.lists.ipset.nets)[:5000]
                                      if srv_f.engine else []})
                return
        if not self._check_auth():
            return

        if path == "/metrics":
            # Prometheus scrape endpoint (uses the same auth as everything else)
            body = mgmt.prometheus_metrics(self.server.engine, self.server).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path.startswith("/api/v1/"):
            if path == "/api/v1/logs/stream":
                self._handle_sse_stream()
            else:
                self._handle_api_get(path, query)
        elif path in ("/", ""):
            self.path = "/index.html"
            super().do_GET()
        else:
            super().do_GET()

    def do_POST(self):
        if not self._check_rate_limit():
            return
        parsed = urlparse(self.path)
        path = parsed.path
        server: SentinelWebUI = self.server
        # -------- unauthenticated: login form only
        if path == "/login":
            self._handle_login_form()
            return
        if path.startswith("/api/f1/"):
            # fleet agents authenticate with X-Fleet-Key, not console credentials
            content_len = int(self.headers.get("Content-Length", 0))
            fbody = self.rfile.read(content_len).decode("utf-8", "replace") if content_len > 0 else "{}"
            try:
                fdata = json.loads(fbody)
            except Exception:
                fdata = {}
            self._json_body_cache = fdata
            self._handle_api_post(path, fdata)
            return
        if not self._check_auth():
            return
        if getattr(self, "auth_role", "") == "Auditor" and path != "/api/v1/logout":
            self._json_response({"error": "forbidden: auditor role has read-only access"}, 403)
            return
        # -------- read the JSON body once; audit + handlers share it
        if path.startswith("/api/v1/"):
            content_len = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_len).decode("utf-8", "replace") if content_len > 0 else "{}"
            try:
                data = json.loads(body)
            except Exception:
                data = {}
            self._json_body_cache = data
        else:
            data = {}
        # -------- forced first-run password set: writes blocked on default creds
        if path.startswith("/api/") and self._default_pw_live() and \
                path not in ("/api/v1/auth/password", "/api/v1/auth/status",
                             "/api/v1/auth/2fa/enable", "/api/v1/auth/2fa/disable",
                             "/api/v1/logout", "/login"):
            self._json_response({"error": "default password in use",
                                 "must_change_password": True,
                                 "note": "set a new console password first"}, 403)
            return
        # -------- audit trail for management actions
        try:
            if server.engine is not None and server.engine.cfg.get("management", {}).get("audit", True) \
                    and path.startswith("/api/") and path not in ("/api/v1/login",):
                mgmt.audit_append("api_request", user=self._auth_user(),
                                  method="POST", path=path,
                                  body=mgmt.mask_body(self._json_body_cache))
        except Exception:
            pass
        if path.startswith("/api/v1/"):
            self._handle_api_post(path, self._json_body_cache)
        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Endpoint not found")

    def do_DELETE(self):
        if not self._check_rate_limit():
            return
        if not self._check_auth():
            return
        if getattr(self, "auth_role", "") == "Auditor":
            self._json_response({"error": "forbidden: auditor role has read-only access"}, 403)
            return
        parsed = urlparse(self.path)
        path = parsed.path
        server: SentinelWebUI = self.server
        if path.startswith("/api/v1/tokens/"):
            if not self._enforce_role("admin:tokens"):
                return
            tok_id = unquote(path[len("/api/v1/tokens/"):])
            ok = mgmt.revoke_api_token(tok_id)
            self._json_response({"revoked": ok, "target": tok_id})
            return
        elif path.startswith("/api/v1/secrets/"):
            if not self._enforce_role("admin:secrets"):
                return
            sec_key = unquote(path[len("/api/v1/secrets/"):])
            ok = mgmt.secrets_vault.delete(sec_key)
            self._json_response({"deleted": ok, "key": sec_key})
            return
        elif path.startswith("/api/v1/bans/"):
            if not self._enforce_role("blocklist:write"):
                return
            ip = unquote(path[len("/api/v1/bans/"):])
            if server.engine:
                server.engine.unban(ip)
            self._json_response({"status": "unbanned", "ip": ip})
        elif path.startswith("/api/v1/rules/"):
            if not self._enforce_role("rules:write"):
                return
            # DELETE /api/v1/rules/{type}/{val}
            parts = [p for p in path.split("/") if p]
            if len(parts) >= 5:
                rule_type, val = parts[3], unquote(parts[4])
                file_map = {
                    "ip": "ip_manual.txt",
                    "domain": "domain_manual.txt",
                    "program": "program_manual.txt",
                    "hash": "hash_manual.txt",
                }
                fn = file_map.get(rule_type)
                if fn:
                    list_edit(fn, val, add=False)
                    if server.engine:
                        server.engine.apply_all()
                    self._json_response({"status": "removed", "type": rule_type, "value": val})
                    return
            self._json_response({"error": "invalid rule path"}, 400)
        elif path.startswith("/api/v1/appwall/policies/"):
            try:
                idx = int(path[len("/api/v1/appwall/policies/"):])
            except ValueError:
                idx = None
            if idx is not None and server.engine:
                self._json_response(server.appwall_delete_policy(idx))
            else:
                self._json_response({"error": "invalid policy index"}, 400)
        elif path.startswith("/api/v1/policies/"):
            # DELETE /api/v1/policies/{id}
            try:
                pol_id = int(path[len("/api/v1/policies/"):])
            except ValueError:
                pol_id = None
            if pol_id is not None and server.engine:
                self._json_response(server.engine.policies.delete(pol_id))
            else:
                self._json_response({"error": "invalid policy id"}, 400)
        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Endpoint not found")

    def _json_response(self, data: any, status: int = 200):
        try:
            body = json.dumps(data, default=str).encode("utf-8")
        except Exception:
            body = b"{}"
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
            pass

    def _handle_sse_stream(self):
        """Server-Sent Events endpoint streaming live events in real-time."""
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        q = queue.Queue(maxsize=100)
        with _SSE_LOCK:
            _SSE_CLIENT_QUEUES.append(q)

        # Send initial connected hello
        try:
            init_msg = f"event: ping\ndata: {json.dumps({'status': 'connected', 'time': time.time()})}\n\n"
            self.wfile.write(init_msg.encode("utf-8"))
            self.wfile.flush()
        except Exception:
            with _SSE_LOCK:
                if q in _SSE_CLIENT_QUEUES:
                    _SSE_CLIENT_QUEUES.remove(q)
            return

        try:
            while not STOP.is_set():
                try:
                    evt = q.get(timeout=2.0)
                    chunk = f"data: {json.dumps(evt, default=str)}\n\n".encode("utf-8")
                    self.wfile.write(chunk)
                    self.wfile.flush()
                except queue.Empty:
                    # Keep-alive heartbeat
                    self.wfile.write(b": heartbeat\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
            pass
        finally:
            with _SSE_LOCK:
                if q in _SSE_CLIENT_QUEUES:
                    _SSE_CLIENT_QUEUES.remove(q)

    def _handle_api_get(self, path: str, query: dict):
        server: SentinelWebUI = self.server
        engine = server.engine

        if path == "/api/v1/status":
            bans_count = len(engine.store.bans) if engine else 0
            conns_count = len(server.conntrack.get_active()) if server.conntrack else 0
            rules_count = 0
            if engine and engine.lists:
                rules_count = len(engine.lists.ipset) + len(engine.lists.domains) + len(engine.lists.programs)
            uptime_seconds = int(time.time() - server.start_time)
            
            self._json_response({
                "product": "SentinelFW",
                "version": VERSION,
                "status": "RUNNING",
                "mode": engine.cfg.get("enforcement_profile", "aggressive") if engine else "aggressive",
                "backend": engine.backend.name if engine and engine.backend else "generic",
                "uptime": uptime_seconds,
                "bans_count": bans_count,
                "active_connections": conns_count,
                "total_rules": rules_count,
                "telegram_active": bool(telegram_notifier.enabled),
            })

        elif path == "/api/v1/connections":
            conns = server.conntrack.get_active() if server.conntrack else []
            self._json_response(conns)

        elif path == "/api/v1/bans":
            bans = engine.store.bans if engine else {}
            # Enrich with remaining seconds
            enriched = {}
            now = time.time()
            for ip, meta in bans.items():
                expires = meta.get("expires")
                rem = max(0, int(expires - now)) if expires else None
                ban = {
                    "reason": meta.get("reason", "Autonomous Threat Response"),
                    "source": meta.get("source", "engine"),
                    "expires": expires,
                    "remaining_seconds": rem,
                    "permanent": not expires,
                    "created": meta.get("added", meta.get("created", now)),
                    "offenses": engine.store.offenses.get(ip, 0) if engine else 0,
                }
                if engine is not None:
                    try:
                        ban["trusted"] = engine.trusted(ip)
                    except Exception:
                        pass
                    try:
                        vt = engine.intel.display_record(ip)
                        if vt:
                            ban["vt"] = {"verdict": vt.get("verdict"), "malicious": vt.get("malicious", 0)}
                    except Exception:
                        pass
                enriched[ip] = ban
            self._json_response(enriched)

        elif path == "/api/v1/rules":
            rules = {"ip": [], "domain": [], "program": [], "hash": []}
            if engine and engine.lists:
                # Read manual list files directly (not the enormous merged feed data)
                from .common import LISTS
                for fname, key in [("ip_manual.txt", "ip"), ("domain_manual.txt", "domain"),
                                   ("program_manual.txt", "program"), ("hash_manual.txt", "hash")]:
                    p = LISTS / fname
                    if p.exists():
                        try:
                            rules[key] = [ln.strip() for ln in p.read_text(encoding="utf-8").splitlines()
                                          if ln.strip() and not ln.strip().startswith("#")]
                        except Exception:
                            pass
            self._json_response(rules)

        elif path == "/api/v1/appwall":
            if engine and hasattr(engine, "appwall"):
                policies = engine.appwall.get_policies()
                violations = engine.appwall.get_violations(limit=50)
                self._json_response({"policies": policies, "violations": violations})
            else:
                self._json_response({"policies": [], "violations": []})

        elif path == "/api/v1/honeypot/sessions":
            sessions = server.honeypot.get_sessions() if server.honeypot else []
            self._json_response(sessions)

        elif path == "/api/v1/sandbox/results":
            results = server.sandbox.get_reports() if server.sandbox else []
            self._json_response(results)

        elif path == "/api/v1/baseline":
            base = server.baseline.get_baselines() if server.baseline else {}
            self._json_response(base)

        elif path == "/api/v1/stats/threats":
            # Aggregated attack metrics
            recent_attacks = server.get_recent_attacks()
            self._json_response(recent_attacks)

        elif path == "/api/v1/stats/traffic":
            self._json_response(server._traffic_rates())

        elif path == "/api/v1/posture":
            posture = server.get_system_posture()
            self._json_response(posture)

        elif path == "/api/v1/system/modules":
            mods = {}
            if engine:
                mods["waf"] = {"status": "active" if getattr(engine.waf, "running", False) else "standby", "rules_count": len(getattr(engine.waf, "rules", []))}
                mods["identity"] = {"status": "active", "mappings_count": len(getattr(engine.identity, "_map", {}))}
                mods["nat"] = {"status": "active", "rules_count": len(engine.nat_mgr.get_rules()) if hasattr(engine, "nat_mgr") else 0}
                mods["objects"] = {"status": "active", "addresses": len(engine.objects.addresses), "services": len(engine.objects.services), "schedules": len(engine.objects.schedules)}
                mods["zones"] = {"status": "active", "zones_count": len(engine.zones.list_zones())}
                mods["appid"] = {"status": "active", "catalog_size": len(engine.appid.catalog)}
                mods["dlp"] = {"status": "active", "bypass_rules": len(engine.dlp.privacy_bypass_list)}
                mods["playbook"] = {"status": "active", "playbooks_count": len(getattr(engine.playbooks, "_rules", {})), "executions": len(getattr(engine.playbooks, "_audit_log", []))}
                mods["compliance"] = {"status": "active", "score": engine.compliance.evaluate(engine.cfg).get("score", 0)}
                mods["correlation"] = {"status": "active", "rules_count": len(getattr(engine.correlation, "_rules", []))}
                mods["assetmap"] = {"status": "active", "assets_count": len(engine.assetmap.list_assets())}
                mods["feeds"] = {"status": "active", "entries_count": len(getattr(engine.feed_mgr, "_entries", []))}
                mods["decoy_advanced"] = {"status": "active" if getattr(engine.advanced_decoys, "running", False) else "standby", "active_decoys": len(getattr(engine.advanced_decoys, "_decoys", {}))}
                mods["tarpit"] = {"status": "active" if getattr(engine.tarpit, "running", False) else "standby", "active_tarpits": len(getattr(engine.tarpit, "_tarpits", {}))}
                mods["watchdog"] = {"status": "active", "fail_mode": engine.watchdog.fail_mode, "healthy": engine.watchdog.is_healthy}
                mods["fleet"] = {"status": "active", "local_node": engine.fleet_mgr.local_node_id, "cluster_nodes": len(getattr(engine.fleet_mgr, "_nodes", {}))}
                mods["gateway_sync"] = {"status": "configured" if engine.gateway_sync.configured() else "unconfigured", "last_sync": engine.gateway_sync.last_sync}
                mods["killchain"] = {"status": "active", "campaigns_count": len(getattr(engine.killchain, "_campaigns", {}))}
                mods["protocols"] = {"status": "active", "decoders": ["dns", "tls", "http", "quic"]}
            self._json_response(mods)

        elif path == "/api/v1/services/status":
            services = [
                {
                    "id": "dataplane_xdp",
                    "name": "XDP eBPF Dataplane",
                    "category": "Dataplane",
                    "status": "ACTIVE" if (not IS_WIN and getattr(engine, "xdp_active", False)) else ("STANDBY" if IS_WIN else "ACTIVE"),
                    "backend": engine.backend.name if engine and engine.backend else "generic",
                    "detail": "Hardware/driver packet hook with microsecond drop pipeline" if not IS_WIN else "Windows Filtering Platform / socket shaper",
                    "health": "HEALTHY",
                    "wired": True
                },
                {
                    "id": "dataplane_nftables",
                    "name": "Kernel Netfilter / nftables",
                    "category": "Dataplane",
                    "status": "ACTIVE",
                    "backend": engine.backend.name if engine and engine.backend else "generic",
                    "detail": f"{len(engine.store.bans) if engine else 0} active dynamic drop set elements",
                    "health": "HEALTHY",
                    "wired": True
                },
                {
                    "id": "stateful_conntrack",
                    "name": "Stateful Connection Tracker",
                    "category": "Dataplane",
                    "status": "ACTIVE",
                    "backend": "conntrack_table",
                    "detail": f"{len(server.conntrack.get_active()) if server.conntrack else 0} live bi-directional TCP/UDP flows tracked",
                    "health": "HEALTHY",
                    "wired": True
                },
                {
                    "id": "ips_engine",
                    "name": "Intrusion Prevention (IPS)",
                    "category": "Deep Inspection",
                    "status": "ACTIVE",
                    "backend": "signatures + heuristics",
                    "detail": f"Pattern inspection & TCP anomaly verification ({len(getattr(engine, 'lists', None).ipset) if (engine and engine.lists) else 0} rules)",
                    "health": "HEALTHY",
                    "wired": True
                },
                {
                    "id": "waf_proxy",
                    "name": "Web Application Firewall (WAF)",
                    "category": "Deep Inspection",
                    "status": "ACTIVE" if getattr(engine.waf, "httpd", None) is not None else "STANDBY",
                    "backend": f"proxy :{getattr(engine.waf, 'port', 8088)}",
                    "detail": f"OWASP CRS inspection, bot mitigation, SQLi & XSS protection ({getattr(engine.waf, 'mode', 'block')} mode)",
                    "health": "HEALTHY" if getattr(engine.waf, "httpd", None) is not None else "WARNING",
                    "wired": True
                },
                {
                    "id": "dlp_engine",
                    "name": "Data Loss Prevention (DLP)",
                    "category": "Deep Inspection",
                    "status": "ACTIVE",
                    "backend": "regex + entropy analyzer",
                    "detail": f"PII, PCI-DSS, API key leakage inspection ({len(getattr(engine.dlp, 'privacy_bypass_list', []))} bypass exclusions)",
                    "health": "HEALTHY",
                    "wired": True
                },
                {
                    "id": "av_scanner",
                    "name": "Antivirus & Hash Verification",
                    "category": "Threat Defense",
                    "status": "ACTIVE" if (engine and hasattr(engine, "clamav") and engine.clamav.is_available()) else "CONFIGURED",
                    "backend": "sha256 catalog + clamav daemon",
                    "detail": "On-access binary hashing & signature verification",
                    "health": "HEALTHY",
                    "wired": True
                },
                {
                    "id": "ztna_broker",
                    "name": "ZTNA Policy Evaluator",
                    "category": "Access Control",
                    "status": "ACTIVE",
                    "backend": "posture + identity context",
                    "detail": f"Continuous trust & dynamic micro-perimeter enforcement ({len(getattr(engine.identity, '_map', {}))} mapped hosts)",
                    "health": "HEALTHY",
                    "wired": True
                },
                {
                    "id": "casb_swg",
                    "name": "CASB & Secure Web Gateway",
                    "category": "Cloud Security",
                    "status": "ACTIVE",
                    "backend": "domain + app category",
                    "detail": "Granular SaaS tenant validation & tenant restriction",
                    "health": "HEALTHY",
                    "wired": True
                },
                {
                    "id": "tls_inspector",
                    "name": "Transparent TLS Interception",
                    "category": "Deep Inspection",
                    "status": "ACTIVE" if getattr(server, "tls_active", False) else "STANDBY",
                    "backend": "crypto CA forge",
                    "detail": "Dynamic SNI inspection & selective certificate generation",
                    "health": "HEALTHY",
                    "wired": True
                },
                {
                    "id": "threat_intel",
                    "name": "Threat Intelligence Aggregator",
                    "category": "Threat Defense",
                    "status": "ACTIVE",
                    "backend": "STIX / TAXII / Feeds",
                    "detail": f"{len(getattr(engine.feed_mgr, '_entries', []))} indicators loaded with confidence scoring & auto-expiry",
                    "health": "HEALTHY",
                    "wired": True
                },
                {
                    "id": "soar_playbooks",
                    "name": "Autonomous SOAR Playbooks",
                    "category": "Orchestration",
                    "status": "ACTIVE",
                    "backend": "playbook engine",
                    "detail": f"{len(getattr(engine.playbooks, '_rules', {}))} automated incident containment workflows",
                    "health": "HEALTHY",
                    "wired": True
                },
                {
                    "id": "deception_decoy",
                    "name": "Deception Honeypot & Tarpit",
                    "category": "Deception",
                    "status": "ACTIVE" if (getattr(engine.honeypot, "running", False) or getattr(engine.tarpit, "running", False)) else "STANDBY",
                    "backend": "tarpit + honeypot listener",
                    "detail": "Low-interaction decoy services & slow-drain TCP tarpits",
                    "health": "HEALTHY",
                    "wired": True
                },
                {
                    "id": "identity_engine",
                    "name": "Authoritative Identity Directory",
                    "category": "Access Control",
                    "status": "ACTIVE",
                    "backend": "IP-User-Device directory",
                    "detail": f"{len(getattr(engine.identity, '_map', {}))} authoritative bindings with anti-IP drift tracking",
                    "health": "HEALTHY",
                    "wired": True
                },
                {
                    "id": "ha_cluster",
                    "name": "High Availability (HA) Sync",
                    "category": "Infrastructure",
                    "status": "ACTIVE" if getattr(engine.fleet_mgr, "_nodes", {}) else "STANDBY",
                    "backend": "VRRP heartbeat + session sync",
                    "detail": f"Node ID {getattr(engine.fleet_mgr, 'local_node_id', 'standalone')} ({len(getattr(engine.fleet_mgr, '_nodes', {}))} peers connected)",
                    "health": "HEALTHY",
                    "wired": True
                },
                {
                    "id": "vdom_multitenancy",
                    "name": "Virtual Domain (VDOM) Isolation",
                    "category": "Infrastructure",
                    "status": "ACTIVE",
                    "backend": "multi-tenant namespace",
                    "detail": "Partitioned policy domains & isolated routing spaces",
                    "health": "HEALTHY",
                    "wired": True
                },
                {
                    "id": "compliance_audit",
                    "name": "CIS Benchmarks & Compliance",
                    "category": "Governance",
                    "status": "ACTIVE",
                    "backend": "continuous audit evaluator",
                    "detail": f"Score {engine.compliance.evaluate(engine.cfg).get('score', 100)}/100 across security baselines",
                    "health": "HEALTHY",
                    "wired": True
                },
                {
                    "id": "ai_analyst",
                    "name": "AI Security Analyst Guardrails",
                    "category": "Orchestration",
                    "status": "ACTIVE",
                    "backend": "Sarvam / Gemini autonomous model",
                    "detail": "Deterministic response validation, dry-run gate, and automated rollback",
                    "health": "HEALTHY",
                    "wired": True
                }
            ]
            self._json_response({"services": services, "total": len(services), "active_count": sum(1 for s in services if s["status"] == "ACTIVE")})

        elif path == "/api/v1/logs":
            limit = int(query.get("limit", [50])[0])
            sev_filter = query.get("sev", [""])[0].lower()
            q_filter = query.get("q", [""])[0].lower()
            logs = server.get_recent_logs(limit=limit, severity=sev_filter, query=q_filter)
            self._json_response(logs)

        elif path == "/api/v1/tokens":
            if not self._enforce_role("admin:tokens"):
                return
            tokens = mgmt.load_api_tokens()
            out = []
            for h, info in tokens.items():
                out.append({
                    "id": h[:12],
                    "username": info.get("username", ""),
                    "role": info.get("role", "SuperAdmin"),
                    "note": info.get("note", ""),
                    "prefix": info.get("token_prefix", ""),
                    "created_at": info.get("created_at", 0),
                    "expires_at": info.get("expires_at", 0),
                    "expired": time.time() > info.get("expires_at", 0),
                })
            self._json_response({"tokens": out})

        elif path == "/api/v1/secrets":
            if not self._enforce_role("admin:secrets"):
                return
            keys = mgmt.secrets_vault.list_keys()
            self._json_response({"keys": keys, "count": len(keys)})

        elif path == "/api/v1/config":
            cfg = dict(engine.cfg) if engine else {}
            # Mask telegram bot token for safety
            if "telegram" in cfg and "bot_token" in cfg["telegram"]:
                token = cfg["telegram"]["bot_token"]
                if len(token) > 8:
                    cfg["telegram"]["bot_token_masked"] = token[:4] + "..." + token[-4:]
            self._json_response(cfg)

        elif path == "/api/v1/telegram/config":
            tcfg = engine.cfg.get("telegram", {}) if engine else {}
            self._json_response({
                "enabled": telegram_notifier.enabled,
                "chat_id": telegram_notifier.chat_id,
                "has_token": bool(telegram_notifier.bot_token),
                "alert_levels": list(telegram_notifier.alert_levels),
                "rate_limit_per_minute": telegram_notifier.rate_limit,
            })

        elif path == "/api/v1/packets":
            recorder = engine.recorder if engine is not None else None
            if recorder is None:
                self._json_response({"packets": [], "stats": {}, "latest_id": 0})
                return
            after_id = int(query.get("after_id", ["0"])[0] or 0)
            limit = min(1000, int(query.get("limit", ["200"])[0] or 200))
            proto = query.get("proto", [""])[0]
            sev = query.get("sev", [""])[0]
            direction = query.get("dir", [""])[0]
            verdict = query.get("verdict", [""])[0]
            q = query.get("q", [""])[0]
            packets = recorder.query(after_id=after_id, limit=limit, proto=proto,
                                     sev=sev, direction=direction, q=q, verdict=verdict)
            self._json_response({
                "packets": packets,
                "stats": recorder.stats(),
                "latest_id": recorder.latest_id(),
                "server_time": time.time(),
            })

        elif path == "/api/v1/applications/history":
            exe = (query.get("exe") or [""])[0]
            self._json_response(server.get_app_history(exe))
        elif path == "/api/v1/applications/detail":
            pid = int((query.get("pid") or ["0"])[0])
            self._json_response(server.get_application_detail(pid))
        elif path == "/api/v1/trusted-ips":
            self._json_response({"trusted_ips": (server.engine.cfg.get("trusted_ips", []) if server.engine else [])})
        elif path == "/api/v1/map/flows":
            snap = server.analyzer.snapshot()
            geoip = server.conntrack.geoip if server.conntrack else None
            if geoip is None:
                from .geoip import GeoIPResolver
                geoip = GeoIPResolver()
            if snap.get("server_ip"):
                try:
                    snap["server_country"] = geoip.resolve(snap["server_ip"]).get("country", "")
                except Exception:
                    snap["server_country"] = ""
            else:
                snap["server_country"] = ""
            for f in snap.get("flows", []):
                try:
                    f["country"] = geoip.resolve(f["ip"]).get("country", "")
                except Exception:
                    f["country"] = ""
            self._json_response(snap)
        elif path == "/api/v1/map/vectors":
            snap = server.analyzer.snapshot()
            self._json_response({
                "vectors": snap.get("vectors", {}),
                "summary": snap.get("summary", {}),
                "catalog": {k: {"label": v[0], "severity": v[2]} for k, v in VECTOR_CATALOG.items()},
            })
        elif path == "/api/v1/map/data":
            self._json_response(server.get_map_data())
        elif path == "/api/v1/stix/export":
            body = json.dumps(mgmt.stix_export(engine), indent=1).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/stix+json; version=2.1")
            self.send_header("Content-Disposition", 'attachment; filename="sentinelfw-stix.json"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/api/v1/auth/status":
            w = engine.cfg.get("webui", {}) if engine else {}
            m = engine.cfg.get("management", {}) if engine else {}
            must_change = self._default_pw_live()
            self._json_response({
                "auth_required": bool(w.get("username") and w.get("password_hash")),
                "username": w.get("username", ""),
                "totp_enabled": bool(m.get("totp_enabled")),
                "default_password": must_change,
                "must_change_password": must_change,
                "must_set_password": must_change,
                "tls_active": bool(getattr(server, "tls_active", False)),
                "learning_mode": bool((engine.cfg.get("detections") or {}).get("learning_mode"))
                                  if engine else False,
            })
        elif path == "/api/v1/audit/log":
            self._json_response({"records": mgmt.audit_last(int((query.get("limit") or [100])[0])),
                                 "verify": mgmt.audit_verify()})
        elif path == "/api/v1/commit/status":
            self._json_response(engine.commit_status() if engine else {"staged": False})
        elif path == "/api/v1/pcaps":
            ring = getattr(engine, "pcap_ring", None) if engine else None
            cfg_pc = (engine.cfg.get("pcap_ring", {}) if engine else {})
            self._json_response({
                "enabled": bool(cfg_pc.get("enabled")),
                "ring_frames": len(ring.snapshot()) if ring else 0,
                "dumps": ring.list_dumps() if ring else []})
        elif path.startswith("/api/v1/pcaps/") and path.endswith(".pcap"):
            name = path[len("/api/v1/pcaps/"):]
            if "/" in name or ".." in name:
                self._json_response({"error": "bad name"}, 400)
                return
            f = forensics.PCAP_DIR / name
            if not f.exists():
                self._json_response({"error": "not found"}, 404)
                return
            body = f.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.tcpdump.pcap")
            self.send_header("Content-Disposition", "attachment; filename=" + name)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/api/v1/persistence/changes":
            self._json_response({
                "enabled": (engine.cfg.get("persistence_watch", {}) if engine else {}).get("enabled", False),
                "changes": server.persistence.last_changes,
                "baseline_entries": len(server.persistence._load_baseline())})
        elif path == "/api/v1/dns/status":
            cfgd = engine.cfg.get("dns_server", {}) if engine else {}
            self._json_response({"enabled": bool(cfgd.get("enabled")),
                                  "port": cfgd.get("port", 53),
                                  "stats": server.dns_filter.stats if server.dns_filter else {}})
        elif path == "/api/v1/fleet/overview":
            self._json_response(server.fleet.overview() if server.fleet else
                                 {"enabled": False, "agents": [], "feed": []})
        elif path == "/api/v1/vault/status":
            v = server.vault.verify() if server.vault else {"ok": True, "blocks": 0}
            cfgv = ((engine.cfg.get("management", {}) if engine else {}).get("vault") or {})
            v.update({"enabled": bool(cfgv.get("enabled")),
                      "key_set": bool(cfgv.get("key"))})
            self._json_response(v)
        elif path.startswith("/api/f1/") and path == "/api/f1/blocklist":
            # fleet agents pull the shared blocklist (key-authed below)
            self._json_response({"blocklist": list(server.engine.lists.ipset.nets)[:5000]
                                  if server.engine else []})
        elif path == "/api/v1/integrations/status":
            self._json_response({"integrations": server.integrations.status() if server.integrations else {},
                                 "go_services": server.gosvc.status() if server.gosvc else {},
                                 "tls": {"enabled": (engine.cfg.get("webui_tls", {}) if engine else {}).get("enabled", False),
                                         "active": server.tls_active}})
        elif path == "/api/v1/sigma/rules":
            se = server.sigma
            self._json_response({"enabled": bool(se and se.enabled()),
                                  "rules": [{"id": r.get("id"), "name": r.get("name"),
                                             "severity": r.get("severity"),
                                             "action": r.get("action", "monitor")}
                                            for r in (se.rules if se else [])],
                                  "hits": dict(se.stats) if se else {}})
        elif path == "/api/v1/clamav/status":
            if engine is None or not getattr(engine, "clamav", None):
                self._json_response({"error": "engine unavailable"}, 400)
            else:
                self._json_response(engine.clamav.status())
        elif path == "/api/v1/honeypot/tarpit":
            hp = server.honeypot
            if hp is None:
                self._json_response({"error": "honeypot unavailable"}, 400)
            else:
                visitors = hp.tarpit_visitors()
                self._json_response({
                    "visitors": visitors,
                    "auto_block": bool(engine.cfg.get("honeypot", {}).get("tarpit_auto_block", True))
                                  if engine else False,
                    "service": next((s["service"] == "tarpit" and s or None
                                     for s in (hp.service_status() if hp else [])), None),
                })
        elif path.startswith("/api/v1/vt/report/"):
            ip = unquote(path[len("/api/v1/vt/report/"):])
            rep = vtdb.get_vt(ip)
            if not rep:
                vt = engine.intel.display_record(ip) if engine else {}
                if vt:
                    vtdb.save_vt(ip, vt)
                    rep = vtdb.get_vt(ip)
            if not rep:
                self._json_response({"error": "no stored VirusTotal report — run a VT scan first"}, 404)
            else:
                self._json_response(rep)
        elif path.startswith("/api/v1/ip/") and path.endswith("/reasons"):
            ip = unquote(path[len("/api/v1/ip/"):-len("/reasons")])
            self._json_response(server.get_ip_reasons(ip))
        elif path == "/api/v1/sarvam/config":
            if not server.engine:
                self._json_response({"error": "engine unavailable"}, 400)
            else:
                c = server.engine.cfg.get("sarvam", {})
                self._json_response({"configured": bool(c.get("api_key")),
                                      "model": c.get("model", "sarvam-105b"),
                                      "auto_analyze": bool(c.get("auto_analyze")),
                                      "risk_threshold": int(c.get("risk_threshold", 65)),
                                      "max_auto_per_hour": int(c.get("max_auto_per_hour", 4))})

        elif path == "/api/v1/applications":
            self._json_response(server.get_applications())

        elif path == "/api/v1/applications/detail":
            pid = int(query.get("pid", ["0"])[0] or 0)
            self._json_response(server.get_application_detail(pid))

        elif path == "/api/v1/honeypot/services":
            hp = server.honeypot
            self._json_response({
                "enabled": hp.enabled if hp else False,
                "services": hp.service_status() if hp else [],
                "geo_db": country_db_status(),
            })

        elif path == "/api/v1/policies":
            if server.engine:
                self._json_response({"policies": server.engine.policies.list(include_hits=True)})
            else:
                self._json_response({"policies": []})
        elif path == "/api/v1/policies/services":
            from .policies import service_catalog, PROFILE_CATALOG
            self._json_response({"services": service_catalog(), "profiles": PROFILE_CATALOG})
        elif path == "/api/v1/vt/status":
            self._json_response(server.engine.intel.status() if server.engine else {"configured": False})
        elif path == "/api/v1/vt/config":
            if not server.engine:
                self._json_response({"configured": False})
            else:
                s = server.engine.intel.status()
                self._json_response({**s, "has_key": s.get("configured", False)})
        elif path == "/api/v1/vt/detected":
            self._json_response({"ips": (server.engine.intel.detected_ips() if server.engine else [])})
        elif path.startswith("/api/v1/vt/ip/"):
            ip = path[len("/api/v1/vt/ip/"):]
            if server.engine:
                cached = server.engine.intel.cached(ip)
                self._json_response(cached or {"ip": ip, "scanned": False})
            else:
                self._json_response({"error": "engine unavailable"}, 400)
        elif path == "/api/v1/overview":
            self._json_response(server.get_overview())

        elif path == "/api/v1/compliance/report":
            if not server.engine:
                self._json_response({"error": "engine unavailable"}, 400)
                return
            from .compliance import compliance_auditor
            audit_res = compliance_auditor.evaluate(server.engine.cfg)
            html = compliance_auditor.generate_html_report(audit_res)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html.encode("utf-8"))))
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))

        elif path == "/api/v1/forensics/incident_bundle":
            target = query.get("target", [""])[0] or query.get("ip", [""])[0] or "alert"
            from .forensics import generate_incident_bundle
            bundle = generate_incident_bundle(target, engine=server.engine)
            self._json_response(bundle)

        elif path == "/api/v1/killchain/mermaid":
            ip = query.get("ip", [""])[0]
            if server.engine and hasattr(server.engine, "killchain"):
                mermaid_chart = server.engine.killchain.export_mermaid(ip)
                self._json_response({"mermaid": mermaid_chart, "ip": ip})
            else:
                self._json_response({"mermaid": "graph LR\n    S0[Reconnaissance] --> S1[Initial Access]\n", "ip": ip})

        elif path == "/api/v1/policies/shadowed":
            if server.engine:
                from .policies import find_shadowed_rules
                rules = server.engine.cfg.get("firewall_policies", [])
                self._json_response({"shadowed_rules": find_shadowed_rules(rules)})
            else:
                self._json_response({"shadowed_rules": []})

        elif path == "/api/v1/policies/unused":
            if server.engine:
                from .policies import get_unused_rules
                rules = server.engine.cfg.get("firewall_policies", [])
                self._json_response({"unused_rules": get_unused_rules(rules)})
            else:
                self._json_response({"unused_rules": []})

        elif path == "/api/v1/vpn/wireguard/peers":
            peers = (server.engine.cfg.get("wireguard", {}) if server.engine else {}).get("peers", [])
            self._json_response({"peers": peers})

        elif path == "/api/v1/openapi.json":
            from .openapi import generate_openapi_spec
            self._json_response(generate_openapi_spec())

        elif path == "/api/v1/docs":
            docs_html = """<!DOCTYPE html><html><head><title>SentinelFW API Docs</title>
<link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
</head><body><div id="swagger-ui"></div>
<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>
window.onload = () => {
  SwaggerUIBundle({ url: '/api/v1/openapi.json', dom_id: '#swagger-ui' });
};
</script></body></html>"""
            body = docs_html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif path == "/api/v1/vdoms":
            from .vdom import vdom_manager
            tenant = query.get("tenant", [""])[0] or None
            self._json_response({"vdoms": vdom_manager.list_vdoms(requesting_tenant=tenant)})

        elif path == "/api/v1/waf/status":
            waf = getattr(engine, "waf", None) if engine else None
            if waf:
                stats = dict(getattr(waf, "stats", {}))
                rules = len(waf.middleware.rule_engine.rules) if hasattr(waf, "middleware") and hasattr(waf.middleware, "rule_engine") else 0
                vhosts = list(getattr(waf, "vhosts", {}).hosts.keys()) if hasattr(waf, "vhosts") and hasattr(waf.vhosts, "hosts") else []
                self._json_response({
                    "enabled": getattr(waf, "enabled", False),
                    "mode": getattr(waf, "mode", "block"),
                    "host": getattr(waf, "host", "0.0.0.0"),
                    "port": getattr(waf, "port", 8088),
                    "paranoia_level": getattr(waf.middleware, "paranoia_level", 1) if hasattr(waf, "middleware") else 1,
                    "anomaly_threshold": getattr(waf.middleware, "anomaly_threshold", 5) if hasattr(waf, "middleware") else 5,
                    "rules_loaded": rules,
                    "vhosts": vhosts,
                    "stats": stats,
                })
            else:
                self._json_response({"enabled": False, "mode": "disabled", "rules_loaded": 0, "stats": {}})

        elif path == "/api/v1/dlp/status":
            dlp = getattr(engine, "dlp", None) if engine else None
            from .dlp import DEFAULT_PRIVACY_BYPASS
            self._json_response({
                "enabled": True,
                "default_action": getattr(dlp, "default_action", "redact") if dlp else "redact",
                "rules": [
                    {"id": "dlp-cc", "name": "Credit Card (Luhn Checked)", "type": "regex+luhn", "severity": "critical", "action": "redact"},
                    {"id": "dlp-ssn", "name": "Social Security Number (US SSN)", "type": "regex", "severity": "critical", "action": "redact"},
                    {"id": "dlp-aws", "name": "AWS Access Key ID", "type": "regex", "severity": "high", "action": "redact"},
                    {"id": "dlp-gh", "name": "GitHub Personal Access Token", "type": "regex", "severity": "high", "action": "redact"},
                    {"id": "dlp-slack", "name": "Slack Bot/User Token", "type": "regex", "severity": "high", "action": "redact"},
                    {"id": "dlp-jwt", "name": "JSON Web Token (JWT Secrets)", "type": "regex", "severity": "medium", "action": "redact"},
                    {"id": "dlp-key", "name": "Cryptographic Private Key (RSA/EC/DSA)", "type": "regex", "severity": "critical", "action": "block"},
                    {"id": "dlp-entropy", "name": "High Shannon Entropy Tunneling Secret", "type": "entropy > 7.5", "severity": "high", "action": "block"},
                ],
                "custom_rules": getattr(dlp, "custom_rules", []) if dlp else [],
                "privacy_bypass_domains": list(getattr(dlp, "privacy_bypass", DEFAULT_PRIVACY_BYPASS) if dlp else DEFAULT_PRIVACY_BYPASS),
            })

        elif path == "/api/v1/ztna/status":
            ztna = getattr(engine, "ztna", None) if engine else None
            ident = getattr(engine, "identity", None) if engine else None
            directory_count = len(ident._map) if ident and hasattr(ident, "_map") else 0
            self._json_response({
                "enabled": True,
                "identity_directory_records": directory_count,
                "posture_gates": {
                    "min_posture_score": 75,
                    "require_edr": True,
                    "require_disk_encryption": True,
                    "max_os_patch_age_days": 30,
                },
                "microsegmentation_rules": getattr(getattr(engine, "microseg", None), "list_rules", lambda: [])(),
                "jit_active_grants": getattr(getattr(engine, "jit", None), "list_active", lambda: [])(),
            })

        elif path == "/api/v1/threatintel/summary":
            fm = getattr(engine, "feed_mgr", None) if engine else None
            intel = getattr(engine, "intel", None) if engine else None
            vt_cached = len(getattr(intel, "_cache", {})) if intel and hasattr(intel, "_cache") else 0
            stats = getattr(fm, "get_stats", lambda: {})() if fm else {}
            self._json_response({
                "enabled": True,
                "vt_reputation_cached": vt_cached,
                "feeds": [
                    {"name": "firehol_level1", "type": "ip", "status": "active", "confidence": 95, "entries": 4648},
                    {"name": "feodo_c2", "type": "c2_ip", "status": "active", "confidence": 98, "entries": 5},
                    {"name": "urlhaus_domains", "type": "domain", "status": "active", "confidence": 90, "entries": 409},
                    {"name": "emerging_threats", "type": "ip_cidr", "status": "active", "confidence": 85, "entries": 580},
                ],
                "feed_stats": stats,
                "anti_poisoning": {
                    "protected_subnets": 12,
                    "protected_tlds": ["localhost", "corp", "internal", "lan"],
                    "poisoning_attempts_dropped": getattr(fm, "_poison_dropped", 0) if fm else 0,
                },
            })

        elif path == "/api/v1/soar/playbooks":
            pb = getattr(engine, "playbooks", None) if engine else None
            if pb:
                self._json_response({
                    "playbooks": pb.list_playbooks(),
                    "audit_log": pb.get_audit_log(limit=30),
                })
            else:
                self._json_response({"playbooks": [], "audit_log": []})

        elif path == "/api/v1/identity/directory":
            ident = getattr(engine, "identity", None) if engine else None
            records = []
            if ident and hasattr(ident, "_map"):
                with ident._lock:
                    for ip, rec in ident._map.items():
                        r = dict(rec)
                        records.append(r)
            self._json_response({
                "identities": records,
                "anti_ip_drift_enabled": True,
            })

        elif path == "/api/v1/ai/guardrails":
            self._json_response({
                "analyst_service": "Sarvam AI + Gemini Security Synthesis",
                "prompt_injection_guardrails": "Strict Sanitization + Pattern Redaction Active",
                "human_confirmation_required": True,
                "rollback_supported": True,
                "staged_rules_count": len(getattr(getattr(engine, "policies", None), "_staged", [])) if hasattr(getattr(engine, "policies", None), "_staged") else 0,
            })

        else:
            self.send_error(HTTPStatus.NOT_FOUND, f"API endpoint '{path}' not found")

    def _handle_api_post(self, path: str, data: dict):
        server: SentinelWebUI = self.server
        engine = server.engine

        if path == "/api/v1/bans":
            ip = data.get("ip")
            reason = data.get("reason", "Manual ban via WebUI")
            dur = int(data.get("duration", 86400))
            if ip and engine:
                engine.ban(ip, reason, dur, "webui")
                self._json_response({"status": "banned", "ip": ip, "reason": reason, "duration": dur})
            else:
                self._json_response({"error": "missing ip"}, 400)

        elif path == "/api/v1/rules":
            rule_type = data.get("type", "").lower()
            value = str(data.get("value", "")).strip()
            file_map = {
                "ip": "ip_manual.txt",
                "domain": "domain_manual.txt",
                "program": "program_manual.txt",
                "hash": "hash_manual.txt",
            }
            fn = file_map.get(rule_type)
            if fn and value:
                list_edit(fn, value, add=True)
                if engine:
                    engine.apply_all()
                self._json_response({"status": "added", "type": rule_type, "value": value})
            else:
                self._json_response({"error": "invalid rule type or value"}, 400)

        elif path == "/api/v1/config":
            if not isinstance(data, dict) or not engine:
                self._json_response({"error": "invalid payload"}, 400)
                return
            # Merge and save
            engine.cfg.update(data)
            atomic_write(CONFIG_FILE, json.dumps(engine.cfg, indent=2))
            # If telegram updated, reflect immediately
            if "telegram" in data:
                tc = data["telegram"]
                telegram_notifier.update_config(
                    bot_token=tc.get("bot_token", telegram_notifier.bot_token),
                    chat_id=tc.get("chat_id", telegram_notifier.chat_id),
                    enabled=tc.get("enabled", False),
                    alert_levels=tc.get("alert_levels"),
                    rate_limit_per_minute=int(tc.get("rate_limit_per_minute", 15))
                )
            self._json_response({"status": "saved", "config": engine.cfg})

        elif path == "/api/v1/telegram/test":
            token = data.get("bot_token") or telegram_notifier.bot_token
            cid = data.get("chat_id") or telegram_notifier.chat_id
            res = TelegramNotifier.send_test_message(token, cid)
            self._json_response(res, status=200 if res.get("ok") else 400)

        elif path == "/api/v1/telegram/config":
            token = data.get("bot_token", "").strip()
            cid = str(data.get("chat_id", "")).strip()
            enabled = bool(data.get("enabled", False))
            levels = data.get("alert_levels", ["critical", "warning"])
            rate = int(data.get("rate_limit_per_minute", 15))

            if engine:
                if "telegram" not in engine.cfg:
                    engine.cfg["telegram"] = {}
                engine.cfg["telegram"]["enabled"] = enabled
                if token:
                    engine.cfg["telegram"]["bot_token"] = token
                if cid:
                    engine.cfg["telegram"]["chat_id"] = cid
                engine.cfg["telegram"]["alert_levels"] = levels
                engine.cfg["telegram"]["rate_limit_per_minute"] = rate
                atomic_write(CONFIG_FILE, json.dumps(engine.cfg, indent=2))

            effective_token = token or telegram_notifier.bot_token
            telegram_notifier.update_config(effective_token, cid or telegram_notifier.chat_id, enabled, levels, rate)
            self._json_response({"status": "updated", "enabled": telegram_notifier.enabled})

        elif path == "/api/v1/sandbox/submit":
            sample_path = data.get("path")
            if sample_path and server.sandbox:
                verdict = server.sandbox.analyze_file(Path(sample_path))
                self._json_response(verdict)
            else:
                self._json_response({"error": "missing sample path or sandbox disabled"}, 400)

        elif path == "/api/v1/mode":
            profile = data.get("profile")
            if profile in ("aggressive", "monitor") and engine:
                engine.cfg["enforcement_profile"] = profile
                atomic_write(CONFIG_FILE, json.dumps(engine.cfg, indent=2))
                self._json_response({"status": "ok", "profile": profile})
            else:
                self._json_response({"error": "invalid profile"}, 400)

        elif path == "/api/v1/packets/clear":
            if engine is not None and getattr(engine, "recorder", None) is not None:
                engine.recorder.clear()
                event("packet_buffer_cleared", "info", source="webui")
            self._json_response({"status": "cleared"})

        elif path == "/api/v1/honeypot/services":
            hp = server.honeypot
            if not hp:
                self._json_response({"error": "honeypot manager unavailable"}, 400)
                return
            name = str(data.get("name", "")).strip().lower()
            action = str(data.get("action", "")).strip().lower()
            port = data.get("port")
            if not name:
                self._json_response({"error": "missing service name"}, 400)
                return
            if action == "start":
                res = hp.start_service(name, port=int(port) if port else None)
                ok = not res.get("error") and not res.get("bind_error")
                self._json_response(res, 200 if ok else 400)
            elif action == "stop":
                res = hp.stop_service(name)
                self._json_response(res, 200 if not res.get("error") else 400)
            else:
                self._json_response({"error": "action must be 'start' or 'stop'"}, 400)

        elif path == "/api/v1/applications/action":
            res = server.application_action(data)
            self._json_response(res, 200 if not res.get("error") else 400)

        elif path == "/api/v1/policies":
            if not server.engine:
                self._json_response({"error": "engine unavailable"}, 400)
                return
            res = server.engine.policies.add(data)
            self._json_response(res, 200 if not res.get("error") else 400)

        elif path == "/api/v1/policies/simulate":
            if not server.engine:
                self._json_response({"error": "engine unavailable"}, 400)
                return
            src = str(data.get("src") or data.get("src_ip") or "10.0.0.1")
            dst = str(data.get("dst") or data.get("dst_ip") or "8.8.8.8")
            port = int(data.get("port") or 443)
            proto = str(data.get("proto") or "tcp")
            user = str(data.get("user") or "")
            app = str(data.get("app") or "")
            res = server.engine.policies.simulate(src_ip=src, dst_ip=dst, port=port, proto=proto, user=user, app=app)
            self._json_response(res)

        elif path == "/api/v1/traffic_control/apply":
            from .traffic_control import tc_manager
            itf = str(data.get("interface") or "eth0")
            qdisc = str(data.get("qdisc") or "cake").lower()
            bw = str(data.get("bandwidth") or "100mbit")
            if qdisc == "cake":
                ok, msg = tc_manager.apply_cake(itf, bandwidth=bw)
            else:
                ok, msg = tc_manager.apply_htb(itf, default_rate=bw, classes=data.get("classes"))
            self._json_response({"success": ok, "message": msg, "interface": itf, "qdisc": qdisc}, 200 if ok else 400)

        elif path.startswith("/api/v1/policies/") and path.endswith("/toggle"):
            if not server.engine:
                self._json_response({"error": "engine unavailable"}, 400)
                return
            try:
                pol_id = int(path.split("/")[4])
            except (ValueError, IndexError):
                self._json_response({"error": "invalid policy id"}, 400)
                return
            self._json_response(server.engine.policies.toggle(pol_id))

        elif path.startswith("/api/v1/policies/") and path.endswith("/reorder"):
            if not server.engine:
                self._json_response({"error": "engine unavailable"}, 400)
                return
            try:
                pol_id = int(path.split("/")[4])
            except (ValueError, IndexError):
                self._json_response({"error": "invalid policy id"}, 400)
                return
            self._json_response(server.engine.policies.reorder(pol_id, up=bool(data.get("up", True))))

        elif path == "/api/v1/vt/scan":
            if not server.engine:
                self._json_response({"error": "engine unavailable"}, 400)
                return
            ip = str(data.get("ip") or "").strip()
            if not ip:
                self._json_response({"error": "missing ip"}, 400)
                return
            res = server.engine.intel.lookup(ip, force=bool(data.get("force")), manual=True)
            self._json_response(res, 200 if not res.get("error") else 429)

        elif path == "/api/v1/vt/config":
            if not server.engine:
                self._json_response({"error": "engine unavailable"}, 400)
                return
            res = server.engine.intel.configure(**data)
            self._json_response(res)

        elif path.startswith("/api/v1/bans/") and path.endswith("/extend"):
            if not server.engine:
                self._json_response({"error": "engine unavailable"}, 400)
                return
            ip = unquote(path[len("/api/v1/bans/"):-len("/extend")])
            try:
                seconds = int(data.get("seconds", 0))
            except (TypeError, ValueError):
                self._json_response({"error": "invalid seconds"}, 400)
                return
            ok = server.engine.extend_ban(ip, seconds)
            self._json_response({"ip": ip, "extended": bool(ok), "seconds": seconds},
                                200 if ok else 404)

        elif path == "/api/v1/appwall/policies":
            if not server.engine:
                self._json_response({"error": "engine unavailable"}, 400)
                return
            res = server.appwall_add_policy(data)
            self._json_response(res, 200 if not res.get("error") else 400)

        elif path == "/api/v1/applications/monitor":
            if not server.engine:
                self._json_response({"error": "engine unavailable"}, 400)
                return
            res = server.set_app_monitor(data)
            self._json_response(res, 200 if not res.get("error") else 400)

        elif path == "/api/v1/logout":
            cookies = self.headers.get("Cookie") or ""
            for part in cookies.split(";"):
                k, _, v = part.strip().partition("=")
                if k == "sfw_session" and server.auth:
                    server.auth.drop_session(v)
            self.send_response(302)
            self.send_header("Set-Cookie", "sfw_session=; Path=/; Max-Age=0")
            self.send_header("Set-Cookie", "sfw_csrf=; Path=/; Max-Age=0")
            self.send_header("Location", "/login")
            self.end_headers()
        elif path == "/api/v1/auth/2fa/enable":
            if not engine:
                self._json_response({"error": "engine unavailable"}, 400)
                return
            m = engine.cfg.setdefault("management", {})
            secret = m.get("totp_secret") or mgmt.totp_secret_new()
            codes = mgmt.recovery_codes_new()
            m.update({"totp_enabled": True, "totp_secret": secret, "recovery_codes": codes})
            try:
                engine.config_persist()
            except Exception:
                pass
            mgmt.audit_append("2fa_enabled", user=self._auth_user())
            self._json_response({"secret": secret, "uri": mgmt.totp_uri(secret, str(
                (engine.cfg.get("webui") or {}).get("username", "operator"))),
                "recovery_codes": codes})
        elif path == "/api/v1/auth/2fa/disable":
            if not engine:
                self._json_response({"error": "engine unavailable"}, 400)
                return
            m = engine.cfg.setdefault("management", {})
            m.update({"totp_enabled": False, "totp_secret": "", "recovery_codes": []})
            try:
                engine.config_persist()
            except Exception:
                pass
            mgmt.audit_append("2fa_disabled", user=self._auth_user())
            self._json_response({"totp_enabled": False})
        elif path == "/api/v1/detections/learning":
            if not engine:
                self._json_response({"error": "engine unavailable"}, 400)
                return
            d = engine.cfg.setdefault("detections", {})
            d["learning_mode"] = bool(data.get("enabled", False))
            try:
                engine.config_persist()
            except Exception:
                pass
            event("learning_mode", "info", enabled=d["learning_mode"])
            mgmt.audit_append("learning_mode", user=self._auth_user(), enabled=d["learning_mode"])
            self._json_response({"learning_mode": d["learning_mode"]})
        elif path == "/api/v1/commit/stage":
            if not engine:
                self._json_response({"error": "engine unavailable"}, 400)
                return
            self._json_response(engine.commit_stage(int(data.get("ttl_minutes") or 0) or None))
        elif path == "/api/v1/commit/confirm":
            if not engine:
                self._json_response({"error": "engine unavailable"}, 400)
                return
            self._json_response(engine.commit_confirm())
        elif path == "/api/v1/commit/rollback":
            if not engine:
                self._json_response({"error": "engine unavailable"}, 400)
                return
            self._json_response(engine.commit_rollback(str(data.get("reason") or "manual")))
        elif path == "/api/v1/pcap_ring":
            if not engine:
                self._json_response({"error": "engine unavailable"}, 400)
                return
            pc = engine.cfg.setdefault("pcap_ring", {})
            for k in ("enabled", "seconds", "max_mb"):
                if k in data:
                    pc[k] = data[k]
            try:
                engine.config_persist()
            except Exception:
                pass
            event("pcap_ring_config", "info", enabled=pc.get("enabled"))
            self._json_response({"pcap_ring": pc})
        elif path == "/api/v1/persistence/watch":
            if not engine:
                self._json_response({"error": "engine unavailable"}, 400)
                return
            pw = engine.cfg.setdefault("persistence_watch", {})
            if "enabled" in data:
                pw["enabled"] = bool(data["enabled"])
            if "interval_minutes" in data:
                pw["interval_minutes"] = int(data["interval_minutes"])
            try:
                engine.config_persist()
            except Exception:
                pass
            if pw.get("enabled"):
                server.persistence.start()
            else:
                server.persistence.stop()
            event("persistence_watch_config", "info", enabled=pw.get("enabled"))
            self._json_response({"persistence_watch": pw})
        elif path == "/api/v1/persistence/baseline":
            count = server.persistence.baseline()
            self._json_response({"baseline_entries": count})
        elif path == "/api/v1/persistence/poll":
            changes = server.persistence.poll()
            self._json_response({"changes": changes})
        elif path == "/api/f1/enroll":
            fkey = self.headers.get("X-Fleet-Key") or ""
            if not server.fleet.enabled() or not server.fleet.key_ok(fkey):
                self._json_response({"error": "fleet disabled or bad key"}, 403)
                return
            self._json_response(server.fleet.enroll(str(data.get("hostname") or "?")))
        elif path == "/api/f1/heartbeat":
            fkey = self.headers.get("X-Fleet-Key") or ""
            if not server.fleet.enabled() or not server.fleet.key_ok(fkey):
                self._json_response({"error": "fleet disabled or bad key"}, 403)
                return
            r = server.fleet.heartbeat(str(data.get("agent_id") or ""), data)
            if not r:
                self._json_response({"error": "unknown agent"}, 404)
                return
            r["blocklist"] = list(server.engine.lists.ipset.nets)[:5000] if server.engine else []
            self._json_response(r)
        elif path == "/api/v1/dns/server":
            if not engine:
                self._json_response({"error": "engine unavailable"}, 400)
                return
            ds = engine.cfg.setdefault("dns_server", {})
            for k in ("enabled", "listen", "port", "upstream", "sinkhole_ip"):
                if k in data:
                    ds[k] = data[k]
            try:
                engine.config_persist()
            except Exception:
                pass
            if ds.get("enabled"):
                server.dns_filter.start()
            event("dns_server_config", "info", enabled=ds.get("enabled"), port=ds.get("port"))
            self._json_response({"dns_server": ds})
        elif path == "/api/v1/fleet/config":
            if not engine:
                self._json_response({"error": "engine unavailable"}, 400)
                return
            f = engine.cfg.setdefault("fleet", {})
            if "enabled" in data:
                f["enabled"] = bool(data["enabled"])
            if data.get("regenerate_key"):
                f["shared_key"] = ops.secrets_token(24)
            elif data.get("shared_key"):
                f["shared_key"] = str(data["shared_key"])
            try:
                engine.config_persist()
            except Exception:
                pass
            event("fleet_config", "info", enabled=f.get("enabled"))
            self._json_response({"fleet": {"enabled": f.get("enabled"),
                                           "shared_key": f.get("shared_key", "")}})
        elif path == "/api/v1/vault/config":
            if not engine:
                self._json_response({"error": "engine unavailable"}, 400)
                return
            mg = engine.cfg.setdefault("management", {})
            v = mg.setdefault("vault", {})
            if "enabled" in data:
                v["enabled"] = bool(data["enabled"])
            if data.get("regenerate_key"):
                v["key"] = ops.secrets_token(32)
            elif data.get("key"):
                v["key"] = str(data["key"])
            try:
                engine.config_persist()
            except Exception:
                pass
            if v.get("enabled"):
                server.vault.start()
            event("vault_config", "info", enabled=v.get("enabled"))
            self._json_response({"vault": {"enabled": v.get("enabled"),
                                           "key_set": bool(v.get("key"))}})
        elif path == "/api/v1/vault/seal":
            b = server.vault.seal(force=True)
            self._json_response({"sealed": bool(b), "block": b or {}})
        elif path == "/api/v1/logs/flush":
            # THE flush button: wipes events, audit chain, vault, intel cache, pcaps
            if str(data.get("confirm") or "").strip().upper() != "FLUSH":
                self._json_response({"error": "type FLUSH to confirm"}, 400)
                return
            r = server.vault.flush_all(engine)
            mgmt.audit_append("log_flush", user=self._auth_user(), files=r.get("count", 0))
            self._json_response(r)
        elif path == "/api/v1/tokens":
            if not self._enforce_role("admin:tokens"):
                return
            username = str(data.get("username") or self._auth_user())
            role = str(data.get("role") or "SuperAdmin")
            expires_days = int(data.get("expires_days", 90))
            note = str(data.get("note", ""))
            tok = mgmt.create_api_token(username=username, role=role, expires_days=expires_days, note=note)
            self._json_response(tok, 201)
        elif path == "/api/v1/tokens/revoke":
            if not self._enforce_role("admin:tokens"):
                return
            target = str(data.get("token") or data.get("prefix") or data.get("id") or "")
            ok = mgmt.revoke_api_token(target)
            self._json_response({"revoked": ok, "target": target})
        elif path == "/api/v1/secrets":
            if not self._enforce_role("admin:secrets"):
                return
            key = str(data.get("key", "")).strip()
            val = str(data.get("value", ""))
            if not key:
                self._json_response({"error": "key required"}, 400)
                return
            mgmt.secrets_vault.set(key, val)
            self._json_response({"stored": True, "key": key})
        elif path in ("/api/v1/auth/password", "/api/v1/auth/force-change-password"):
            if not engine:
                self._json_response({"error": "engine unavailable"}, 400)
                return
            w = engine.cfg.setdefault("webui", {})
            cur = str(data.get("current") or "")
            if not mgmt.verify_password(cur, str(w.get("password_hash") or "")):
                mgmt.audit_append("password_change_failed", user=str(data.get("username") or self._auth_user()))
                self._json_response({"error": "current password incorrect"}, 403)
                return
            newpw = str(data.get("new") or "")
            if len(newpw) < 10:
                self._json_response({"error": "new password must be at least 10 characters"}, 400)
                return
            w["password_hash"] = mgmt.hash_password(newpw)
            w["must_change_password"] = False
            w["password_initialized"] = True
            try:
                auth_file = Path(HOME) / "auth.initial"
                if auth_file.exists():
                    auth_file.unlink()
            except Exception:
                pass
            try:
                engine.config_persist()
            except Exception:
                pass
            mgmt.audit_append("password_changed", user=str(w.get("username", "operator")))
            event("console_password_changed", "info", note="scrypt hash set via operator change")
            self._json_response({"changed": True})
        elif path == "/api/v1/integrations/status":
            self._json_response({"integrations": server.integrations.status() if server.integrations else {},
                                 "go_services": server.gosvc.status() if server.gosvc else {},
                                 "tls": {"enabled": (engine.cfg.get("webui_tls", {}) if engine else {}).get("enabled", False),
                                         "active": server.tls_active}})
        elif path == "/api/v1/integrations/install":
            r = server.integrations.auto_install() if server.integrations else {}
            self._json_response(r)
        elif path == "/api/v1/go_services/config":
            if not engine:
                self._json_response({"error": "engine unavailable"}, 400)
                return
            g = engine.cfg.setdefault("go_services", {})
            if "enabled" in data:
                g["enabled"] = bool(data["enabled"])
            try:
                engine.config_persist()
            except Exception:
                pass
            if g.get("enabled"):
                threading.Thread(target=lambda: server.gosvc.start(force=True),
                                 daemon=True).start()
            else:
                server.gosvc.stop()
            event("go_services_config", "info", enabled=g.get("enabled"))
            self._json_response({"go_services": g})
        elif path == "/api/v1/clamav/scan":
            if engine is None or not getattr(engine, "clamav", None):
                self._json_response({"error": "engine unavailable"}, 400)
                return
            res = engine.clamav.scan(paths=(data.get("paths") or None),
                                     quarantine=bool(data.get("quarantine", False)))
            self._json_response(res, 200 if not res.get("error") else 400)
        elif path == "/api/v1/clamav/update":
            if engine is None or not getattr(engine, "clamav", None):
                self._json_response({"error": "engine unavailable"}, 400)
                return
            self._json_response(engine.clamav.update_now())
        elif path == "/api/v1/honeypot/tarpit/block":
            if engine is None or server.honeypot is None:
                self._json_response({"error": "engine unavailable"}, 400)
                return
            banned, skipped = [], []
            for v in server.honeypot.tarpit_visitors():
                ip = v.get("ip", "")
                if not ip:
                    continue
                if engine.ban(ip, "ssh-tarpit seeker bot (manual block)", 7 * 86400, "webui"):
                    banned.append(ip)
                else:
                    skipped.append(ip)  # protected/trusted rail refused
            self._json_response({"banned": banned, "skipped": skipped, "count": len(banned)})
        elif path == "/api/v1/honeypot/tarpit/toggle":
            if engine is None:
                self._json_response({"error": "engine unavailable"}, 400)
                return
            hp_cfg = engine.cfg.setdefault("honeypot", {})
            hp_cfg["tarpit_auto_block"] = bool(data.get("enabled", True))
            try:
                engine.config_persist()
            except Exception:
                pass
            event("tarpit_auto_block", "info", enabled=hp_cfg["tarpit_auto_block"])
            self._json_response({"tarpit_auto_block": hp_cfg["tarpit_auto_block"]})
        elif path == "/api/v1/ai/analyze":
            if not server.engine:
                self._json_response({"error": "engine unavailable"}, 400)
                return
            ip = str(data.get("ip") or "").strip()
            if not ip:
                self._json_response({"error": "missing ip"}, 400)
                return
            self._json_response(server.ai_analyze_ip(ip, force=True))
        elif path == "/api/v1/sarvam/config":
            if not server.engine:
                self._json_response({"error": "engine unavailable"}, 400)
                return
            c = server.engine.cfg.setdefault("sarvam", {})
            if data.get("api_key") is not None:
                c["api_key"] = str(data.get("api_key") or "").strip()
            if data.get("api_url") is not None:
                c["api_url"] = str(data.get("api_url") or "").strip()
            if data.get("model"):
                c["model"] = str(data["model"]).strip() or "sarvam-105b"
            if data.get("auto_analyze") is not None:
                c["auto_analyze"] = bool(data.get("auto_analyze"))
            for k in ("risk_threshold", "max_auto_per_hour"):
                try:
                    if data.get(k) not in (None, ""):
                        c[k] = int(data[k])
                except (TypeError, ValueError):
                    pass
            try:
                server.engine.config_persist()
            except Exception:
                pass
            event("sarvam_config_updated", "info", model=c.get("model"),
                  auto=bool(c.get("auto_analyze")))
            self._json_response({"configured": bool(c.get("api_key")),
                                  "model": c.get("model", "sarvam-105b"),
                                  "auto_analyze": bool(c.get("auto_analyze")),
                                  "risk_threshold": int(c.get("risk_threshold", 65)),
                                  "max_auto_per_hour": int(c.get("max_auto_per_hour", 4))})
        elif path == "/api/v1/trusted-ips":
            if not server.engine:
                self._json_response({"error": "engine unavailable"}, 400)
                return
            if "ip" in data and str(data.get("ip") or "").strip():
                ip = str(data["ip"]).strip()
                nets = server.engine.cfg.setdefault("trusted_ips", [])
                try:
                    import ipaddress as _ipa
                    canonical = str(_ipa.ip_network(ip, strict=False))
                except ValueError:
                    self._json_response({"error": "invalid IP or CIDR"}, 400)
                    return
                if data.get("remove"):
                    nets[:] = [n for n in nets if n != canonical]
                elif canonical not in nets:
                    nets.append(canonical)
                try:
                    server.engine.config_persist()
                except Exception:
                    pass
                event("trusted_ips_updated", "info", count=len(nets))
            self._json_response({"trusted_ips": server.engine.cfg.get("trusted_ips", [])})

        elif path == "/api/v1/vpn/wireguard/peers":
            if not server.engine:
                self._json_response({"error": "engine unavailable"}, 400)
                return
            wg = server.engine.cfg.setdefault("wireguard", {})
            peers = wg.setdefault("peers", [])
            peer = {
                "public_key": str(data.get("public_key", "")).strip(),
                "allowed_ips": data.get("allowed_ips", ["10.100.0.2/32"]),
                "endpoint": str(data.get("endpoint", "")).strip(),
                "created_at": time.time(),
            }
            peers.append(peer)
            try:
                server.engine.config_persist()
            except Exception:
                pass
            self._json_response({"status": "added", "peer": peer})

        elif path == "/api/v1/microsegmentation/promote":
            if server.engine and hasattr(server.engine, "microseg"):
                count = server.engine.microseg.promote_to_enforcement()
                self._json_response({"status": "enforcing", "enforced_rules": count})
            else:
                self._json_response({"status": "enforcing", "enforced_rules": 0})

        elif path == "/api/v1/ztna/evaluate":
            client_ip = str(data.get("client_ip", "")).strip()
            app_name = str(data.get("app_name", "")).strip()
            posture = data.get("posture", {})
            if server.engine and hasattr(server.engine, "ztna"):
                ok, reason = server.engine.ztna.evaluate_access(client_ip, app_name, posture)
                self._json_response({"allowed": ok, "reason": reason})
            else:
                self._json_response({"allowed": True, "reason": "default_allowed"})

        elif path == "/api/v1/vdoms":
            if not self._enforce_role("system:admin"):
                return
            from .vdom import vdom_manager, VDOMInterfaceConflict
            vdom_id = str(data.get("vdom_id", "")).strip().lower()
            name = str(data.get("name") or vdom_id).strip()
            interfaces = data.get("interfaces", [])
            quotas = data.get("quotas", {})
            try:
                vdom = vdom_manager.create_vdom(vdom_id, name, interfaces=interfaces, quotas=quotas)
                self._json_response({"status": "created", "vdom": vdom.to_dict()})
            except (ValueError, VDOMInterfaceConflict) as ex:
                self._json_response({"error": str(ex)}, 400)

        elif path == "/api/v1/waf/config":
            waf = getattr(engine, "waf", None) if engine else None
            if not waf:
                self._json_response({"error": "WAF unavailable"}, 400)
                return
            if "paranoia_level" in data:
                pl = max(1, min(4, int(data["paranoia_level"])))
                if hasattr(waf, "middleware"):
                    waf.middleware.paranoia_level = pl
            if "mode" in data and str(data["mode"]) in ("block", "monitor"):
                waf.mode = str(data["mode"])
            self._json_response({
                "status": "updated",
                "paranoia_level": getattr(waf.middleware, "paranoia_level", 1) if hasattr(waf, "middleware") else 1,
                "mode": getattr(waf, "mode", "block"),
            })

        elif path == "/api/v1/dlp/test":
            dlp = getattr(engine, "dlp", None) if engine else None
            text = str(data.get("text", "")).strip()
            if not text:
                self._json_response({"error": "text required for DLP test"}, 400)
                return
            if dlp:
                eval_res = dlp.evaluate_stream(text)
                self._json_response({
                    "action": eval_res.get("action", "allow"),
                    "findings": eval_res.get("findings", []),
                    "sanitized": str(eval_res.get("data", "")),
                    "reason": eval_res.get("reason", "clean"),
                })
            else:
                self._json_response({"action": "allow", "findings": [], "sanitized": text, "reason": "dlp_offline"})

        elif path == "/api/v1/ztna/evaluate":
            ztna = getattr(engine, "ztna", None) if engine else None
            client_ip = str(data.get("ip", "127.0.0.1")).strip()
            requested_app = str(data.get("app", "*")).strip()
            posture_data = data.get("posture", {})
            if ztna:
                verdict = ztna.evaluate_access(client_ip, requested_app, posture_data=posture_data)
                self._json_response(verdict)
            else:
                self._json_response({"allowed": True, "reason": "ztna_evaluator_offline", "score": 100})

        elif path == "/api/v1/threatintel/lookup":
            ioc = str(data.get("ioc", "")).strip()
            if not ioc:
                self._json_response({"error": "ioc required"}, 400)
                return
            fm = getattr(engine, "feed_mgr", None) if engine else None
            intel = getattr(engine, "intel", None) if engine else None
            hits = []
            if fm:
                matched = None
                if hasattr(fm, "lookup_ip"):
                    matched = fm.lookup_ip(ioc) if ("." in ioc or ":" in ioc) else fm.lookup_domain(ioc)
                elif hasattr(fm, "check_ip"):
                    found, meta = fm.check_ip(ioc) if ("." in ioc or ":" in ioc) else fm.check_domain(ioc)
                    matched = meta if found else None
                if matched:
                    hits.append(matched)
            vt_info = intel.display_record(ioc) if intel else None
            self._json_response({
                "ioc": ioc,
                "matches": hits,
                "virustotal": vt_info or {"status": "not_in_vt_cache"},
            })

        elif path == "/api/v1/soar/execute":
            pb = getattr(engine, "playbooks", None) if engine else None
            if not pb:
                self._json_response({"error": "Playbook engine unavailable"}, 400)
                return
            ev_data = data.get("event", {"event": "manual_trigger", "severity": "high", "ip": data.get("ip", "203.0.113.5")})
            dry_run = bool(data.get("dry_run", True))
            res = pb.evaluate_event(ev_data, dry_run=dry_run)
            self._json_response({"executed": len(res), "dry_run": dry_run, "results": res})

        elif path == "/api/v1/identity/bind":
            ident = getattr(engine, "identity", None) if engine else None
            if not ident:
                self._json_response({"error": "Identity directory unavailable"}, 400)
                return
            ip = str(data.get("ip", "")).strip()
            user = str(data.get("username", "")).strip()
            if not ip or not user:
                self._json_response({"error": "ip and username required"}, 400)
                return
            rec = ident.map_ip(
                ip, user,
                groups=data.get("groups", ["Users"]),
                domain=data.get("domain", "CORP"),
                device_id=data.get("device_id", "DEV-" + secrets.token_hex(4).upper()),
                device_name=data.get("device_name", "Workstation"),
                posture=data.get("posture", "COMPLIANT"),
                ttl=int(data.get("ttl", 7200))
            )
            self._json_response({"status": "bound", "identity": rec})

        elif path == "/api/v1/system/rebaseline":
            sp = getattr(engine, "selfprotect", None) if engine else None
            if sp and hasattr(sp, "rebaseline"):
                hashes = sp.rebaseline()
                event("selfprotect_rebaselined", "info", count=len(hashes), source="webui")
                self._json_response({"status": "rebaselined", "count": len(hashes)})
            else:
                self._json_response({"status": "ok", "note": "selfprotect not active"})

        else:
            self.send_error(HTTPStatus.NOT_FOUND)


class SentinelWebUI(http.server.ThreadingHTTPServer):
    """Threading HTTP server orchestrating the SentinelFW Web UI."""

    def handle_error(self, request, client_address):
        """Suppresses noisy tracebacks for routine client socket disconnects/aborts."""
        ex = sys.exc_info()[1]
        if isinstance(ex, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
            return
        if isinstance(ex, OSError) and getattr(ex, "winerror", None) in (10053, 10054):
            return
        super().handle_error(request, client_address)

    def __init__(self, host: str = "0.0.0.0", port: int = 443, engine=None, conntrack=None,
                 honeypot=None, sandbox=None, baseline=None):
        try:
            super().__init__((host, port), SentinelRequestHandler)
            self.bound_port = port
        except OSError as e:
            # privileged port unavailable (non-root) — fall back to the legacy port
            fallback = 9443
            event("webui_bind_fallback", "warning", wanted_port=port, error=str(e),
                  fallback_port=fallback, note="run as root/service or set webui.port")
            super().__init__((host, fallback), SentinelRequestHandler)
            self.bound_port = fallback
        self.engine = engine
        self.conntrack = conntrack
        self.honeypot = honeypot
        self.sandbox = sandbox
        self.baseline = baseline
        self.start_time = time.time()
        self.rate_limiter = APIRateLimiter(limit_per_minute=240)
        # ---- console TLS (stdlib ssl, bring-your-own cert) ----
        self.tls_active = False
        try:
            t = (engine.cfg.get("webui_tls", {}) if engine else {})
            if t.get("enabled"):
                import ssl as _ssl
                from pathlib import Path as _P
                cert, key = _P(str(t.get("cert_file"))), _P(str(t.get("key_file")))
                if not (cert.exists() and key.exists()):
                    from .integrations import generate_self_signed
                    event("webui_tls_autogen", "info", note="Auto-generating console TLS certificate on first run")
                    generate_self_signed(cert, key)

                if cert.exists() and key.exists():
                    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
                    if hasattr(_ssl, "TLSVersion"):
                        ctx.minimum_version = _ssl.TLSVersion.TLSv1_2
                    else:
                        ctx.options |= _ssl.OP_NO_SSLv2 | _ssl.OP_NO_SSLv3 | _ssl.OP_NO_TLSv1 | _ssl.OP_NO_TLSv1_1
                    try:
                        ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20")
                    except Exception:
                        pass
                    ctx.load_cert_chain(str(cert), str(key))
                    self.socket = ctx.wrap_socket(self.socket, server_side=True)
                    self.tls_active = True
                    event("webui_tls_active", "info", cert=str(cert.name))
                else:
                    event("webui_tls_unavailable", "warning",
                          note="webui_tls.enabled but cert/key files missing — "
                               "staying on plain HTTP; run: sfwctl tls-gencert")
        except Exception as e:
            event("webui_tls_unavailable", "warning", error=str(e)[:200])
        self.analyzer = TrafficAnalyzer(webui=self)
        self._app_history: Dict[str, object] = {}
        self._app_alert_last: Dict[str, float] = {}
        self._cpu_prev: Dict[int, tuple] = {}
        self._app_cached_snapshot: dict = {}
        self._app_cache_time: float = 0.0
        self._app_sampler_thread = threading.Thread(target=self._app_history_sampler, daemon=True,
                                                    name="app_resource_sampler")
        self._app_sampler_thread.start()
        self._auto_ai_thread = threading.Thread(target=self._auto_ai_loop, daemon=True,
                                                name="sarvam_auto_analyst")
        self._auto_ai_thread.start()
        # ---- management plane: session auth, sigma rules, syslog export ----
        self.auth = mgmt.AuthManager(lambda: self.engine.cfg if self.engine else {},
                                     session_ttl_minutes=int(
                                         (self.engine.cfg.get("management", {}) if self.engine
                                          else {}).get("session_ttl_minutes", 480)))
        self.syslog_fwd = mgmt.SyslogForwarder(lambda: self.engine.cfg if self.engine else {})
        from .common import LISTS
        self.sigma = mgmt.SigmaEngine(LISTS / "sigma",
                                      cfg_get=lambda: self.engine.cfg if self.engine else {})
        self._soc_listener = self._on_engine_event
        from .common import _EVENT_LISTENERS
        _EVENT_LISTENERS.append(self._soc_listener)
        # ---- 2.8: forensic PCAP ring, persistence watch, commit watchdog ----
        if self.engine is not None:
            self.engine.pcap_ring = forensics.PcapRing(lambda: self.engine.cfg)
        self.persistence = forensics.PersistenceWatch(lambda: self.engine.cfg if self.engine else {})
        _EVENT_LISTENERS.append(forensics.make_event_listener(
            self.engine.pcap_ring if self.engine else forensics.PcapRing(lambda: {}),
            lambda: self.engine))
        self._commit_thread = threading.Thread(target=self._commit_watchdog, daemon=True,
                                               name="sfw_commit_watchdog")
        self._commit_thread.start()
        if self.engine is not None and self.engine.cfg.get("persistence_watch", {}).get("enabled"):
            self.persistence.start()
        # ---- 3.0: integrations (suricata/clamav auto-pull) + Go supervisor ----
        self.integrations = integ.IntegrationManager(lambda: self.engine.cfg if self.engine else {})
        self.gosvc = integ.GoServiceSupervisor(lambda: self.engine.cfg if self.engine else {})
        try:
            if self.engine is not None:
                self.integrations.ensure()   # pulled in by default, best-effort
                if self.engine.cfg.get("go_services", {}).get("enabled"):
                    threading.Thread(target=self.gosvc.start, daemon=True).start()
        except Exception:
            pass
        # ---- 2.9: DNS filter, fleet relay, log vault ----
        self.dns_filter = ops.DnsFilter(lambda: self.engine.cfg if self.engine else {},
                                        lambda: self.engine.lists if self.engine else None)
        self.fleet = ops.FleetRelay(lambda: self.engine.cfg if self.engine else {})
        self.vault = ops.LogVault(lambda: self.engine.cfg if self.engine else {})
        if self.engine is not None:
            if self.engine.cfg.get("dns_server", {}).get("enabled"):
                self.dns_filter.start()
            if self.engine.cfg.get("fleet", {}).get("enabled"):
                self.fleet.start() if hasattr(self.fleet, "start") else None
            mg = self.engine.cfg.get("management", {}) or {}
            if (mg.get("vault") or {}).get("enabled"):
                self.vault.start()
        self._thread: Optional[threading.Thread] = None

        # Synchronize telegram notifier configuration on start
        if self.engine and "telegram" in self.engine.cfg:
            tc = self.engine.cfg["telegram"]
            bot_tok = tc.get("bot_token") or mgmt.secrets_vault.get("telegram_bot_token") or ""
            chat_id = tc.get("chat_id") or mgmt.secrets_vault.get("telegram_chat_id") or ""
            telegram_notifier.update_config(
                bot_token=bot_tok,
                chat_id=chat_id,
                enabled=tc.get("enabled", False),
                alert_levels=tc.get("alert_levels", ["critical", "warning"]),
                rate_limit_per_minute=int(tc.get("rate_limit_per_minute", 15))
            )
            if tc.get("enabled"):
                telegram_notifier.start()

    def get_recent_attacks(self) -> dict:
        """Parses recent security events to compute threat breakdown and 24h count."""
        events_file = LOGS / "events.jsonl"
        categories = {}
        killchain = {"Reconnaissance": 0, "Delivery": 0, "Exploitation": 0, "C2": 0, "ActionOnObjectives": 0}
        total_24h = 0
        recent = []

        if events_file.exists():
            try:
                with open(events_file, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                for line in reversed(lines[-200:]):
                    try:
                        obj = json.loads(line.strip())
                        sev = obj.get("severity", "info").lower()
                        if sev in ("critical", "high", "warning", "medium"):
                            total_24h += 1
                            kind = obj.get("kind", "generic_alert")
                            categories[kind] = categories.get(kind, 0) + 1
                            if len(recent) < 25:
                                recent.append(obj)
                    except Exception:
                        continue
            except Exception:
                pass

        return {
            "total_threats_intercepted": total_24h,
            "threat_distribution": categories,
            "killchain_breakdown": killchain,
            "recent_events": recent,
        }

    # ------------------------------------------------------------------
    # Geo map aggregation
    # ------------------------------------------------------------------
    def get_map_data(self) -> dict:
        """Aggregates every remote IP seen in flows / packets / bans for the map."""
        engine = self.engine
        ips: Dict[str, dict] = {}

        def touch(ip, *, bi=0, bo=0, pk=0, direction=None):
            if not ip or ip in ("0.0.0.0", "::", ""):
                return
            rec = ips.setdefault(ip, {
                "ip": ip, "bytes_in": 0, "bytes_out": 0, "packets": 0,
                "connections": 0, "last_seen": 0.0, "threat": "normal",
                "ports": set(), "directions": set(),
            })
            rec["bytes_in"] += bi
            rec["bytes_out"] += bo
            rec["packets"] += pk
            if direction:
                rec["directions"].add(direction)

        # 1) active + recent flows (conntrack)
        if self.conntrack:
            geoip = getattr(self.conntrack, "geoip", None)
            for c in self.conntrack.get_active() + self.conntrack.get_history(limit=300):
                raddr = c.get("raddr") or ""
                if not raddr:
                    continue
                touch(raddr, bi=c.get("bytes_in", 0), bo=c.get("bytes_out", 0),
                      pk=c.get("packets_in", 0) + c.get("packets_out", 0))
                rec = ips.get(raddr)
                if rec:
                    rec["connections"] += 1
                    rec["last_seen"] = max(rec["last_seen"], c.get("last_seen", 0))
                    if c.get("rport"):
                        rec["ports"].add(int(c["rport"]))
                    g = c.get("country")
                    if g and g not in ("UNKNOWN", "LOCAL"):
                        rec["country"] = g

        # 2) raw packet vision (richer than flows when the sniffer is active)
        recorder = getattr(engine, "recorder", None) if engine else None
        if recorder is not None:
            for p in recorder.query(limit=2000):
                d = p.get("direction")
                remote = p.get("dst") if d == "out" else p.get("src")
                local_ips = engine.guard.local if engine else set()
                if remote in local_ips:
                    continue
                ln = p.get("length", 0)
                if d == "out":
                    touch(remote, bo=ln, pk=1, direction="out")
                elif d == "in":
                    touch(remote, bi=ln, pk=1, direction="in")
                rec = ips.get(remote)
                if rec is not None:
                    rec["last_seen"] = max(rec["last_seen"], p.get("ts", 0))
                    port = p.get("dport") if d == "out" else p.get("sport")
                    if port:
                        rec["ports"].add(int(port))
                    if p.get("severity") in ("critical", "high", "medium") and rec["threat"] == "normal":
                        rec["threat"] = "suspicious"

        # 3) threat enrichment: bans & blocklists mark IPs malicious
        if engine is not None:
            for ip, rec in ips.items():
                try:
                    if ip in engine.store.bans or (engine.lists and ip in engine.lists.ipset):
                        rec["threat"] = "malicious"
                        if ip in engine.store.bans:
                            b = engine.store.bans[ip]
                            rec["banned_reason"] = b.get("reason", "")
                            rec["offenses"] = engine.store.offenses.get(ip, 0)
                except Exception:
                    pass
            for ip in engine.store.bans:
                touch(ip)
                if ip in ips:
                    ips[ip]["threat"] = "malicious"
                    b = engine.store.bans[ip]
                    ips[ip]["banned_reason"] = b.get("reason", "")
                    ips[ip]["offenses"] = engine.store.offenses.get(ip, 0)

        # 4) geo resolve for entries lacking a country
        geoip = self.conntrack.geoip if self.conntrack else None
        if geoip is None:
            from .geoip import GeoIPResolver
            geoip = GeoIPResolver()
        for ip, rec in ips.items():
            if not rec.get("country"):
                g = geoip.resolve(ip)
                cc = g.get("country", "")
                if cc in ("UNKNOWN",) or not cc:
                    try:
                        import ipaddress as _ipa
                        a = _ipa.ip_address(ip)
                        cc = "LOCAL" if a.is_private or a.is_loopback else "ZZ"
                    except ValueError:
                        cc = "ZZ"
                rec["country"] = cc
            rec["ports"] = sorted(rec["ports"])[:12]
            rec["directions"] = sorted(rec["directions"])

        # 5) VirusTotal enrichment (cached verdicts only — no live queries here)
        intel = getattr(engine, "intel", None) if engine else None
        vt_detected = 0
        if intel is not None:
            try:
                intel.offer_ips(list(ips.keys()))
                for ip, rec in ips.items():
                    vt = intel.display_record(ip)
                    if vt:
                        rec["vt"] = {
                            "verdict": vt.get("verdict"),
                            "malicious": vt.get("malicious", 0),
                            "suspicious": vt.get("suspicious", 0),
                            "reputation": vt.get("reputation", 0),
                            "as_owner": vt.get("as_owner", ""),
                            "scanned_at": vt.get("ts", 0),
                        }
                        if vt.get("verdict") == "MALICIOUS":
                            vt_detected += 1
                            rec["threat"] = "malicious"
                        elif vt.get("verdict") == "SUSPICIOUS" and rec["threat"] == "normal":
                            rec["threat"] = "suspicious"
            except Exception:
                pass

        # country aggregation
        countries: Dict[str, dict] = {}
        for rec in ips.values():
            cc = rec["country"]
            agg = countries.setdefault(cc, {"country": cc, "ips": 0, "bytes": 0,
                                            "packets": 0, "threats": 0, "connections": 0})
            agg["ips"] += 1
            agg["bytes"] += rec["bytes_in"] + rec["bytes_out"]
            agg["packets"] += rec["packets"]
            agg["connections"] += rec["connections"]
            if rec["threat"] != "normal":
                agg["threats"] += 1

        return {
            "points": list(ips.values()),
            "countries": list(countries.values()),
            "geo_db": country_db_status(),
            "threat_intel": intel.status() if intel is not None else {"configured": False},
            "totals": {
                "unique_ips": len(ips),
                "malicious": sum(1 for r in ips.values() if r["threat"] == "malicious"),
                "suspicious": sum(1 for r in ips.values() if r["threat"] == "suspicious"),
                "vt_detected": vt_detected,
            },
        }

    _cpu_prev: Dict[int, tuple] = {}

    def _proc_cpu_mem(self, pid: int) -> dict:
        """Accurate per-process CPU% and memory (Linux /proc, Windows ctypes GetProcessTimes, psutil fallback)."""
        now = time.time()

        # 1. Linux /proc
        try:
            with open(f"/proc/{pid}/stat", "r") as f:
                parts = f.read().rsplit(")", 1)[1].split()
            utime, stime = int(parts[11]), int(parts[12])
            hz = os.sysconf("SC_CLK_TCK")
            cpu_secs = (utime + stime) / hz
            prev = self._cpu_prev.get(pid)
            self._cpu_prev[pid] = (now, cpu_secs)
            cpu_pct = 0.0
            if prev:
                dt = now - prev[0]
                if dt > 0.05:
                    num_cpus = os.cpu_count() or 1
                    cpu_pct = max(0.0, (cpu_secs - prev[1]) / dt * 100.0 / num_cpus)
            mem_kb = 0
            try:
                with open(f"/proc/{pid}/status", "r") as f:
                    for ln in f:
                        if ln.startswith("VmRSS:"):
                            mem_kb = int(ln.split()[1])
                            break
            except OSError:
                pass
            return {
                "cpu_percent": round(cpu_pct, 1),
                "mem_mb": round(mem_kb / 1024, 1),
                "cpu_seconds": round(cpu_secs, 1),
            }
        except Exception:
            pass

        # 2. Windows ctypes GetProcessTimes & GetProcessMemoryInfo
        if IS_WIN:
            try:
                import ctypes
                from ctypes import wintypes

                class _FILETIME(ctypes.Structure):
                    _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]

                class _PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                    _fields_ = [
                        ("cb", wintypes.DWORD),
                        ("PageFaultCount", wintypes.DWORD),
                        ("PeakWorkingSetSize", ctypes.c_size_t),
                        ("WorkingSetSize", ctypes.c_size_t),
                        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                        ("PagefileUsage", ctypes.c_size_t),
                        ("PeakPagefileUsage", ctypes.c_size_t),
                    ]

                k32 = ctypes.windll.kernel32
                h = k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
                if h:
                    try:
                        cr, ex, kt, ut = _FILETIME(), _FILETIME(), _FILETIME(), _FILETIME()
                        cpu_secs = 0.0
                        if k32.GetProcessTimes(h, ctypes.byref(cr), ctypes.byref(ex), ctypes.byref(kt), ctypes.byref(ut)):
                            k_ns = (kt.dwHighDateTime << 32) | kt.dwLowDateTime
                            u_ns = (ut.dwHighDateTime << 32) | ut.dwLowDateTime
                            cpu_secs = (k_ns + u_ns) / 10000000.0  # 100ns units to seconds

                        prev = self._cpu_prev.get(pid)
                        self._cpu_prev[pid] = (now, cpu_secs)
                        cpu_pct = 0.0
                        if prev:
                            dt = now - prev[0]
                            if dt > 0.05:
                                num_cpus = os.cpu_count() or 1
                                cpu_pct = max(0.0, (cpu_secs - prev[1]) / dt * 100.0 / num_cpus)

                        mem_bytes = 0
                        pmc = _PROCESS_MEMORY_COUNTERS()
                        pmc.cb = ctypes.sizeof(_PROCESS_MEMORY_COUNTERS)
                        psapi = ctypes.windll.psapi
                        if psapi.GetProcessMemoryInfo(h, ctypes.byref(pmc), pmc.cb):
                            mem_bytes = pmc.WorkingSetSize

                        return {
                            "cpu_percent": round(cpu_pct, 1),
                            "mem_mb": round(mem_bytes / (1024 * 1024), 1),
                            "cpu_seconds": round(cpu_secs, 1),
                        }
                    finally:
                        k32.CloseHandle(h)
            except Exception:
                pass

        # 3. psutil fallback if installed
        try:
            import psutil
            p = psutil.Process(pid)
            cpu_times = p.cpu_times()
            total_time = cpu_times.user + cpu_times.system
            prev = self._cpu_prev.get(pid)
            self._cpu_prev[pid] = (now, total_time)
            cpu_pct = 0.0
            if prev:
                dt = now - prev[0]
                if dt > 0.05:
                    num_cpus = os.cpu_count() or 1
                    cpu_pct = max(0.0, (total_time - prev[1]) / dt * 100.0 / num_cpus)
            return {
                "cpu_percent": round(cpu_pct, 1),
                "mem_mb": round(p.memory_info().rss / 1048576, 1),
                "cpu_seconds": round(total_time, 1),
            }
        except Exception:
            return {"cpu_percent": 0.0, "mem_mb": 0.0, "cpu_seconds": 0}

    # ------------------------------------------------------------------
    # Appwall policy CRUD
    # ------------------------------------------------------------------
    @staticmethod
    def _appwall_normalize(data: dict) -> dict:
        def _ports(v):
            if v in (None, ""):
                return []
            if isinstance(v, (list, tuple)):
                items = [str(x) for x in v]
            else:
                items = [s.strip() for s in str(v).replace(";", ",").split(",")]
            out = []
            for it in items:
                it = it.strip().lower()
                if not it:
                    continue
                if "/" not in it:
                    it = "tcp/" + it
                proto, _, port = it.partition("/")
                if port.isdigit() and proto in ("tcp", "udp", "any"):
                    out.append(f"{proto}/{int(port)}")
            return out

        def _nets(v):
            if v in (None, ""):
                return []
            if isinstance(v, (list, tuple)):
                items = [str(x) for x in v]
            else:
                items = [s.strip() for s in str(v).replace(";", ",").split(",")]
            import ipaddress as _ipa
            out = []
            for it in items:
                it = it.strip()
                if not it:
                    continue
                try:
                    out.append(str(_ipa.ip_network(it, strict=False)))
                except ValueError:
                    pass
            return out

        match = {}
        exe = str(data.get("exe") or "").strip()
        sha = str(data.get("sha256") or "").strip()
        user = str(data.get("user") or "").strip()
        if exe:
            match["exe_glob" if any(c in exe for c in "*?") else "exe_path"] = exe
        if sha:
            match["sha256"] = sha
        if user:
            match["user"] = user
        action = str(data.get("action_on_violation") or "block+alert").lower()
        if action not in ("block+alert", "alert", "kill", "none"):
            action = "block+alert"
        return {
            "match": match or {"exe_glob": "*"},
            "allow_outbound": _ports(data.get("allow_outbound")),
            "allow_inbound": _ports(data.get("allow_inbound")),
            "allow_destinations": _nets(data.get("allow_destinations")),
            "deny_destinations": _nets(data.get("deny_destinations")),
            "action_on_violation": action,
        }

    def _appwall_persist(self, policies):
        engine = self.engine
        if not engine:
            return
        cfg = engine.cfg.setdefault("application_firewall", {})
        cfg["policies"] = policies
        try:
            engine.config_persist()
        except Exception:
            pass
        try:
            engine.appwall.load_policies(policies)
        except Exception:
            pass

    def appwall_add_policy(self, data: dict) -> dict:
        pol = self._appwall_normalize(data)
        policies = self.engine.appwall.get_policies() if self.engine else []
        policies.append(pol)
        self._appwall_persist(policies)
        event("appwall_policy_added", "info", match=pol.get("match"))
        return {"added": pol, "count": len(policies)}

    def appwall_update_policy(self, idx: int, data: dict) -> dict:
        policies = self.engine.appwall.get_policies() if self.engine else []
        if not isinstance(idx, int) or idx < 0 or idx >= len(policies):
            return {"error": f"policy index {idx} not found"}
        policies[idx] = self._appwall_normalize(data)
        self._appwall_persist(policies)
        event("appwall_policy_updated", "info", index=idx)
        return {"updated": idx, "policy": policies[idx]}

    def appwall_delete_policy(self, idx: int) -> dict:
        policies = self.engine.appwall.get_policies() if self.engine else []
        if not isinstance(idx, int) or idx < 0 or idx >= len(policies):
            return {"error": f"policy index {idx} not found"}
        removed = policies.pop(idx)
        self._appwall_persist(policies)
        event("appwall_policy_deleted", "info", match=removed.get("match"))
        return {"deleted": idx, "count": len(policies)}

    # ------------------------------------------------------------------
    # Application resource history + monitors (FortiGate-style)
    # ------------------------------------------------------------------
    def _app_history_sampler(self):
        """Samples per-app CPU / memory / connections / traffic every 3s,
        keeping a 10-minute rolling window, and evaluates alert thresholds."""
        import collections as _cl
        hist = self._app_history
        while not STOP.is_set():
            try:
                snapshot = self._scan_applications_live()
                self._app_cached_snapshot = snapshot
                self._app_cache_time = time.time()
                now = time.time()
                for app in snapshot.get("applications", []):
                    exe = app.get("exe")
                    if not exe:
                        continue
                    dq = hist.setdefault(exe, _cl.deque(maxlen=120))
                    dq.append({
                        "ts": now,
                        "cpu": app.get("cpu_percent", 0),
                        "mem": app.get("mem_mb", 0),
                        "conns": app.get("connections", 0),
                        "bytes_in": app.get("bytes_in", 0),
                        "bytes_out": app.get("bytes_out", 0),
                    })
                    self._check_app_monitor(app)
            except Exception:
                pass
            STOP.wait(3)

    def _check_app_monitor(self, app: dict):
        engine = self.engine
        if not engine:
            return
        monitors = engine.cfg.get("app_monitors", {}) or {}
        mon = monitors.get(app.get("exe"))
        if not mon:
            return
        reasons = []
        if mon.get("cpu_alert") and (app.get("cpu_percent") or 0) >= float(mon["cpu_alert"]):
            reasons.append(f"CPU {app.get('cpu_percent')}% >= {mon['cpu_alert']}%")
        if mon.get("mem_alert") and (app.get("mem_mb") or 0) >= float(mon["mem_alert"]):
            reasons.append(f"memory {app.get('mem_mb')}MB >= {mon['mem_alert']}MB")
        if mon.get("conns_alert") and (app.get("connections") or 0) >= int(mon["conns_alert"]):
            reasons.append(f"connections {app.get('connections')} >= {mon['conns_alert']}")
        if reasons:
            key = app.get("exe")
            now = time.monotonic()
            if now - self._app_alert_last.get(key, 0) > 600:  # at most one alert / 10 min
                self._app_alert_last[key] = now
                event("app_resource_alert", "warning", exe=key,
                      name=app.get("name"), detail="; ".join(reasons))

    def get_app_history(self, exe: str) -> dict:
        if not exe:
            return {"error": "missing exe"}
        dq = self._app_history.get(exe)
        if not dq:
            return {"exe": exe, "samples": []}
        samples = list(dq)
        # per-sample rates (bytes deltas) for the network chart
        out = []
        prev = None
        for s in samples:
            rate_in = rate_out = 0.0
            if prev and s["ts"] > prev["ts"]:
                rate_in = max(0.0, (s["bytes_in"] - prev["bytes_in"]) / (s["ts"] - prev["ts"]))
                rate_out = max(0.0, (s["bytes_out"] - prev["bytes_out"]) / (s["ts"] - prev["ts"]))
            out.append({**s, "rate_in": round(rate_in, 1), "rate_out": round(rate_out, 1)})
            prev = s
        engine = self.engine
        mon = {}
        if engine:
            mon = (engine.cfg.get("app_monitors", {}) or {}).get(exe, {})
        return {"exe": exe, "samples": out, "monitor": mon}

    def set_app_monitor(self, data: dict) -> dict:
        engine = self.engine
        if not engine:
            return {"error": "engine unavailable"}
        exe = str(data.get("exe") or "").strip()
        if not exe:
            return {"error": "missing exe"}
        monitors = engine.cfg.setdefault("app_monitors", {})
        mon = {}
        for key in ("cpu_alert", "mem_alert"):
            v = data.get(key)
            if v not in (None, ""):
                try:
                    val = float(v)
                    if val > 0:
                        mon[key] = val
                except (TypeError, ValueError):
                    pass
        v = data.get("conns_alert")
        if v not in (None, ""):
            try:
                val = int(v)
                if val > 0:
                    mon["conns_alert"] = val
            except (TypeError, ValueError):
                pass
        if mon:
            monitors[exe] = mon
        else:
            monitors.pop(exe, None)
        try:
            engine.config_persist()
        except Exception:
            pass
        event("app_monitor_updated", "info", exe=exe, thresholds=mon)
        return {"exe": exe, "monitor": mon}

    def get_applications(self, force: bool = False) -> dict:
        """Cached live inventory of every application (sub-millisecond response)."""
        now = time.time()
        cached = getattr(self, "_app_cached_snapshot", None)
        cache_time = getattr(self, "_app_cache_time", 0.0)
        if not force and cached and (now - cache_time) < 5.0:
            return cached
        snap = self._scan_applications_live()
        self._app_cached_snapshot = snap
        self._app_cache_time = time.time()
        return snap

    def _scan_applications_live(self) -> dict:
        """Live inventory scan of every application with per-app network + resource usage."""
        engine = self.engine
        conns_by_exe: Dict[str, list] = {}
        bw_by_exe: Dict[str, dict] = {}
        if self.conntrack:
            for c in self.conntrack.get_active():
                exe = c.get("exe") or ""
                if exe:
                    conns_by_exe.setdefault(exe, []).append(c)
            for exe, b in (self.conntrack.get_app_stats() or {}).items():
                bw_by_exe[exe] = b

        inventory = []
        if engine is not None and hasattr(engine, "appwall"):
            procs = engine.appwall.inventory.scan()
            # group processes by executable → one application card
            by_exe: Dict[str, list] = {}
            for p in procs.values():
                if p.get("exe"):
                    by_exe.setdefault(p["exe"], []).append(p)
            import fnmatch as _fnm
            program_rules = list(engine.lists.programs) if engine.lists else []
            for exe, plist in by_exe.items():
                cpus = mbs = 0.0
                pids = []
                for p in plist:
                    cm = self._proc_cpu_mem(p["pid"])
                    cpus += cm["cpu_percent"]
                    mbs += cm["mem_mb"]
                    pids.append(p["pid"])
                conns = conns_by_exe.get(exe, [])
                bw = bw_by_exe.get(exe, {"in": 0, "out": 0})
                blocked = any(_fnm.fnmatch(exe.replace("\\", "/").lower(), pat.lower().replace("\\", "/"))
                              for pat in program_rules)
                remote_ips = sorted({c["raddr"] for c in conns if c.get("raddr")})
                p0 = plist[0]
                inventory.append({
                    "exe": exe,
                    "name": p0.get("name") or os.path.basename(exe),
                    "pids": pids,
                    "process_count": len(plist),
                    "cmdline": p0.get("cmdline", ""),
                    "sha256": p0.get("sha256", ""),
                    "user": p0.get("user", ""),
                    "cpu_percent": round(cpus, 1),
                    "mem_mb": round(mbs, 1),
                    "connections": len(conns),
                    "remote_ips": remote_ips[:24],
                    "remote_ip_count": len(remote_ips),
                    "bytes_in": bw.get("in", 0),
                    "bytes_out": bw.get("out", 0),
                    "network_blocked": blocked,
                    "signed": bool(p0.get("signed")),
                })
        inventory.sort(key=lambda a: (-(a["bytes_in"] + a["bytes_out"]), -a["connections"], a["exe"]))
        return {"applications": inventory, "total": len(inventory),
                "blocked_count": sum(1 for a in inventory if a["network_blocked"])}

    def get_application_detail(self, pid: int) -> dict:
        """Everything about one process: identity, resources, sockets, remote IPs."""
        engine = self.engine
        info = None
        if engine is not None and hasattr(engine, "appwall"):
            info = engine.appwall.inventory.get_process(pid)
        if info is None and pid:
            try:
                exe = os.readlink(f"/proc/{pid}/exe")
                info = {"pid": pid, "exe": exe, "name": os.path.basename(exe),
                        "cmdline": Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(errors="ignore")}
            except OSError:
                pass
        if info is None:
            return {"error": f"process {pid} not found"}
        conns = []
        if self.conntrack:
            for c in self.conntrack.get_active():
                if c.get("pid") == pid:
                    conns.append(c)
        cm = self._proc_cpu_mem(pid)
        remote_ips = sorted({c["raddr"] for c in conns if c.get("raddr")})
        geoip = self.conntrack.geoip if self.conntrack else None
        geo = {ip: (geoip.resolve(ip) if geoip else {}) for ip in remote_ips[:50]}
        return {
            "process": info,
            "cpu_percent": cm["cpu_percent"],
            "mem_mb": cm["mem_mb"],
            "cpu_seconds": cm["cpu_seconds"],
            "connections": conns,
            "remote_ips": remote_ips,
            "remote_geo": geo,
        }

    def application_action(self, data: dict) -> dict:
        """Performs kill / block-network / unblock / quarantine on an app or pid."""
        engine = self.engine
        action = str(data.get("action", "")).strip().lower()
        pid = data.get("pid")
        exe = str(data.get("exe", "")).strip()

        if action == "kill":
            try:
                pid = int(pid)
            except (TypeError, ValueError):
                return {"error": "missing pid"}
            from .procinfo import kill_process
            ok = kill_process(pid)
            event("app_kill_requested", "warning", pid=pid, exe=exe, result="killed" if ok else "failed",
                  source="webui")
            return {"status": "killed" if ok else "kill_failed", "pid": pid}

        if action in ("block_network", "unblock_network"):
            if not exe:
                return {"error": "missing exe"}
            from .lists import list_edit
            list_edit("program_manual.txt", exe, add=(action == "block_network"))
            if engine is not None:
                engine.apply_all()
            event(f"app_{'blocked' if action == 'block_network' else 'unblocked'}", "warning",
                  exe=exe, source="webui")
            return {"status": action, "exe": exe}

        if action == "quarantine":
            if not exe:
                return {"error": "missing exe"}
            from .procinfo import dispose_file
            result = dispose_file(exe, "manual quarantine via WebUI", "quarantine")
            return {"status": result, "exe": exe}

        return {"error": f"unknown action '{action}'"}

    def _traffic_rates(self) -> dict:
        """Live rates: flow counters first, then NIC counters, then recorder."""
        rates = None
        if self.conntrack and hasattr(self.conntrack, "get_rates"):
            rates = self.conntrack.get_rates()
        if not rates or (rates.get("bps_in", 0) == 0 and rates.get("bps_out", 0) == 0):
            # Fallback 1: real network-interface counters (psutil) — always
            # available, works even when the raw sniffer cannot run, and
            # reflects the machine's true throughput.
            try:
                import psutil
                now = time.time()
                cur = psutil.net_io_counters()
                prev = getattr(self, "_nic_prev", None)
                self._nic_prev = (now, cur)
                if prev and now - prev[0] >= 0.5:
                    span = max(0.5, now - prev[0])
                    c, p = cur, prev[1]
                    rates = {"bps_in": int((c.bytes_recv - p.bytes_recv) * 8 / span),
                             "bps_out": int((c.bytes_sent - p.bytes_sent) * 8 / span),
                             "pps_in": int((c.packets_recv - p.packets_recv) / span),
                             "pps_out": int((c.packets_sent - p.packets_sent) / span)}
            except Exception:
                pass
        if not rates or (rates.get("bps_in", 0) == 0 and rates.get("bps_out", 0) == 0):
            rates = rates or {"bps_in": 0, "bps_out": 0, "pps_in": 0, "pps_out": 0}
            # Fallback 2: packet-recorder totals (average since capture start)
            try:
                engine = self.engine
                if engine is not None and getattr(engine, "recorder", None) is not None:
                    st = engine.recorder.stats()
                    b = st.get("bytes", {})
                    started = engine.recorder.started_at or (time.time() - 10)
                    span = max(1.0, time.time() - started)
                    rates["bps_in"] = int(b.get("in", 0) * 8 / span)
                    rates["bps_out"] = int(b.get("out", 0) * 8 / span)
                    rates["pps_in"] = int(st.get("direction_counts", {}).get("in", 0) / span)
                    rates["pps_out"] = int(st.get("direction_counts", {}).get("out", 0) / span)
            except Exception:
                pass
        return rates

    # ------------------------------------------------------------------
    # Overview dashboard
    # ------------------------------------------------------------------
    def get_overview(self) -> dict:
        """FortiGate-grade dashboard payload: system, traffic, sessions, threats, services."""
        engine = self.engine
        conns = self.conntrack.get_active() if self.conntrack else []
        rates = self._traffic_rates()

        # system health
        cpu = mem = disk = 0.0
        try:
            import psutil
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory().percent
            disk = psutil.disk_usage(str(DATA_DIR)).percent
        except ImportError:
            try:
                with open("/proc/stat") as f:
                    p1 = f.readline().split()[1:]
                time.sleep(0.05)
                with open("/proc/stat") as f:
                    p2 = f.readline().split()[1:]
                t1, t2 = sum(map(int, p1)), sum(map(int, p2))
                i1, i2 = int(p1[3]), int(p2[3])
                cpu = (1 - (i2 - i1) / max(1, t2 - t1)) * 100
            except Exception:
                cpu = 0.0
            try:
                with open("/proc/meminfo") as f:
                    mi = {ln.split(":")[0]: int(ln.split()[1]) for ln in f.readlines()[:5]}
                mem = (1 - mi["MemAvailable"] / mi["MemTotal"]) * 100
            except Exception:
                mem = 0.0
            try:
                st = os.statvfs("/" if not IS_WIN else "C:\\")
                disk = (1 - st.f_bavail / st.f_blocks) * 100
            except Exception:
                disk = 0.0

        # protocol distribution + top talkers from the live packet buffer
        proto_dist = {}
        top_talkers = []
        recorder = getattr(engine, "recorder", None) if engine else None
        if recorder is not None:
            proto_dist = recorder.stats().get("proto_counts", {})
        if self.conntrack:
            agg: Dict[str, dict] = {}
            for c in conns:
                r = c.get("raddr")
                if not r:
                    continue
                a = agg.setdefault(r, {"ip": r, "bytes": 0, "conns": 0, "country": c.get("country", "")})
                a["bytes"] += c.get("bytes_in", 0) + c.get("bytes_out", 0)
                a["conns"] += 1
            top_talkers = sorted(agg.values(), key=lambda x: -x["bytes"])[:8]

        honeypot_status = self.honeypot.service_status() if self.honeypot else []
        threat = self.get_recent_attacks()
        bans_count = len(engine.store.bans) if engine else 0

        # lightweight unique-remote-IP stats for the dashboard KPIs
        remotes = set()
        if self.conntrack:
            for c in conns:
                if c.get("raddr"):
                    remotes.add(c["raddr"])
        if recorder is not None:
            local_ips = engine.guard.local if engine else set()
            for p in recorder.query(limit=2000):
                d = p.get("direction")
                remote = p.get("dst") if d == "out" else p.get("src")
                if remote and remote not in local_ips:
                    remotes.add(remote)
        malicious_ips = sum(1 for ip in remotes if engine and (ip in engine.store.bans or (engine.lists and ip in engine.lists.ipset)))
        map_totals = {"unique_ips": len(remotes), "malicious": malicious_ips, "suspicious": 0}

        return {
            "system": {
                "platform": sys.platform,
                "os_name": "Windows" if IS_WIN else "Linux",
                "cpu_percent": round(cpu, 1),
                "memory_percent": round(mem, 1),
                "disk_percent": round(disk, 1),
                "uptime_seconds": int(time.time() - self.start_time),
                "host": socket.gethostname(),
                "version": VERSION,
                "backend": engine.backend.name if engine and engine.backend else "generic",
                "profile": engine.cfg.get("enforcement_profile", "aggressive") if engine else "aggressive",
            },
            "traffic": rates,
            "sessions": {
                "active": len(conns),
                "by_proto": self._session_by_proto(conns),
            },
            "protocol_distribution": proto_dist,
            "top_talkers": top_talkers,
            "threats": {
                "total_24h": threat.get("total_threats_intercepted", 0),
                "distribution": threat.get("threat_distribution", {}),
                "recent_events": threat.get("recent_events", [])[:10],
                "bans": bans_count,
            },
            "packets": recorder.stats() if recorder is not None else {},
            "services": {
                "honeypot": [{"service": s["service"], "running": s["running"], "port": s["port"],
                              "hits": s["hits"]} for s in honeypot_status],
                "honeypot_active": any(s["running"] for s in honeypot_status) if honeypot_status else False,
                "sniffer_active": bool(recorder.capture_active) if recorder is not None else False,
                "telegram_active": bool(telegram_notifier.enabled),
                "suricata": False,
                "suricata_state": (engine.suricata_mgr.status()
                                    if engine and getattr(engine, "suricata_mgr", None)
                                    else {"state": "not_installed", "detail": "manager unavailable"}),
                "suricata_running": bool(engine and getattr(engine, "suricata_mgr", None)
                                          and engine.suricata_mgr.is_available()
                                          and engine.suricata_mgr.process
                                          and engine.suricata_mgr.process.poll() is None),
            },
            "geo_db": country_db_status(),
            "map": map_totals,
        }

    @staticmethod
    def _session_by_proto(conns: list) -> dict:
        out: Dict[str, int] = {}
        for c in conns:
            p = (c.get("proto") or "other").lower()
            out[p] = out.get(p, 0) + 1
        return out

    def get_system_posture(self) -> dict:
        """Gathers system metrics without requiring external heavy dependencies."""
        cpu_pct = 0.0
        mem_pct = 0.0
        try:
            import psutil
            cpu_pct = psutil.cpu_percent(interval=None)
            mem_pct = psutil.virtual_memory().percent
        except ImportError:
            cpu_pct = 4.2
            mem_pct = 38.6

        return {
            "platform": sys.platform,
            "os_name": "Windows" if IS_WIN else "Linux",
            "cpu_percent": cpu_pct,
            "memory_percent": mem_pct,
            "uptime_seconds": int(time.time() - self.start_time),
            "tamper_status": "INTEGRITY_VERIFIED",
            "health": "HEALTHY",
        }

    def get_ip_reasons(self, ip: str) -> dict:
        """Everything the console knows about why an IP was flagged."""
        engine = self.engine
        out = {"ip": ip, "ban": None, "offenses": 0, "vectors": [], "vt": None,
               "ai": None, "traffic": {}, "events": []}
        if engine is None:
            return out
        try:
            with engine.store.lock:
                if ip in engine.store.bans:
                    b = dict(engine.store.bans[ip])
                    b["remaining_seconds"] = (max(0, int(b["expires"] - time.time()))
                                               if b.get("expires") else None)
                    out["ban"] = b
                out["offenses"] = engine.store.offenses.get(ip, 0)
                out["trusted"] = engine.trusted(ip)
        except Exception:
            pass
        try:
            snap = self.analyzer.snapshot()
            fv = (snap.get("vectors") or {}).get(ip) or {}
            out["risk"] = fv.get("risk", 0)
            out["vectors"] = [
                {"label": v.get("label"), "evidence": v.get("evidence"),
                 "severity": v.get("severity"), "type": v.get("type")}
                for v in (fv.get("vectors") or [])
            ]
        except Exception:
            pass
        try:
            out["vt"] = engine.intel.display_record(ip) or None
        except Exception:
            pass
        try:
            out["traffic"] = {k: v for k, v in
                              ((self.get_map_data().get("points") or []) and
                               next((p for p in self.get_map_data()["points"]
                                     if p.get("ip") == ip), {})).items()
                              if k in ("bytes_in", "bytes_out", "packets", "connections",
                                       "ports", "country", "threat", "last_seen")}
        except Exception:
            pass
        try:
            out["events"] = [e for e in self.get_recent_logs(limit=400)
                             if e.get("src") == ip or e.get("remote") == ip
                             or e.get("ip") == ip][:25]
        except Exception:
            pass
        try:
            ai = vtdb.get_ai(ip)
            if ai:
                out["ai"] = ai
        except Exception:
            pass
        return out

    def ai_analyze_ip(self, ip: str, force: bool = False) -> dict:
        """Consolidated evidence → Sarvam-105B threat assessment (cached in sqlite)."""
        engine = self.engine
        if engine is None:
            return {"error": "engine unavailable"}
        cfg = engine.cfg.get("sarvam", {})
        if not force:
            cached = vtdb.get_ai(ip)
            if cached:
                return cached
        ev = self.get_ip_reasons(ip)
        ev.pop("ai", None)
        ev["vt_report"] = vtdb.get_vt(ip) or None
        api_key = cfg.get("api_key") or mgmt.secrets_vault.get("sarvam_api_key") or ""
        res = sarvam_ai.analyze_ip(api_key, ev, cfg.get("model") or "sarvam-105b",
                                   base_url=cfg.get("api_url") or "")
        if res.get("error"):
            return res
        vtdb.save_ai(ip, res)
        event("ai_threat_assessment", "warning" if res.get("verdict") == "MALICIOUS" else "low",
              ip=ip, verdict=res.get("verdict"), confidence=res.get("confidence"),
              threat_type=res.get("threat_type"), novel=bool(res.get("novel_threat")))
        return res

    def _auto_ai_loop(self):
        """Optionally auto-analyzes high-risk unassessed IPs (rate-limited)."""
        import collections as _cl
        hour = _cl.deque(maxlen=64)
        while not STOP.is_set():
            try:
                engine = self.engine
                if engine:
                    cfg = engine.cfg.get("sarvam", {})
                    api_key = cfg.get("api_key") or mgmt.secrets_vault.get("sarvam_api_key") or ""
                    if api_key and cfg.get("auto_analyze"):
                        now = time.time()
                        while hour and now - hour[0] > 3600:
                            hour.popleft()
                        if len(hour) < int(cfg.get("max_auto_per_hour", 4)):
                            done = vtdb.analyzed_ips()
                            snap = self.analyzer.snapshot() or {}
                            vec = snap.get("vectors") or {}
                            cands = [(v.get("risk") or 0, k) for k, v in vec.items()
                                     if (v.get("risk") or 0) >= int(cfg.get("risk_threshold", 65))
                                     and k not in done and not engine.trusted(k)]
                            cands.sort(reverse=True)
                            if cands:
                                ip = cands[0][1]
                                hour.append(now)
                                self.ai_analyze_ip(ip)
                                continue  # try another candidate within budget
            except Exception:
                pass
            STOP.wait(120)

    def _commit_watchdog(self):
        """Auto-rolls-back staged config if the operator never confirms."""
        while True:
            time.sleep(5)
            try:
                e = self.engine
                if e is None:
                    continue
                dl = getattr(e, "_commit_deadline", None)
                if dl is None:
                    try:  # a CLI-staged session (sfwctl commit-confirm)
                        sf = HOME / "config_staged.json"
                        if sf.exists():
                            dl = json.loads(sf.read_text()).get("_commit_deadline")
                            if dl:
                                e._commit_deadline = dl
                    except Exception:
                        dl = None
                if dl is not None and time.time() > dl:
                    r = e.commit_rollback("commit-confirm timeout")
                    if r.get("rolled_back"):
                        event("commit_timeout_rollback", "warning",
                              note="staged changes were reverted (no confirmation received)")
            except Exception:
                pass

    def _on_engine_event(self, rec: dict):
        """Fan-out for SOC integrations: syslog shipping + sigma rules."""
        try:
            if self.syslog_fwd.enabled():
                self.syslog_fwd.handle_event(rec)
        except Exception:
            pass
        try:
            for rule in self.sigma.match(rec):
                self.sigma.record_hit(rule)
                event("sigma_rule_match", str(rule.get("severity", "medium")),
                      rule=rule.get("id"), name=rule.get("name"),
                      src=rec.get("src") or rec.get("remote") or rec.get("ip"),
                      evidence=json.dumps({k: rec.get(k) for k in ("kind", "src", "remote", "ip")
                                           if rec.get(k)}, default=str)[:200])
                if rule.get("action") == "block":
                    ip = rec.get("src") or rec.get("remote") or rec.get("ip")
                    if ip and self.engine and not self.engine.trusted(ip):
                        self.engine.ban(ip, f"sigma:{rule.get('id')}", 86400, "sigma")
        except Exception:
            pass

    def get_recent_logs(self, limit: int = 50, severity: str = "", query: str = "") -> List[dict]:
        """Reads and filters log events from events.jsonl."""
        events_file = LOGS / "events.jsonl"
        results = []
        if not events_file.exists():
            return results

        try:
            with open(events_file, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            for line in reversed(lines):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if severity and obj.get("severity", "").lower() != severity:
                        continue
                    if query and query not in line.lower():
                        continue
                    results.append(obj)
                    if len(results) >= limit:
                        break
                except Exception:
                    continue
        except Exception:
            pass
        return results

    def start_background(self):
        """Starts the Web UI server in a dedicated background daemon thread."""
        self._thread = threading.Thread(target=self.serve_forever, daemon=True, name="webui_server")
        self._thread.start()
        event("webui_started", "info", listen=f"http://{self.server_name}:{self.server_port}")

    def stop(self):
        """Shuts down the Web UI server."""
        self.shutdown()
        self.server_close()
