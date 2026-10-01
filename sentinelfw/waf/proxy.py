"""SentinelFW WAF Reverse Proxy Server.

Runs a high-performance reverse proxy fronting configured backend services with:
- Virtual hosts (VHostManager)
- OWASP CRS-style rule evaluation (WAFMiddleware)
- Bot mitigation (BotMitigator)
- Credential stuffing shield (CredentialShield)
- REST/JSON API protection (APIProtector)
- File upload scanning & sandbox handoff (UploadScanner)
- Upstream load balancing and health checks (LoadBalancer)
"""

import http.server
import json
import socketserver
import threading
import time
import urllib.parse
import urllib.request
from http import HTTPStatus
from pathlib import Path
from typing import Dict, List, Optional

from ..common import event
from .api_protect import APIProtector
from .bot import BotMitigator
from .credential import CredentialShield
from .loadbalancer import LoadBalancer
from .middleware import WAFMiddleware
from .upload import UploadScanner
from .vhosts import VHostManager
from ..identity import directory, ZTNAEvaluator
import secrets


class WAFRequestHandler(http.server.BaseHTTPRequestHandler):
    """Handles incoming HTTP requests through the multi-layer WAF inspection pipeline."""

    server_version = "SentinelFW-WAF/4.0"

    def log_message(self, format, *args):
        # Suppress default stderr logging
        pass

    def do_GET(self):
        self._handle_request("GET")

    def do_POST(self):
        self._handle_request("POST")

    def do_PUT(self):
        self._handle_request("PUT")

    def do_DELETE(self):
        self._handle_request("DELETE")

    def do_HEAD(self):
        self._handle_request("HEAD")

    def _handle_request(self, method: str):
        proxy: "WAFProxyServer" = self.server.proxy_controller
        client_ip = self.client_address[0] if self.client_address else "127.0.0.1"

        # 1. Read request body
        content_len = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(content_len) if content_len > 0 else b""

        # 2. Extract headers
        headers_dict = {k: v for k, v in self.headers.items()}
        host = headers_dict.get("Host") or headers_dict.get("host") or ""

        # Update stats
        with proxy.lock:
            proxy.stats["requests_total"] += 1

        # Layer 0: ZTNA Contextual Access & Posture Evaluation
        if getattr(proxy, "ztna_enabled", False):
            token = headers_dict.get("X-ZTNA-Token") or ""
            auth_hdr = headers_dict.get("Authorization") or ""
            if auth_hdr.lower().startswith("bearer "):
                token = auth_hdr[7:].strip()

            posture_hdr = headers_dict.get("X-Device-Posture")
            posture_data = None
            if posture_hdr:
                try:
                    posture_data = json.loads(posture_hdr)
                except Exception:
                    pass

            app_target = host.split(":")[0].strip().lower() if host else "default"
            if app_target in proxy.ztna._app_entitlements or "*" in proxy.ztna._app_entitlements:
                target_key = app_target if app_target in proxy.ztna._app_entitlements else "*"
                allowed, ztna_reason = proxy.ztna.evaluate_access(
                    client_ip=client_ip,
                    app_name=target_key,
                    posture_data=posture_data,
                    token=token if token else None,
                )
                if not allowed:
                    self._block_request(403, "ZTNA Access Denied", ztna_reason)
                    with proxy.lock:
                        proxy.stats["requests_blocked_ztna"] = proxy.stats.get("requests_blocked_ztna", 0) + 1
                    return

        # 3. Layer 1: Bot Mitigation
        bot_res = proxy.bot.evaluate_request(headers_dict, client_ip)
        if bot_res.get("block"):
            self._block_request(403, "Bot Mitigation Triggered", bot_res.get("reason", "automated_bot"))
            with proxy.lock:
                proxy.stats["requests_blocked_bot"] += 1
            return

        # 4. Layer 2: Credential Stuffing Shield (on login paths)
        parsed_uri = urllib.parse.urlparse(self.path)
        path = parsed_uri.path
        if path in ("/login", "/api/v1/login", "/auth", "/admin/login"):
            cred_res = proxy.cred_shield.record_attempt(client_ip, path)
            if cred_res.get("blocked"):
                self._block_request(429, "Too Many Login Attempts", "credential_shield_rate_limit")
                with proxy.lock:
                    proxy.stats["requests_blocked_cred"] += 1
                return

        # 5. Layer 3: API Protection
        content_type = headers_dict.get("Content-Type", "")
        if "application/json" in content_type and body:
            api_res = proxy.api_protect.validate_payload(body, path)
            if not api_res.get("valid"):
                self._block_request(400, "API Security Violation", api_res.get("error", "malformed_json"))
                with proxy.lock:
                    proxy.stats["requests_blocked_api"] += 1
                return

        # 6. Layer 4: File Upload Inspection & Sandbox Detonation
        if "multipart/form-data" in content_type and body:
            upload_res = proxy.uploader.scan_upload(body)
            if upload_res.get("blocked"):
                self._block_request(403, "Malicious Upload Blocked", upload_res.get("reason", "dangerous_extension"))
                with proxy.lock:
                    proxy.stats["requests_blocked_upload"] += 1
                return
            # If executable detected, pass to sandbox
            if upload_res.get("requires_detonation") and proxy.engine and hasattr(proxy.engine, "sandbox"):
                try:
                    s_file = Path(upload_res["saved_sample_path"])
                    report = proxy.engine.sandbox.analyze_file(s_file)
                    if report.get("verdict") == "MALICIOUS":
                        self._block_request(403, "Sandbox Detonation: Malicious Payload", "sandbox_verdict_malicious")
                        with proxy.lock:
                            proxy.stats["requests_blocked_upload"] += 1
                        return
                except Exception:
                    pass

        # 7. Layer 5: OWASP Core Rule Set / Anomaly Scoring WAF Middleware
        waf_res = proxy.middleware.inspect_request(
            method=method,
            uri=self.path,
            headers=headers_dict,
            body=body,
            client_ip=client_ip,
        )

        if waf_res.get("block") and proxy.mode == "block":
            matched = waf_res.get("matched_rules", [])
            rule_id = matched[0]["id"] if matched else "CRS-ANOMALY"
            self._block_request(403, "WAF Security Violation", f"Rule hit: {rule_id}")
            with proxy.lock:
                proxy.stats["requests_blocked_waf"] += 1
                for r in matched:
                    rid = str(r.get("id"))
                    proxy.stats["rule_hits"][rid] = proxy.stats["rule_hits"].get(rid, 0) + 1
            return

        # 8. Upstream Proxy Forwarding
        upstream = proxy.vhosts.get_upstream(host)
        if not upstream:
            # Standalone inspection endpoint
            resp_body = json.dumps({
                "waf": "SentinelFW-WAF",
                "status": "passed",
                "anomaly_score": waf_res.get("score", 0),
                "client_ip": client_ip,
                "timestamp": int(time.time()),
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)
            with proxy.lock:
                proxy.stats["requests_passed"] += 1
            return

        # Forward to configured upstream
        target_url = f"{upstream.rstrip('/')}{self.path}"
        try:
            req = urllib.request.Request(target_url, data=body if body else None, method=method)
            for k, v in headers_dict.items():
                if k.lower() not in ("host", "content-length"):
                    req.add_header(k, v)
            req.add_header("X-Forwarded-For", client_ip)
            req.add_header("X-Forwarded-Proto", "http")

            with urllib.request.urlopen(req, timeout=10) as up_resp:
                self.send_response(up_resp.status)
                for k, v in up_resp.headers.items():
                    if k.lower() not in ("transfer-encoding", "content-length"):
                        self.send_header(k, v)
                up_body = up_resp.read()
                self.send_header("Content-Length", str(len(up_body)))
                self.end_headers()
                self.wfile.write(up_body)
                with proxy.lock:
                    proxy.stats["requests_passed"] += 1
        except Exception as ex:
            self._block_request(502, "Bad Gateway", f"Upstream communication failure: {str(ex)[:100]}")

    def _block_request(self, code: int, title: str, reason: str):
        body = json.dumps({
            "error": "request_blocked",
            "title": title,
            "reason": reason,
            "status": code,
            "incident_id": f"WAF-{int(time.time())}-{secrets.token_hex(4)}",
        }).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        event("waf_request_blocked", "warning", status=code, title=title, reason=reason)


class WAFProxyServer:
    """Multi-layer Web Application Firewall reverse proxy controller."""

    def __init__(self, cfg: Optional[dict] = None, engine=None):
        self.cfg = cfg or {}
        w_cfg = self.cfg.get("waf", {})
        self.enabled = bool(w_cfg.get("enabled", False))
        self.mode = str(w_cfg.get("mode", "block"))  # "block" or "monitor"
        self.port = int(w_cfg.get("listen_port", 8088))
        self.host = str(w_cfg.get("listen_host", "0.0.0.0"))
        self.engine = engine
        self.lock = threading.RLock()

        # Subsystems
        self.middleware = WAFMiddleware(
            paranoia_level=int(w_cfg.get("paranoia_level", 1)),
            anomaly_threshold=int(w_cfg.get("anomaly_threshold", 5)),
        )
        self.vhosts = VHostManager(w_cfg.get("vhosts", {}))
        bot_cfg = w_cfg.get("bot_mitigation", {})
        bot_sec = bot_cfg.get("challenge_secret", "sentinelfw-challenge-secret") if isinstance(bot_cfg, dict) else str(bot_cfg or "sentinelfw-challenge-secret")
        self.bot = BotMitigator(challenge_secret=bot_sec)

        cs_cfg = w_cfg.get("credential_shield", {})
        if isinstance(cs_cfg, dict):
            self.cred_shield = CredentialShield(
                max_ip_failures=cs_cfg.get("max_ip_failures", 10),
                max_user_failures=cs_cfg.get("max_user_failures", 5),
                window_seconds=cs_cfg.get("window_seconds", 300),
                spray_threshold=cs_cfg.get("spray_threshold", 5)
            )
        else:
            self.cred_shield = CredentialShield()

        self.api_protect = APIProtector()

        up_cfg = w_cfg.get("upload_inspection", {})
        if isinstance(up_cfg, dict):
            self.uploader = UploadScanner(max_file_size=up_cfg.get("max_file_size", 10 * 1024 * 1024))
        else:
            self.uploader = UploadScanner()

        lb_cfg = w_cfg.get("load_balancers", {})
        lb_algo = lb_cfg.get("algorithm", "round_robin") if isinstance(lb_cfg, dict) else "round_robin"
        self.loadbalancer = LoadBalancer(algorithm=lb_algo)

        # ZTNA Contextual Engine
        self.ztna = ZTNAEvaluator(directory=directory)
        ztna_cfg = w_cfg.get("ztna", {})
        self.ztna_enabled = bool(ztna_cfg.get("enabled", True))
        for app_name, app_pol in ztna_cfg.get("applications", {}).items():
            self.ztna.register_app(
                app_name=app_name,
                allowed_groups=app_pol.get("allowed_groups", []),
                min_posture_score=app_pol.get("min_posture_score", 70),
                require_mfa=app_pol.get("require_mfa", False),
                max_risk_score=app_pol.get("max_risk_score", 75),
            )

        self.httpd = None
        self._thread = None
        self.stats = {
            "requests_total": 0,
            "requests_passed": 0,
            "requests_blocked_waf": 0,
            "requests_blocked_bot": 0,
            "requests_blocked_cred": 0,
            "requests_blocked_api": 0,
            "requests_blocked_upload": 0,
            "requests_blocked_ztna": 0,
            "rule_hits": {},
        }

    def start(self) -> bool:
        with self.lock:
            if self.httpd is not None:
                return True
            candidate_ports = [self.port]
            if self.port in (8088, 8080):
                candidate_ports.extend([8089, 8090, 8888, 18088])

            bound = False
            last_err = None
            for p in candidate_ports:
                try:
                    server_address = (self.host, p)
                    httpd = socketserver.TCPServer(server_address, WAFRequestHandler, bind_and_activate=False)
                    httpd.allow_reuse_address = True
                    httpd.server_bind()
                    httpd.server_activate()
                    httpd.proxy_controller = self
                    self.port = httpd.server_address[1]
                    self.httpd = httpd
                    bound = True
                    break
                except OSError as e:
                    last_err = e
                    continue

            if not bound:
                event("waf_proxy_start_failed", "warning", error=str(last_err)[:200])
                self.httpd = None
                return False

            try:
                self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True, name="sfw_waf_proxy")
                self._thread.start()
                event("waf_proxy_started", "info", host=self.host, port=self.port, mode=self.mode)
                return True
            except Exception as e:
                event("waf_proxy_start_failed", "warning", error=str(e)[:200])
                self.httpd = None
                return False

    def stop(self):
        with self.lock:
            if self.httpd:
                try:
                    self.httpd.shutdown()
                    self.httpd.server_close()
                except Exception:
                    pass
                self.httpd = None
                event("waf_proxy_stopped", "info")

    def status(self) -> dict:
        with self.lock:
            return {
                "enabled": self.enabled,
                "running": self.httpd is not None,
                "mode": self.mode,
                "listen": f"{self.host}:{self.port}",
                "stats": dict(self.stats),
                "vhosts_count": len(self.vhosts.vhosts) if hasattr(self.vhosts, "vhosts") else 0,
            }
