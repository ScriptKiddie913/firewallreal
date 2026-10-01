"""Tests for the 3.0 hardening layer: integrations, go supervisor, gateway_sync."""
import json
import os
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

TMP = tempfile.mkdtemp(prefix="sfwtest_int_")
os.environ["SENTINELFW_HOME"] = TMP
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinelfw import integrations as integ  # noqa: E402
from sentinelfw import gateway_sync  # noqa: E402


# ---------------------------------------------------------------- env keys
def test_get_key_env_wins():
    cfg = {"sarvam": {"api_key": "from-config"}}
    assert integ.get_key(cfg, "sarvam", "api_key", "SFW_TEST_KEY_X") == "from-config"
    os.environ["SFW_TEST_KEY_X"] = "from-env"
    try:
        assert integ.get_key(cfg, "sarvam", "api_key", "SFW_TEST_KEY_X") == "from-env"
    finally:
        del os.environ["SFW_TEST_KEY_X"]


def test_store_env_overrides_and_persist_safety():
    from sentinelfw.config import Store
    os.environ["SFW_VT_KEY"] = "vt-env-key"
    try:
        s = Store()
        assert s.cfg["threat_intel"]["virustotal_api_key"] == "vt-env-key"
        out = {}
        s.persist_env_safe(lambda: out.update(json.loads(json.dumps(s.cfg))))
        assert out["threat_intel"]["virustotal_api_key"] == ""
        # in-memory value survived the persist
        assert s.cfg["threat_intel"]["virustotal_api_key"] == "vt-env-key"
    finally:
        del os.environ["SFW_VT_KEY"]


# ---------------------------------------------------------------- integrations
def test_integration_detect_with_fake_binaries():
    fake = Path(TMP) / "bin"
    fake.mkdir(exist_ok=True)
    ext = ".bat" if sys.platform.startswith("win") else ""
    for name in ("suricata", "clamscan"):
        p = fake / (name + ext)
        p.write_text("@echo off\n" if ext else "#!/bin/sh\n")
        p.chmod(0o755)
    old_path = os.environ.get("PATH", "")
    os.environ["PATH"] = f"{fake}{os.pathsep}{old_path}"
    try:
        im = integ.IntegrationManager(lambda: {})
        det = im.detect()
        assert det["suricata"] and det["clamav"]
    finally:
        os.environ["PATH"] = old_path


def test_integration_detect_missing():
    im = integ.IntegrationManager(lambda: {"integrations": {}})
    det = im.detect()
    # on the test host either state is fine; shape must be right
    assert set(det) == {"suricata", "clamav", "freshclam"}
    assert isinstance(det["suricata"], bool)


def test_auto_install_disabled_noop():
    im = integ.IntegrationManager(lambda: {"integrations": {"auto_install": False}})
    r = im.auto_install()
    assert r["attempted"] is False and "disabled" in r["note"]

def test_go_supervisor_states():
    gs = integ.GoServiceSupervisor(lambda: {"go_services": {"enabled": False}})
    if not integ.GoServiceSupervisor.go_available():
        assert gs.status()["state"] == "go_not_installed"
    # force a fake binary and supervise a real sleeping process
    ext = ".bat" if sys.platform.startswith("win") else ""
    gs.bin_path = Path(tempfile.gettempdir()) / f"sfw_fake_daemon_{os.getpid()}{ext}"
    if ext:
        gs.bin_path.write_text("@echo off\nping -n 60 127.0.0.1 >nul\n")
    else:
        gs.bin_path.write_text("#!/bin/sh\nsleep 60\n")
    gs.bin_path.chmod(0o755)
    assert gs.start(force=True)
    time.sleep(0.3)
    st = gs.status()
    assert st["state"] == "running" and st["pid"]
    gs.stop()
    time.sleep(0.3)
    assert gs.status()["state"] != "running" 


def test_go_supervisor_disabled_start():
    gs = integ.GoServiceSupervisor(lambda: {"go_services": {"enabled": False}})
    gs.bin_path = None
    assert gs.start() is False


# ---------------------------------------------------------------- TLS cert
def test_generate_self_signed():
    cert = Path(TMP) / "c.crt"
    key = Path(TMP) / "c.key"
    if integ.shutil.which("openssl"):
        assert integ.generate_self_signed(cert, key)
        assert cert.exists() and key.exists() and cert.stat().st_size > 100
    else:
        assert not integ.generate_self_signed(cert, key)


# ---------------------------------------------------------------- gateway_sync
def test_gateway_sync_unconfigured_is_honest():
    g = gateway_sync.GatewaySyncClient()
    if g.policy_cache_path.exists():
        try:
            os.remove(g.policy_cache_path)
        except OSError:
            pass
    assert not g.configured()
    assert g.sync_with_gateway() is False
    assert not g.policy_cache_path.exists()   # no fake policy cache
    p = g.collect_posture()
    assert "edr_active" not in p             # never fabricated


def test_gateway_sync_real_checkin():
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.dumps({"policy": {"blocked_ips": ["203.0.113.7"]}})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body.encode())
        def log_message(self, *a):
            pass
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        g = gateway_sync.GatewaySyncClient(
            gateway_url=f"http://127.0.0.1:{srv.server_port}",
            posture_provider=lambda: {"bans": 3, "real_signal": True})
        assert g.sync_with_gateway() is True
        cached = g.load_cached_policy()
        assert cached.get("policy", {}).get("blocked_ips") == ["203.0.113.7"]
    finally:
        srv.shutdown()


def test_gateway_sync_unreachable_no_cache():
    g = gateway_sync.GatewaySyncClient(gateway_url="http://127.0.0.1:1",
                                        posture_provider=lambda: {})
    try:
        os.remove(g.policy_cache_path)
    except OSError:
        pass
    assert g.sync_with_gateway() is False
    assert not g.policy_cache_path.exists()


import unittest
class TestIntegrationsSuite(unittest.TestCase):
    pass
for _k, _v in list(globals().items()):
    if _k.startswith('test_') and callable(_v):
        setattr(TestIntegrationsSuite, _k, lambda self, f=_v: f())
