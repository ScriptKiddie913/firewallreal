"""Tests for the 2.7 management-plane + SOC layer (mgmt.py)."""
import json
import os
import sys
import tempfile
import time
from pathlib import Path

TMP = tempfile.mkdtemp(prefix="sfwtest_mgmt_")
os.environ["SENTINELFW_HOME"] = TMP
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinelfw import mgmt  # noqa: E402


# ---------------------------------------------------------------- scrypt
def test_scrypt_roundtrip():
    h = mgmt.hash_password("S3cret!pass")
    assert h.startswith("scrypt$") and "$" in h
    assert mgmt.verify_password("S3cret!pass", h)
    assert not mgmt.verify_password("wrong", h)


def test_legacy_sha256_still_verifies():
    import hashlib
    legacy = hashlib.sha256(b"oldpw").hexdigest()
    assert mgmt.verify_password("oldpw", legacy)
    assert not mgmt.verify_password("nope", legacy)


# ---------------------------------------------------------------- TOTP
def test_totp_roundtrip():
    s = mgmt.totp_secret_new()
    assert len(s) >= 30
    code = mgmt.totp_now(s)
    assert mgmt.totp_verify(code, s)
    assert not mgmt.totp_verify("000000" if code != "000000" else "111111", s)


def test_totp_window():
    s = mgmt.totp_secret_new()
    past = mgmt.totp_now(s, t=time.time() - 30)
    assert mgmt.totp_verify(past, s)  # one step drift accepted


def test_recovery_codes_format():
    codes = mgmt.recovery_codes_new(5)
    assert len(codes) == 5 and all("-" in c for c in codes)


# ---------------------------------------------------------------- sessions
def _auth(cfg=None):
    cfg = cfg or {"webui": {"username": "admin", "password_hash": mgmt.hash_password("pw")}}
    return mgmt.AuthManager(lambda: cfg, session_ttl_minutes=10)


def test_login_and_session():
    a = _auth()
    res = a.login("admin", "pw", "")
    assert res.get("session_id") and res.get("csrf")
    s = a.validate_session(res["session_id"])
    assert s and s["user"] == "admin"
    assert a.check_csrf(res["session_id"], res["csrf"])
    assert not a.check_csrf(res["session_id"], "bogus")


def test_login_bad_password():
    a = _auth()
    assert "error" in a.login("admin", "nope", "")


def test_login_lockout():
    a = _auth()
    for _ in range(8):
        r = a.login("admin", "bad", "", client_ip="1.2.3.4")
    r = a.login("admin", "pw", "", client_ip="1.2.3.4")
    assert "locked out" in r.get("error", "")
    # a different client is unaffected
    assert a.login("admin", "pw", "", client_ip="5.6.7.8").get("session_id")


def test_login_totp_required():
    cfg = {"webui": {"username": "admin", "password_hash": mgmt.hash_password("pw")},
           "management": {"totp_enabled": True, "totp_secret": mgmt.totp_secret_new(),
                          "recovery_codes": ["12345-67890"]}}
    a = mgmt.AuthManager(lambda: cfg)
    r = a.login("admin", "pw", "")
    assert r.get("totp_required")
    code = mgmt.totp_now(cfg["management"]["totp_secret"])
    assert a.login("admin", "pw", code).get("session_id")
    # a wrong recovery code is rejected
    r2 = a.login("admin", "pw", "99999-00000")
    assert r2.get("totp_required")
    # a valid recovery code logs in and is consumed (single use)
    r3 = a.login("admin", "pw", "12345-67890")
    assert r3.get("session_id")
    r4 = a.login("admin", "pw", "12345-67890")
    assert r4.get("totp_required")  # already consumed


# ---------------------------------------------------------------- audit log
def test_audit_chain_verifies_and_detects_tampering():
    f = mgmt.AUDIT_FILE
    if f.exists():
        try:
            f.unlink()
        except OSError:
            pass
    try:
        mgmt.audit_append("unit_test_action", user="pytest", foo="bar")
        mgmt.audit_append("another_action", user="pytest")
        r = mgmt.audit_verify()
        assert r["ok"] and r["records"] >= 2
        # tamper with the file
        lines = f.read_text(encoding="utf-8").splitlines()
        lines[0] = lines[0].replace("unit_test_action", "EVIL_EDIT")
        f.write_text("\n".join(lines) + "\n", encoding="utf-8")
        r2 = mgmt.audit_verify()
        assert not r2["ok"] and r2["first_bad"]
    finally:
        if f.exists():
            try:
                f.unlink()
            except OSError:
                pass


def test_mask_body_hides_secrets():
    out = mgmt.mask_body({"password": "hunter2", "api_key": "ABC", "name": "fine"})
    assert "hunter2" not in out and "ABC" not in out and "fine" in out


# ---------------------------------------------------------------- sigma
def test_sigma_engine_seeds_and_matches():
    d = Path(TMP) / "lists" / "sigma_test"
    eng = mgmt.SigmaEngine(d)
    assert len(eng.rules) >= 5  # bundled starter rules seeded
    hits = eng.match({"kind": "honeypot_ssh_hit", "src": "9.9.9.9"})
    assert any(r["id"] == "sfw-hp-ssh-001" for r in hits)
    hits2 = eng.match({"kind": "honeypot_ssh_hit", "src": "9.9.9.9", "severity": "low"})
    assert hits2  # exact-field rule still matches (selection only pins kind)


def test_sigma_glob_and_list():
    d = Path(TMP) / "lists" / "sigma_glob"
    d.mkdir(parents=True, exist_ok=True)
    (d / "t.json").write_text(json.dumps({
        "id": "t1", "name": "t", "severity": "low", "action": "monitor",
        "selection": {"kind": "x_*", "user": ["root", "admin"], "src": "185.*"}}), encoding="utf-8")
    eng = mgmt.SigmaEngine(d)
    assert eng.match({"kind": "x_login", "user": "root", "src": "185.1.2.3"})
    assert not eng.match({"kind": "x_login", "user": "nobody", "src": "185.1.2.3"})
    assert not eng.match({"kind": "y_login", "user": "root", "src": "185.1.2.3"})


def test_sigma_disabled():
    d = Path(TMP) / "lists" / "sigma_off"
    d.mkdir(parents=True, exist_ok=True)
    (d / "t.json").write_text(json.dumps({
        "id": "t2", "name": "t", "severity": "low", "action": "monitor",
        "selection": {"kind": "z"}}), encoding="utf-8")
    eng = mgmt.SigmaEngine(d, cfg_get=lambda: {"sigma": {"enabled": False}})
    assert eng.match({"kind": "z"}) == []


# ---------------------------------------------------------------- exports
def test_stix_export_shape():
    b = mgmt.stix_export(None)
    assert b["type"] == "bundle" and b["objects"]
    assert b["objects"][0]["type"] == "identity"
    assert b["id"].startswith("bundle--")


def test_prometheus_shape():
    out = mgmt.prometheus_metrics(None, None)
    assert "sentinelfw_uptime_seconds" in out


# ---------------------------------------------------------------- syslog
def test_syslog_cef_format(tmp_path=None):
    import socket as s
    sock = s.socket(s.AF_INET, s.SOCK_DGRAM)
    port = s.bind if False else None
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    fwd = mgmt.SyslogForwarder(lambda: {"syslog": {"enabled": True, "host": "127.0.0.1",
                                                    "port": port, "proto": "udp",
                                                    "format": "cef"}})
    fwd.handle_event({"kind": "ip_banned", "severity": "high", "src": "1.2.3.4"})
    fwd.handle_event({"kind": "heartbeat", "severity": "info"})
    data, _ = sock.recvfrom(65535)
    line = data.decode()
    assert line.startswith("CEF:0|SentinelFW|SentinelFW|3.0|ip_banned")
    assert "src=1.2.3.4" in line
    sock.close()


def test_syslog_rfc5424_format():
    import socket as s
    sock = s.socket(s.AF_INET, s.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    fwd = mgmt.SyslogForwarder(lambda: {"syslog": {"enabled": True, "host": "127.0.0.1",
                                                    "port": port, "proto": "udp",
                                                    "format": "rfc5424"}})
    fwd.handle_event({"kind": "ip_banned", "severity": "high", "src": "1.2.3.4"})
    data, _ = sock.recvfrom(65535)
    line = data.decode()
    # <PRI>1 TIMESTAMP HOST APP PROCID MSGID STRUCTURED-DATA MSG
    assert line.startswith("<") and ">1 " in line
    assert "SentinelFW - ip_banned" in line
    assert "[sentinelfw event_id=" in line and "src=1.2.3.4" in line
    sock.close()


def test_syslog_disabled_silent():
    fwd = mgmt.SyslogForwarder(lambda: {"syslog": {"enabled": False}})
    fwd.handle_event({"kind": "x"})  # must not raise
    assert not fwd.enabled()


def test_first_run_password():
    h = mgmt.first_run_password()
    assert h.startswith('scrypt$')
    assert len(h) > 30


def test_rbac_matrix_permissions():
    assert mgmt.has_permission("SuperAdmin", "anything:write")
    assert mgmt.has_permission("SuperAdmin", "system:admin")
    assert mgmt.has_permission("SecurityAdmin", "policies:write")
    assert mgmt.has_permission("SecurityAdmin", "rules:read")
    assert not mgmt.has_permission("SecurityAdmin", "routes:write")
    assert not mgmt.has_permission("SecurityAdmin", "admin:tokens")
    assert mgmt.has_permission("NetworkAdmin", "routes:write")
    assert mgmt.has_permission("NetworkAdmin", "interfaces:read")
    assert not mgmt.has_permission("NetworkAdmin", "policies:write")
    assert mgmt.has_permission("Auditor", "policies:read")
    assert mgmt.has_permission("Auditor", "routes:read")
    assert not mgmt.has_permission("Auditor", "policies:write")
    assert not mgmt.has_permission("Auditor", "routes:write")


def test_api_tokens_lifecycle():
    tok = mgmt.create_api_token(username="test_user", role="SecurityAdmin", expires_days=1, note="ci-test")
    raw = tok["token"]
    assert raw.startswith("sfw_tok_")
    info = mgmt.verify_api_token(raw)
    assert info is not None
    assert info["username"] == "test_user"
    assert info["role"] == "SecurityAdmin"
    
    # expired token
    tokens = mgmt.load_api_tokens()
    tokens[tok["token_hash"]]["expires_at"] = time.time() - 10
    mgmt.save_api_tokens(tokens)
    assert mgmt.verify_api_token(raw) is None
    
    # revoke
    assert mgmt.revoke_api_token(tok["token_hash"])
    assert mgmt.verify_api_token(raw) is None


def test_secrets_vault_encrypt_decrypt():
    import tempfile
    td = Path(tempfile.mkdtemp())
    vault = mgmt.SecretsVault(key_path=td / ".key", data_path=td / "vault.dat")
    vault.set("sarvam_api_key", "sarvam_secret_12345")
    vault.set("telegram_bot_token", "bot_secret_98765")
    
    assert vault.get("sarvam_api_key") == "sarvam_secret_12345"
    assert vault.get("telegram_bot_token") == "bot_secret_98765"
    assert vault.list_keys() == ["sarvam_api_key", "telegram_bot_token"]
    
    # Tamper detection
    raw = (td / "vault.dat").read_bytes()
    tampered = bytearray(raw)
    tampered[-5] ^= 0xFF
    (td / "vault.dat").write_bytes(tampered)
    val = vault.get("sarvam_api_key")
    assert val is None # load failed safely
        
    vault.delete("sarvam_api_key")

import unittest
class TestMgmtSuite(unittest.TestCase):
    pass
for _k, _v in list(globals().items()):
    if _k.startswith('test_') and callable(_v):
        setattr(TestMgmtSuite, _k, lambda self, f=_v: f())
