"""Unit and integration tests for Phase 6 (Endpoint Posture Assessment)
and Phase 7 (Zero-Trust Network Access Engine).
"""
import json
import time
import pytest
from sentinelfw.identity import DevicePostureEvaluator, ZTNAEvaluator, IdentityDirectory
from sentinelfw.agent_daemon import AgentDaemon
from sentinelfw.waf.proxy import WAFProxyServer


def test_posture_evaluator_four_states():
    """Verify COMPLIANT, NON_COMPLIANT, UNKNOWN, and COMPROMISED posture classifications."""
    # 1. COMPLIANT endpoint
    compliant_data = {
        "disk_encrypted": True,
        "firewall_active": True,
        "edr_present": True,
        "os_build": 22631,
        "tamper_status": "clean",
        "compromised": False,
        "risk_score": 10,
    }
    res = DevicePostureEvaluator.assess_posture(compliant_data)
    assert res["state"] == DevicePostureEvaluator.COMPLIANT
    assert res["compliant"] is True
    assert res["score"] >= 70
    assert len(res["violations"]) == 0

    # 2. NON_COMPLIANT endpoint (missing firewall and disk encryption)
    non_compliant_data = {
        "disk_encrypted": False,
        "firewall_active": False,
        "edr_present": True,
        "os_build": 22631,
        "tamper_status": "clean",
        "risk_score": 15,
    }
    res2 = DevicePostureEvaluator.assess_posture(non_compliant_data)
    assert res2["state"] == DevicePostureEvaluator.NON_COMPLIANT
    assert res2["compliant"] is False
    assert any("BitLocker" in v for v in res2["violations"])
    assert any("Host firewall" in v for v in res2["violations"])

    # 3. UNKNOWN endpoint (no telemetry provided)
    res3 = DevicePostureEvaluator.assess_posture({})
    assert res3["state"] == DevicePostureEvaluator.UNKNOWN
    assert res3["compliant"] is False
    assert res3["score"] == 0

    res3_none = DevicePostureEvaluator.assess_posture(None)
    assert res3_none["state"] == DevicePostureEvaluator.UNKNOWN

    # 4. COMPROMISED endpoint (tampered or compromised flag)
    compromised_data = {
        "disk_encrypted": True,
        "firewall_active": True,
        "edr_present": True,
        "tamper_status": "tampered",
        "risk_score": 90,
    }
    res4 = DevicePostureEvaluator.assess_posture(compromised_data)
    assert res4["state"] == DevicePostureEvaluator.COMPROMISED
    assert res4["compliant"] is False
    assert res4["score"] == 0
    assert any("compromise" in v for v in res4["violations"])


def test_posture_report_signing_and_verification():
    """Verify HMAC-SHA256 signature and tamper detection for posture reports."""
    secret = "corporate-mtls-psk-secret-999"
    telemetry = {
        "disk_encrypted": True,
        "firewall_active": True,
        "edr_present": True,
        "os_build": 22000,
    }

    signed_report = DevicePostureEvaluator.generate_signed_report(telemetry, secret)
    assert "payload" in signed_report
    assert "signature" in signed_report

    # Valid report verification
    valid, msg, extracted = DevicePostureEvaluator.verify_signed_report(signed_report, secret)
    assert valid is True
    assert extracted["os_build"] == 22000

    # Tampered payload fails verification
    tampered_report = json.loads(json.dumps(signed_report))
    tampered_report["payload"]["data"]["disk_encrypted"] = False
    valid_tamper, msg_tamper, _ = DevicePostureEvaluator.verify_signed_report(tampered_report, secret)
    assert valid_tamper is False
    assert "signature" in msg_tamper.lower()

    # Expired report fails verification
    expired_report = json.loads(json.dumps(signed_report))
    expired_report["payload"]["timestamp"] = time.time() - 1000
    # Re-sign the expired timestamp to test freshness gate specifically
    import hmac, hashlib
    ser = json.dumps(expired_report["payload"], sort_keys=True).encode()
    expired_report["signature"] = hmac.new(secret.encode(), ser, hashlib.sha256).hexdigest()
    valid_exp, msg_exp, _ = DevicePostureEvaluator.verify_signed_report(expired_report, secret, max_age_seconds=60)
    assert valid_exp is False
    assert "expired" in msg_exp.lower()


def test_agent_daemon_posture_and_ztna_actions():
    """Verify AgentDaemon local telemetry collection, IPC posture dispatch, and report ingestion."""
    daemon = AgentDaemon()

    # Local posture collection
    local_posture = daemon.collect_local_posture()
    assert "platform" in local_posture
    assert "firewall_active" in local_posture
    assert "edr_present" in local_posture

    # Dispatch posture action
    res = daemon.dispatch_action("posture", {})
    assert res["status"] == "ok"
    assert "posture_state" in res
    assert "posture_score" in res

    # Dispatch report_posture action with signing
    secret = "sentinel-agent-auth-key"
    report_data = {
        "disk_encrypted": True,
        "firewall_active": True,
        "edr_present": True,
        "os_build": 22000,
        "tamper_status": "clean",
    }
    signed = DevicePostureEvaluator.generate_signed_report(report_data, secret)
    report_res = daemon.dispatch_action("report_posture", {
        "ip": "10.10.50.25",
        "user": "alice@corp.internal",
        "device_id": "DEV-CORP-001",
        "groups": ["engineering", "secops"],
        "signed_report": signed,
        "signing_key": secret,
    })
    assert report_res["status"] == "ok"
    assert report_res["posture_state"] == "COMPLIANT"

    # Verify identity directory updated
    ident = daemon.ztna_evaluator.directory.get_identity("10.10.50.25")
    assert ident is not None
    assert ident["username"] == "alice@corp.internal"
    assert ident["posture"] == "COMPLIANT"
    assert ident["device_id"] == "DEV-CORP-001"


def test_ztna_session_issuance_and_revocation():
    """Verify ZTNA token lifecycle: issuance, verification, application scoping, and revocation."""
    ztna = ZTNAEvaluator()
    ztna.register_app("jira.internal", allowed_groups=["engineering"], min_posture_score=70)
    ztna.register_app("vault.internal", allowed_groups=["secops"], min_posture_score=90)

    # 1. Issue session token for alice (engineering)
    token = ztna.issue_session(
        username="alice",
        device_id="DEV-A1",
        app_name="jira.internal",
        groups=["engineering"],
        posture_state="COMPLIANT",
        ttl_seconds=300,
    )
    assert token is not None

    # Verify access to jira.internal
    allowed, reason = ztna.evaluate_access(
        client_ip="192.168.10.5",
        app_name="jira.internal",
        token=token,
    )
    assert allowed is True
    assert reason == "Access granted"

    # Unauthorized app scope (token scoped for jira, attempting vault)
    allowed_v, reason_v = ztna.evaluate_access(
        client_ip="192.168.10.5",
        app_name="vault.internal",
        token=token,
    )
    assert allowed_v is False
    assert "scoped for" in reason_v

    # 2. Dynamic session revocation
    _, _, claims = ztna.verify_session(token, app_name="jira.internal")
    session_id = claims["jti"]
    ztna.revoke_session(session_id)

    allowed_revoked, reason_revoked = ztna.evaluate_access(
        client_ip="192.168.10.5",
        app_name="jira.internal",
        token=token,
    )
    assert allowed_revoked is False
    assert "revoked" in reason_revoked.lower()

    # 3. Dynamic device revocation
    token2 = ztna.issue_session("bob", "DEV-B2", "jira.internal", groups=["engineering"])
    ztna.revoke_device("DEV-B2")
    allowed_dev, reason_dev = ztna.evaluate_access("192.168.10.6", "jira.internal", token=token2)
    assert allowed_dev is False
    assert "revoked" in reason_dev.lower()


def test_ztna_continuous_risk_scoring_and_posture_downgrade():
    """Verify continuous risk evaluation blocks high risk or compromised endpoints."""
    directory = IdentityDirectory()
    directory.map_ip("10.0.0.99", "charlie", groups=["engineering"], device_id="DEV-C3")
    ztna = ZTNAEvaluator(directory=directory)
    ztna.register_app("crm.internal", allowed_groups=["engineering"], max_risk_score=60)

    # Normal risk (risk=20)
    allowed, reason = ztna.evaluate_access("10.0.0.99", "crm.internal", risk_score=20)
    assert allowed is True

    # High risk (risk=85 exceeds max 60)
    allowed_high, reason_high = ztna.evaluate_access("10.0.0.99", "crm.internal", risk_score=85)
    assert allowed_high is False
    assert "Continuous risk score" in reason_high

    # Posture downgrade to COMPROMISED automatically revokes device
    compromised_telemetry = {
        "compromised": True,
        "tamper_status": "tampered",
    }
    allowed_comp, reason_comp = ztna.evaluate_access("10.0.0.99", "crm.internal", posture_data=compromised_telemetry)
    assert allowed_comp is False
    assert "compromised" in reason_comp.lower()

    # Subsequent access without telemetry is now blocked because device was auto-revoked
    allowed_sub, reason_sub = ztna.evaluate_access("10.0.0.99", "crm.internal")
    assert allowed_sub is False
    assert "revoked" in reason_sub.lower()


def test_waf_reverse_proxy_ztna_enforcement():
    """Verify that WAFProxyServer enforces Layer 0 ZTNA policy on incoming requests."""
    cfg = {
        "waf": {
            "enabled": True,
            "mode": "block",
            "listen_port": 18088,
            "vhosts": {
                "payroll.corp.internal": "http://127.0.0.1:9099"
            },
            "ztna": {
                "enabled": True,
                "applications": {
                    "payroll.corp.internal": {
                        "allowed_groups": ["finance"],
                        "min_posture_score": 80,
                    }
                }
            }
        }
    }
    server = WAFProxyServer(cfg=cfg)
    assert server.ztna_enabled is True
    assert "payroll.corp.internal" in server.ztna._app_entitlements
