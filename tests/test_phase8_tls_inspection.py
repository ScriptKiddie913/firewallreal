"""Unit and integration tests for Phase 8: Transparent TLS Inspection Engine.
Validates privacy-conscious bypass rules, upstream certificate chain verification,
certificate pinning detection, and QUIC/HTTP3 fallback policies.
"""
import time
import pytest
from sentinelfw.protocols.tls import (
    TLSInspector,
    TLSPrivacyBypassManager,
    UpstreamCertValidator,
    CertPinningTracker,
    TLSInspectionPolicy,
)


def test_tls_privacy_bypass_categories():
    """Verify banking, healthcare, and government categories are exempted from decryption."""
    mgr = TLSPrivacyBypassManager()

    # Banking bypass
    bypass, reason = mgr.should_bypass("online.chase.com")
    assert bypass is True
    assert "chase.com" in reason

    bypass_bofa, _ = mgr.should_bypass("secure.bankofamerica.com")
    assert bypass_bofa is True

    bypass_fidelity, _ = mgr.should_bypass("invest.fidelity.com")
    assert bypass_fidelity is True

    # Healthcare bypass
    bypass_health, _ = mgr.should_bypass("patient.mychart.com")
    assert bypass_health is True

    # Government bypass
    bypass_gov, _ = mgr.should_bypass("taxpayers.irs.gov")
    assert bypass_gov is True

    # Regular commercial/untrusted traffic must NOT bypass
    bypass_github, _ = mgr.should_bypass("github.com")
    assert bypass_github is False

    bypass_c2, _ = mgr.should_bypass("evil-c2-listener.top")
    assert bypass_c2 is False


def test_tls_privacy_custom_rules():
    """Verify dynamic addition and removal of enterprise privacy bypass rules."""
    mgr = TLSPrivacyBypassManager(custom_bypass_rules=["*.internal-hr.corp", "secure-payroll.net"])

    # Matches custom wildcard
    bypass_hr, _ = mgr.should_bypass("portal.internal-hr.corp")
    assert bypass_hr is True

    # Matches exact domain
    bypass_pay, _ = mgr.should_bypass("secure-payroll.net")
    assert bypass_pay is True

    # Remove rule
    mgr.remove_rule("secure-payroll.net")
    bypass_pay_removed, _ = mgr.should_bypass("secure-payroll.net")
    assert bypass_pay_removed is False


def test_upstream_certificate_validation():
    """Verify upstream certificate expiry and SAN matching."""
    now = time.time()
    valid_cert = {
        "notBefore": now - 3600,
        "notAfter": now + 86400 * 30,
        "subjectAltName": ["api.example.com", "*.corp.example.com"],
        "commonName": "api.example.com",
    }

    # Exact SAN match
    valid, msg = UpstreamCertValidator.validate_certificate(valid_cert, "api.example.com", now=now)
    assert valid is True
    assert msg == "valid"

    # Wildcard SAN match
    valid_wild, _ = UpstreamCertValidator.validate_certificate(valid_cert, "vpn.corp.example.com", now=now)
    assert valid_wild is True

    # Hostname mismatch
    valid_mismatch, reason = UpstreamCertValidator.validate_certificate(valid_cert, "attacker.com", now=now)
    assert valid_mismatch is False
    assert "hostname_mismatch" in reason

    # Expired certificate
    expired_cert = {
        "notBefore": now - 86400 * 60,
        "notAfter": now - 3600,
        "subjectAltName": ["api.example.com"],
    }
    valid_exp, reason_exp = UpstreamCertValidator.validate_certificate(expired_cert, "api.example.com", now=now)
    assert valid_exp is False
    assert "expired" in reason_exp

    # Not yet valid certificate
    future_cert = {
        "notBefore": now + 3600,
        "notAfter": now + 86400 * 30,
        "subjectAltName": ["api.example.com"],
    }
    valid_fut, reason_fut = UpstreamCertValidator.validate_certificate(future_cert, "api.example.com", now=now)
    assert valid_fut is False
    assert "not_yet_valid" in reason_fut


def test_cert_pinning_auto_bypass():
    """Verify that repeated certificate pinning alerts trigger automatic bypass."""
    tracker = CertPinningTracker(failure_threshold=3, auto_bypass_ttl=3600)
    domain = "pinned-mobile-app.bank.com"

    # Initially not bypassed
    assert tracker.is_auto_bypassed(domain) is False

    # First alert (alert 46 unknown_ca)
    bypassed1, count1 = tracker.record_alert(domain, alert_code=46)
    assert bypassed1 is False
    assert count1 == 1
    assert tracker.is_auto_bypassed(domain) is False

    # Second alert
    bypassed2, count2 = tracker.record_alert(domain, alert_code=46)
    assert bypassed2 is False
    assert count2 == 2

    # Third alert reaches threshold -> activates auto-bypass
    bypassed3, count3 = tracker.record_alert(domain, alert_code=46)
    assert bypassed3 is True
    assert count3 == 3
    assert tracker.is_auto_bypassed(domain) is True


def test_unified_tls_inspection_policy():
    """Verify decision pipeline: QUIC fallback, pinning bypass, privacy bypass, upstream cert check, inspection."""
    policy = TLSInspectionPolicy(quic_policy="force_fallback")

    # 1. QUIC traffic triggers fallback drop to enforce TCP/TLS
    quic_res = policy.evaluate("youtube.com", is_quic=True)
    assert quic_res["action"] == "drop"
    assert "fallback" in quic_res["reason"].lower()

    # 2. Banking traffic triggers privacy bypass
    bank_res = policy.evaluate("online.chase.com")
    assert bank_res["action"] == "bypass"
    assert "chase.com" in bank_res["reason"]

    # 3. Upstream certificate failure triggers block
    now = time.time()
    bad_cert = {
        "notBefore": now - 3600,
        "notAfter": now + 3600,
        "subjectAltName": ["mismatch.com"],
    }
    cert_res = policy.evaluate("service.internal", cert_data=bad_cert)
    assert cert_res["action"] == "block"
    assert "hostname_mismatch" in cert_res["reason"]

    # 4. Standard traffic is marked for full inspection
    normal_cert = {
        "notBefore": now - 3600,
        "notAfter": now + 3600,
        "subjectAltName": ["api.cloud.io"],
    }
    normal_res = policy.evaluate("api.cloud.io", cert_data=normal_cert)
    assert normal_res["action"] == "inspect"
    assert normal_res["reason"] == "full_inspection_eligible"
