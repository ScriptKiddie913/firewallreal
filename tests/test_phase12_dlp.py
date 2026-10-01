"""Unit and integration tests for Phase 12: Content-Aware Data Loss Prevention (DLP).
Validates Luhn credit cards, SSNs, API tokens, private keys, Shannon entropy scanning,
custom corporate regex patterns, in-place redaction, and stream policy actions.
"""
import pytest
from sentinelfw.dlp import (
    DLPAction,
    DLPInspector,
    EnterpriseDLPManager,
    luhn_check,
    calculate_entropy,
)


def test_luhn_credit_card_and_ssn_detection():
    """Verify Luhn checksum validation on card numbers and US SSN regex."""
    dlp = EnterpriseDLPManager()

    # Valid Visa card (4111...)
    valid_visa = "4111 1111 1111 1111"
    assert luhn_check(valid_visa) is True

    # Invalid card number (fails Luhn)
    invalid_card = "4111 1111 1111 1112"
    assert luhn_check(invalid_card) is False

    text_with_cc = f"Please process order using card {valid_visa} thank you."
    findings = dlp.scan_content(text_with_cc)
    assert len(findings) == 1
    assert findings[0]["type"] == "dlp_credit_card"
    assert "1111" in findings[0]["match"]

    # US SSN detection
    text_with_ssn = "Customer SSN is 123-45-6789 on file."
    findings_ssn = dlp.scan_content(text_with_ssn)
    assert len(findings_ssn) == 1
    assert findings_ssn[0]["type"] == "dlp_ssn"
    assert "***-**-6789" in findings_ssn[0]["match"]


def test_api_keys_and_private_key_detection():
    """Verify detection of AWS, GitHub, Slack tokens and private keys."""
    dlp = EnterpriseDLPManager()

    sample = (
        "AWS credentials: AKIAIOSFODNN7EXAMPLE\n"
        "GitHub token: ghp_1234567890abcdefghijklmnopqrstuvwxyz\n"
        "Slack token: xoxb-1234567890-abcdefghijklmnop\n"
        "-----BEGIN RSA PRIVATE KEY-----\n"
    )
    findings = dlp.scan_content(sample)
    types = [f["type"] for f in findings]
    assert "dlp_api_token" in types
    assert "dlp_private_key" in types
    providers = [f.get("provider") for f in findings if "provider" in f]
    assert "AWS" in providers
    assert "GitHub" in providers
    assert "Slack" in providers


def test_custom_corporate_patterns():
    """Verify registration and matching of proprietary corporate expressions."""
    dlp = EnterpriseDLPManager()
    dlp.add_custom_pattern(
        name="EmployeeID",
        pattern=r"\bEMP-[0-9]{6}\b",
        severity="medium",
        action=DLPAction.BLOCK,
    )

    text = "Employee record: EMP-982341 reviewed."
    findings = dlp.scan_content_with_custom(text)
    assert len(findings) == 1
    assert findings[0]["type"] == "dlp_custom_pattern"
    assert findings[0]["provider"] == "EmployeeID"
    assert "EMP-982341" in findings[0]["match"]


def test_in_place_content_redaction():
    """Verify that sensitive secrets are sanitized in-place when redaction is enabled."""
    dlp = EnterpriseDLPManager()
    dirty_text = (
        "User 123-45-6789 bought product with card 4111 1111 1111 1111 using "
        "AWS key AKIAIOSFODNN7EXAMPLE."
    )

    clean_text, findings = dlp.redact_content(dirty_text)
    assert len(findings) >= 3
    assert "123-45-6789" not in clean_text
    assert "***-**-6789" in clean_text
    assert "4111 1111 1111 1111" not in clean_text
    assert "AKIAIOSFODNN7EXAMPLE" not in clean_text
    assert "[REDACTED_AWS_KEY]" in clean_text


def test_dlp_stream_evaluation_and_actions():
    """Verify stream evaluation: BLOCK, REDACT, and ALLOW actions."""
    dlp = EnterpriseDLPManager()

    # 1. Clean payload -> ALLOW
    clean_res = dlp.evaluate_stream("Normal clean business email body.", direction="upload")
    assert clean_res["action"] == DLPAction.ALLOW
    assert len(clean_res["findings"]) == 0

    # 2. Leaked credit card with BLOCK policy
    dirty_text = "Card number 4111 1111 1111 1111"
    block_res = dlp.evaluate_stream(dirty_text, direction="upload", policy_action=DLPAction.BLOCK)
    assert block_res["action"] == DLPAction.BLOCK
    assert "dlp_credit_card" in block_res["reason"]

    # 3. Leaked credit card with REDACT policy
    redact_res = dlp.evaluate_stream(dirty_text, direction="download", policy_action=DLPAction.REDACT)
    assert redact_res["action"] == DLPAction.REDACT
    assert "4111 1111 1111 1111" not in redact_res["data"]

    # 4. Privacy exemption domain bypasses scan
    exempt_res = dlp.evaluate_stream(dirty_text, domain="patient.mychart.com")
    assert exempt_res["action"] == DLPAction.ALLOW
