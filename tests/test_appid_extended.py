"""Unit tests for Phase 3: Deep Application Identification (App-ID).
Tests SNI detection, HTTP host detection, payload banners, numerical confidence scores,
risk/category mappings, and unclassified traffic handling.
"""

import pytest
from sentinelfw.appid import AppIDClassifier


def test_appid_sni_detection():
    classifier = AppIDClassifier()

    # Telegram via SNI
    res1 = classifier.identify(sni="web.telegram.org")
    assert res1["app"] == "Telegram"
    assert res1["category"] == "Messaging"
    assert res1["risk"] == "medium"
    assert res1["confidence_score"] >= 0.90
    assert res1["matched_by"] == "sni"

    # OpenAI / ChatGPT
    res2 = classifier.identify(sni="api.openai.com")
    assert res2["app"] == "OpenAI-ChatGPT"
    assert res2["category"] == "AI / LLM"
    assert res2["confidence_score"] >= 0.90

    # WhatsApp
    res3 = classifier.identify(sni="web.whatsapp.com")
    assert res3["app"] == "WhatsApp"
    assert res3["category"] == "Messaging"


def test_appid_payload_signatures():
    classifier = AppIDClassifier()

    # SSH banner
    res1 = classifier.identify(payload=b"SSH-2.0-OpenSSH_8.9p1 Ubuntu\r\n")
    assert res1["app"] == "SSH"
    assert res1["category"] == "Remote Access"
    assert res1["confidence_score"] >= 0.95

    # SMB protocol header
    res2 = classifier.identify(payload=b"\x00\x00\x00\x45\xffSMB\x72\x00\x00\x00\x00")
    assert res2["app"] == "SMB"
    assert res2["category"] == "File Sharing"

    # Redis ping/pong
    res3 = classifier.identify(payload=b"+PONG\r\n")
    assert res3["app"] == "Redis"
    assert res3["category"] == "Database"


def test_appid_unknown_traffic():
    classifier = AppIDClassifier()

    res = classifier.identify(payload=b"\xaa\xbb\xcc\xdd\xee", proto="tcp", dport=49152)
    assert res["app"] == "Unknown"
    assert res["category"] == "Unknown"
    assert res["risk"] == "unknown"
    assert res["confidence_score"] == 0.0
    assert res["matched_by"] == "none"
