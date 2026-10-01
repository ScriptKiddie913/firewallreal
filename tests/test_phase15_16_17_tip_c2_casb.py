"""Unit and integration tests for:
- Phase 15: Threat Intelligence Platform (TIP) & Ingestion Subsystem
- Phase 16: Advanced C2 & Botnet Detection
- Phase 17: Cloud Access Security Broker (CASB) & Shadow IT
"""
import time
import pytest
from sentinelfw.feeds import ThreatIntelFeeds
from sentinelfw.c2 import StatisticalBeaconDetector, C2RiskScorer
from sentinelfw.casb import TenantRestrictionEngine, ShadowITEngine


def test_tip_feed_ingestion_and_poisoning_protection():
    """Verify feed ingestion, parsing, and anti-poisoning guards against private/loopback IPs."""
    tip = ThreatIntelFeeds()

    # Feed with a mix of public malicious IPs and poisoned internal addresses
    raw_feed = [
        "198.51.100.55 ; Malicious Botnet C2",
        "203.0.113.128/25",
        "10.0.0.1 ; Poisoned internal RFC1918 gateway",
        "127.0.0.1 ; Poisoned loopback",
        "192.168.1.100 ; Poisoned internal workstation",
        "224.0.0.5 ; Poisoned multicast",
    ]

    added = tip.add_feed_entries("Spamhaus-Test", raw_feed, confidence=95, tags=["botnet", "c2"])
    assert added == 2  # Only the two public routable entries accepted

    # Public malicious IP matches
    matched, details = tip.check_ip("198.51.100.55")
    assert matched is True
    assert details["source"] == "Spamhaus-Test"
    assert details["confidence"] == 95

    # Poisoned internal IP does NOT match
    matched_priv, _ = tip.check_ip("10.0.0.1")
    assert matched_priv is False

    matched_loop, _ = tip.check_ip("127.0.0.1")
    assert matched_loop is False


def test_tip_stix2_and_misp_ingestion():
    """Verify STIX 2.1 bundle and MISP JSON parsing across IP, domain, and hash indicators."""
    tip = ThreatIntelFeeds()

    # 1. STIX 2.1 Bundle
    stix_data = {
        "type": "bundle",
        "objects": [
            {
                "type": "indicator",
                "pattern": "[ipv4-addr:value = '198.51.100.99'] AND [domain-name:value = 'evil-c2-beacon.org']",
                "confidence": 90,
            },
            {
                "type": "indicator",
                "pattern": "[file:hashes.'SHA-256' = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f']",
                "confidence": 95,
            }
        ]
    }
    stix_count = tip.ingest_stix2("ThreatConnect-STIX", stix_data)
    assert stix_count == 3

    # Check parsed domain
    d_matched, d_info = tip.check_domain("evil-c2-beacon.org")
    assert d_matched is True
    assert d_info["source"] == "ThreatConnect-STIX"

    # Check parsed hash
    h_matched, h_info = tip.check_hash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
    assert h_matched is True

    # 2. MISP Event
    misp_data = {
        "Event": {
            "Attribute": [
                {"type": "domain", "value": "apt29-exfil.biz"},
                {"type": "ip-dst", "value": "198.51.100.88"},
            ]
        }
    }
    misp_count = tip.ingest_misp("MISP-Circle", misp_data)
    assert misp_count == 2
    d_misp, _ = tip.check_domain("apt29-exfil.biz")
    assert d_misp is True


def test_statistical_beaconing_detection():
    """Verify metronomic beaconing calculation and random traffic distinction."""
    detector = StatisticalBeaconDetector(min_samples=5, max_cv=0.20)

    # 1. Metronomic beaconing: exactly every 10 seconds (+/- 0.2s jitter)
    src = "192.168.1.10"
    dst = "c2.attacker.com"
    base_t = 1000.0
    for i in range(8):
        jitter = 0.1 if (i % 2 == 0) else -0.1
        stats = detector.record_connection(src, dst, timestamp=base_t + (i * 10.0) + jitter)

    assert stats["is_beacon"] is True
    assert stats["cv"] < 0.10
    assert stats["beacon_score"] >= 80

    # 2. Sporadic human traffic: erratic intervals (1s, 45s, 3s, 120s, 15s)
    src_h = "192.168.1.20"
    dst_h = "news.example.com"
    erratic_timestamps = [1000.0, 1001.0, 1046.0, 1049.0, 1169.0, 1184.0]
    for t in erratic_timestamps:
        h_stats = detector.record_connection(src_h, dst_h, timestamp=t)

    assert h_stats["is_beacon"] is False
    assert h_stats["cv"] > 0.40


def test_c2_risk_scorer_and_verdicts():
    """Verify combined C2 risk calculation across beaconing, threat intel, and DNS signals."""
    detector = StatisticalBeaconDetector(min_samples=5, max_cv=0.20)
    scorer = C2RiskScorer(beacon_detector=detector)

    src = "10.10.10.5"
    dst = "stealth-c2.net"
    # Prime metronomic beaconing
    base_t = 2000.0
    for i in range(6):
        detector.record_connection(src, dst, timestamp=base_t + (i * 5.0))

    # Evaluate combined threat (beaconing + reputation hit)
    res = scorer.evaluate_c2(
        src_ip=src,
        dst_host=dst,
        reputation_hit=True,
        dns_tunnel_or_dga=True,
    )
    assert res["c2_score"] >= 80
    assert res["action"] == "QUARANTINE"
    assert res["severity"] == "CRITICAL"
    assert len(res["signals"]) >= 3


def test_casb_tenant_restrictions_and_shadow_it():
    """Verify tenant restriction headers and Shadow IT bandwidth accounting."""
    # 1. Tenant Restriction Header Injection
    tenant_engine = TenantRestrictionEngine(
        m365_tenants=["contoso.onmicrosoft.com"],
        m365_context_id="9b0a-context-guid",
        google_domains=["corp.contoso.com"],
    )

    m365_headers = tenant_engine.get_headers_for_host("login.microsoftonline.com")
    assert m365_headers.get("Restrict-Access-To-Tenants") == "contoso.onmicrosoft.com"
    assert m365_headers.get("Restrict-Access-Context") == "9b0a-context-guid"

    google_headers = tenant_engine.get_headers_for_host("accounts.google.com")
    assert google_headers.get("X-GoogApps-Allowed-Domains") == "corp.contoso.com"

    # Non-tenant host has no injected headers
    random_headers = tenant_engine.get_headers_for_host("github.com")
    assert len(random_headers) == 0

    # 2. Shadow IT Discovery & Accounting
    shadow_it = ShadowITEngine()

    # Sanctioned app
    t1 = shadow_it.record_traffic("alice@corp.com", "sharepoint.com", upload_bytes=5000, download_bytes=10000)
    assert t1["sanctioned"] is True
    assert t1["app_name"] == "Microsoft 365"

    # Unsanctioned app (WeTransfer)
    t2 = shadow_it.record_traffic("alice@corp.com", "wetransfer.com", upload_bytes=50000000, download_bytes=0)
    assert t2["sanctioned"] is False
    assert t2["app_name"] == "WeTransfer"

    # Unsanctioned summary
    summary = shadow_it.get_unsanctioned_summary()
    assert len(summary) == 1
    assert summary[0]["app_name"] == "WeTransfer"
    assert summary[0]["upload_bytes"] == 50000000
