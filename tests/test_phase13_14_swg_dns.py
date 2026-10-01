"""Unit and integration tests for Phase 13: Secure Web Gateway (SWG) & URL Filtering
and Phase 14: Advanced DNS Security & Sinkholing.
"""
import time
import pytest
from sentinelfw.swg import (
    WebCategory,
    URLCategorizer,
    DomainReputationEngine,
    SWGPolicyEnforcer,
)
from sentinelfw.protocols.dns import (
    DNSInspector,
    DNSSinkholeManager,
    DoHDoTDetector,
)


def test_url_categorization():
    """Verify that domain names are classified into security and business categories."""
    categorizer = URLCategorizer()

    # Built-in category matches
    cat_gambling, _ = categorizer.categorize_domain("bet365.com")
    assert cat_gambling == WebCategory.GAMBLING

    cat_social, _ = categorizer.categorize_domain("m.facebook.com")
    assert cat_social == WebCategory.SOCIAL_MEDIA

    cat_dev, _ = categorizer.categorize_domain("raw.github.com")
    assert cat_dev == WebCategory.DEVELOPER_TOOLS

    cat_malware, _ = categorizer.categorize_domain("drop.malicious-c2.net")
    assert cat_malware == WebCategory.MALWARE

    # Unknown domain falls back to Unknown
    cat_unknown, _ = categorizer.categorize_domain("random-obscure-site-1234.org")
    assert cat_unknown == WebCategory.UNKNOWN


def test_domain_reputation_and_typosquatting():
    """Verify detection of suspicious TLDs, typosquatting imitation, and NRDs."""
    # 1. Suspicious TLD detection
    is_bad_tld, reason_tld = DomainReputationEngine.check_suspicious_tld("cheap-phish.xyz")
    assert is_bad_tld is True
    assert ".xyz" in reason_tld

    is_good_tld, _ = DomainReputationEngine.check_suspicious_tld("company.com")
    assert is_good_tld is False

    # 2. Typosquatting detection
    is_typo_paypal, reason_paypal = DomainReputationEngine.check_typosquatting("paypa1.com")
    assert is_typo_paypal is True
    assert "paypal" in reason_paypal

    is_typo_google, reason_google = DomainReputationEngine.check_typosquatting("go0gle.com")
    assert is_typo_google is True
    assert "google" in reason_google

    # Authentic brand domain is not flagged as a typosquat
    is_real_google, _ = DomainReputationEngine.check_typosquatting("google.com")
    assert is_real_google is False

    # 3. Newly registered domain (NRD) check
    now = time.time()
    recent_reg = now - (86400 * 5)  # 5 days old
    is_nrd, reason_nrd = DomainReputationEngine.check_newly_registered("fresh-scam.net", recent_reg, nrd_threshold_days=30)
    assert is_nrd is True
    assert "Newly registered" in reason_nrd

    old_reg = now - (86400 * 500)  # 500 days old
    is_old, _ = DomainReputationEngine.check_newly_registered("established.com", old_reg, nrd_threshold_days=30)
    assert is_old is False


def test_swg_policy_enforcement():
    """Verify SWG request evaluation across blocked categories and reputation filters."""
    enforcer = SWGPolicyEnforcer(
        blocked_categories=[WebCategory.GAMBLING, WebCategory.ADULT, WebCategory.MALWARE],
        block_suspicious_tlds=True,
        block_typosquatting=True,
    )

    # 1. Blocked category (Gambling)
    res_gamble = enforcer.evaluate_request("pokerstars.com")
    assert res_gamble["action"] == "BLOCK"
    assert "Gambling" in res_gamble["reason"]

    # 2. Blocked typosquatting (paypa1.com)
    res_typo = enforcer.evaluate_request("paypa1.com")
    assert res_typo["action"] == "BLOCK"
    assert "typosquatting" in res_typo["reason"].lower()

    # 3. Blocked suspicious TLD (.top)
    res_tld = enforcer.evaluate_request("malware-beacon.top")
    assert res_tld["action"] == "BLOCK"
    assert "top-level domain" in res_tld["reason"].lower()

    # 4. Allowed business domain
    res_dev = enforcer.evaluate_request("github.com")
    assert res_dev["action"] == "ALLOW"
    assert res_dev["category"] == WebCategory.DEVELOPER_TOOLS


def test_dns_tunneling_and_dga_detection():
    """Verify behavioral DNS query inspection for tunnels and DGA generation."""
    # 1. Base32 / Hex tunneling payload
    tunnel_qname = "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890.exfil.tunnel.com"
    attack, details = DNSInspector.inspect_query(tunnel_qname)
    assert attack == "c2_dns_tunnel"
    assert details["label_len"] > 30

    # 2. High-entropy DGA domain (e.g. xzkvnmqwrptz.biz)
    dga_qname = "xzkvnmqwrptz.biz"
    attack_dga, details_dga = DNSInspector.inspect_query(dga_qname)
    assert attack_dga == "c2_domain_gen"
    assert details_dga["entropy"] > 3.0

    # 3. Normal business query
    attack_normal, _ = DNSInspector.inspect_query("api.slack.com")
    assert attack_normal is None


def test_dns_sinkhole_and_rpz_routing():
    """Verify Response Policy Zones and malicious query routing to sinkhole."""
    sinkhole = DNSSinkholeManager(sinkhole_ip="10.254.254.254")

    # Add custom RPZ rule
    sinkhole.add_rpz_rule("c2-malware-active.com", action="sinkhole")
    sinkhole.add_rpz_rule("phishing-drop.net", action="nxdomain")

    # 1. SINKHOLE action
    res_sink = sinkhole.evaluate_and_route("c2-malware-active.com", client_ip="192.168.1.50")
    assert res_sink["action"] == "SINKHOLE"
    assert res_sink["sinkhole_ip"] == "10.254.254.254"
    assert res_sink["event"]["client_ip"] == "192.168.1.50"

    # Query log contains the sinkhole event
    events = sinkhole.get_sinkhole_events()
    assert len(events) >= 1
    assert events[-1]["qname"] == "c2-malware-active.com"

    # 2. NXDOMAIN action
    res_nx = sinkhole.evaluate_and_route("phishing-drop.net")
    assert res_nx["action"] == "NXDOMAIN"

    # 3. Clean query passes forward
    res_clean = sinkhole.evaluate_and_route("microsoft.com")
    assert res_clean["action"] == "FORWARD"


def test_doh_and_dot_bypass_detection():
    """Verify identification of DNS over HTTPS (DoH) and DNS over TLS (DoT)."""
    # 1. DoT packet on standard port 853
    assert DoHDoTDetector.is_dot_packet(853, proto="tcp") is True
    assert DoHDoTDetector.is_dot_packet(53, proto="udp") is False

    # 2. DoH request to public provider
    is_doh_cf, reason_cf = DoHDoTDetector.is_doh_request("cloudflare-dns.com", "/dns-query")
    assert is_doh_cf is True
    assert "cloudflare-dns.com" in reason_cf

    # 3. DoH standard path on generic host
    is_doh_path, _ = DoHDoTDetector.is_doh_request("custom-dns.io", "/dns-query?name=example.com")
    assert is_doh_path is True

    # 4. Standard HTTP request
    is_standard, _ = DoHDoTDetector.is_doh_request("company.com", "/index.html")
    assert is_standard is False
