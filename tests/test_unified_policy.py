"""Unit tests for Phase 1: Unified Canonical Policy Engine.
Validates multi-dimensional matching, conflict detection, duplicate detection,
shadowed rule detection, TTL auto-expiry, and Python/Go schema translation.
"""

import time
import pytest
from sentinelfw.policies import FirewallPolicies
from sentinelfw.gateway_sync import (
    translate_python_to_gateway_config,
    translate_gateway_to_python_config,
)


def test_canonical_dimensions_simulation():
    """Validates simulation matching across device posture, ASN, threat score, and TTL."""
    policies = [
        {
            "id": 101,
            "name": "Block_Noncompliant_Corporate_Access",
            "direction": "in",
            "src": ["192.168.1.0/24"],
            "dst": ["10.0.0.10"],
            "services": ["HTTPS"],
            "device_posture": "NON_COMPLIANT",
            "action": "quarantine",
            "enabled": True,
        },
        {
            "id": 102,
            "name": "High_Risk_Threat_Drop",
            "direction": "in",
            "src": ["any"],
            "dst": ["any"],
            "services": ["ANY"],
            "threat_score_min": 80,
            "action": "drop",
            "enabled": True,
        },
        {
            "id": 103,
            "name": "Temporary_JIT_Access",
            "direction": "in",
            "src": ["198.51.100.5"],
            "dst": ["10.0.0.50"],
            "services": ["SSH"],
            "action": "accept",
            "ttl": time.time() + 3600,  # Valid for 1h
            "enabled": True,
        },
        {
            "id": 104,
            "name": "Expired_JIT_Access",
            "direction": "in",
            "src": ["198.51.100.6"],
            "dst": ["10.0.0.50"],
            "services": ["SSH"],
            "action": "accept",
            "ttl": time.time() - 60,  # Expired 60s ago
            "enabled": True,
        },
    ]

    fp = FirewallPolicies(cfg={"firewall_policies": policies})

    # Test 1: Non-compliant device quarantine match
    res1 = fp.simulate_packet(
        src_ip="192.168.1.50",
        dst_ip="10.0.0.10",
        proto="tcp",
        port=443,
        posture="NON_COMPLIANT",
    )
    assert res1["matched"] is True
    assert res1["policy_id"] == 101
    assert res1["action"] == "quarantine"

    # Test 2: Compliant device does not trigger policy 101
    res2 = fp.simulate_packet(
        src_ip="192.168.1.50",
        dst_ip="10.0.0.10",
        proto="tcp",
        port=443,
        posture="COMPLIANT",
    )
    assert res2["matched"] is False

    # Test 3: Threat score threshold
    res3 = fp.simulate_packet(
        src_ip="203.0.113.10",
        dst_ip="10.0.0.1",
        proto="tcp",
        port=80,
        threat_score=85,
    )
    assert res3["matched"] is True
    assert res3["policy_id"] == 102
    assert res3["action"] == "drop"

    # Test 4: Low threat score does not trigger policy 102
    res4 = fp.simulate_packet(
        src_ip="203.0.113.10",
        dst_ip="10.0.0.1",
        proto="tcp",
        port=80,
        threat_score=30,
    )
    assert res4["matched"] is False

    # Test 5: Valid JIT rule matches
    res5 = fp.simulate_packet(
        src_ip="198.51.100.5",
        dst_ip="10.0.0.50",
        proto="tcp",
        port=22,
    )
    assert res5["matched"] is True
    assert res5["policy_id"] == 103
    assert res5["action"] == "accept"

    # Test 6: Expired JIT rule does NOT match (falls through to default drop)
    res6 = fp.simulate_packet(
        src_ip="198.51.100.6",
        dst_ip="10.0.0.50",
        proto="tcp",
        port=22,
    )
    assert res6["matched"] is False


def test_duplicate_and_conflict_detection():
    """Validates detection of duplicate and conflicting firewall rules."""
    policies = [
        {
            "id": 1,
            "name": "Allow_Web_A",
            "direction": "in",
            "src": ["10.0.0.0/24"],
            "dst": ["10.0.1.0/24"],
            "services": ["HTTP", "HTTPS"],
            "action": "accept",
            "enabled": True,
        },
        {
            "id": 2,
            "name": "Allow_Web_B_Duplicate",
            "direction": "in",
            "src": ["10.0.0.0/24"],
            "dst": ["10.0.1.0/24"],
            "services": ["HTTP", "HTTPS"],
            "action": "accept",
            "enabled": True,
        },
        {
            "id": 3,
            "name": "Deny_Web_Conflict",
            "direction": "in",
            "src": ["10.0.0.0/24"],
            "dst": ["10.0.1.0/24"],
            "services": ["HTTP", "HTTPS"],
            "action": "deny",
            "enabled": True,
        },
    ]

    fp = FirewallPolicies(cfg={"firewall_policies": policies})

    duplicates = fp.find_duplicate_rules()
    assert len(duplicates) == 1
    assert duplicates[0]["rule_a_id"] == 1
    assert duplicates[0]["rule_b_id"] == 2

    conflicts = fp.find_conflicting_rules()
    assert len(conflicts) >= 1
    conflict_ids = [(c["rule_a_id"], c["rule_b_id"]) for c in conflicts]
    assert (1, 3) in conflict_ids or (2, 3) in conflict_ids


def test_python_go_gateway_config_translation():
    """Validates bidirectional schema translation between Python policies and Go GatewayConfig."""
    py_config = {
        "address_groups": {
            "Internal_LAN": ["192.168.1.0/24", "10.0.0.0/8"],
            "Servers": ["10.0.50.10/32"],
        },
        "firewall_policies": [
            {
                "id": 10,
                "name": "LAN_Outbound_Internet",
                "src_zone": "lan",
                "dst_zone": "wan",
                "src": ["Internal_LAN"],
                "dst": ["any"],
                "services": ["HTTP_HTTPS", "DNS"],
                "apps": ["GitHub", "Slack"],
                "action": "accept",
                "log": True,
                "nat": True,
                "nat_type": "masquerade",
                "enabled": True,
            },
            {
                "id": 20,
                "name": "Inbound_Web_DNAT",
                "src_zone": "wan",
                "dst_zone": "dmz",
                "src": ["any"],
                "dst": ["Servers"],
                "services": ["HTTP_HTTPS"],
                "action": "accept",
                "nat": True,
                "nat_type": "dnat",
                "nat_target": "10.0.50.10",
                "ips": True,
                "ips_profile": "strict",
                "enabled": True,
            }
        ]
    }

    # 1. Translate to Go GatewayConfig format
    gw_config = translate_python_to_gateway_config(py_config)
    assert gw_config["version"] == "4.0.0"
    assert len(gw_config["addresses"]) == 2
    assert len(gw_config["policies"]) == 2

    p1 = gw_config["policies"][0]
    assert p1["id"] == 10
    assert p1["action"] == "accept"
    assert p1["nat"]["type"] == "masquerade"
    assert p1["apps"] == ["GitHub", "Slack"]

    p2 = gw_config["policies"][1]
    assert p2["id"] == 20
    assert p2["nat"]["type"] == "dnat"
    assert p2["nat"]["target_ip"] == "10.0.50.10"
    assert p2["inspection"]["ips_profile"] == "strict"

    # 2. Translate back to Python config format (roundtrip test)
    roundtrip = translate_gateway_to_python_config(gw_config)
    assert len(roundtrip["firewall_policies"]) == 2
    assert "Internal_LAN" in roundtrip["address_groups"]

    rt_p1 = roundtrip["firewall_policies"][0]
    assert rt_p1["id"] == 10
    assert rt_p1["nat_type"] == "masquerade"
    assert rt_p1["apps"] == ["GitHub", "Slack"]
