"""Unit tests for Phase 2: Stateful Dataplane Conntrack & NAT Engine.
Tests TCP state machine, flag validation, UDP/ICMP tracking, NAT/PAT translation,
connection limits, SYN flood protection, and metrics reporting.
"""

import time
import pytest
from sentinelfw.stateful_engine import (
    StatefulFirewallEngine,
    STATE_NEW,
    STATE_SYN_SENT,
    STATE_SYN_RECV,
    STATE_ESTABLISHED,
    STATE_FIN_WAIT,
    STATE_CLOSE_WAIT,
    STATE_TIME_WAIT,
)


def test_tcp_three_way_handshake_and_teardown():
    """Validates complete TCP handshake and state transitions."""
    engine = StatefulFirewallEngine()

    # 1. Client sends SYN
    verdict, reason, session = engine.process_packet(
        src_ip="192.168.1.100", dst_ip="10.0.0.5", proto="tcp",
        src_port=50000, dst_port=443,
        tcp_flags={"syn": True}, seq=1000
    )
    assert verdict == "ALLOW"
    assert session is not None
    assert session.state == STATE_SYN_SENT
    assert session.packets_orig == 1

    # 2. Server replies SYN+ACK
    verdict2, reason2, session2 = engine.process_packet(
        src_ip="10.0.0.5", dst_ip="192.168.1.100", proto="tcp",
        src_port=443, dst_port=50000,
        tcp_flags={"syn": True, "ack": True}, seq=5000, ack=1001
    )
    assert verdict2 == "ALLOW"
    assert session2.state == STATE_SYN_RECV
    assert session2.packets_reply == 1

    # 3. Client finishes handshake with ACK -> ESTABLISHED
    verdict3, reason3, session3 = engine.process_packet(
        src_ip="192.168.1.100", dst_ip="10.0.0.5", proto="tcp",
        src_port=50000, dst_port=443,
        tcp_flags={"ack": True}, seq=1001, ack=5001
    )
    assert verdict3 == "ALLOW"
    assert session3.state == STATE_ESTABLISHED

    # 4. Client sends FIN
    verdict4, reason4, session4 = engine.process_packet(
        src_ip="192.168.1.100", dst_ip="10.0.0.5", proto="tcp",
        src_port=50000, dst_port=443,
        tcp_flags={"fin": True, "ack": True}
    )
    assert verdict4 == "ALLOW"
    assert session4.state == STATE_FIN_WAIT


def test_tcp_flag_anomalies_and_out_of_state_drops():
    """Validates that malformed TCP flags and out-of-state packets are dropped."""
    engine = StatefulFirewallEngine()

    # 1. NULL Scan (No flags set) -> DROP
    verdict1, reason1, _ = engine.process_packet(
        src_ip="198.51.100.1", dst_ip="10.0.0.1", proto="tcp",
        src_port=45000, dst_port=80, tcp_flags={}
    )
    assert verdict1 == "DROP"
    assert "NULL scan" in reason1

    # 2. SYN+FIN anomaly -> DROP
    verdict2, reason2, _ = engine.process_packet(
        src_ip="198.51.100.1", dst_ip="10.0.0.1", proto="tcp",
        src_port=45000, dst_port=80, tcp_flags={"syn": True, "fin": True}
    )
    assert verdict2 == "DROP"
    assert "SYN+FIN" in reason2

    # 3. XMAS scan (FIN+PSH+URG) -> DROP
    verdict3, reason3, _ = engine.process_packet(
        src_ip="198.51.100.1", dst_ip="10.0.0.1", proto="tcp",
        src_port=45000, dst_port=80, tcp_flags={"fin": True, "psh": True, "urg": True}
    )
    assert verdict3 == "DROP"

    # 4. Bare ACK packet with no existing session -> Out of state DROP
    verdict4, reason4, _ = engine.process_packet(
        src_ip="198.51.100.1", dst_ip="10.0.0.1", proto="tcp",
        src_port=45000, dst_port=80, tcp_flags={"ack": True}
    )
    assert verdict4 == "DROP"
    assert "out of state" in reason4

    assert engine.get_invalid_packets_count() >= 3
    assert engine.get_drops_count() >= 4


def test_udp_and_icmp_state_tracking():
    """Validates UDP and ICMP pseudo-state flows."""
    engine = StatefulFirewallEngine()

    # UDP Outbound Query
    v1, _, s1 = engine.process_packet(
        src_ip="192.168.1.50", dst_ip="8.8.8.8", proto="udp",
        src_port=53530, dst_port=53, payload_len=45
    )
    assert v1 == "ALLOW"
    assert s1.state == STATE_NEW

    # UDP Inbound Reply -> ESTABLISHED
    v2, _, s2 = engine.process_packet(
        src_ip="8.8.8.8", dst_ip="192.168.1.50", proto="udp",
        src_port=53, dst_port=53530, payload_len=120
    )
    assert v2 == "ALLOW"
    assert s2.state == STATE_ESTABLISHED
    assert s2.bytes_orig == 45
    assert s2.bytes_reply == 120

    # ICMP Echo Request / Reply
    v3, _, s3 = engine.process_packet(
        src_ip="192.168.1.50", dst_ip="1.1.1.1", proto="icmp"
    )
    assert v3 == "ALLOW"
    assert s3.state == STATE_NEW

    v4, _, s4 = engine.process_packet(
        src_ip="1.1.1.1", dst_ip="192.168.1.50", proto="icmp"
    )
    assert v4 == "ALLOW"
    assert s4.state == STATE_ESTABLISHED


def test_stateful_pat_translation():
    """Validates Port Address Translation (PAT) and reverse reply matching."""
    engine = StatefulFirewallEngine()

    # Outbound TCP SYN
    v1, _, session = engine.process_packet(
        src_ip="192.168.1.20", dst_ip="93.184.216.34", proto="tcp",
        src_port=51532, dst_port=80, tcp_flags={"syn": True}
    )
    assert v1 == "ALLOW"

    # Apply PAT through gateway public IP
    gw_ip, pat_port = engine.apply_pat(session, gateway_ip="203.0.113.1")
    assert gw_ip == "203.0.113.1"
    assert pat_port >= 20000

    # Remote server replies to translated tuple (203.0.113.1:pat_port)
    v2, _, reply_session = engine.process_packet(
        src_ip="93.184.216.34", dst_ip="203.0.113.1", proto="tcp",
        src_port=80, dst_port=pat_port, tcp_flags={"syn": True, "ack": True}
    )
    assert v2 == "ALLOW"
    # Resolved back to the original internal session!
    assert reply_session.id == session.id
    assert reply_session.src_ip == "192.168.1.20"
    assert reply_session.src_port == 51532


def test_connection_limits_and_diagnostics():
    """Validates per-source limits and metrics exposure."""
    engine = StatefulFirewallEngine(max_connections=100, max_per_source=2)

    # First connection from source
    v1, _, _ = engine.process_packet(
        src_ip="10.0.0.1", dst_ip="10.0.0.2", proto="tcp",
        src_port=1000, dst_port=80, tcp_flags={"syn": True}
    )
    assert v1 == "ALLOW"

    # Second connection from source
    v2, _, _ = engine.process_packet(
        src_ip="10.0.0.1", dst_ip="10.0.0.2", proto="tcp",
        src_port=1001, dst_port=80, tcp_flags={"syn": True}
    )
    assert v2 == "ALLOW"

    # Third connection exceeds max_per_source=2 -> DROP
    v3, reason3, _ = engine.process_packet(
        src_ip="10.0.0.1", dst_ip="10.0.0.2", proto="tcp",
        src_port=1002, dst_port=80, tcp_flags={"syn": True}
    )
    assert v3 == "DROP"
    assert "Per-source connection limit" in reason3

    # Diagnostics inspection
    assert engine.get_active_connections_count() == 2
    talkers = engine.get_top_talkers(limit=5)
    assert len(talkers) >= 1
    assert talkers[0][0] == "10.0.0.1"

    dests = engine.get_top_destinations(limit=5)
    assert len(dests) >= 1
    assert dests[0][0] == "10.0.0.2"
