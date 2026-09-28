"""Unit tests for SentinelFW 3.0 Phase 3: Attack Detection, Classification & Mapping."""
import unittest
from sentinelfw.anomaly import BaselineEngine, RollingMetric
from sentinelfw.attack_classifier import AttackClassifier, AttackEvent
from sentinelfw.killchain import KillChainTracker
from sentinelfw.mitre_mapper import MITREMapper


class TestMITREMapper(unittest.TestCase):
    def test_direct_and_partial_mapping(self):
        m1 = MITREMapper.map_attack("port_scan_tcp_syn")
        self.assertEqual(m1["tactic"], "TA0043")
        self.assertEqual(m1["technique"], "T1595.001")

        m2 = MITREMapper.map_attack("sql_injection_union")
        self.assertEqual(m2["tactic"], "TA0001")

        m3 = MITREMapper.map_attack("c2_dns_tunnel")
        self.assertEqual(m3["tactic"], "TA0011")

        # Unknown maps gracefully to fallback
        m4 = MITREMapper.map_attack("brand_new_attack_vector")
        self.assertTrue(m4["tactic"].startswith("TA"))


class TestAttackClassifier(unittest.TestCase):
    def setUp(self):
        self.classifier = AttackClassifier()

    def test_classify_suricata_alert(self):
        ev = {
            "src_ip": "45.33.32.156",
            "src_port": 40123,
            "dest_ip": "192.168.1.100",
            "dest_port": 80,
            "proto": "TCP",
            "alert": {
                "signature": "ET EXPLOIT Apache Log4j JNDI",
                "severity": 1,
                "signature_id": 2034324,
            }
        }
        res = self.classifier.classify("suricata", ev)
        self.assertEqual(res.attack_type, "log4shell")
        self.assertEqual(res.severity, "critical")
        self.assertEqual(res.source_ip, "45.33.32.156")
        self.assertEqual(res.mitre_tactic, "TA0001")

    def test_classify_sniffer_event(self):
        ev = {
            "src": "198.51.100.99",
            "sport": 1234,
            "dst": "192.168.1.100",
            "dport": 443,
            "proto": "tcp",
            "name": "sql_injection_union",
            "severity": "high",
        }
        res = self.classifier.classify("sniffer", ev)
        self.assertEqual(res.attack_type, "sql_injection_union")
        self.assertEqual(res.kill_chain_phase, "initial_access")


class TestKillChainTracker(unittest.TestCase):
    def test_killchain_campaign_progression(self):
        tracker = KillChainTracker(window_seconds=600)
        ip = "203.0.113.50"

        # Stage 1: Port Scan (Reconnaissance)
        ev1 = AttackEvent(
            timestamp=100.0,
            attack_id="a1",
            source_ip=ip,
            source_port=1234,
            dest_ip="192.168.1.5",
            dest_port=80,
            protocol="tcp",
            attack_type="port_scan_tcp_syn",
            attack_subtype="recon",
            mitre_tactic="TA0043",
            mitre_technique="T1595.001",
            mitre_name="Port Scan",
            kill_chain_phase="reconnaissance",
            severity="medium",
            confidence=0.9,
        )
        c1 = tracker.track(ev1)
        self.assertEqual(c1.escalation_level, "monitor")
        self.assertEqual(c1.highest_stage_idx, 0)

        # Stage 2: Web Exploit (Exploitation)
        ev2 = AttackEvent(
            timestamp=105.0,
            attack_id="a2",
            source_ip=ip,
            source_port=1235,
            dest_ip="192.168.1.5",
            dest_port=80,
            protocol="tcp",
            attack_type="log4shell",
            attack_subtype="exploit",
            mitre_tactic="TA0001",
            mitre_technique="T1190",
            mitre_name="Log4Shell",
            kill_chain_phase="exploitation",
            severity="critical",
            confidence=0.95,
        )
        c2 = tracker.track(ev2)
        self.assertEqual(c2.escalation_level, "ban")
        self.assertEqual(c2.highest_stage_idx, 3)

        # Stage 3: C2 Callback (Command & Control)
        ev3 = AttackEvent(
            timestamp=110.0,
            attack_id="a3",
            source_ip=ip,
            source_port=4444,
            dest_ip="192.168.1.5",
            dest_port=53,
            protocol="udp",
            attack_type="c2_dns_tunnel",
            attack_subtype="c2",
            mitre_tactic="TA0011",
            mitre_technique="T1071.004",
            mitre_name="DNS C2",
            kill_chain_phase="command_and_control",
            severity="critical",
            confidence=0.99,
        )
        c3 = tracker.track(ev3)
        self.assertEqual(c3.escalation_level, "critical_lockdown")


class TestBaselineEngine(unittest.TestCase):
    def test_z_score_spike_detection(self):
        metric = RollingMetric("test_metric", window_samples=100)
        # Train baseline around mean ~10.0 with typical natural variance
        for val in [8.0, 10.0, 12.0, 9.0, 11.0, 10.0] * 5:
            metric.add(val)

        # Normal slight variance (value 11.0 is within 1 std dev)
        z_norm = metric.z_score(11.0)
        self.assertLess(z_norm, 3.0)

        # Massive attack spike: 1000.0
        z_spike = metric.z_score(1000.0)
        self.assertGreater(z_spike, 5.0)


if __name__ == "__main__":
    unittest.main()
