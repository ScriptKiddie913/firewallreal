"""Unit tests for SentinelFW 3.0 Phase 1 (Suricata) and Phase 2 (AppWall/Conntrack)."""
import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from sentinelfw.appwall import ApplicationFirewall, ApplicationInventory, AppPolicyRule
from sentinelfw.conntrack import ConnectionRecord, ConnectionTracker
from sentinelfw.geoip import GeoIPResolver
from sentinelfw.suricata_ingest import SuricataIngest
from sentinelfw.suricata_manager import SuricataManager


class TestGeoIP(unittest.TestCase):
    def test_special_ranges(self):
        resolver = GeoIPResolver()
        self.assertEqual(resolver.resolve("192.168.1.1")["country"], "PRIVATE")
        self.assertEqual(resolver.resolve("10.0.0.5")["country"], "PRIVATE")
        self.assertEqual(resolver.resolve("127.0.0.1")["country"], "LOOPBACK")
        self.assertEqual(resolver.resolve("8.8.8.8")["country"], "US")
        self.assertEqual(resolver.resolve("8.8.8.8")["asn"], 15169)
        self.assertEqual(resolver.resolve("1.1.1.1")["country"], "AU")


class TestSuricataIntegration(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="sfw-suri-test-")
        self.eve_file = Path(self.tmp_dir) / "eve.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_suricata_config_generation(self):
        mgr = SuricataManager({"suricata": {"enabled": True}})
        mgr.config_dir = Path(self.tmp_dir) / "config"
        mgr.rules_dir = mgr.config_dir / "rules"
        mgr.log_dir = Path(self.tmp_dir) / "logs"
        cfg_file = mgr.generate_config()
        self.assertTrue(cfg_file.exists())
        content = cfg_file.read_text()
        self.assertIn("eve-log:", content)
        self.assertIn("suricata.rules", content)

    def test_suricata_ingest_parsing(self):
        alerts = []
        ingest = SuricataIngest(self.eve_file, on_event=lambda ev: alerts.append(ev))

        # Write test EVE JSON lines
        events = [
            {
                "event_type": "alert",
                "src_ip": "198.51.100.22",
                "src_port": 54321,
                "dest_ip": "192.168.1.50",
                "dest_port": 80,
                "proto": "TCP",
                "alert": {"signature": "ET EXPLOIT Log4j JNDI", "severity": 1, "signature_id": 2034324}
            },
            {
                "event_type": "dns",
                "src_ip": "192.168.1.50",
                "dns": {"rrname": "c2.evilcorp.com", "rrtype": "A", "rcode": "NOERROR"}
            },
            {
                "event_type": "http",
                "src_ip": "198.51.100.23",
                "http": {"hostname": "target.local", "url": "/wp-login.php", "http_method": "POST"}
            },
            {
                "event_type": "tls",
                "src_ip": "192.168.1.50",
                "tls": {"sni": "malicious-c2.net", "ja3": {"hash": "51c64c77e60f39ac3e17763edd8203f4"}}
            },
            {
                "event_type": "fileinfo",
                "src_ip": "198.51.100.25",
                "fileinfo": {"filename": "payload.exe", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
            }
        ]

        with open(self.eve_file, "w", encoding="utf-8") as f:
            for e in events:
                f.write(json.dumps(e) + "\n")

        # Process lines directly through parser
        with open(self.eve_file, "r", encoding="utf-8") as f:
            for line in f:
                ingest._process_line(line.strip())

        stats = ingest.stats
        self.assertEqual(stats["alerts"], 1)
        self.assertEqual(stats["dns"], 1)
        self.assertEqual(stats["http"], 1)
        self.assertEqual(stats["tls"], 1)
        self.assertEqual(stats["files"], 1)
        self.assertEqual(len(alerts), 5)


class TestAppWall(unittest.TestCase):
    def test_policy_matching_and_evaluation(self):
        policies = [
            {
                "match": {"exe_path": "C:/Program Files/Firefox/firefox.exe"},
                "allow_outbound": ["tcp/80", "tcp/443", "udp/443"],
                "allow_destinations": ["0.0.0.0/0"],
                "deny_destinations": ["10.0.0.0/8"],
                "action_on_violation": "block+alert",
            },
            {
                "match": {"exe_glob": "*/AppData/*/*.exe"},
                "allow_outbound": [],
                "action_on_violation": "kill+quarantine",
            },
        ]
        wall = ApplicationFirewall({"application_firewall": {"enabled": True, "policies": policies}})

        # 1. Allowed Firefox web browsing
        allowed, reason, action = wall.evaluate_connection(
            pid=123, exe="C:/Program Files/Firefox/firefox.exe",
            direction="outbound", proto="tcp", remote_ip="8.8.8.8", remote_port=443
        )
        self.assertTrue(allowed)

        # 2. Blocked Firefox trying to hit disallowed port
        allowed, reason, action = wall.evaluate_connection(
            pid=123, exe="C:/Program Files/Firefox/firefox.exe",
            direction="outbound", proto="tcp", remote_ip="8.8.8.8", remote_port=22
        )
        self.assertFalse(allowed)
        self.assertEqual(action, "block+alert")

        # 3. Blocked Firefox trying to hit denied LAN CIDR
        allowed, reason, action = wall.evaluate_connection(
            pid=123, exe="C:/Program Files/Firefox/firefox.exe",
            direction="outbound", proto="tcp", remote_ip="10.1.2.3", remote_port=443
        )
        self.assertFalse(allowed)
        self.assertIn("denied CIDR", reason)

        # 4. Glob matching for untrusted executable in AppData
        allowed, reason, action = wall.evaluate_connection(
            pid=456, exe="C:/Users/User/AppData/Local/Temp/miner.exe",
            direction="outbound", proto="tcp", remote_ip="198.51.100.1", remote_port=80
        )
        self.assertFalse(allowed)
        self.assertEqual(action, "kill+quarantine")


class TestConntrack(unittest.TestCase):
    def test_connection_flow_tracking(self):
        tracker = ConnectionTracker({"connection_tracker": {"enabled": True}})
        # Simulate active flow updates
        tracker.update_flow_stats("tcp", "192.168.1.10", 50000, "8.8.8.8", 443, 1024, 2, l7_proto="tls")
        tracker.snapshot()
        active = tracker.get_active()
        self.assertIsInstance(active, list)


if __name__ == "__main__":
    unittest.main()
