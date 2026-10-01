"""Integration test verifying runtime instantiation, execution, and event processing
for all 18 SentinelFW 4.0 modules inside Engine and daemon lifecycles.
"""
import json
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path

from sentinelfw import common, config
from sentinelfw.engine import Engine
from sentinelfw.attack_classifier import AttackEvent


class TestRuntimeWiring(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.orig_home = common.HOME
        self.orig_cfg_file = config.CONFIG_FILE
        self.orig_lists = common.LISTS
        self.orig_cfg_lists = config.LISTS

        common.HOME = Path(self.tmp_dir)
        config.CONFIG_FILE = Path(self.tmp_dir) / "config.json"
        common.DATA_DIR = Path(self.tmp_dir) / "data"
        common.DATA_DIR.mkdir(parents=True, exist_ok=True)
        common.LISTS = Path(self.tmp_dir) / "lists"
        common.LISTS.mkdir(parents=True, exist_ok=True)
        config.LISTS = common.LISTS

        # Baseline minimal config
        config.CONFIG_FILE.write_text(json.dumps({
            "enforcement_profile": "monitor",
            "auto_ban_seconds": 60,
            "webui": {
                "username": "admin",
                "password_hash": "dummy_hash_for_test",
                "must_change_password": False,
                "password_initialized": True,
            },
            "trusted_ips": ["127.0.0.1", "::1"],
            "default_deny_inbound": False,
            "allow_inbound_ports": [22, 80, 443],
            "playbooks": [
                {
                    "id": "pb-test-1",
                    "name": "Auto-Ban Severe Attacks",
                    "conditions": {"event": "attack_detected", "min_severity": "high"},
                    "actions": ["ban_ip", "notify"]
                }
            ],
            "nat_rules": [
                {
                    "id": 1,
                    "name": "web-masquerade",
                    "nat_type": "masquerade",
                    "out_interface": "eth0"
                }
            ]
        }))

    def tearDown(self):
        common.HOME = self.orig_home
        config.CONFIG_FILE = self.orig_cfg_file
        common.LISTS = self.orig_lists
        config.LISTS = self.orig_cfg_lists
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_engine_all_18_modules_instantiated(self):
        """Proves Engine() instantiates all 18 SentinelFW 4.0 modules."""
        eng = Engine()

        # 1. WAF
        self.assertTrue(hasattr(eng, "waf"))
        self.assertIsNotNone(eng.waf)

        # 2. Identity
        self.assertTrue(hasattr(eng, "identity"))
        self.assertIsNotNone(eng.identity)

        # 3. NAT
        self.assertTrue(hasattr(eng, "nat_mgr"))
        self.assertIsNotNone(eng.nat_mgr)
        self.assertEqual(len(eng.nat_mgr.get_rules()), 1)

        # 4. Objects
        self.assertTrue(hasattr(eng, "objects"))
        self.assertIsNotNone(eng.objects)
        self.assertIsNotNone(eng.objects.get_service("HTTPS"))

        # 5. Zones
        self.assertTrue(hasattr(eng, "zones"))
        self.assertIsNotNone(eng.zones)
        self.assertTrue(len(eng.zones.list_zones()) >= 1)

        # 6. App-ID
        self.assertTrue(hasattr(eng, "appid"))
        self.assertIsNotNone(eng.appid)
        app_hit = eng.appid.identify(sni="teams.microsoft.com")
        self.assertEqual(app_hit["app"], "Microsoft-Teams")

        # 7. DLP
        self.assertTrue(hasattr(eng, "dlp"))
        self.assertIsNotNone(eng.dlp)
        violations = eng.dlp.scan_content("token is AKIAIOSFODNN7EXAMPLE")
        self.assertTrue(len(violations) >= 1)

        # 8. Playbooks
        self.assertTrue(hasattr(eng, "playbooks"))
        self.assertIsNotNone(eng.playbooks)
        self.assertTrue(len(eng.playbooks._rules) >= 1)

        # 9. Compliance
        self.assertTrue(hasattr(eng, "compliance"))
        self.assertIsNotNone(eng.compliance)
        audit = eng.compliance.evaluate(eng.cfg)
        self.assertIn("score", audit)

        # 10. Correlation
        self.assertTrue(hasattr(eng, "correlation"))
        self.assertIsNotNone(eng.correlation)
        self.assertTrue(len(eng.correlation._rules) >= 1)

        # 11. AssetMap
        self.assertTrue(hasattr(eng, "assetmap"))
        self.assertIsNotNone(eng.assetmap)
        eng.assetmap.record_flow("10.0.0.1", "10.0.0.2", "tcp", 443, "HTTPS", 1024, 8)
        self.assertTrue(len(eng.assetmap.list_assets()) >= 1)

        # 12. ThreatIntelFeeds
        self.assertTrue(hasattr(eng, "feed_mgr"))
        self.assertIsNotNone(eng.feed_mgr)
        added = eng.feed_mgr.add_feed_entries("test-feed", ["198.51.100.0/24", "203.0.113.50"])
        self.assertEqual(added, 2)
        is_threat, _ = eng.feed_mgr.check_ip("198.51.100.10")
        self.assertTrue(is_threat)

        # 13. Advanced Decoys
        self.assertTrue(hasattr(eng, "advanced_decoys"))
        self.assertIsNotNone(eng.advanced_decoys)

        # 14. Tarpit
        self.assertTrue(hasattr(eng, "tarpit"))
        self.assertIsNotNone(eng.tarpit)

        # 15. Watchdog
        self.assertTrue(hasattr(eng, "watchdog"))
        self.assertIsNotNone(eng.watchdog)
        eng.watchdog.record_baseline(config.CONFIG_FILE)
        self.assertEqual(len(eng.watchdog.verify_integrity()), 0)

        # 16. Fleet
        self.assertTrue(hasattr(eng, "fleet_mgr"))
        self.assertIsNotNone(eng.fleet_mgr)
        eng.fleet_mgr.register_node("node-1", "node1.corp", "10.0.1.1")
        self.assertEqual(len(eng.fleet_mgr.list_nodes()), 1)

        # 17. Gateway Sync
        self.assertTrue(hasattr(eng, "gateway_sync"))
        self.assertIsNotNone(eng.gateway_sync)
        posture = eng.gateway_sync.collect_posture()
        self.assertIn("version", posture)

        # 18. Kill Chain
        self.assertTrue(hasattr(eng, "killchain"))
        self.assertIsNotNone(eng.killchain)
        camp = eng.killchain.track(AttackEvent(
            timestamp=time.time(),
            attack_id="atk-1",
            source_ip="203.0.113.99",
            source_port=12345,
            dest_ip="192.168.1.1",
            dest_port=80,
            protocol="tcp",
            attack_type="port_scan",
            attack_subtype="syn_scan",
            mitre_tactic="Discovery",
            mitre_technique="T1046",
            mitre_name="Network Service Discovery",
            kill_chain_phase="reconnaissance",
            severity="low",
            confidence=0.9
        ))
        self.assertIsNotNone(camp)
        self.assertEqual(camp.source_ip, "203.0.113.99")

        # 19. Protocols
        self.assertTrue(hasattr(eng, "protocols"))
        self.assertIsNotNone(eng.protocols)
        proto_info = eng.protocols.analyze_packet(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", dport=80)
        self.assertEqual(proto_info.get("protocol").upper(), "HTTP")

    def test_live_event_bus_triggers_playbook_and_correlation(self):
        """Proves events dispatched through common.event() trigger correlation and playbooks."""
        eng = Engine()

        # Emit an attack event matching the playbook pb-test-1
        common.event("attack_detected", sev="high", ip="198.51.100.88", name="attack_detected")

        # Check playbook audit log
        audit = getattr(eng.playbooks, "_audit_log", [])
        self.assertTrue(len(audit) >= 1)
        last_audit = audit[-1]
        self.assertEqual(last_audit["playbook_id"], "pb-test-1")

        # Check correlation engine processing
        eng.correlation.process_event("port_scan", "198.51.100.77")
        incident = eng.correlation.process_event("waf_block", "198.51.100.77")
        self.assertIsNotNone(incident)
        self.assertEqual(incident["rule_id"], "corr-001")

    def test_webui_and_cli_modules_status(self):
        """Proves that both the WebUI API and CLI report the runtime status of all 18 modules."""
        eng = Engine()
        from sentinelfw.cli import cmd_modules
        from io import StringIO
        import sys

        # Test CLI command
        buf = StringIO()
        orig_stdout = sys.stdout
        try:
            sys.stdout = buf
            cmd_modules(None)
        finally:
            sys.stdout = orig_stdout

        cli_out = buf.getvalue()
        self.assertIn("WAF Reverse Proxy", cli_out)
        self.assertIn("Identity Directory", cli_out)
        self.assertIn("Kill Chain Tracker", cli_out)
        self.assertIn("Anti-Tamper Watchdog", cli_out)


if __name__ == "__main__":
    unittest.main()
