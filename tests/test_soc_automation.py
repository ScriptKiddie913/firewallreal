"""Tests for SentinelFW Block 7: Asset Map, Threat Intel, Playbooks, Correlation, and Compliance."""
import tempfile
import unittest
from pathlib import Path
from sentinelfw.assetmap import AssetFlowMap
from sentinelfw.feeds import ThreatIntelFeeds
from sentinelfw.playbook import PlaybookEngine
from sentinelfw.correlation import CorrelationEngine, CorrelationRule
from sentinelfw.compliance import ComplianceAuditor


class TestSOCAutomationBlock7(unittest.TestCase):
    def test_asset_flow_map(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_flow.db"
            afm = AssetFlowMap(db_path=db_path)

            afm.record_flow("192.168.1.10", "1.1.1.1", "tcp", 443, app="HTTPS", bytes_count=1500)
            afm.record_flow("192.168.1.10", "8.8.8.8", "udp", 53, app="DNS", bytes_count=120)
            afm.record_flow("192.168.1.20", "1.1.1.1", "tcp", 443, app="HTTPS", bytes_count=2000)

            talkers = afm.get_top_talkers(limit=5)
            self.assertEqual(len(talkers), 2)
            self.assertEqual(talkers[0]["src_ip"], "192.168.1.10")
            self.assertEqual(talkers[0]["flow_count"], 2)

            apps = afm.get_app_distribution()
            self.assertEqual(len(apps), 2)
            self.assertEqual(apps[0]["app"], "HTTPS")

            assets = afm.list_assets()
            self.assertEqual(len(assets), 2)

    def test_threat_intel_feeds(self):
        feeds = ThreatIntelFeeds()
        raw_list = [
            "# Spamhaus DROP list",
            "198.51.100.0/24 ; SBL1234",
            "203.0.113.50/32 ; Botnet C2",
        ]
        added = feeds.add_feed_entries("Spamhaus-DROP", raw_list, confidence=90, tags=["c2", "drop"])
        self.assertEqual(added, 2)

        # Match in subnet
        is_bad, details = feeds.check_ip("198.51.100.42")
        self.assertTrue(is_bad)
        self.assertEqual(details["source"], "Spamhaus-DROP")
        self.assertEqual(details["confidence"], 90)

        # Non-matching IP
        clean_bad, _ = feeds.check_ip("8.8.8.8")
        self.assertFalse(clean_bad)

    def test_playbook_engine(self):
        banned_ips = []
        def dummy_ban(ip, reason):
            banned_ips.append(ip)
            return True

        pb = PlaybookEngine(ban_callback=dummy_ban)
        pb.add_playbook({
            "id": "pb-critical-waf",
            "name": "Auto-Ban Critical WAF",
            "conditions": {"event": "waf_block", "min_severity": "high", "min_threat_score": 10},
            "actions": ["ban_ip", "notify"],
        })

        ev = {"event": "waf_block", "severity": "high", "score": 15, "ip": "203.0.113.99"}

        # Dry run
        dry_res = pb.evaluate_event(ev, dry_run=True)
        self.assertEqual(len(dry_res), 1)
        self.assertEqual(len(banned_ips), 0)

        # Live execution
        live_res = pb.evaluate_event(ev, dry_run=False)
        self.assertEqual(len(live_res), 1)
        self.assertIn("203.0.113.99", banned_ips)

    def test_correlation_engine(self):
        corr = CorrelationEngine()
        # Add custom correlation: login_failed -> file_download
        corr.add_rule(CorrelationRule(
            id="test-corr",
            name="Login Failure Followed by Download",
            sequence=["login_failed", "file_download"],
            window_seconds=60,
        ))

        ip = "192.0.2.15"
        # Step 1: login failed
        r1 = corr.process_event("login_failed", ip)
        self.assertIsNone(r1)

        # Step 2: file download
        r2 = corr.process_event("file_download", ip)
        self.assertIsNotNone(r2)
        self.assertEqual(r2["rule_id"], "test-corr")
        self.assertEqual(r2["ip"], ip)

    def test_compliance_auditor(self):
        auditor = ComplianceAuditor()
        cfg = {
            "webui": {
                "password_initialized": True,
                "tls_enabled": True,
                "totp_enabled": True,
            },
            "audit_log": {"enabled": True},
            "traffic_control": {"anti_spoofing_enabled": True},
            "firewall_policies": [{"id": 1, "enabled": True}],
        }
        res = auditor.evaluate(cfg)
        self.assertEqual(res["score"], 100)
        self.assertEqual(res["grade"], "A+")

        html_report = auditor.generate_html_report(res)
        self.assertIn("100/100", html_report)
        self.assertIn("SentinelFW Security Rating", html_report)


if __name__ == "__main__":
    unittest.main()
