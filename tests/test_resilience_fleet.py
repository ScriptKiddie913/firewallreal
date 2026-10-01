"""Tests for SentinelFW Block 8: Watchdog, Anti-Tamper, Fleet, and Resilience."""
import tempfile
import time
import unittest
from pathlib import Path
from sentinelfw.watchdog import WatchdogGuard
from sentinelfw.fleet import FleetManager


class TestResilienceFleetBlock8(unittest.TestCase):
    def test_watchdog_anti_tamper(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            wd = WatchdogGuard()
            test_file = Path(tmpdir) / "config.json"
            test_file.write_text('{"version": "4.0.0"}', encoding="utf-8")

            # 1. Record baseline
            wd.record_baseline(test_file)
            violations = wd.verify_integrity()
            self.assertEqual(len(violations), 0)

            # 2. Modify file -> should detect tamper
            test_file.write_text('{"version": "4.0.0", "backdoor": true}', encoding="utf-8")
            violations2 = wd.verify_integrity()
            self.assertEqual(len(violations2), 1)
            self.assertEqual(violations2[0]["status"], "modified")

            # 3. Delete file -> should detect missing
            test_file.unlink()
            violations3 = wd.verify_integrity()
            self.assertEqual(len(violations3), 1)
            self.assertEqual(violations3[0]["status"], "missing")

    def test_watchdog_liveness(self):
        wd = WatchdogGuard(fail_mode="fail_open")
        self.assertTrue(wd.check_liveness(max_interval=5.0))
        # Simulate stall
        wd._last_heartbeat = time.time() - 10.0
        self.assertFalse(wd.check_liveness(max_interval=5.0))
        self.assertFalse(wd.is_healthy)

    def test_fleet_manager(self):
        fleet = FleetManager(local_node_id="node-leader")

        # 1. Node Registration
        n1 = fleet.register_node("node-1", "fw-nyc", "192.168.1.1", version="4.0.0", role="follower")
        self.assertEqual(n1.hostname, "fw-nyc")
        self.assertEqual(n1.status, "online")

        # 2. Heartbeat with config hash
        fleet.record_heartbeat("node-1", config_hash="hash-abc-123")
        nodes = fleet.list_nodes()
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0]["config_hash"], "hash-abc-123")

        # 3. Fleet drift detection
        drifted = fleet.detect_fleet_drift(expected_config_hash="hash-xyz-999")
        self.assertEqual(len(drifted), 1)
        self.assertEqual(drifted[0]["node_id"], "node-1")

        # 4. Distributed ban sharing
        ban_rec = fleet.share_ban("203.0.113.77", reason="WAF SQLi attack", duration=10)
        self.assertEqual(ban_rec["ip"], "203.0.113.77")

        bans = fleet.get_shared_bans()
        self.assertEqual(len(bans), 1)
        self.assertEqual(bans[0]["ip"], "203.0.113.77")


if __name__ == "__main__":
    unittest.main()
