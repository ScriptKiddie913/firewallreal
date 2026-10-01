"""Tests for SentinelFW Block 6: Deception, Tarpits, Canaries, and Attacker Intel."""
import tempfile
import unittest
from pathlib import Path
from sentinelfw.tarpit import TarpitServer, TarpitConnection
from sentinelfw.canary_tokens import CanaryManager
from sentinelfw.decoy_advanced import AdvancedDecoyEngine, ROTATING_BANNERS


class TestDeceptionBlock6(unittest.TestCase):
    def test_tarpit_server_lifecycle(self):
        tarpit = TarpitServer(port=22222, proto="ssh", max_conns=50, delay_seconds=1.0)
        status = tarpit.status()
        self.assertEqual(status["proto"], "ssh")
        self.assertEqual(status["max_conns"], 50)
        self.assertFalse(status["running"])

    def test_canary_tokens_and_trip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = CanaryManager(storage_dir=Path(tmpdir))

            # 1. AWS Key Canary
            kid, sec = mgr.generate_aws_canary(label="aws-backup")
            self.assertTrue(kid.startswith("AKIA"))
            self.assertEqual(len(kid), 20)

            # 2. GitHub Token Canary
            gh_tok = mgr.generate_github_canary(label="gh-ci")
            self.assertTrue(gh_tok.startswith("ghp_"))

            # 3. Deploy Canary File
            env_path = Path(tmpdir) / ".env.production"
            res = mgr.deploy_canary_file(env_path, file_type="env")
            self.assertTrue(env_path.exists())
            self.assertIn("GITHUB_API_TOKEN", env_path.read_text())

            # 4. Check traffic trip detection
            benign = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
            self.assertIsNone(mgr.check_traffic_for_canaries(benign, "192.168.1.10"))

            # Malicious payload leaking the AWS key
            malicious = f"POST /api/exfil HTTP/1.1\r\nAuthorization: {kid}\r\n\r\n"
            tripped = mgr.check_traffic_for_canaries(malicious, "203.0.113.88")
            self.assertIsNotNone(tripped)
            self.assertTrue(tripped["triggered"])
            self.assertEqual(tripped["trigger_ip"], "203.0.113.88")

    def test_advanced_decoys_and_feedback(self):
        engine = AdvancedDecoyEngine()

        # Rotating banner
        ssh_banner = engine.get_banner("ssh")
        self.assertTrue(ssh_banner.startswith(b"SSH-2.0-"))

        # Attacker interaction & profiling
        res1 = engine.record_decoy_event(
            ip="198.51.100.99",
            service="ssh",
            creds={"user": "root", "pass": "admin123"},
        )
        self.assertEqual(res1["feedback_action"], "monitor")
        prof1 = res1["profile"]
        self.assertEqual(prof1["credentials_attempted"], 1)
        self.assertEqual(prof1["threat_score"], 25)

        # Attacker executes a shell command -> triggers firewall tightening
        res2 = engine.record_decoy_event(
            ip="198.51.100.99",
            service="ssh",
            command="cat /etc/shadow",
        )
        self.assertEqual(res2["feedback_action"], "tighten_firewall")
        prof2 = res2["profile"]
        self.assertEqual(prof2["commands_executed"], 1)
        self.assertGreaterEqual(prof2["threat_score"], 50)
        self.assertTrue(any(t["id"] == "T1059" for t in prof2["mitre_tactics"]))


if __name__ == "__main__":
    unittest.main()
