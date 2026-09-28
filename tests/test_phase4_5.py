"""Unit tests for SentinelFW 3.0 Phase 4 (Deception) & Phase 5 (Behavioral Sandbox)."""
import os
import socket
import tempfile
import time
import unittest
from pathlib import Path

from sentinelfw.decoy import CanarySystem
from sentinelfw.honeypot import HTTPHoneypot, HoneypotManager
from sentinelfw.sandbox import Sandbox
from sentinelfw.sandbox_verdict import SandboxVerdict
from sentinelfw.scanner_redirect import ScannerRedirector


class TestHoneypot(unittest.TestCase):
    def test_http_honeypot_interaction(self):
        sessions = []
        # Listen on high ephemeral port
        hp = HTTPHoneypot(port=18080, on_session=lambda s: sessions.append(s))
        hp.start()
        time.sleep(0.1)

        try:
            # Simulate attacker probe
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(("127.0.0.1", 18080))
                s.sendall(b"GET /wp-login.php HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                resp = s.recv(1024)
                self.assertIn(b"403 Forbidden", resp)

            time.sleep(0.1)
            self.assertEqual(len(sessions), 1)
            self.assertIn("GET /wp-login.php", sessions[0].commands[0])
        finally:
            if hp.sock:
                hp.sock.close()


class TestDecoy(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sfw-canary-")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_canary_tamper_detection(self):
        canary = CanarySystem({"canary": {"enabled": True}}, base_dir=Path(self.tmp))
        planted = canary.get_planted_decoys()
        self.assertGreaterEqual(len(planted), 1)

        # Tamper with planted file
        target = Path(planted[0]["path"])
        target.write_text("TAMPERED DATA BY ATTACKER")

        alerts = canary.check_decoys()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["event"], "tampered")


class TestScannerRedirect(unittest.TestCase):
    def test_scanner_redirect_expiry(self):
        sr = ScannerRedirector({"honeypot": {"auto_redirect_scanners": True, "redirect_window_seconds": 1}})
        self.assertTrue(sr.redirect_scanner("198.51.100.77"))
        self.assertEqual(len(sr.get_active()), 1)

        # Sleep past window
        time.sleep(1.2)
        expired = sr.tick()
        self.assertIn("198.51.100.77", expired)
        self.assertEqual(len(sr.get_active()), 0)


class TestSandbox(unittest.TestCase):
    def test_verdict_scoring(self):
        # 1. Clean activity
        clean = SandboxVerdict.evaluate([])
        self.assertEqual(clean["verdict"], "CLEAN")

        # 2. Suspicious activity (score 50)
        suspicious = SandboxVerdict.evaluate(["bad_network_connection"])
        self.assertEqual(suspicious["verdict"], "SUSPICIOUS")

        # 3. Malicious activity (score 130)
        malicious = SandboxVerdict.evaluate([
            "creates_temp_executable",  # 20
            "drops_and_executes_payload",  # 70
            "mass_file_modification",  # 40
        ])
        self.assertEqual(malicious["verdict"], "MALICIOUS")
        self.assertEqual(malicious["total_score"], 130)

    def test_sandbox_file_detonation(self):
        sb = Sandbox({"sandbox": {"enabled": True, "max_execution_seconds": 5}})
        # Create dummy script that creates a secondary script file
        tmp = tempfile.mkdtemp(prefix="sfw-sample-")
        try:
            if os.name == "nt":
                sample = Path(tmp) / "dropper.bat"
                sample.write_text("@echo off\r\necho payload > dropped_miner.exe\r\n")
            else:
                sample = Path(tmp) / "dropper.sh"
                sample.write_text("#!/bin/sh\necho payload > dropped_miner.exe\n")

            report = sb.analyze_file(sample)
            self.assertEqual(report["sample_name"], sample.name)
            self.assertIn("dropped_miner.exe", report["files_created"])
            self.assertIn("creates_temp_executable", report["indicators"])
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
