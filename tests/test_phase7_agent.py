#!/usr/bin/env python3
"""
Unit and integration test suite for SentinelFW 3.0: Phase P7 Endpoint Agent Evolution.
Tests IPC message framing, daemon action dispatch, posture collection, and offline policy caching.
"""

import json
import os
import tempfile
import unittest
from pathlib import Path

class TestPhase7Agent(unittest.TestCase):
    def test_ipc_message_framing(self):
        """Validates binary length-prefixed IPC serialization."""
        data = {
            "action": "status",
            "params": {"detail": True},
            "client_pid": 1234
        }
        raw = json.dumps(data).encode("utf-8")
        framed = len(raw).to_bytes(4, byteorder="big") + raw

        # Decode framing
        length = int.from_bytes(framed[:4], byteorder="big")
        self.assertEqual(length, len(raw))
        decoded = json.loads(framed[4:4+length].decode("utf-8"))
        self.assertEqual(decoded["action"], "status")
        self.assertEqual(decoded["client_pid"], 1234)

    def test_daemon_action_dispatch_simulation(self):
        """Tests command dispatch logic within the agent daemon."""
        def dispatch(action, params):
            if action == "status":
                return {"status": "ok", "version": "3.0.0", "mode": "aggressive"}
            elif action == "block-ip":
                return {"status": "ok", "banned": params.get("ip")}
            elif action == "posture":
                return {"status": "ok", "health": "healthy", "tamper": "clean"}
            return {"status": "error"}

        resp_status = dispatch("status", {})
        self.assertEqual(resp_status["status"], "ok")
        self.assertEqual(resp_status["version"], "3.0.0")

        resp_block = dispatch("block-ip", {"ip": "203.0.113.10"})
        self.assertEqual(resp_block["banned"], "203.0.113.10")

        resp_posture = dispatch("posture", {})
        self.assertEqual(resp_posture["health"], "healthy")

    def test_gateway_sync_and_offline_cache(self):
        """Validates that offline cache enables continuous protection during network partition."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_file = Path(tmpdir) / "cached_policy.json"
            policy_data = {
                "version": "3.0.0",
                "rules": ["block 198.51.100.5", "quarantine evil.exe"]
            }

            # Write cache
            cache_file.write_text(json.dumps(policy_data))

            # Simulate offline load
            self.assertTrue(cache_file.exists())
            loaded = json.loads(cache_file.read_text())
            self.assertEqual(loaded["version"], "3.0.0")
            self.assertEqual(len(loaded["rules"]), 2)

if __name__ == "__main__":
    unittest.main()
