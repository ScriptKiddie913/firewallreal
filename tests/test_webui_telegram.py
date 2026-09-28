"""Tests for SentinelFW WebUI and Telegram Dispatcher Engine."""
import json
import unittest
from unittest.mock import MagicMock, patch

from sentinelfw.common import event, register_event_listener
from sentinelfw.telegram_bot import TelegramNotifier


class TestTelegramNotifier(unittest.TestCase):
    def setUp(self):
        self.notifier = TelegramNotifier(
            bot_token="123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11",
            chat_id="-100987654321",
            alert_levels=["critical", "warning"],
            rate_limit_per_minute=10,
            enabled=True,
        )

    def test_message_formatting_clean_no_emoji(self):
        test_evt = {
            "kind": "port_scan",
            "severity": "critical",
            "ts": "2026-09-28 14:00:00",
            "src_ip": "198.51.100.44",
            "src_port": 49152,
            "action": "banned",
            "reason": "Scanned 25 ports in 2 seconds"
        }
        formatted = self.notifier.format_event(test_evt)
        self.assertIn("[SENTINELFW CRITICAL] PORT SCAN", formatted)
        self.assertIn("Source IP : 198.51.100.44:49152", formatted)
        self.assertIn("Action    : banned", formatted)
        # Verify no emojis
        for char in formatted:
            self.assertTrue(ord(char) < 0x1F000, f"Emoji or special pictograph detected: {char}")

    def test_severity_filter(self):
        # Info should not be enqueued when only critical and warning are watched
        info_evt = {"kind": "heartbeat", "severity": "info"}
        self.notifier.notify(info_evt)
        self.assertEqual(self.notifier._queue.qsize(), 0)

        # Critical should be enqueued
        crit_evt = {"kind": "syn_flood", "severity": "critical", "src_ip": "198.51.100.99"}
        self.notifier.notify(crit_evt)
        self.assertEqual(self.notifier._queue.qsize(), 1)

    def test_send_test_message_missing_creds(self):
        res = TelegramNotifier.send_test_message("", "")
        self.assertFalse(res["ok"])
        self.assertIn("required", res["error"])

    @patch("urllib.request.urlopen")
    def test_send_test_message_mock_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"ok": True, "result": {"message_id": 1}}).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        res = TelegramNotifier.send_test_message("fake_token", "fake_chat_id")
        self.assertTrue(res["ok"])
        self.assertIn("successfully", res["message"])


if __name__ == "__main__":
    unittest.main()
