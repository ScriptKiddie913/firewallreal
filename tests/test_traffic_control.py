"""Unit tests for SentinelFW Traffic Control, Rate Limiting, and Anti-Spoofing."""
import time
import unittest
from sentinelfw.traffic_control import (
    AntiSpoofingGuard,
    FloodMitigator,
    HandshakeTracker,
    TokenBucketLimiter,
)


class TestTrafficControl(unittest.TestCase):

    def test_token_bucket_limiter(self):
        # Limiter with 10 tokens/sec, capacity 5
        tb = TokenBucketLimiter(rate=10.0, capacity=5.0)
        # Should allow 5 consecutive requests (consuming entire capacity)
        for _ in range(5):
            self.assertTrue(tb.allow("client_1"))
        # 6th immediate request should be rejected
        self.assertFalse(tb.allow("client_1"))

        # Different client should have its own separate bucket
        self.assertTrue(tb.allow("client_2"))

        # After short pause (0.15s), at least 1 token should replenish
        time.sleep(0.15)
        self.assertTrue(tb.allow("client_1"))

    def test_handshake_tracker(self):
        tracker = HandshakeTracker()
        client = "198.51.100.55"
        server = "203.0.113.10"

        self.assertFalse(tracker.is_confirmed(client))

        # 1. Client sends SYN (sport 45000 -> dport 443)
        tracker.observe_packet(proto=6, flags=0x02, src=client, sport=45000, dst=server, dport=443)
        self.assertFalse(tracker.is_confirmed(client))

        # 2. Client sends ACK (flags 0x10) to complete handshake
        tracker.observe_packet(proto=6, flags=0x10, src=client, sport=45000, dst=server, dport=443)
        self.assertTrue(tracker.is_confirmed(client))

    def test_anti_spoofing_guard(self):
        # 1. Protected IPs
        for ip in ("127.0.0.1", "10.0.0.5", "192.168.1.100", "1.1.1.1", "8.8.8.8"):
            should_ban, reason = AntiSpoofingGuard.evaluate_ban(ip, attack_score=999, handshake_confirmed=True)
            self.assertFalse(should_ban)
            self.assertEqual(reason, "protected")

        # 2. Unconfirmed handshake with normal attack score
        target = "203.0.113.80"
        should_ban, reason = AntiSpoofingGuard.evaluate_ban(target, attack_score=60, handshake_confirmed=False)
        self.assertFalse(should_ban)
        self.assertEqual(reason, "deferred_pending_handshake")

        # 3. Confirmed handshake with normal attack score
        should_ban, reason = AntiSpoofingGuard.evaluate_ban(target, attack_score=70, handshake_confirmed=True)
        self.assertTrue(should_ban)
        self.assertEqual(reason, "banned")

        # 4. Severe attack score (>= 100) bans even without handshake (emergency volumetric mitigation)
        attacker = "203.0.113.200"
        should_ban, reason = AntiSpoofingGuard.evaluate_ban(attacker, attack_score=120, handshake_confirmed=False)
        self.assertTrue(should_ban)
        self.assertEqual(reason, "banned")

    def test_flood_mitigator(self):
        fm = FloodMitigator(icmp_pps=5.0, syn_pps=5.0, total_pps=20.0)
        src = "198.51.100.77"

        # ICMP flood
        allowed_count = 0
        violation = None
        for _ in range(15):
            allow, viol = fm.inspect_packet(proto=1, flags=0, src=src, sport=0, dst="10.0.0.1", dport=0, icmp_type=8)
            if allow:
                allowed_count += 1
            else:
                violation = viol
        self.assertEqual(violation, "icmp_flood")
        self.assertLessEqual(allowed_count, 11)


if __name__ == "__main__":
    unittest.main()
