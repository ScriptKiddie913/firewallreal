"""Tests for SentinelFW Block 5: Policy Engine, Identity, and App-ID."""
import time
import unittest
from sentinelfw.policies import (
    FirewallPolicies,
    is_schedule_active,
    resolve_fqdn,
    _norm_addr_list,
)
from sentinelfw.identity import (
    IdentityDirectory,
    verify_jwt,
)
from sentinelfw.appid import (
    AppIDClassifier,
    classifier,
)
import base64
import hashlib
import hmac
import json


class TestPoliciesBlock5(unittest.TestCase):
    def setUp(self):
        self.cfg = {
            "firewall_policies": [
                {
                    "id": 1,
                    "name": "Block-Malicious-Countries",
                    "enabled": True,
                    "action": "deny",
                    "direction": "in",
                    "src": ["any"],
                    "dst": ["any"],
                    "src_countries": ["RU", "CN"],
                    "services": ["ANY"],
                },
                {
                    "id": 2,
                    "name": "Allow-Web-DMZ",
                    "enabled": True,
                    "action": "accept",
                    "direction": "in",
                    "src": ["any"],
                    "dst": ["@DMZ_SERVERS"],
                    "services": ["HTTP", "HTTPS"],
                },
                {
                    "id": 3,
                    "name": "Shadowed-Web-DMZ",
                    "enabled": True,
                    "action": "accept",
                    "direction": "in",
                    "src": ["any"],
                    "dst": ["192.168.1.50/32"],
                    "services": ["HTTP"],
                }
            ],
            "address_groups": {
                "DMZ_SERVERS": ["192.168.1.0/24"]
            }
        }
        self.pols = FirewallPolicies(self.cfg)

    def test_schedule_evaluation(self):
        # Schedule active on Monday 09:00 - 17:00
        sched = {"days": ["mon"], "start": "09:00", "end": "17:00"}
        # A Monday at 10:30 (2026-09-28 10:30 UTC: 1790591400 is Monday)
        t_mon_1030 = time.mktime(time.strptime("2026-09-28 10:30", "%Y-%m-%d %H:%M"))
        t_mon_1800 = time.mktime(time.strptime("2026-09-28 18:00", "%Y-%m-%d %H:%M"))
        t_tue_1030 = time.mktime(time.strptime("2026-09-29 10:30", "%Y-%m-%d %H:%M"))

        self.assertTrue(is_schedule_active(sched, at_time=t_mon_1030))
        self.assertFalse(is_schedule_active(sched, at_time=t_mon_1800))
        self.assertFalse(is_schedule_active(sched, at_time=t_tue_1030))

    def test_address_groups_and_fqdn(self):
        # Test address group CRUD
        self.pols.set_address_group("INTERNAL", ["10.0.0.0/8", "172.16.0.0/12"])
        grps = self.pols.get_address_groups()
        self.assertIn("INTERNAL", grps)
        self.assertEqual(len(grps["INTERNAL"]), 2)

        # Normalization with address groups
        nets = _norm_addr_list(["@INTERNAL"], address_groups=grps)
        self.assertEqual(len(nets), 2)

        # FQDN caching
        ips = resolve_fqdn("localhost")
        self.assertTrue(len(ips) >= 1)

    def test_commit_confirm_and_rollback(self):
        # Stage an addition
        res = self.pols.stage("add", {
            "name": "Temp-Test-Rule",
            "action": "deny",
            "src": ["203.0.113.5"],
            "dst": ["any"],
            "services": ["SSH"],
        })
        self.assertEqual(res["status"], "staged")
        self.assertEqual(len(self.pols.get_staged()), 1)

        # Commit with timeout
        c_res = self.pols.commit(timeout_seconds=60)
        self.assertEqual(c_res["status"], "committed")
        self.assertEqual(len(self.pols.raw), 4)

        # Confirm commit
        conf_res = self.pols.confirm()
        self.assertEqual(conf_res["status"], "confirmed")

        # Stage a deletion and rollback
        pid = self.pols.raw[-1]["id"]
        self.pols.stage("delete", pol_id=pid)
        self.pols.commit(timeout_seconds=60)
        self.assertEqual(len(self.pols.raw), 3)

        rb_res = self.pols.rollback()
        self.assertEqual(rb_res["status"], "rolled_back")
        self.assertEqual(len(self.pols.raw), 4)

    def test_packet_simulation(self):
        # Malicious country packet: blocked by Rule 1
        res1 = self.pols.simulate_packet("203.0.113.1", "192.168.1.10", "tcp", 80, src_country="RU")
        self.assertTrue(res1["matched"])
        self.assertEqual(res1["policy_id"], 1)
        self.assertEqual(res1["action"], "deny")

        # DMZ Web packet from allowed country: accepted by Rule 2 (using @DMZ_SERVERS)
        res2 = self.pols.simulate_packet("203.0.113.1", "192.168.1.10", "tcp", 443, src_country="US")
        self.assertTrue(res2["matched"])
        self.assertEqual(res2["policy_id"], 2)
        self.assertEqual(res2["action"], "accept")

        # Unmatched packet falls through to implicit deny
        res3 = self.pols.simulate_packet("203.0.113.1", "10.10.10.10", "tcp", 22, src_country="FR")
        self.assertFalse(res3["matched"])
        self.assertEqual(res3["action"], "drop")

        # Configurable default action via argument
        res4 = self.pols.simulate_packet("203.0.113.1", "10.10.10.10", "tcp", 22, default_action="accept")
        self.assertFalse(res4["matched"])
        self.assertEqual(res4["action"], "accept")

        # Configurable default action via config dictionary
        self.pols.cfg["default_policy_action"] = "reject"
        res5 = self.pols.simulate_packet("203.0.113.1", "10.10.10.10", "tcp", 22)
        self.assertFalse(res5["matched"])
        self.assertEqual(res5["action"], "reject")
        self.pols.cfg.pop("default_policy_action", None)

    def test_find_shadowed_rules(self):
        shadowed = self.pols.find_shadowed_rules()
        self.assertTrue(len(shadowed) >= 1)
        self.assertEqual(shadowed[0]["shadowed_id"], 3)
        self.assertEqual(shadowed[0]["shadowed_by_id"], 2)


class TestIdentityAndAppID(unittest.TestCase):
    def test_identity_directory(self):
        dir_inst = IdentityDirectory()
        dir_inst.map_ip("192.168.1.100", "alice", groups=["Engineering", "SecOps"], ttl=2)
        ident = dir_inst.get_identity("192.168.1.100")
        self.assertIsNotNone(ident)
        self.assertEqual(ident["username"], "alice")
        self.assertIn("SecOps", ident["groups"])

        # Revocation
        self.assertTrue(dir_inst.revoke_ip("192.168.1.100"))
        self.assertIsNone(dir_inst.get_identity("192.168.1.100"))

    def test_jwt_verification(self):
        secret = "super-secret-key-12345"
        header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
        claims = {
            "sub": "user-42",
            "iss": "sentinelfw-auth",
            "aud": "sentinelfw-api",
            "exp": time.time() + 3600,
        }
        payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
        sig = hmac.new(secret.encode(), f"{header}.{payload}".encode("ascii"), hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        token = f"{header}.{payload}.{sig_b64}"

        # Valid
        ok, res_claims, msg = verify_jwt(token, secret=secret, expected_issuer="sentinelfw-auth", expected_audience="sentinelfw-api")
        self.assertTrue(ok)
        self.assertEqual(res_claims["sub"], "user-42")

        # Wrong secret
        bad_ok, _, _ = verify_jwt(token, secret="wrong-secret")
        self.assertFalse(bad_ok)

        # Expired token
        expired_claims = dict(claims, exp=time.time() - 100)
        exp_payload = base64.urlsafe_b64encode(json.dumps(expired_claims).encode()).rstrip(b"=").decode()
        exp_sig = hmac.new(secret.encode(), f"{header}.{exp_payload}".encode("ascii"), hashlib.sha256).digest()
        exp_token = f"{header}.{exp_payload}.{base64.urlsafe_b64encode(exp_sig).rstrip(b'=').decode()}"
        exp_ok, _, _ = verify_jwt(exp_token, secret=secret, leeway=0)
        self.assertFalse(exp_ok)

    def test_appid_classification(self):
        clf = AppIDClassifier()

        # SNI matching
        res1 = clf.identify(sni="app.slack.com")
        self.assertEqual(res1["app"], "Slack")
        self.assertEqual(res1["confidence"], "high")

        # HTTP Host matching
        res2 = clf.identify(host="api.github.com")
        self.assertEqual(res2["app"], "GitHub")

        # Payload matching (BitTorrent)
        res3 = clf.identify(payload=b"\x13BitTorrent protocol\x00\x00")
        self.assertEqual(res3["app"], "BitTorrent")
        self.assertEqual(res3["risk"], "high")

        # Port fallback (Redis)
        res4 = clf.identify(dport=6379)
        self.assertEqual(res4["app"], "Redis")
        self.assertEqual(res4["confidence"], "low")


if __name__ == "__main__":
    unittest.main()
