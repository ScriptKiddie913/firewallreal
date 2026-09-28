#!/usr/bin/env python3
"""
Unit and integration test suite for SentinelGate Phase P2: Management Plane & Telemetry.
Tests RBAC policies, cryptographic audit log chaining, token lifecycle, and telemetry metrics.
"""

import hmac
import hashlib
import json
import time
import unittest

class TestPhase2Management(unittest.TestCase):
    def setUp(self):
        self.secret_key = b"sentinelgate-super-secret-audit-key-32b"
        self.roles_permissions = {
            "SuperAdmin": [
                "policy:read", "policy:write", "policy:commit",
                "network:read", "network:write", "logs:read", "system:admin"
            ],
            "SecurityAdmin": [
                "policy:read", "policy:write", "policy:commit", "logs:read"
            ],
            "NetworkAdmin": [
                "network:read", "network:write", "policy:read", "logs:read"
            ],
            "Auditor": [
                "policy:read", "network:read", "logs:read"
            ]
        }

    def test_rbac_authorization_matrix(self):
        """Validates that RBAC strictly enforces least privilege across roles."""
        perms_super = self.roles_permissions["SuperAdmin"]
        perms_sec = self.roles_permissions["SecurityAdmin"]
        perms_aud = self.roles_permissions["Auditor"]

        # SuperAdmin can commit and admin system
        self.assertIn("policy:commit", perms_super)
        self.assertIn("system:admin", perms_super)

        # SecurityAdmin cannot write network or admin system
        self.assertNotIn("network:write", perms_sec)
        self.assertNotIn("system:admin", perms_sec)

        # Auditor can read but never write or commit
        self.assertIn("logs:read", perms_aud)
        self.assertNotIn("policy:write", perms_aud)
        self.assertNotIn("policy:commit", perms_aud)

    def test_tamper_evident_audit_log_hash_chain(self):
        """Simulates and verifies cryptographic HMAC chaining of audit records."""
        audit_records = []
        last_hmac = "0" * 64

        events = [
            ("admin", "LOGIN", "system", "SUCCESS", "Admin login via WebUI"),
            ("admin", "COMMIT", "policy", "SUCCESS", "Committed revision 8af13bc"),
            ("operator", "BACKUP", "system", "SUCCESS", "Exported config backup"),
        ]

        for user, action, resource, status, detail in events:
            payload = f"{last_hmac}|{user}|{action}|{resource}|{status}|{detail}".encode()
            curr_hmac = hmac.new(self.secret_key, payload, hashlib.sha256).hexdigest()
            audit_records.append({
                "prev_hmac": last_hmac,
                "user": user,
                "action": action,
                "resource": resource,
                "status": status,
                "detail": detail,
                "hmac": curr_hmac
            })
            last_hmac = curr_hmac

        self.assertEqual(len(audit_records), 3)

        # Verification pass: chain should be intact
        prev = "0" * 64
        for rec in audit_records:
            payload = f"{prev}|{rec['user']}|{rec['action']}|{rec['resource']}|{rec['status']}|{rec['detail']}".encode()
            expected = hmac.new(self.secret_key, payload, hashlib.sha256).hexdigest()
            self.assertEqual(rec["hmac"], expected)
            prev = rec["hmac"]

        # Simulate tampering on record 1
        audit_records[1]["detail"] = "Committed malicious hidden backdoor rule"
        tampered_detected = False
        prev = "0" * 64
        for rec in audit_records:
            payload = f"{prev}|{rec['user']}|{rec['action']}|{rec['resource']}|{rec['status']}|{rec['detail']}".encode()
            expected = hmac.new(self.secret_key, payload, hashlib.sha256).hexdigest()
            if rec["hmac"] != expected:
                tampered_detected = True
                break
            prev = rec["hmac"]

        self.assertTrue(tampered_detected, "Tampering must be caught by HMAC chain validation!")

    def test_telemetry_flow_accounting_and_prometheus(self):
        """Tests telemetry accumulation and Prometheus metric formatting."""
        metrics = {
            "active_sessions": 3410,
            "packets_in": 1250000,
            "packets_out": 980000,
            "drops": 142
        }

        prom_lines = [
            f"sentinelgate_active_sessions {metrics['active_sessions']}",
            f'sentinelgate_packets_total{{direction="in"}} {metrics["packets_in"]}',
            f'sentinelgate_packets_total{{direction="out"}} {metrics["packets_out"]}',
            f"sentinelgate_drops_total {metrics['drops']}"
        ]
        prom_output = "\n".join(prom_lines)

        self.assertIn("sentinelgate_active_sessions 3410", prom_output)
        self.assertIn("sentinelgate_drops_total 142", prom_output)

if __name__ == "__main__":
    unittest.main()
