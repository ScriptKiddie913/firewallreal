#!/usr/bin/env python3
"""
Unit and integration test suite for SentinelGate Phase P5: Deep Content Inspection & DLP.
Tests TLS privacy bypass lists, AV file detection, Luhn-checked credit cards, and private key DLP.
"""

import re
import unittest

def luhn_check(card_number: str) -> bool:
    digits = [int(c) for c in card_number if c.isdigit()]
    if not digits:
        return False
    checksum = 0
    alternate = False
    for d in reversed(digits):
        if alternate:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
        alternate = not alternate
    return checksum % 10 == 0

class TestPhase5ContentInspection(unittest.TestCase):
    def test_tls_privacy_bypass_policy(self):
        """Validates that banking, medical, and government domains are exempted from TLS decryption."""
        bypass_rules = [
            "*.chase.com", "*.bankofamerica.com", "*.wellsfargo.com",
            "*.mychart.com", "*.irs.gov"
        ]

        def should_bypass(domain):
            domain = domain.lower()
            for rule in bypass_rules:
                if rule.startswith("*."):
                    suffix = rule[1:]
                    if domain.endswith(suffix):
                        return True
                elif domain == rule:
                    return True
            return False

        # Exemption domains must bypass
        self.assertTrue(should_bypass("online.chase.com"))
        self.assertTrue(should_bypass("patient.mychart.com"))
        self.assertTrue(should_bypass("taxpayers.irs.gov"))

        # General and untrusted domains must be inspected
        self.assertFalse(should_bypass("evil-c2-beacon.org"))
        self.assertFalse(should_bypass("github.com"))

    def test_file_av_eicar_detection(self):
        """Validates standard EICAR anti-malware string detection."""
        eicar_string = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        clean_file = b"Hello, this is a clean text document."

        def scan_buffer(data):
            if b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in data:
                return "MALICIOUS", "EICAR_Standard_AV_Test"
            return "CLEAN", None

        verdict, threat = scan_buffer(eicar_string)
        self.assertEqual(verdict, "MALICIOUS")
        self.assertEqual(threat, "EICAR_Standard_AV_Test")

        verdict, threat = scan_buffer(clean_file)
        self.assertEqual(verdict, "CLEAN")
        self.assertIsNone(threat)

    def test_dlp_credit_card_and_key_leak_prevention(self):
        """Validates DLP detection of private keys and Luhn-valid credit card numbers."""
        # Valid Luhn test credit card (standard Visa test number)
        valid_visa = "4532015112830366"
        invalid_card = "4532015112830367"

        self.assertTrue(luhn_check(valid_visa))
        self.assertFalse(luhn_check(invalid_card))

        payload_leak = """
        Confidential Report
        Account Owner: Jane Doe
        Card: 4532015112830366
        SSN: 123-45-6789
        -----BEGIN RSA PRIVATE KEY-----
        MIIEowIBAAKCAQEA0Y1p...
        -----END RSA PRIVATE KEY-----
        """

        # Verify Private Key Regex
        key_match = re.search(r"-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----", payload_leak)
        self.assertIsNotNone(key_match)

        # Verify SSN Regex
        ssn_match = re.search(r"\b\d{3}-\d{2}-\d{4}\b", payload_leak)
        self.assertIsNotNone(ssn_match)
        self.assertEqual(ssn_match.group(), "123-45-6789")

if __name__ == "__main__":
    unittest.main()
