import os
import shutil
import tempfile
import unittest
from pathlib import Path

from sentinelfw.vault import Vault, KEY_MAPPINGS


class TestVault(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sfw-vault-test-")
        self.vault_path = Path(self.tmp) / "vault.enc"
        self.vault = Vault(self.vault_path)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_set_and_get_secret(self):
        self.vault.set("my_secret_token", "super_secret_payload_12345")
        
        # Verify persistence and encryption on disk
        self.assertTrue(self.vault_path.exists())
        raw_disk = self.vault_path.read_bytes()
        self.assertNotIn(b"super_secret_payload_12345", raw_disk)

        # Verify new Vault instance can unseal
        vault2 = Vault(self.vault_path)
        val = vault2.get("my_secret_token")
        self.assertEqual(val, "super_secret_payload_12345")

    def test_environment_override_precedence(self):
        self.vault.set("vt_api_key", "stored_vault_key")
        
        # Without env var, returns stored key
        self.assertEqual(self.vault.get("vt_api_key"), "stored_vault_key")

        # With env var set, env takes precedence
        os.environ["SFW_VT_KEY"] = "override_from_env_999"
        try:
            self.assertEqual(self.vault.get("vt_api_key"), "override_from_env_999")
        finally:
            del os.environ["SFW_VT_KEY"]

    def test_migration_of_plaintext_keys(self):
        cfg = {
            "threat_intel": {
                "virustotal_api_key": "raw_vt_key_to_migrate",
            },
            "telegram": {
                "bot_token": "raw_telegram_token_to_migrate",
            },
            "sarvam": {
                "api_key": "raw_sarvam_key_to_migrate",
            },
        }

        migrated = self.vault.migrate_plaintext_keys(cfg)
        self.assertTrue(migrated)

        # Assert plaintext keys are replaced with vault pointers in config
        self.assertEqual(cfg["threat_intel"]["virustotal_api_key"], "vault:vt_api_key")
        self.assertEqual(cfg["telegram"]["bot_token"], "vault:telegram_bot_token")
        self.assertEqual(cfg["sarvam"]["api_key"], "vault:sarvam_api_key")

        # Assert secrets are accessible through vault interface
        self.assertEqual(self.vault.get("vt_api_key"), "raw_vt_key_to_migrate")
        self.assertEqual(self.vault.get("telegram_bot_token"), "raw_telegram_token_to_migrate")
        self.assertEqual(self.vault.get("sarvam_api_key"), "raw_sarvam_key_to_migrate")
