import os
import shutil
import tempfile
import unittest
from pathlib import Path

from sentinelfw import common
from sentinelfw.engine import Engine
from sentinelfw import mgmt


class TestP0Credentials(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sfw-cred-test-")
        os.environ["SENTINELFW_HOME"] = self.tmp
        import sentinelfw.common as c
        import sentinelfw.config as cfg
        import sentinelfw.engine as eng
        self.orig_paths = {
            "c_home": c.HOME, "c_cfg": c.CONFIG_FILE, "c_lists": c.LISTS, "c_quar": c.QUAR,
            "cfg_home": cfg.HOME, "cfg_cfg": cfg.CONFIG_FILE,
            "eng_home": eng.HOME, "eng_cfg": eng.CONFIG_FILE
        }
        p = Path(self.tmp)
        c.HOME = cfg.HOME = eng.HOME = p
        c.CONFIG_FILE = cfg.CONFIG_FILE = eng.CONFIG_FILE = p / "config.json"
        c.LISTS = cfg.LISTS = p / "lists"
        c.QUAR = cfg.QUAR = p / "quarantine"

    def tearDown(self):
        import sentinelfw.common as c
        import sentinelfw.config as cfg
        import sentinelfw.engine as eng
        c.HOME = self.orig_paths["c_home"]
        c.CONFIG_FILE = self.orig_paths["c_cfg"]
        c.LISTS = self.orig_paths["c_lists"]
        c.QUAR = self.orig_paths["c_quar"]
        cfg.HOME = self.orig_paths["cfg_home"]
        cfg.CONFIG_FILE = self.orig_paths["cfg_cfg"]
        cfg.LISTS = self.orig_paths["c_lists"]
        cfg.QUAR = self.orig_paths["c_quar"]
        eng.HOME = self.orig_paths["eng_home"]
        eng.CONFIG_FILE = self.orig_paths["eng_cfg"]
        os.environ.pop("SENTINELFW_HOME", None)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_first_run_generates_random_otp_and_persists_operator_password(self):
        # 1. First run on a fresh HOME generates OTP and sets must_change_password
        engine1 = Engine()
        w1 = engine1.cfg.get("webui", {})
        
        self.assertTrue(bool(w1.get("password_hash")), "First run must generate password_hash")
        self.assertTrue(w1.get("must_change_password"), "First run must set must_change_password to True")
        
        # Verify auth.initial file was written
        auth_file = Path(self.tmp) / "auth.initial"
        self.assertTrue(auth_file.exists(), "auth.initial must be created on first run")
        content = auth_file.read_text()
        self.assertIn("one_time_password=", content)
        otp = ""
        for line in content.splitlines():
            if line.startswith("one_time_password="):
                otp = line.split("=", 1)[1]
        self.assertTrue(len(otp) >= 16)
        self.assertTrue(mgmt.verify_password(otp, w1["password_hash"]))

        # 2. Operator sets a custom password
        custom_password = "SuperSecretCustomPassword2026!"
        custom_hash = mgmt.hash_password(custom_password)
        w1["password_hash"] = custom_hash
        w1["must_change_password"] = False
        w1["password_initialized"] = True
        engine1.config_persist()

        # 3. Simulate daemon restart by re-initializing Engine()
        engine2 = Engine()
        w2 = engine2.cfg.get("webui", {})

        # Assert operator password hash is unchanged and survives restart
        self.assertEqual(w2["password_hash"], custom_hash, "Custom operator password hash must survive restart!")
        self.assertFalse(w2.get("must_change_password"), "must_change_password must remain False for custom password")
        self.assertTrue(mgmt.verify_password(custom_password, w2["password_hash"]))

        # Assert old default credentials and OTP are rejected
        self.assertFalse(mgmt.verify_password("Hotmeha21@", w2["password_hash"]))
        self.assertFalse(mgmt.verify_password(otp, w2["password_hash"]))
