import json
import os
import struct
import tempfile
from pathlib import Path

# Set up isolated SENTINELFW_HOME before tests import common
_TEST_HOME = tempfile.mkdtemp(prefix="sfw_isolated_test_")
os.environ.setdefault("SENTINELFW_HOME", _TEST_HOME)

try:
    import pytest
except ImportError:
    pytest = None

if pytest is not None:
    @pytest.fixture
    def temp_home(tmp_path):
        old = os.environ.get("SENTINELFW_HOME")
        os.environ["SENTINELFW_HOME"] = str(tmp_path)
        yield tmp_path
        if old:
            os.environ["SENTINELFW_HOME"] = old

    @pytest.fixture
    def temp_config(tmp_path):
        from sentinelfw.config import DEFAULT_CONFIG
        p = tmp_path / "config.json"
        p.write_text(json.dumps(DEFAULT_CONFIG, indent=2), encoding="utf-8")
        return p

    @pytest.fixture
    def temp_pcap(tmp_path):
        p = tmp_path / "test.pcap"
        # Standard pcap global header: magic(4), v_maj(2), v_min(2), thiszone(4), sigfigs(4), snaplen(4), network(4)
        ghdr = struct.pack("=IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        p.write_bytes(ghdr)
        return p
