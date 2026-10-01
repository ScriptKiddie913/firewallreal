"""Tests for the 2.8 forensics & ops-safety layer (forensics.py)."""
import json
import os
import struct
import sys
import tempfile
import time
from pathlib import Path

TMP = tempfile.mkdtemp(prefix="sfwtest_forensics_")
os.environ["SENTINELFW_HOME"] = TMP
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinelfw import forensics  # noqa: E402
from sentinelfw.netlens import deep_parse  # noqa: E402


# --------------------------------------------------------------- helpers
def _client_hello(ciphers=(0x1301, 0xC02B), exts=((0, b"\x00\x05\x00\x00\x02h2"),),
                  version=0x0303):
    def ext(t, body):
        return struct.pack("!HH", t, len(body)) + body
    cs = b"".join(struct.pack("!H", c) for c in ciphers)
    ext_bytes = b"".join(ext(t, b) for t, b in exts)
    body = struct.pack("!H", version) + b"\x00" * 32 + b"\x00" + \
        struct.pack("!H", len(cs)) + cs + b"\x01\x00" + \
        struct.pack("!H", len(ext_bytes)) + ext_bytes
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


# --------------------------------------------------------------- JA3
def test_ja3_computes_expected_hash():
    exts = ((0, b"\x00\x05\x00\x00\x02h2"),                        # server_name h2
            (10, struct.pack("!HH", 2, 0x001D)),                    # supported_groups x25519
            (11, b"\x01\x00"))                                      # ec_point_formats
    hello = _client_hello(ciphers=(0x1301, 0xC02B), exts=exts)
    r = forensics.ja3_from_client_hello(hello)
    assert r and r["sni"] == "h2"
    import hashlib
    ja3_str = r["ja3_string"]
    assert ja3_str == "771,4865-49195,0-10-11,29,0", ja3_str
    assert r["ja3"] == hashlib.md5(ja3_str.encode()).hexdigest()


def test_ja3_strips_grease():
    hello = _client_hello(ciphers=(0x0A0A, 0x1301, 0x1A1A))
    r = forensics.ja3_from_client_hello(hello)
    assert "4865" in r["ja3_string"] and "2570" not in r["ja3_string"] and "6682" not in r["ja3_string"]


def test_ja3_rejects_non_hello():
    assert forensics.ja3_from_client_hello(b"\x17\x03\x03\x00\x10" + b"\x00" * 16) is None
    assert forensics.ja3_from_client_hello(b"") is None


def test_deep_parse_exposes_ja3():
    hello = _client_hello()
    tcp = struct.pack("!HHIIBBHHH", 51000, 443, 1, 1, 0x50, 0x18, 8192, 0, 0)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp) + len(hello), 1, 0,
                     64, 6, 0, b"\x01\x02\x03\x04", b"\x05\x06\x07\x08")
    rec = deep_parse(ip + tcp + hello, eth=False, direction="out")
    tls = rec["layers"].get("tls", {})
    assert tls.get("ja3") and "JA3" in rec["info"]


# --------------------------------------------------------------- PcapRing
def test_pcap_ring_window_and_dump():
    cfg = {"pcap_ring": {"enabled": True, "seconds": 2, "max_mb": 1}}
    ring = forensics.PcapRing(lambda: cfg)
    now = time.time()
    ring.add(now - 5, struct.pack("!I", 99) * 10, eth=False)   # outside window -> evicted
    for i in range(3):
        ring.add(now - 1 + i * 0.4, struct.pack("!I", i) * 10, eth=False)
    frames = ring.snapshot()
    assert len(frames) == 3  # old frame evicted, 3 recent kept
    out = ring.dump("unittest")
    assert out is not None and out.exists()
    raw = out.read_bytes()
    magic, _, _, _, _, snaplen, linktype = struct.unpack("<IHHiIII", raw[:24])
    assert magic == 0xA1B2C3D4 and linktype == 101
    assert (forensics.PCAP_DIR / out.name).exists()


def test_pcap_ring_disabled_silent():
    ring = forensics.PcapRing(lambda: {"pcap_ring": {"enabled": False}})
    ring.add(time.time(), b"x" * 50)
    assert ring.snapshot() == []


def test_event_listener_dumps_on_ban():
    cfg = {"pcap_ring": {"enabled": True, "seconds": 10, "max_mb": 1}}
    ring = forensics.PcapRing(lambda: cfg)
    listener = forensics.make_event_listener(ring, lambda: None)
    ring.add(time.time(), b"\x45" + b"\x00" * 19, eth=False)
    listener({"kind": "ip_banned", "src": "203.0.113.66"})
    dumps = ring.list_dumps()
    assert any("203.0.113.66" in d["name"] for d in dumps)
    # non-alert events must not dump
    ring.clear()
    listener({"kind": "heartbeat"})
    assert ring.list_dumps() == [d for d in ring.list_dumps()]


# --------------------------------------------------------------- PersistenceWatch
def test_persistence_watch_detects_changes():
    tmp = Path(TMP) / "persist"
    tmp.mkdir(exist_ok=True)
    target = tmp / "some_cron"
    target.write_text("original")
    watch = forensics.PersistenceWatch(lambda: {})
    watch._linux_targets = lambda: [str(target)]
    watch._linux_dirs = lambda: [str(tmp)]
    watch.state_file = Path(TMP) / "persist_baseline.json"  # outside the watched dir
    n = watch.baseline()
    assert n >= 2
    assert watch.poll() == []
    # modify + add a sibling dir entry
    target.write_text("tampered")
    (tmp / "evil.service").write_text("[Service]\nExecStart=/bin/x\n")
    changes = watch.poll()
    kinds = {(c["where"], c["change"]) for c in changes}
    assert ("file:" + str(target), "modified") in kinds
    assert any("evil.service" in c["item"] and c["change"] == "added" for c in changes)
    # removing is detected after the operator accepted the new state (re-baseline)
    watch.baseline()
    assert watch.poll() == []
    (tmp / "evil.service").unlink()
    changes2 = watch.poll()
    assert any("evil.service" in c["item"] and c["change"] == "removed" for c in changes2)


def test_persistence_baseline_rebases():
    tmp = Path(TMP) / "persist2"
    tmp.mkdir(exist_ok=True)
    target = tmp / "rc.local"
    target.write_text("v1")
    watch = forensics.PersistenceWatch(lambda: {})
    watch._linux_targets = lambda: [str(target)]
    watch._linux_dirs = lambda: []
    watch.state_file = tmp / "baseline.json"
    watch.baseline()
    target.write_text("v2")
    assert watch.poll()
    watch.baseline()   # operator accepts the new state
    assert watch.poll() == []


import unittest
class TestForensicsSuite(unittest.TestCase):
    pass
for _k, _v in list(globals().items()):
    if _k.startswith('test_') and callable(_v):
        setattr(TestForensicsSuite, _k, lambda self, f=_v: f())
