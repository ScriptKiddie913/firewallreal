"""Tests for the 2.9 ops layer: DNS filter, fleet, log vault."""
import json
import os
import socket
import struct
import sys
import tempfile
import threading
import time
from pathlib import Path

TMP = Path(tempfile.mkdtemp(prefix="sfwtest_ops_"))
os.environ["SENTINELFW_HOME"] = str(TMP)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinelfw import ops  # noqa: E402
import sentinelfw.common as common  # noqa: E402

common.HOME = TMP
common.DATA_DIR = TMP
common.LOGS = TMP / "logs"
ops.LOGS = TMP / "logs"
HOME = TMP


def _dns_query(qname: str, tid=b"AB"):
    q = b"".join(bytes([len(l)]) + l.encode() for l in qname.split(".")) + b"\x00"
    return tid + struct.pack("!HHHHH", 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", 1, 1)


class _MockLists:
    def __init__(self, domains):
        self.domains = set()
        self.manual_domains = set(domains)


def _mock_upstream(port_holder):
    """A tiny UDP DNS responder returning 1.2.3.4 for any A query."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port_holder.append(s.getsockname()[1])

    def loop():
        while True:
            try:
                data, addr = s.recvfrom(4096)
            except OSError:
                return
            qname, _ = ops._dns_name_parse(data, 12)
            resp = data[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + data[12:]
            resp += ops._dns_name_wire(qname) + struct.pack("!HHIH", 1, 1, 300, 4) + \
                socket.inet_aton("1.2.3.4")
            s.sendto(resp, addr)

    threading.Thread(target=loop, daemon=True).start()
    return s


# ---------------------------------------------------------------- DNS
def test_dns_filter_blocks():
    f = ops.DnsFilter(lambda: {"dns_server": {"enabled": True, "sinkhole_ip": "0.0.0.0"}},
                      lambda: _MockLists({"ads.example.com"}))
    resp = f.handle_query(_dns_query("ads.example.com"))
    assert resp is not None and socket.inet_aton("0.0.0.0") in resp
    assert f.stats["blocked"] == 1


def test_dns_filter_suffix_match():
    f = ops.DnsFilter(lambda: {"dns_server": {"enabled": True, "sinkhole_ip": "0.0.0.0"}},
                      lambda: _MockLists({"doubleclick.net"}))
    assert f.handle_query(_dns_query("tracker.doubleclick.net")) is not None
    assert f.stats["blocked"] == 1


def test_dns_filter_forwards_and_caches():
    ports = []
    up = _mock_upstream(ports)
    cfg = {"dns_server": {"enabled": True, "sinkhole_ip": "0.0.0.0",
                          "upstream": [f"127.0.0.1:{ports[0]}"]}}
    f = ops.DnsFilter(lambda: cfg, lambda: _MockLists({"blocked.example"}))
    resp = f.handle_query(_dns_query("good.example.org"))
    assert resp is not None and socket.inet_aton("1.2.3.4") in resp
    # second query hits the cache and never touches the wire
    resp2 = f.handle_query(_dns_query("good.example.org", tid=b"CD"))
    assert resp2 is not None and resp2[:2] == b"CD"  # retid rewrite works
    assert f.stats["cache_hits"] == 1
    up.close()


def test_dns_filter_leaves_non_a_alone():
    ports = []
    up = _mock_upstream(ports)
    cfg = {"dns_server": {"enabled": True,
                          "upstream": [f"127.0.0.1:{ports[0]}"]}}
    f = ops.DnsFilter(lambda: cfg, lambda: _MockLists({"blocked.example"}))
    q = _dns_query("blocked.example")
    q = q[:-4] + struct.pack("!HH", 28, 1)  # AAAA
    resp = f.handle_query(q)  # AAAA not subject to blocking in v1
    assert resp is not None
    up.close()


# ---------------------------------------------------------------- fleet
def test_fleet_relay_flow():
    f = HOME / "fleet.json"
    if f.exists():
        try:
            os.unlink(f)
        except OSError:
            pass
    key = "k-" + ops.secrets_token(16)
    cfg = {"fleet": {"enabled": True, "shared_key": key}}
    r = ops.FleetRelay(lambda: cfg)
    assert r.enabled() and r.key_ok(key) and not r.key_ok("wrong")
    e = r.enroll("host-a")
    assert e["agent_id"]
    hb = r.heartbeat(e["agent_id"], {"hostname": "host-a", "version": "2.9",
                                     "platform": "linux",
                                     "stats": {"bans": 3, "offenses": 9},
                                     "recent_events": [{"kind": "ip_banned", "ip": "1.2.3.4"}],
                                     "top_offenders": [{"ip": "1.2.3.4", "count": 9}]})
    assert hb.get("ok")
    ov = r.overview()
    assert ov["enabled"] and len(ov["agents"]) == 1
    a = ov["agents"][0]
    assert a["hostname"] == "host-a" and a["online"] and a["stats"]["bans"] == 3
    assert any(x["agent"] == "host-a" for x in ov["feed"])
    assert r.heartbeat("bogus", {}) == {}


# ---------------------------------------------------------------- vault
def test_vault_seal_and_verify():
    cfg = {"management": {"vault": {"enabled": True, "key": "testkey123",
                                    "seal_interval_seconds": 60}}}
    vf = ops.VAULT_DIR / "chain.json"
    if vf.exists():
        try:
            os.unlink(vf)
        except OSError:
            pass
    logs = HOME / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    test_log = logs / "test_events.jsonl"
    if test_log.exists():
        try:
            os.unlink(test_log)
        except OSError:
            pass
    v = ops.LogVault(lambda: cfg, log_file=test_log)
    test_log.write_text(json.dumps({"kind": "a"}) + "\n" +
                        json.dumps({"kind": "b"}) + "\n")
    b1 = v.seal(force=True)
    assert b1 and b1["records"] == 2 and b1["index"] == 0
    test_log.write_text(test_log.read_text() +
                        json.dumps({"kind": "c"}) + "\n")
    b2 = v.seal(force=True)
    assert b2["index"] == 1 and b2["records"] == 1
    assert b2["prev"] == b1["hash"]
    r = v.verify()
    assert r["ok"] and r["blocks"] == 2 and r["records"] == 3


def test_vault_detects_tampering():
    iso = Path(tempfile.mkdtemp(prefix="sfwvault_"))
    cfg = {"management": {"vault": {"enabled": True, "key": "testkey123"}}}
    logs = HOME / "logs"
    logs.mkdir(parents=True, exist_ok=True)

    def mk():
        v = ops.LogVault(lambda: cfg)
        v.chain_file = iso / "chain.json"   # isolated chain, shared event log
        return v

    def add_events(n):
        with open(logs / "events.jsonl", "a") as f:
            for i in range(n):
                f.write(json.dumps({"kind": f"t{n}{i}"}) + "\n")

    v = mk()
    add_events(2)
    assert v.seal(force=True)["index"] == 0
    add_events(1)
    assert v.seal(force=True)["index"] == 1
    add_events(3)
    assert v.seal(force=True)["index"] == 2

    # forge the record count of block 0 -> HMAC mismatch, detected
    pristine = v.chain_file.read_text()
    ch = json.loads(pristine)
    assert len(ch) == 3
    ch[0]["records"] = 99
    v.chain_file.write_text(json.dumps(ch))
    r = v.verify()
    assert not r["ok"] and r["first_bad"] == 0

    # restore, then delete the MIDDLE block -> index/prev linkage breaks
    v2 = mk()
    v2.chain_file.write_text(pristine)
    ch = json.loads(v2.chain_file.read_text())
    assert v2.verify()["ok"]
    v2.chain_file.write_text(json.dumps([ch[0], ch[2]]))
    r2 = v2.verify()
    assert not r2["ok"]

    # append a forged block with a bogus prev -> linkage break
    v3 = mk()
    ch = json.loads(v3.chain_file.read_text())
    fake = dict(ch[-1])
    fake["index"] = len(ch)
    fake["prev"] = "0" * 64
    ch.append(fake)
    v3.chain_file.write_text(json.dumps(ch))
    assert not v3.verify()["ok"]


def test_vault_wrong_key_fails_verify():
    cfg = {"management": {"vault": {"enabled": True, "key": "right"}}}
    v = ops.LogVault(lambda: cfg)
    logs = HOME / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    (logs / "events.jsonl").write_text(json.dumps({"kind": "a"}) + "\n")
    v.seal(force=True)
    bad = ops.LogVault(lambda: {"management": {"vault": {"enabled": True, "key": "wrong"}}})
    assert not bad.verify()["ok"]


def test_vault_flush_wipes_everything():
    cfg = {"management": {"vault": {"enabled": True, "key": "testkey123"}}}
    v = ops.LogVault(lambda: cfg)
    logs = HOME / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    (logs / "events.jsonl").write_text(json.dumps({"kind": "secret"}) + "\n")
    (HOME / "audit.log").write_text("auditline\n")
    (HOME / "pcaps").mkdir(exist_ok=True)
    (HOME / "pcaps" / "x.pcap").write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 40)
    v.seal(force=True)
    r = v.flush_all()
    assert r["count"] >= 3
    assert not (HOME / "audit.log").exists()
    assert not (HOME / "pcaps" / "x.pcap").exists()
    # a fresh genesis block exists right after the flush (provably fresh chain)
    r = v.verify()
    assert r["ok"] and r["blocks"] == 1 and "log_flush_executed" in \
        (HOME / "logs" / "events.jsonl").read_text()


import unittest
class TestOpsSuite(unittest.TestCase):
    def setUp(self):
        common.HOME = TMP
        common.DATA_DIR = TMP
        common.LOGS = TMP / "logs"
        ops.LOGS = TMP / "logs"

for _k, _v in list(globals().items()):
    if _k.startswith('test_') and callable(_v):
        setattr(TestOpsSuite, _k, lambda self, f=_v: f())
