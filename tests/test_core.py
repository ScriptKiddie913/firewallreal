import ipaddress, os, socket, struct, sys, tempfile, unittest
from pathlib import Path

TMP = tempfile.mkdtemp(prefix="sfw-test-")
os.environ["SENTINELFW_HOME"] = TMP
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentinelfw import monitors, procinfo  # noqa: E402
from sentinelfw.common import *  # noqa: E402,F401
from sentinelfw.config import DEFAULT_CONFIG, Store  # noqa: E402
from sentinelfw.detector import Detector  # noqa: E402
from sentinelfw.lists import IPSet, Lists, extract_domains, extract_hashes, extract_ips, list_edit  # noqa: E402
from sentinelfw.packets import parse_dns, parse_packet  # noqa: E402


def ip4(src, dst, proto, l4):
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, 0, 64, proto, 0, socket.inet_aton(src), socket.inet_aton(dst)) + l4


def tcp(dport, flags, sport=4444):
    return struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 1000, 0, 0)


class FakeEngine:
    def __init__(self):
        self.cfg = DEFAULT_CONFIG
        self.stats = __import__("collections").Counter()
        self.bans = []
        self.guard = type("G", (), {"protected": lambda s, ip: ip.startswith("10.")})()
        self.lists = Lists()
        self.lists.domains = {"evil.example.com"}

    def blocked(self, ip): return False
    def domain_blocked(self, n): return n == "evil.example.com"
    def ban(self, ip, reason, *a, **k): self.bans.append((ip, reason))


class Lists_(unittest.TestCase):
    def test_ipset_and_feed_safety(self):
        s = IPSet([ipaddress.ip_network(x) for x in ["1.2.3.0/24", "2001:db8::/32"]])
        self.assertIn("1.2.3.9", s); self.assertIn("2001:db8::1", s); self.assertNotIn("1.2.4.1", s)
        r = extract_ips("10.0.0.0/8\n8.8.8.0/24 ; SBL\n0.0.0.0/0\n1.1.1.1\n", feed=True)
        self.assertEqual([str(x) for x in r], ["8.8.8.0/24", "1.1.1.1/32"])

    def test_domains_hashes(self):
        self.assertEqual(extract_domains("127.0.0.1 localhost\n0.0.0.0 a.evil.com # x\nbad.org\n1.2.3.44\n"), {"a.evil.com", "bad.org"})
        self.assertEqual(len(extract_hashes("a" * 64 + "\nnothex\n")), 1)


class Packets(unittest.TestCase):
    def test_tcp_parse(self):
        p = parse_packet(ip4("8.8.4.4", "192.168.1.5", 6, tcp(22, 2) + b"GET /"), False)
        self.assertEqual((p["dport"], p["flags"], p["payload"]), (22, 2, b"GET /"))

    def test_dns(self):
        q = b"".join(bytes([len(x)]) + x.encode() for x in "evil.example.com".split(".")) + b"\0" + struct.pack("!HH", 1, 1)
        query = struct.pack("!6H", 1, 0x0100, 1, 0, 0, 0) + q
        self.assertEqual(parse_dns(query)["questions"], ["evil.example.com"])
        resp = struct.pack("!6H", 1, 0x8180, 1, 1, 0, 0) + q + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("6.6.6.6")
        self.assertEqual(parse_dns(resp)["answers"], ["6.6.6.6"])


class Detection(unittest.TestCase):
    def setUp(self):
        self.e = FakeEngine(); self.d = Detector(self.e)

    def feed(self, src, l4, t, out=False):
        self.d.inspect(parse_packet(ip4(src, "192.168.1.5", 6, l4), False), out, t)

    def test_port_scan(self):
        for i in range(1, 30): self.feed("8.8.4.4", tcp(i, 2), i * 0.1)
        self.assertIn(("8.8.4.4", "port_scan"), self.e.bans)

    def test_invalid_flags_and_signature_and_protected(self):
        self.feed("9.9.9.9", tcp(80, 0), 1)
        self.feed("7.7.7.7", tcp(80, 0x18) + b"GET /?a=1 UNION SELECT 1", 2)
        self.feed("10.1.1.1", tcp(80, 0), 3)
        self.assertIn(("9.9.9.9", "invalid_tcp_flags:00"), self.e.bans)
        self.assertIn(("7.7.7.7", "signature:sql_injection_union"), self.e.bans)
        self.assertFalse([b for b in self.e.bans if b[0] == "10.1.1.1"])

    def test_brute_force(self):
        for i in range(20): self.feed("5.5.5.5", tcp(22, 2, 1000 + i), i * 0.5)
        self.assertTrue(any(b[1].startswith("brute_force") for b in self.e.bans))


class ExecHook(unittest.TestCase):
    def test_parse_proc_event(self):
        ev = struct.pack("=IIQ", 2, 0, 0) + struct.pack("=ii", 1234, 1234)
        cn = struct.pack("=IIIIHH", 1, 1, 0, 0, len(ev), 0) + ev
        msg = struct.pack("=IHHII", 16 + len(cn), 3, 0, 0, 0) + cn
        self.assertEqual(monitors.parse_proc_events(msg), [1234])
        fork = struct.pack("=IIQ", 1, 0, 0) + struct.pack("=iiii", 1, 1, 2, 2)
        cn = struct.pack("=IIIIHH", 1, 1, 0, 0, len(fork), 0) + fork
        self.assertEqual(monitors.parse_proc_events(struct.pack("=IHHII", 16 + len(cn), 3, 0, 0, 0) + cn), [])


class Response(unittest.TestCase):
    def setUp(self):
        Store()  # creates dirs
        self.kills = []
        monitors.kill_process = lambda pid: self.kills.append(pid) or True
        e = FakeEngine(); e.cfg = dict(DEFAULT_CONFIG); e.lists.programs = ["/opt/evil/*"]
        e.lists.hashes = set()
        self.r = monitors.Responder(e)

    def test_blocked_program_killed_and_quarantined(self):
        d = Path(TMP) / "evil"; d.mkdir(exist_ok=True)
        f = d / "bad.bin"; f.write_bytes(b"x")
        self.r.e.lists.programs = [str(d / "*")]
        self.assertTrue(self.r.check_exe(4242, str(f), exec_time=True))
        self.assertEqual(self.kills, [4242]); self.assertFalse(f.exists())
        m = procinfo.manifest_load(); self.assertEqual(len(m), 1)

    def test_heuristic_never_touches_system_paths(self):
        self.assertFalse(self.r.check_exe(77, "/usr/bin/curl (deleted)"))
        self.assertEqual(self.kills, [])
        self.assertEqual(procinfo.dispose_file("/usr/bin/ls", "t", "delete"), "protected")

    def test_monitor_profile_only_logs(self):
        self.r.e.cfg["enforcement_profile"] = "monitor"
        d = Path(TMP) / "evil2"; d.mkdir(exist_ok=True); f = d / "b"; f.write_bytes(b"x")
        self.r.e.lists.programs = [str(d / "*")]
        self.r.check_exe(9, str(f), exec_time=True)
        self.assertEqual(self.kills, []); self.assertTrue(f.exists())

    def test_delete_mode_and_expiry(self):
        f = Path(TMP) / "gone.bin"; f.write_bytes(b"y")
        self.assertEqual(procinfo.dispose_file(str(f), "t", "delete"), "deleted"); self.assertFalse(f.exists())
        g = Path(TMP) / "old.bin"; g.write_bytes(b"z")
        procinfo.dispose_file(str(g), "t", "quarantine")
        m = procinfo.manifest_load()
        for v in m.values(): v["time"] -= 30 * 86400
        procinfo.manifest_save(m)
        self.assertGreaterEqual(procinfo.quarantine_expire(7), 1)


if __name__ == "__main__":
    unittest.main()
