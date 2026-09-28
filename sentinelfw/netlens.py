"""SentinelFW NetLens — deep packet vision.

Wireshark-grade packet capture pipeline: deep protocol parsing (Ethernet, VLAN,
IPv4/IPv6, TCP, UDP, ICMP, DNS, HTTP, TLS), a bounded ring buffer of recent
packets with raw-frame hexdumps, live per-protocol / per-severity counters, and
an optional deterministic simulator used for demos and offline testing.
"""
import os
import socket
import struct
import threading
import time
from collections import deque
from typing import Optional

from .common import event
from .packets import dns_name, parse_dns

# ---------------------------------------------------------------------------
# Protocol tables
# ---------------------------------------------------------------------------

IP_PROTO = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6", 47: "GRE",
            50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF", 132: "SCTP"}

WELL_KNOWN_PORTS = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http", 88: "kerberos", 110: "pop3",
    123: "ntp", 135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
    514: "syslog", 587: "smtp", 631: "ipp", 636: "ldaps", 993: "imaps", 995: "pop3s",
    1080: "socks", 1433: "mssql", 1521: "oracle", 1883: "mqtt", 2222: "ssh",
    2121: "ftp", 2323: "telnet", 2375: "docker", 2376: "docker-tls", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5672: "amqp", 5900: "vnc", 6379: "redis",
    8080: "http-alt", 8443: "https-alt", 9443: "sentinel-ui", 11211: "memcached",
    27017: "mongodb", 6443: "kubernetes",
}

TCP_FLAG_BITS = {0x01: "FIN", 0x02: "SYN", 0x04: "RST", 0x08: "PSH",
                 0x10: "ACK", 0x20: "URG", 0x40: "ECE", 0x80: "CWR"}

MAX_HEX_BYTES = 512  # raw bytes retained per packet for the hexdump pane


def _hex(b: bytes) -> str:
    return b.hex()


# ---------------------------------------------------------------------------
# Deep parser
# ---------------------------------------------------------------------------

def deep_parse(buf: bytes, eth: bool, direction: Optional[str] = None,
               iface: str = "") -> Optional[dict]:
    """Parse a raw link-layer or raw-IP frame into a rich, Wireshark-style tree.

    Returns None for unparsable frames. The result dict contains:
      meta:   ts, direction, iface, length, protocol, info, severity, verdict
      layers: ethernet, vlan, ip, ipv6, tcp, udp, icmp, dns, http, tls
      hex:    hex string of first MAX_HEX_BYTES bytes
    """
    if not buf:
        return None
    rec = {
        "ts": time.time(),
        "direction": direction or "",
        "iface": iface,
        "length": len(buf),
        "protocol": "UNKNOWN",
        "info": "",
        "severity": "info",
        "verdict": "ALLOW",
        "layers": {},
        "hex": _hex(buf[:MAX_HEX_BYTES]),
        "hex_total": len(buf),
    }
    layers = rec["layers"]
    off = 0
    proto_num = 0

    if eth:
        if len(buf) < 14:
            return None
        dmac = ":".join(f"{b:02x}" for b in buf[0:6])
        smac = ":".join(f"{b:02x}" for b in buf[6:12])
        et = struct.unpack("!H", buf[12:14])[0]
        off = 14
        if et == 0x8100 and len(buf) >= 18:
            vid = struct.unpack("!H", buf[14:16])[0] & 0x0FFF
            layers["vlan"] = {"vid": vid}
            et = struct.unpack("!H", buf[16:18])[0]
            off = 18
        layers["ethernet"] = {"dst_mac": dmac, "src_mac": smac, "ethertype": f"0x{et:04x}"}
        v = 4 if et == 0x0800 else 6 if et == 0x86DD else 0
    else:
        if not buf:
            return None
        v = buf[0] >> 4

    if v == 4:
        if len(buf) < off + 20:
            return None
        ihl = (buf[off] & 0x0F) * 4
        if ihl < 20 or len(buf) < off + ihl:
            return None
        tot = struct.unpack("!H", buf[off + 2:off + 4])[0]
        pid_ = struct.unpack("!H", buf[off + 4:off + 6])[0]
        frag = struct.unpack("!H", buf[off + 6:off + 8])[0]
        ttl = buf[off + 8]
        proto_num = buf[off + 9]
        csum = struct.unpack("!H", buf[off + 10:off + 12])[0]
        src = socket.inet_ntoa(buf[off + 12:off + 16])
        dst = socket.inet_ntoa(buf[off + 16:off + 20])
        flags = (frag >> 13) & 0x7
        foff = frag & 0x1FFF
        fl = [n for b, n in ((0x4, "DF"), (0x2, "MF")) if flags & b]
        layers["ip"] = {
            "version": 4, "header_len": ihl, "total_len": tot, "id": pid_,
            "flags": "+".join(fl) or "none", "frag_offset": foff * 8,
            "ttl": ttl, "proto": IP_PROTO.get(proto_num, str(proto_num)),
            "checksum": f"0x{csum:04x}", "src": src, "dst": dst,
        }
        end = off + tot if 0 < tot <= len(buf) - off else len(buf)
        l4 = off + ihl
        rec["src"], rec["dst"] = src, dst
        if foff:
            layers["ip"]["fragmented"] = True
            rec["protocol"] = "IPv4 FRAG"
            rec["info"] = f"Fragmented IPv4 packet (offset {foff * 8}, id {pid_})"
            return rec
    elif v == 6:
        if len(buf) < off + 40:
            return None
        tc = (buf[off] << 8 | buf[off + 1]) >> 4
        flow = ((buf[off] & 0x0F) << 16) | struct.unpack("!H", buf[off + 2:off + 4])[0]
        plen = struct.unpack("!H", buf[off + 4:off + 6])[0]
        hop = buf[off + 7]
        nh = buf[off + 6]
        src = socket.inet_ntop(socket.AF_INET6, buf[off + 8:off + 24])
        dst = socket.inet_ntop(socket.AF_INET6, buf[off + 24:off + 40])
        l4 = off + 40
        end = min(len(buf), l4 + plen)
        while nh in (0, 43, 60, 51) and len(buf) >= l4 + 8:
            if nh == 43:
                nh = buf[l4]
                l4 += 8
            elif nh == 51 or nh == 60:
                nh = buf[l4]
                l4 += (buf[l4 + 1] + 1) * 8
            else:  # hop-by-hop
                nh = buf[l4]
                l4 += (buf[l4 + 1] + 1) * 8
        proto_num = nh
        layers["ipv6"] = {
            "version": 6, "traffic_class": tc, "flow_label": flow,
            "payload_len": plen, "next_header": IP_PROTO.get(proto_num, str(proto_num)),
            "hop_limit": hop, "src": src, "dst": dst,
        }
        rec["src"], rec["dst"] = src, dst
    else:
        return None

    # ---------------- Transport ----------------
    if proto_num == 6 and len(buf) >= l4 + 20:  # TCP
        sport = struct.unpack("!H", buf[l4:l4 + 2])[0]
        dport = struct.unpack("!H", buf[l4 + 2:l4 + 4])[0]
        seq = struct.unpack("!I", buf[l4 + 4:l4 + 8])[0]
        ack = struct.unpack("!I", buf[l4 + 8:l4 + 12])[0]
        doffraw = buf[l4 + 12]
        flags_b = buf[l4 + 13]
        win = struct.unpack("!H", buf[l4 + 14:l4 + 16])[0]
        csum = struct.unpack("!H", buf[l4 + 16:l4 + 18])[0]
        doff = (doffraw >> 4) * 4
        fl = [n for b, n in TCP_FLAG_BITS.items() if flags_b & b]
        payload = buf[l4 + doff:end]
        layers["tcp"] = {
            "src_port": sport, "dst_port": dport, "seq": seq, "ack": ack,
            "header_len": doff, "flags": ",".join(fl) or "None",
            "window": win, "checksum": f"0x{csum:04x}",
            "payload_len": len(payload),
        }
        rec["sport"], rec["dport"], rec["flags"] = sport, dport, flags_b
        rec["src_port"], rec["dst_port"] = sport, dport
        app = WELL_KNOWN_PORTS.get(sport if direction != "out" else dport) or \
            WELL_KNOWN_PORTS.get(dport) or WELL_KNOWN_PORTS.get(sport)
        rec["protocol"] = (app or "TCP").upper()
        # Wireshark-style info line
        fset = set(fl)
        if {"SYN", "ACK"} <= fset:
            info = f"{sport} → {dport} [SYN, ACK] Seq={seq} Ack={ack} Win={win}"
        elif "SYN" in fset:
            info = f"{sport} → {dport} [SYN] Seq={seq} Win={win} Len=0"
        elif "FIN" in fset and "ACK" in fset:
            info = f"{sport} → {dport} [FIN, ACK] Seq={seq} Ack={ack}"
        elif "RST" in fset:
            info = f"{sport} → {dport} [RST] Seq={seq}"
        elif "ACK" in fset and not payload:
            info = f"{sport} → {dport} [ACK] Seq={seq} Ack={ack} Win={win}"
        else:
            info = f"{sport} → {dport} [{','.join(fl) or 'PSH'}] Seq={seq} Ack={ack} Len={len(payload)}"
        rec["info"] = info
        _parse_l7(rec, layers, payload, sport, dport, direction)
    elif proto_num == 17 and len(buf) >= l4 + 8:  # UDP
        sport, dport, ulen, csum = struct.unpack("!HHHH", buf[l4:l4 + 8])
        payload = buf[l4 + 8:end]
        layers["udp"] = {
            "src_port": sport, "dst_port": dport, "length": ulen,
            "checksum": f"0x{csum:04x}", "payload_len": len(payload),
        }
        rec["sport"], rec["dport"] = sport, dport
        rec["src_port"], rec["dst_port"] = sport, dport
        app = WELL_KNOWN_PORTS.get(sport if direction != "out" else dport) or \
            WELL_KNOWN_PORTS.get(dport) or WELL_KNOWN_PORTS.get(sport)
        rec["protocol"] = (app or "UDP").upper()
        rec["info"] = f"{sport} → {dport} Len={len(payload)}"
        _parse_l7(rec, layers, payload, sport, dport, direction)
    elif proto_num in (1, 58) and len(buf) > l4:  # ICMP
        ityp, icode = buf[l4], buf[l4 + 1]
        layers["icmp"] = {"type": ityp, "code": icode,
                          "name": _icmp_name(ityp, icode, proto_num == 58)}
        rec["protocol"] = "ICMPv6" if proto_num == 58 else "ICMP"
        rec["info"] = layers["icmp"]["name"]
    else:
        rec["protocol"] = IP_PROTO.get(proto_num, f"IP({proto_num})").upper()
        rec["info"] = rec["protocol"]
    return rec


def _icmp_name(t: int, c: int, v6: bool) -> str:
    m = {(0, 0): "Echo reply", (8, 0): "Echo request", (3, 0): "Destination unreachable (network)",
         (3, 1): "Destination unreachable (host)", (3, 3): "Port unreachable",
         (11, 0): "TTL exceeded in transit", (5, 1): "Redirect for host"}
    if v6:
        return {(128, 0): "Echo (ping) request", (129, 0): "Echo (ping) reply",
                (1, 0): "No route to host", (4, 0): "Parameter problem",
                (3, 1): "Port unreachable"}.get((t, c), f"ICMPv6 {t}/{c}")
    return m.get((t, c), f"ICMP {t}/{c}")


def _parse_l7(rec, layers, payload: bytes, sport: int, dport: int, direction):
    """Best-effort L7 dissection for the Info column."""
    if not payload:
        return
    # DNS
    if 53 in (sport, dport):
        d = parse_dns(payload)
        if d:
            layers["dns"] = d
            rec["protocol"] = "DNS"
            if d["response"]:
                rec["info"] = f"Response {', '.join(d['answers'][:3]) or 'no answers'} to {', '.join(d['questions'][:2])}"
            else:
                rec["info"] = f"Standard query 0x{payload[:2].hex()} {', '.join(d['questions'][:2])} (A)"
            return
    # HTTP
    if payload[:4] in (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"OPTI", b"PATC") or payload[:5] in (b"HTTP/"):
        try:
            first = payload.split(b"\r\n", 1)[0].decode("ascii", "replace")
            layers["http"] = {"request_line": first}
            rec["protocol"] = "HTTP"
            rec["info"] = first[:120]
            return
        except Exception:
            pass
    # TLS ClientHello SNI
    if payload[0] == 0x16 and payload[:1] == b"\x16" and len(payload) > 43:
        try:
            # TLS record: handshake(22), version, length
            hs_len = struct.unpack("!I", b"\x00" + payload[3:6])[0]
            if payload[5] == 0x01:  # ClientHello
                # Walk: random(32) + session_id + cipher_suites + comp + ext
                o = 43  # 5 rec + 4 hs + 2 ver + 32 rand
                sid_len = payload[o]
                o += 1 + sid_len
                cs_len = struct.unpack("!H", payload[o:o + 2])[0]
                o += 2 + cs_len
                comp_len = payload[o]
                o += 1 + comp_len
                if o + 2 <= len(payload):
                    ext_len = struct.unpack("!H", payload[o:o + 2])[0]
                    o += 2
                    end_ext = min(o + ext_len, len(payload))
                    while o + 4 <= end_ext:
                        et, el = struct.unpack("!HH", payload[o:o + 4])
                        if et == 0:  # server_name
                            sni = payload[o + 4 + 5:o + 4 + 5 + struct.unpack("!H", payload[o + 4 + 3:o + 4 + 5])[0]]
                            layers["tls"] = {"sni": sni.decode("idna", "replace"), "type": "ClientHello"}
                            rec["protocol"] = "TLS"
                            rec["info"] = f"Client Hello (SNI: {layers['tls']['sni']})"
                            return
                        o += 4 + el
        except Exception:
            pass
        if dport in (443, 8443) or sport in (443, 8443):
            rec["protocol"] = "TLS"
            rec["info"] = f"TLS Application Data ({len(payload)} bytes)"


# ---------------------------------------------------------------------------
# Recorder
# ---------------------------------------------------------------------------

class PacketRecorder:
    """Thread-safe bounded packet buffer with live counters and query API."""

    def __init__(self, capacity: int = 8000):
        self.capacity = capacity
        self._buf: deque = deque(maxlen=capacity)
        self._lock = threading.RLock()
        self._next_id = 1
        self._dropped = 0
        self.capture_active = False
        self.capture_error = ""
        self.started_at = 0.0
        # counters
        self._proto_counts: dict = {}
        self._sev_counts: dict = {}
        self._dir_counts = {"in": 0, "out": 0}
        self._bytes = {"in": 0, "out": 0}

    # -- ingest ------------------------------------------------------------
    def record(self, parsed: dict, engine=None) -> Optional[dict]:
        if parsed is None:
            return None
        parsed = dict(parsed)
        parsed["id"] = self._next_id
        self._next_id += 1
        # verdict & severity enrichment
        if engine is not None:
            remote = parsed["dst"] if parsed.get("direction") == "out" else parsed.get("src", "")
            try:
                if remote and engine.blocked(remote):
                    parsed["verdict"] = "BLOCKED"
                    parsed["severity"] = "critical"
            except Exception:
                pass
        if parsed.get("verdict") != "BLOCKED":
            proto = (parsed.get("protocol") or "").lower()
            if proto in ("dns", "http", "tls", "https", "icmp", "udp", "tcp", "ssh", "smb"):
                parsed["severity"] = "info"
        with self._lock:
            self._buf.append(parsed)
            self._proto_counts[parsed.get("protocol", "OTHER")] = \
                self._proto_counts.get(parsed.get("protocol", "OTHER"), 0) + 1
            self._sev_counts[parsed.get("severity", "info")] = \
                self._sev_counts.get(parsed.get("severity", "info"), 0) + 1
            d = parsed.get("direction")
            if d in self._dir_counts:
                self._dir_counts[d] += 1
                self._bytes[d] += parsed.get("length", 0)
        return parsed

    # -- query -------------------------------------------------------------
    def query(self, after_id: int = 0, limit: int = 300, proto: str = "",
              sev: str = "", direction: str = "", q: str = "",
              verdict: str = "") -> list:
        with self._lock:
            out = []
            ql = (q or "").lower()
            for p in reversed(self._buf):
                if p["id"] <= after_id:
                    continue
                if proto and proto.lower() != "all" and p.get("protocol", "").lower() != proto.lower():
                    continue
                if sev and sev.lower() != "all" and p.get("severity", "info").lower() != sev.lower():
                    continue
                if direction and direction.lower() != "all" and p.get("direction", "") != direction.lower():
                    continue
                if verdict and verdict.lower() != "all" and p.get("verdict", "ALLOW").lower() != verdict.lower():
                    continue
                if ql:
                    hay = f"{p.get('src','')} {p.get('dst','')} {p.get('protocol','')} {p.get('info','')}".lower()
                    if ql not in hay:
                        continue
                out.append(p)
                if len(out) >= limit:
                    break
        out.reverse()
        return out

    def clear(self):
        with self._lock:
            self._buf.clear()
            self._proto_counts.clear()
            self._sev_counts.clear()
            self._dir_counts = {"in": 0, "out": 0}
            self._bytes = {"in": 0, "out": 0}
            self._dropped = 0

    def stats(self) -> dict:
        with self._lock:
            return {
                "buffered": len(self._buf),
                "capacity": self.capacity,
                "capture_active": self.capture_active,
                "capture_error": self.capture_error,
                "proto_counts": dict(sorted(self._proto_counts.items(), key=lambda kv: -kv[1])),
                "severity_counts": dict(self._sev_counts),
                "direction_counts": dict(self._dir_counts),
                "bytes": dict(self._bytes),
                "dropped": self._dropped,
            }

    def latest_id(self) -> int:
        with self._lock:
            return self._buf[-1]["id"] if self._buf else 0


# ---------------------------------------------------------------------------
# Deterministic demo simulator (dev / offline only)
# ---------------------------------------------------------------------------

DEMO_APPS = [
    ("142.250.183.14", "IN"), ("172.217.169.78", "IN"), ("13.107.42.14", "OUT"),
    ("104.244.42.1", "OUT"), ("151.101.1.69", "OUT"), ("185.199.108.153", "OUT"),
    ("203.0.113.66", "IN"), ("45.83.66.200", "IN"), ("91.240.118.172", "IN"),
]

_SEV_INTRUSIONS = [
    ("TCP", "Port scan burst detected on ports 21-1024", "high"),
    ("SSH", "Brute force authentication attempts", "critical"),
    ("HTTP", "GET /wp-config.php — web admin probe", "high"),
    ("DNS", "Long-label DNS tunnel pattern", "medium"),
    ("TLS", "Client Hello (SNI: malicious-cdn.example.net)", "high"),
]


class DemoPacketSource(threading.Thread):
    """Feeds plausible synthetic packets into a PacketRecorder.

    Only started when explicitly requested (test server / demo mode);
    never runs in production unless cfg `netlens.simulator` is enabled.
    """

    def __init__(self, recorder: PacketRecorder, banned: Optional[set] = None):
        super().__init__(name="netlens_simulator", daemon=True)
        from .common import STOP
        self._stop_evt = STOP
        self.rec = recorder
        self.banned = banned or set()

    def _tcp_syn(self, src, dst, sport, dport):
        eth = bytes.fromhex("3c:22:fb:01:02:03".replace(":", "")) + bytes.fromhex("a4:bb:6d:11:22:33".replace(":", "")) + struct.pack("!H", 0x0800)
        ihl = 5
        total = 20 + 24
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0x1234, 0x4000, 64, 6, 0,
                         socket.inet_aton(src), socket.inet_aton(dst))
        tcp = struct.pack("!HHIIBBHHH", sport, dport, 1000 + sport, 500, 0x50, 0x02, 64240, 0, 0)
        return eth + ip + tcp

    def _udp_dns(self, src, dst, qname):
        eth = bytes.fromhex("3c:22:fb:01:02:03".replace(":", "")) + bytes.fromhex("a4:bb:6d:11:22:33".replace(":", "")) + struct.pack("!H", 0x0800)
        total = 20 + 8 + 12 + len(qname) + 6
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0x4321, 0, 64, 17, 0,
                         socket.inet_aton(src), socket.inet_aton(dst))
        udp = struct.pack("!HHHH", 33333, 53, 8 + 12 + len(qname) + 6, 0)
        q = struct.pack("!HHHHHH", 0xdead, 0x0100, 1, 0, 0, 0) + \
            bytes([len(qname)]) + qname.encode() + b"\x00" + struct.pack("!HH", 1, 1)
        return eth + ip + udp + q

    def run(self):
        import random
        self.rec.capture_active = True
        self.rec.capture_error = ""
        self.rec.started_at = time.time()
        tid = 0
        while not self._stop_evt.wait(0.7):
            tid += 1
            remote, direction = DEMO_APPS[tid % len(DEMO_APPS)]
            if direction == "IN":
                src, dst = remote, "192.168.1.10"
            else:
                src, dst = "192.168.1.10", remote
            kind = tid % 4
            if kind == 0:
                frame = self._udp_dns(src, dst, "api" + str(tid) + ".example.com")
            else:
                frame = self._tcp_syn(src, dst, 40000 + (tid % 2000), [443, 80, 22, 8080][kind - 1])
            parsed = deep_parse(frame, eth=True, direction=direction.lower(), iface="eth0")
            if parsed:
                if tid % 5 == 0:
                    proto, info, sev = _SEV_INTRUSIONS[(tid // 5) % len(_SEV_INTRUSIONS)]
                    parsed["protocol"], parsed["info"], parsed["severity"] = proto, info, sev
                if remote in self.banned:
                    parsed["verdict"], parsed["severity"] = "BLOCKED", "critical"
                self.rec.record(parsed)
