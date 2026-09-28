"""SentinelFW detector module."""
import argparse, bisect, collections, fnmatch, functools, hashlib, ipaddress, json, logging, logging.handlers, math, os, re, shutil, signal, socket, struct, subprocess, sys, threading, time, urllib.request, uuid
from pathlib import Path
from .common import *  # noqa
from .packets import *  # noqa
from .netlens import deep_parse


class Window:
    def __init__(self, span):
        self.span = span
        self.d = collections.defaultdict(lambda: collections.deque(maxlen=4096))

    def add(self, key, val, now):
        q = self.d[key]
        q.append((now, val))
        cut = now - self.span
        while q and q[0][0] < cut:
            q.popleft()
        return q

    def gc(self, now):
        for k in [k for k, q in self.d.items() if not q or q[-1][0] < now - self.span]:
            del self.d[k]
        if len(self.d) > 200000:
            self.d.clear()


class Detector:
    def __init__(self, eng):
        self.e = eng
        t = self.t = eng.cfg["thresholds"]
        self.w = {n: Window(t[s]) for n, s in (("ports", "port_scan_window"), ("syn", "syn_flood_window"),
                                               ("bf", "brute_force_window"), ("icmp", "icmp_flood_window"),
                                               ("udp", "port_scan_window"), ("sweep", "sweep_window"))}
        self.w["dns"] = Window(60)
        self.sigs = []
        for s in eng.cfg["payload_signatures"]:
            try:
                self.sigs.append((s["name"], re.compile(s["regex"].encode("latin-1"))))
            except (re.error, KeyError, UnicodeEncodeError) as ex:
                event("signature_error", "medium", sig=s, error=ex)
        self.bf_ports = set(t["brute_force_ports"])
        self.quiet = {}
        self.gsyn = collections.deque(maxlen=20000)
        self.last_gc = time.monotonic()

    def once(self, key, secs):
        now = time.monotonic()
        if now - self.quiet.get(key, -1e9) < secs:
            return False
        self.quiet[key] = now
        return True

    def gc(self, now):
        for w in self.w.values():
            w.gc(now)
        m = time.monotonic()
        self.quiet = {k: v for k, v in self.quiet.items() if m - v < 3600}
        self.last_gc = now

    def inspect(self, p, outbound, now):
        e = self.e
        e.stats["packets"] += 1
        if now - self.last_gc > 30:
            self.gc(now)
        remote = p["dst"] if outbound else p["src"]
        if e.blocked(remote):
            e.stats["blocklisted_packets"] += 1
            if self.once(("bl", remote, outbound), 60):
                event("blocked_traffic_seen", "medium", remote=remote, direction="out" if outbound else "in",
                      proto=p["proto"], port=p["dport"] if outbound else p["sport"])
            return
        if p["proto"] == 17 and 53 in (p["sport"], p["dport"]):
            self.dns(p, outbound, now)
        if outbound:
            self.outbound(p, now)
            return
        src, proto, t = p["src"], p["proto"], self.t
        if e.guard.protected(src):
            return
        e.stats["inbound"] += 1
        if proto == 6:
            f = p["flags"]
            if f == 0 or (f & 0x29) == 0x29 or (f & 0x03) == 0x03 or (f & 0x06) == 0x06:
                e.ban(src, f"invalid_tcp_flags:{f:02x}")
                return
            if (f & 0x12) == 0x02:
                self.syn(p, now)
            if p["payload"] and self.sigs:
                data = p["payload"][:4096]
                for name, rx in self.sigs:
                    if rx.search(data):
                        event("ids_signature", "high", src=src, dport=p["dport"], name=name)
                        e.ban(src, f"signature:{name}")
                        return
        elif proto == 17 and p["dport"] not in (53, 67, 68, 123, 5353):
            q = self.w["udp"].add(src, p["dport"], now)
            if len(q) >= t["port_scan_ports"] and len({v for _, v in q}) >= t["port_scan_ports"]:
                e.ban(src, "udp_port_scan")
        elif p["icmp"] in (8, 128):
            q = self.w["icmp"].add(src, 0, now)
            if len(q) >= t["icmp_flood_count"]:
                e.ban(src, "icmp_flood")

    def syn(self, p, now):
        e, t, src, dport = self.e, self.t, p["src"], p["dport"]
        self.gsyn.append(now)
        while self.gsyn and self.gsyn[0] < now - 2:
            self.gsyn.popleft()
        if len(self.gsyn) > 5000 and self.once("gsyn", 60):
            event("distributed_syn_flood", "high", syn_per_2s=len(self.gsyn), note="many sources; no single IP to ban")
        q = self.w["syn"].add(src, 0, now)
        if len(q) >= t["syn_flood_rate"] * t["syn_flood_window"]:
            e.ban(src, "syn_flood")
            return
        q = self.w["ports"].add(src, dport, now)
        if len(q) >= t["port_scan_ports"] and len({v for _, v in q}) >= t["port_scan_ports"]:
            e.ban(src, "port_scan")
            return
        if dport in self.bf_ports:
            q = self.w["bf"].add((src, dport), 0, now)
            if len(q) >= t["brute_force_attempts"]:
                e.ban(src, f"brute_force:{dport}")

    def outbound(self, p, now):
        if p["proto"] == 6 and (p["flags"] & 0x12) == 0x02:
            t = self.t
            q = self.w["sweep"].add(p["dport"], p["dst"], now)
            if len(q) >= t["sweep_hosts"] and len({v for _, v in q}) >= t["sweep_hosts"] and self.once(("sweep", p["dport"]), 120):
                event("outbound_sweep", "high", port=p["dport"], hosts=len({v for _, v in q}),
                      note="this host is scanning many targets - possible compromise")

    def dns(self, p, outbound, now):
        d = parse_dns(p["payload"])
        if not d:
            return
        e = self.e
        for q in d["questions"]:
            blocked = e.domain_blocked(q)
            if outbound and not d["response"]:
                e.stats["dns_queries"] += 1
                if blocked and self.once(("dq", q), 60):
                    event("dns_blocked_query", "medium", domain=q)
                self.tunnel(q, now)
            elif d["response"] and blocked:
                if self.once(("da", q), 60):
                    event("dns_blocked_answer", "high", domain=q, answers=",".join(d["answers"][:8]))
                if e.cfg["dns_block_resolved_ips"]:
                    for ip in d["answers"]:
                        e.ban(ip, f"dns:{q}", 3600, "dns")

    def tunnel(self, q, now):
        labels = q.split(".")
        longest = max(labels, key=len)
        if (len(longest) >= 52 or len(q) >= 120 or (len(longest) >= 30 and entropy(longest) > 3.7)) and self.once(("dt", q[-50:]), 120):
            event("dns_tunnel_suspect", "medium", qname=q[:120])
        parent = ".".join(labels[-2:])
        qd = self.w["dns"].add(parent, labels[0], now)
        if len(qd) >= 150 and len({v for _, v in qd}) >= 120 and self.once(("dtr", parent), 120):
            event("dns_tunnel_suspect", "high", parent=parent, unique_subdomains_60s=len({v for _, v in qd}))


class Sniffer(threading.Thread):
    daemon = True

    def __init__(self, eng):
        super().__init__(name="sniffer")
        self.e = eng
        self.det = Detector(eng)

    def _open(self):
        if IS_LINUX:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
            except OSError:
                pass
        else:
            ip = next((i for i in self.e.guard.local if ":" not in i and not i.startswith("127.")), None)
            if not ip:
                raise RuntimeError("no IPv4 interface found for raw capture")
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.bind((ip, 0))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        s.settimeout(1.0)
        return s

    def run(self):
        try:
            sock = self._open()
        except Exception as ex:  # noqa: BLE001
            event("sniffer_unavailable", "high", error=ex)
            if hasattr(self.e, "recorder") and self.e.recorder is not None:
                self.e.recorder.capture_error = str(ex)
            return
        event("sniffer_started", mode="AF_PACKET" if IS_LINUX else "SIO_RCVALL(IPv4 only)")
        if hasattr(self.e, "recorder") and self.e.recorder is not None:
            self.e.recorder.capture_active = True
            self.e.recorder.started_at = time.time()
        local = self.e.guard.local
        while not STOP.is_set():
            try:
                data, a = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                p = parse_packet(data, IS_LINUX)
                if not p:
                    continue
                if IS_LINUX:
                    if a[2] == 4:
                        out = True
                    elif a[2] == 0:
                        out = False
                    else:
                        continue
                else:
                    local = self.e.guard.local
                    if p["src"] in local:
                        out = True
                    elif p["dst"] in local:
                        out = False
                    else:
                        continue
                # Wireshark-grade deep parse + ring buffer for the Web UI
                if getattr(self.e, "recorder", None) is not None:
                    try:
                        enriched = deep_parse(data, IS_LINUX, "out" if out else "in",
                                               (a[0] or "") if IS_LINUX else "")
                        if enriched is not None:
                            self.e.recorder.record(enriched, engine=self.e)
                    except Exception:  # noqa: BLE001
                        pass
                # Real byte/packet accounting per flow for live rates
                try:
                    self.e.conntrack.update_flow_stats(
                        "tcp" if p["proto"] == 6 else "udp" if p["proto"] == 17 else str(p["proto"]),
                        p["src"], p["sport"], p["dst"], p["dport"], len(data), 1)
                except Exception:  # noqa: BLE001
                    pass
                self.det.inspect(p, out, time.monotonic())
            except Exception as ex:  # noqa: BLE001
                event("sniffer_error", "medium", error=repr(ex))
        if IS_WIN:
            try:
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except OSError:
                pass
        sock.close()
