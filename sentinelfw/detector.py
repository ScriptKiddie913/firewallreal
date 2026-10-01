"""SentinelFW detector module."""
import argparse, bisect, collections, fnmatch, functools, hashlib, ipaddress, json, logging, logging.handlers, math, os, re, shutil, signal, socket, struct, subprocess, sys, threading, time, urllib.request, uuid
from pathlib import Path
from .common import *  # noqa
from .packets import *  # noqa
from .netlens import deep_parse


def _mostly_printable(data: bytes, sample: int = 512, threshold: float = 0.85) -> bool:
    """True when the payload looks like plaintext (HTTP/FTP/SMTP/Telnet)."""
    chunk = data[:sample]
    if not chunk:
        return False
    printable = sum(1 for b in chunk if 32 <= b <= 126 or b in (9, 10, 13))
    return printable / len(chunk) >= threshold


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
        self.w["amp"] = Window(60)
        self.arp_cache = {}  # ip -> (mac, timestamp)
        self.dhcp_servers = set()
        self.llmnr_queries = {}
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
                # Payload signatures only fire on plaintext traffic.
                # Encrypted/binary payloads (TLS on 443/8443, SSH banners, RDP)
                # regularly contain byte sequences that coincidentally match
                # injection patterns, which used to ban half the internet.
                if p["dport"] not in (443, 8443, 22, 3389, 993, 995) and _mostly_printable(data):
                    for name, rx in self.sigs:
                        if rx.search(data):
                            event("ids_signature", "high", src=src, dport=p["dport"], name=name)
                            e.ban(src, f"signature:{name}")
                            return
        elif proto == 17:
            # Check for amplification attacks (DNS, NTP, SSDP, Memcached, CLDAP)
            if p["sport"] in (53, 123, 1900, 11211, 389) and len(p.get("payload") or b"") >= 300:
                self.check_amplification(p, now)
            # Check for rogue DHCP
            if p["dport"] in (67, 68) or p["sport"] in (67, 68):
                self.check_dhcp(p, now)
            # Check for LLMNR / NetBIOS poisoning
            if p["dport"] in (5355, 137):
                self.check_llmnr(p, now)
            if p["dport"] not in (53, 67, 68, 123, 5353):
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

    def check_amplification(self, p, now):
        """Classifies amplification DDoS reflections with tiered defensive responses."""
        sport = p["sport"]
        src = p["src"]
        payload = p.get("payload") or b""
        payload_len = len(payload)

        amp_type = "unknown_amplification"
        is_amp = False

        if sport == 53 and payload_len > 512:
            amp_type = "dns_amplification"
            is_amp = True
        elif sport == 123 and (payload.startswith(b"\x17\x00") or payload.startswith(b"\x16\x02") or payload_len > 400):
            amp_type = "ntp_monlist_amplification"
            is_amp = True
        elif sport == 1900 and (b"HTTP/1.1 200 OK" in payload or payload_len > 300):
            amp_type = "ssdp_amplification"
            is_amp = True
        elif sport == 11211 and (b"STAT " in payload or payload_len > 1024):
            amp_type = "memcached_amplification"
            is_amp = True
        elif sport == 389 and payload_len > 1024:
            amp_type = "cldap_amplification"
            is_amp = True

        if not is_amp:
            return

        # Add to rolling window for volumetric rate evaluation
        q = self.w["amp"].add(src, payload_len, now)
        vol = len(q)
        total_bytes = sum(b for _, b in q)

        # Tier Selection:
        # Tier 1 (low volume / first bursts): rate limit alert
        # Tier 2 (sustained flood): 1-hour ban
        # Tier 3 (massive reflection / >50KB/s or >20 pkts/min): 24-hour ban + kernel offload
        if vol >= 20 or total_bytes > 50000 or payload_len > 4096:
            tier = 3
            ban_duration = 86400
        elif vol >= 5 or total_bytes > 5000:
            tier = 2
            ban_duration = 3600
        else:
            tier = 1
            ban_duration = 0

        if self.once((amp_type, src), 30):
            event(amp_type, "high" if tier == 2 else ("critical" if tier == 3 else "medium"),
                  src=src, sport=sport, payload_bytes=payload_len, rate_60s=vol,
                  total_bytes_60s=total_bytes, tier=tier)

        if tier >= 2 and not self.e.guard.protected(src):
            self.e.ban(src, f"{amp_type}:tier{tier}", ban_duration)

    def check_dhcp(self, p, now):
        """Detects rogue DHCP offers and acknowledgments from unauthorized servers."""
        src = p["src"]
        payload = p.get("payload") or b""
        # DHCP message type is typically option 53 (0x35, len 1, type)
        # Type 2 = DHCPOFFER, Type 5 = DHCPACK
        if b"\x35\x01\x02" in payload or b"\x35\x01\x05" in payload:
            is_gateway = src in getattr(self.e.guard, "gateways", set()) or src == "0.0.0.0"
            is_known = src in self.dhcp_servers or self.e.guard.protected(src)
            if not is_gateway and not is_known:
                if self.once(("rogue_dhcp", src), 60):
                    event("rogue_dhcp_detected", "critical", rogue_server_ip=src,
                          note="unauthorized DHCP response detected on local broadcast domain")

    def check_llmnr(self, p, now):
        """Detects LLMNR and NetBIOS poisoning / spoofed name resolutions."""
        src = p["src"]
        payload = p.get("payload") or b""
        if len(payload) >= 2:
            tx_id = payload[:2]
            # Check if this is a response (flags QR bit set)
            if len(payload) >= 4 and (payload[2] & 0x80):
                prior_src = self.llmnr_queries.get(tx_id)
                if prior_src and prior_src != src:
                    if self.once(("llmnr_poison", tx_id), 60):
                        event("llmnr_nbt_poisoning_suspect", "high", responder_ip=src,
                              conflicting_ip=prior_src,
                              note="multiple conflicting LLMNR/NBT-NS responses for single query")
                else:
                    self.llmnr_queries[tx_id] = src

    def check_arp(self, ip: str, mac: str, now: float):
        """Detects ARP spoofing / cache poisoning (gratuitous ARP mismatch)."""
        if not ip or not mac or ip in ("0.0.0.0", "255.255.255.255"):
            return
        cur = self.arp_cache.get(ip)
        if cur:
            old_mac, _ = cur
            if old_mac.lower() != mac.lower():
                if self.once(("arp_spoof", ip), 60):
                    event("arp_spoof_detected", "critical", ip=ip,
                          current_mac=mac, previous_mac=old_mac,
                          note="conflicting MAC address mapping detected for IP")
        self.arp_cache[ip] = (mac, now)


class Sniffer(threading.Thread):
    daemon = True

    def __init__(self, eng):
        super().__init__(name="sniffer")
        self.e = eng
        self.det = Detector(eng)

    def _open(self):
        """Returns a list of capture sockets covering EVERY active interface.

        Linux: one AF_PACKET socket captures all interfaces at once.
        Windows: one RCVALL raw socket per local IPv4 — the old single-socket
        bind missed adapters (typically grabbing a VMware/Hyper-V virtual NIC
        and none of the real traffic).
        """
        if IS_LINUX:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
            except OSError:
                pass
            s.settimeout(1.0)
            return [s]
        socks = []
        bind_ips = [i for i in self.e.guard.local if ":" not in i and not i.startswith("127.")]
        override = self.e.cfg.get("sniffer", {}).get("bind_ips", [])
        if override:
            bind_ips = [i for i in override if ":" not in i]
        for ip in bind_ips:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                s.bind((ip, 0))
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                s.settimeout(1.0)
                socks.append(s)
            except OSError as ex:
                event("sniffer_iface_failed", "low", ip=ip, error=str(ex)[:120])
        if not socks:
            raise RuntimeError("no IPv4 interface could be opened for raw capture "
                               "(run as Administrator / root)")
        return socks

    def run(self):
        try:
            socks = self._open()
        except Exception as ex:  # noqa: BLE001
            event("sniffer_unavailable", "high", error=ex)
            if hasattr(self.e, "recorder") and self.e.recorder is not None:
                self.e.recorder.capture_error = str(ex)
            return
        event("sniffer_started", mode="AF_PACKET (all ifaces)" if IS_LINUX else
              f"SIO_RCVALL ({len(socks)} interface(s))")
        if hasattr(self.e, "recorder") and self.e.recorder is not None:
            self.e.recorder.capture_active = True
            self.e.recorder.started_at = time.time()
        import select as _select
        while not STOP.is_set():
            try:
                rlist, _, _ = _select.select(socks, [], [], 1.0)
                if not rlist:
                    continue
                data, a = rlist[0].recvfrom(65535)
            except (_select.error, OSError):
                continue
            except Exception:  # noqa: BLE001
                break
            try:
                p = parse_packet(data, IS_LINUX)
                if not p:
                    continue
                third_party = False
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
                        # pass-by wire traffic (visible thanks to promiscuous
                        # RCVALL): show it in the packet monitor, but never run
                        # ban heuristics or flow accounting on it
                        out = False
                        third_party = True
                # Wireshark-grade deep parse + ring buffer for the Web UI
                if getattr(self.e, "recorder", None) is not None:
                    try:
                        direction = "other" if third_party else ("out" if out else "in")
                        enriched = deep_parse(data, IS_LINUX, direction,
                                               (a[0] or "") if IS_LINUX else "")
                        if enriched is not None:
                            self.e.recorder.record(enriched, engine=self.e)
                            # JA3 blocklist enforcement
                            tls = (enriched.get("layers") or {}).get("tls") or {}
                            ja3 = tls.get("ja3")
                            if ja3 and ja3 in (self.e.cfg.get("ja3_blocklist") or []):
                                fp = p["dst"] if out else p["src"]
                                if fp and not self.e.trusted(fp):
                                    self.e.ban(fp, f"ja3:{ja3[:12]}", 86400, "ja3")
                        # forensic PCAP ring (raw IP/eth frames, bounded)
                        ring = getattr(self.e, "pcap_ring", None)
                        if ring is not None and ring.enabled():
                            ring.add(time.time(), data, IS_LINUX)
                    except Exception:  # noqa: BLE001
                        pass
                if third_party:
                    continue
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
        for s in socks:
            try:
                if IS_WIN:
                    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass
