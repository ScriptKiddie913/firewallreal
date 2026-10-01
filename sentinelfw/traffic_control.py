"""SentinelFW Traffic Control & DDoS Mitigation Engine.

Provides token-bucket volumetric rate limiting, 3-way TCP handshake tracking
(anti-spoofing rail), ICMP/SYN flood mitigation, and connection burst protection.
"""
import collections
import ipaddress
import threading
import time
from typing import Dict, List, Optional, Set, Tuple


class TokenBucketLimiter:
    """Token-bucket volumetric rate limiter supporting per-IP and per-destination tracking."""

    def __init__(self, rate: float = 100.0, capacity: float = 200.0):
        self.rate = rate          # Tokens added per second
        self.capacity = capacity  # Maximum burst capacity
        self._buckets: Dict[str, Tuple[float, float]] = {}  # key -> (tokens, last_time)
        self._lock = threading.Lock()

    def allow(self, key: str, tokens: float = 1.0) -> bool:
        """Determines if the requested number of tokens can be consumed."""
        now = time.monotonic()
        with self._lock:
            toks, last = self._buckets.get(key, (self.capacity, now))
            delta = now - last
            toks = min(self.capacity, toks + delta * self.rate)
            if toks >= tokens:
                self._buckets[key] = (toks - tokens, now)
                return True
            else:
                self._buckets[key] = (toks, now)
                return False

    def remaining(self, key: str) -> float:
        """Returns the current available token balance for the key."""
        now = time.monotonic()
        with self._lock:
            if key not in self._buckets:
                return self.capacity
            toks, last = self._buckets[key]
            return min(self.capacity, toks + (now - last) * self.rate)

    def cleanup(self, max_idle: float = 300.0):
        """Purges idle token buckets to prevent unbounded memory growth."""
        now = time.monotonic()
        with self._lock:
            expired = [k for k, (_, last) in self._buckets.items() if now - last > max_idle]
            for k in expired:
                del self._buckets[k]


class HandshakeTracker:
    """
    Tracks TCP 3-way handshakes to confirm client address ownership.
    Prevents attackers from spoofing victim IPs to cause automated firewall bans.
    """

    def __init__(self, max_confirmed: int = 50000, half_open_timeout: float = 30.0):
        self._confirmed_ips: Set[str] = set()
        self._half_open: Dict[Tuple[str, int, str, int], float] = {}
        self.max_confirmed = max_confirmed
        self.half_open_timeout = half_open_timeout
        self._lock = threading.Lock()

    def observe_packet(self, proto: int, flags: int, src: str, sport: int, dst: str, dport: int):
        """Processes observed packet flags to track handshake state transitions."""
        if proto != 6:  # TCP only
            return
        now = time.monotonic()
        flow = (src, sport, dst, dport)
        rev_flow = (dst, dport, src, sport)

        with self._lock:
            # 1. Outgoing/Incoming SYN (Client initiation)
            if (flags & 0x12) == 0x02:
                self._half_open[flow] = now
            # 2. ACK packet without SYN (3rd packet of 3-way handshake or active data)
            elif (flags & 0x10) and not (flags & 0x02):
                if rev_flow in self._half_open or flow in self._half_open:
                    if len(self._confirmed_ips) >= self.max_confirmed:
                        self._confirmed_ips.pop()
                    self._confirmed_ips.add(src)
                    self._half_open.pop(flow, None)
                    self._half_open.pop(rev_flow, None)

    def mark_confirmed(self, ip: str):
        """Explicitly records an IP as confirmed (e.g. from established socket table)."""
        with self._lock:
            if len(self._confirmed_ips) >= self.max_confirmed:
                self._confirmed_ips.pop()
            self._confirmed_ips.add(ip)

    def is_confirmed(self, ip: str) -> bool:
        """Returns True if the IP has completed at least one verified TCP handshake."""
        with self._lock:
            return ip in self._confirmed_ips

    def cleanup(self):
        """Purges expired half-open connection tracking entries."""
        now = time.monotonic()
        with self._lock:
            expired = [k for k, t in self._half_open.items() if now - t > self.half_open_timeout]
            for k in expired:
                del self._half_open[k]


class AntiSpoofingGuard:
    """Enforces safety rails preventing forged packet sources from weaponizing firewall bans."""

    PROTECTED_DEFAULT_IPS = {"127.0.0.1", "1.1.1.1", "8.8.8.8", "9.9.9.9", "1.0.0.1", "8.8.4.4"}

    @classmethod
    def evaluate_ban(cls, ip: str, attack_score: int, handshake_confirmed: bool = False,
                     extra_protected: Optional[Set[str]] = None) -> Tuple[bool, str]:
        """
        Anti-spoofing scoring rail decision engine.
        Returns: (should_ban: bool, reason: str)
        """
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False, "invalid_ip"

        # 1. Loopback, private RFC1918, multicast, and well-known DNS/infrastructure are permanently protected
        RFC_1918 = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        )
        is_rfc1918 = any(a in net for net in RFC_1918)
        if a.is_loopback or a.is_multicast or a.is_link_local or is_rfc1918:
            return False, "protected"

        if str(a) in cls.PROTECTED_DEFAULT_IPS or (extra_protected and str(a) in extra_protected):
            return False, "protected"

        # 2. Handshake requirement rail:
        # Require 3-way handshake verification to ban at normal score levels (< 100).
        # Extremely high scores (>= 100, e.g. active high-rate exploit delivery or multi-vector attack)
        # can still be banned to mitigate emergency volumetric floods.
        if not handshake_confirmed and attack_score < 100:
            return False, "deferred_pending_handshake"

        if attack_score >= 50:
            return True, "banned"

        return False, "accumulating"


class FloodMitigator:
    """Aggregated traffic controller managing ICMP, SYN, and volumetric rate limits."""

    def __init__(self, icmp_pps: float = 20.0, syn_pps: float = 50.0, total_pps: float = 1000.0):
        self.icmp_limiter = TokenBucketLimiter(rate=icmp_pps, capacity=icmp_pps * 2)
        self.syn_limiter = TokenBucketLimiter(rate=syn_pps, capacity=syn_pps * 2)
        self.ip_limiter = TokenBucketLimiter(rate=total_pps, capacity=total_pps * 2)
        self.handshakes = HandshakeTracker()

    def inspect_packet(self, proto: int, flags: int, src: str, sport: int,
                       dst: str, dport: int, icmp_type: Optional[int] = None) -> Tuple[bool, Optional[str]]:
        """
        Evaluates an inbound packet against volumetric thresholds.
        Returns: (allow: bool, violation_type or None)
        """
        # Overall per-IP volumetric rate limiting
        if not self.ip_limiter.allow(src):
            return False, "volumetric_rate_limit_exceeded"

        # ICMP echo flood check
        if proto == 1 and icmp_type in (8, 0):  # Echo Request / Echo Reply
            if not self.icmp_limiter.allow(src):
                return False, "icmp_flood"

        # TCP SYN flood check
        if proto == 6 and (flags & 0x12) == 0x02:
            if not self.syn_limiter.allow(src):
                return False, "syn_flood"

        # Update handshake tracker
        if proto == 6:
            self.handshakes.observe_packet(proto, flags, src, sport, dst, dport)

        return True, None


traffic_controller = FloodMitigator()


# ===========================================================================
# Linux Kernel Traffic Control (tc) Engine: CAKE & HTB (Phase 44)
# ===========================================================================
import shutil
import subprocess

class LinuxTrafficControlManager:
    """
    Directly manages Linux kernel Traffic Control (tc) queuing disciplines.
    Provides line-rate CAKE (Common Applications Kept Enhanced) and HTB
    (Hierarchical Token Bucket) shaping with DSCP classification.
    """

    def __init__(self):
        self.tc_bin = shutil.which("tc")

    def is_available(self) -> bool:
        return self.tc_bin is not None

    def apply_cake(self, interface: str, bandwidth: str = "100mbit",
                   rtt: str = "100ms", diffserv: str = "diffserv4") -> Tuple[bool, str]:
        """
        Applies CAKE smart queue management (SQM) to an interface.
        Mitigates bufferbloat and provides per-flow fairness and DSCP priority queuing.
        """
        if not self.is_available():
            return False, "tc command not found on host"

        cmd = [
            self.tc_bin, "qdisc", "replace", "dev", interface, "root",
            "cake", "bandwidth", bandwidth, "rtt", rtt, diffserv, "ack-filter"
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                return True, f"CAKE SQM successfully enabled on {interface} ({bandwidth})"
            return False, f"tc error: {res.stderr.strip()}"
        except Exception as ex:
            return False, str(ex)

    def apply_htb(self, interface: str, default_rate: str = "100mbit",
                  classes: Optional[List[dict]] = None) -> Tuple[bool, str]:
        """
        Applies Hierarchical Token Bucket (HTB) shaping to an interface with guaranteed
        and burst limits per policy class using direct argument arrays.
        """
        if not self.is_available():
            return False, "tc command not found on host"

        # Validate interface name against command injection
        if not re.match(r"^[a-zA-Z0-9_\-\.:]+$", interface):
            return False, f"Invalid interface name: {interface}"

        commands = [
            [self.tc_bin, "qdisc", "del", "dev", interface, "root"],
            [self.tc_bin, "qdisc", "add", "dev", interface, "root", "handle", "1:", "htb", "default", "30"],
            [self.tc_bin, "class", "add", "dev", interface, "parent", "1:", "classid", "1:1", "htb", "rate", default_rate],
        ]

        if classes:
            for cls in classes:
                cid = str(cls.get("classid", "1:10"))
                rate = str(cls.get("rate", "10mbit"))
                ceil = str(cls.get("ceil", default_rate))
                prio = str(cls.get("prio", 1))
                mark = cls.get("mark")
                commands.append([self.tc_bin, "class", "add", "dev", interface, "parent", "1:1",
                                "classid", cid, "htb", "rate", rate, "ceil", ceil, "prio", prio])
                if mark is not None:
                    commands.append([self.tc_bin, "filter", "add", "dev", interface, "parent", "1:0",
                                    "protocol", "ip", "handle", str(mark), "fw", "classid", cid])
        else:
            commands.append([self.tc_bin, "class", "add", "dev", interface, "parent", "1:1",
                            "classid", "1:10", "htb", "rate", "50mbit", "ceil", default_rate, "prio", "1"])
            commands.append([self.tc_bin, "class", "add", "dev", interface, "parent", "1:1",
                            "classid", "1:30", "htb", "rate", "10mbit", "ceil", default_rate, "prio", "3"])

        try:
            for idx, cmd in enumerate(commands):
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                # First delete command is allowed to fail if no existing root qdisc
                if idx > 0 and res.returncode != 0:
                    return False, f"tc HTB error on {cmd}: {res.stderr.strip()}"
            return True, f"HTB shaping successfully configured on {interface}"
        except Exception as ex:
            return False, str(ex)

    def generate_tc_script(self, interface: str, qdisc_type: str = "cake",
                           bandwidth: str = "100mbit",
                           classes: Optional[List[dict]] = None) -> str:
        """Generates an idempotent shell script for applying tc shaping rules."""
        lines = [
            "#!/usr/bin/env bash",
            f"# SentinelGate Traffic Shaping for {interface}",
            "set -e",
            f"tc qdisc del dev {interface} root 2>/dev/null || true",
        ]

        if qdisc_type == "cake":
            lines.append(f"tc qdisc add dev {interface} root cake bandwidth {bandwidth} ack-filter diffserv4")
        elif qdisc_type == "htb":
            lines.append(f"tc qdisc add dev {interface} root handle 1: htb default 30")
            lines.append(f"tc class add dev {interface} parent 1: classid 1:1 htb rate {bandwidth}")
            if classes:
                for cls in classes:
                    cid = cls.get("classid", "1:10")
                    rate = cls.get("rate", "10mbit")
                    ceil = cls.get("ceil", bandwidth)
                    prio = cls.get("prio", 1)
                    mark = cls.get("mark")
                    lines.append(f"tc class add dev {interface} parent 1:1 classid {cid} htb rate {rate} ceil {ceil} prio {prio}")
                    if mark:
                        lines.append(f"tc filter add dev {interface} parent 1:0 protocol ip handle {mark} fw classid {cid}")
            else:
                lines.append(f"tc class add dev {interface} parent 1:1 classid 1:10 htb rate 50mbit ceil {bandwidth} prio 1")
                lines.append(f"tc class add dev {interface} parent 1:1 classid 1:30 htb rate 10mbit ceil {bandwidth} prio 3")

        return "\n".join(lines) + "\n"

    def teardown(self, interface: str) -> Tuple[bool, str]:
        """Removes all traffic shaping qdiscs from the given interface."""
        if not self.is_available():
            return False, "tc command not found"
        cmd = [self.tc_bin, "qdisc", "del", "dev", interface, "root"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return (res.returncode == 0, res.stderr.strip() if res.returncode != 0 else "Shaping removed")
        except Exception as ex:
            return False, str(ex)


tc_manager = LinuxTrafficControlManager()

