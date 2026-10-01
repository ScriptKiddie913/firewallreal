"""SentinelFW Stateful Dataplane Conntrack & NAT Session Engine.

Provides carrier-grade, packet-level state tracking across TCP, UDP, and ICMP (IPv4 & IPv6):
- Full TCP State Machine: NEW, SYN_SENT, SYN_RECV, ESTABLISHED, FIN_WAIT, CLOSE_WAIT, TIME_WAIT, INVALID
- TCP Flag validation & anomaly detection (SYN+FIN, NULL scan, XMAS, bare FIN)
- UDP bidirectional flow tracking with configurable timeouts
- ICMP Echo-Request / Echo-Reply state matching
- Stateful NAT & PAT (Port Address Translation) bidirectional session translation
- Per-source and per-destination connection limits and SYN flood protection
- Real-time diagnostics: active connections, connection rate, drops, invalid packets, top talkers/destinations
"""

import collections
import ipaddress
import threading
import time
from typing import Dict, List, Optional, Tuple


# Connection States
STATE_NEW = "NEW"
STATE_SYN_SENT = "SYN_SENT"
STATE_SYN_RECV = "SYN_RECV"
STATE_ESTABLISHED = "ESTABLISHED"
STATE_FIN_WAIT = "FIN_WAIT"
STATE_CLOSE_WAIT = "CLOSE_WAIT"
STATE_TIME_WAIT = "TIME_WAIT"
STATE_CLOSED = "CLOSED"
STATE_INVALID = "INVALID"

# Default State Timeouts in Seconds
TIMEOUT_SYN_SENT = 30
TIMEOUT_SYN_RECV = 30
TIMEOUT_ESTABLISHED = 3600  # 1 hour
TIMEOUT_FIN_WAIT = 60
TIMEOUT_CLOSE_WAIT = 60
TIMEOUT_TIME_WAIT = 120
TIMEOUT_UDP_SINGLE = 30
TIMEOUT_UDP_STREAM = 180
TIMEOUT_ICMP = 10


class Session:
    """Represents a single bidirectional stateful flow in the dataplane session table."""

    def __init__(self, session_id: int, src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str):
        self.id = session_id
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto = proto.lower()
        self.version = 6 if ":" in src_ip else 4

        # Tuples
        self.orig_tuple = (self.proto, self.src_ip, self.src_port, self.dst_ip, self.dst_port)
        self.reply_tuple = (self.proto, self.dst_ip, self.dst_port, self.src_ip, self.src_port)

        # NAT State (original -> translated)
        self.nat_type: Optional[str] = None  # "snat", "dnat", "pat", "masquerade"
        self.translated_tuple: Optional[Tuple[str, str, int, str, int]] = None

        # State & Sequence
        self.state = STATE_NEW
        self.created_at = time.time()
        self.last_seen = self.created_at
        self.timeout = TIMEOUT_SYN_SENT if self.proto == "tcp" else TIMEOUT_UDP_SINGLE

        # TCP Sequence tracking
        self.seq_orig = 0
        self.ack_orig = 0
        self.seq_reply = 0
        self.ack_reply = 0

        # Accounting
        self.packets_orig = 0
        self.bytes_orig = 0
        self.packets_reply = 0
        self.bytes_reply = 0

        # Security Inspection Flags
        self.fastpath_eligible = True
        self.needs_ips = False
        self.needs_av = False
        self.needs_tls = False
        self.needs_dlp = False
        self.needs_waf = False

        self.verdict = "ALLOW"
        self.policy_id: Optional[int] = None
        self.application: str = "unknown"

    def is_expired(self, now: float) -> bool:
        return (now - self.last_seen) > self.timeout

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "proto": self.proto,
            "version": self.version,
            "state": self.state,
            "src": f"{self.src_ip}:{self.src_port}",
            "dst": f"{self.dst_ip}:{self.dst_port}",
            "nat_type": self.nat_type,
            "translated": f"{self.translated_tuple[1]}:{self.translated_tuple[2]}->{self.translated_tuple[3]}:{self.translated_tuple[4]}" if self.translated_tuple else None,
            "packets_orig": self.packets_orig,
            "bytes_orig": self.bytes_orig,
            "packets_reply": self.packets_reply,
            "bytes_reply": self.bytes_reply,
            "duration": round(time.time() - self.created_at, 2),
            "fastpath_eligible": self.fastpath_eligible,
            "application": self.application,
        }


class StatefulFirewallEngine:
    """Core stateful packet inspector, conntrack session manager, and NAT engine."""

    def __init__(self, max_connections: int = 500000, max_per_source: int = 2000,
                 max_per_dest: int = 20000, syn_rate_limit: int = 300, ips_engine=None):
        self.max_connections = max_connections
        self.max_per_source = max_per_source
        self.max_per_dest = max_per_dest
        self.syn_rate_limit = syn_rate_limit
        self.ips_engine = ips_engine

        self.lock = threading.RLock()
        self._next_session_id = 1
        self._sessions: Dict[Tuple, Session] = {}  # tuple -> Session
        self._nat_sessions: Dict[Tuple, Session] = {}  # translated_reply_tuple -> Session

        # Aggregation and Limits Tracking
        self._src_counts = collections.defaultdict(int)
        self._dst_counts = collections.defaultdict(int)
        self._syn_rates = collections.defaultdict(lambda: collections.deque(maxlen=syn_rate_limit * 2))

        # Metrics
        self.metric_drops = 0
        self.metric_invalid = 0
        self.metric_syn_floods = 0
        self.metric_total_sessions = 0
        self._connection_rate_window = collections.deque(maxlen=1000)

        # Quarantine enclaves (IP -> { "reason": str, "expires": float, "allowed_ports": set })
        self._quarantined_hosts: Dict[str, dict] = {}

    def quarantine_host(self, ip: str, duration: int = 3600, reason: str = "Compromised host posture",
                        allowed_ports: Optional[set] = None):
        with self.lock:
            self._quarantined_hosts[ip] = {
                "reason": reason,
                "expires": time.time() + duration if duration > 0 else 0.0,
                "allowed_ports": allowed_ports or {53, 67, 68, 8443},
            }

    def unquarantine_host(self, ip: str):
        with self.lock:
            self._quarantined_hosts.pop(ip, None)

    def is_quarantined(self, ip: str) -> Optional[dict]:
        with self.lock:
            info = self._quarantined_hosts.get(ip)
            if not info:
                return None
            if info["expires"] > 0 and time.time() > info["expires"]:
                del self._quarantined_hosts[ip]
                return None
            return info

    def _allocate_pat_port(self) -> int:
        port = self._pat_port_current
        self._pat_port_current += 1
        if self._pat_port_current > self._pat_port_max:
            self._pat_port_current = 20000
        return port

    def process_packet(self, src_ip: str, dst_ip: str, proto: str, src_port: int = 0, dst_port: int = 0,
                       tcp_flags: Optional[Dict[str, bool]] = None, seq: int = 0, ack: int = 0,
                       payload_len: int = 0, payload: bytes = b"") -> Tuple[str, str, Optional[Session]]:
        """Processes a packet through the state machine.
        
        Returns:
            verdict: "ALLOW", "DROP", "REJECT", or "INVALID"
            reason: Explanation of the verdict
            session: Associated Session instance if valid, or None
        """
        clean_proto = proto.lower().strip()
        now = time.time()

        # Stage 0: Quarantine Enclave Enforcement
        q_src = self.is_quarantined(src_ip)
        q_dst = self.is_quarantined(dst_ip)
        if q_src or q_dst:
            q_info = q_src or q_dst
            target_port = dst_port if q_src else src_port
            if target_port not in q_info["allowed_ports"]:
                with self.lock:
                    self.metric_drops += 1
                return "DROP", f"Quarantine Enclave: Host isolated ({q_info['reason']})", None

        # Optional Deep IPS Inspection
        if self.ips_engine and payload:
            ips_verdict = self.ips_engine.inspect_packet({
                "proto": clean_proto,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "payload": payload,
            })
            if ips_verdict.get("action") in ("DROP", "RESET", "QUARANTINE"):
                with self.lock:
                    self.metric_drops += 1
                return "DROP", f"IPS Block: {ips_verdict.get('reason')}", None

        # 1. TCP Flag Validation & Anomaly Detection
        if clean_proto == "tcp" and tcp_flags is not None:
            syn = bool(tcp_flags.get("syn", False))
            ack_f = tcp_flags.get("ack", False)
            fin = tcp_flags.get("fin", False)
            rst = tcp_flags.get("rst", False)
            psh = tcp_flags.get("psh", False)
            urg = tcp_flags.get("urg", False)

            # Anomaly: NULL scan (no flags set)
            if not (syn or ack_f or fin or rst or psh or urg):
                with self.lock:
                    self.metric_invalid += 1
                    self.metric_drops += 1
                return "DROP", "TCP flag anomaly: NULL scan", None

            # Anomaly: SYN+FIN
            if syn and fin:
                with self.lock:
                    self.metric_invalid += 1
                    self.metric_drops += 1
                return "DROP", "TCP flag anomaly: SYN+FIN set", None

            # Anomaly: XMAS scan (FIN+PSH+URG or SYN+RST)
            if (fin and psh and urg) or (syn and rst):
                with self.lock:
                    self.metric_invalid += 1
                    self.metric_drops += 1
                return "DROP", "TCP flag anomaly: Invalid combination", None

            # Anomaly: FIN without ACK
            if fin and not ack_f:
                with self.lock:
                    self.metric_invalid += 1
                    self.metric_drops += 1
                return "DROP", "TCP flag anomaly: FIN without ACK", None

        forward_tuple = (clean_proto, src_ip, src_port, dst_ip, dst_port)
        reverse_tuple = (clean_proto, dst_ip, dst_port, src_ip, src_port)

        with self.lock:
            # 2. Existing Session Lookup (forward, reply, or NAT translated)
            session = self._sessions.get(forward_tuple)
            is_reply = False

            if not session:
                session = self._sessions.get(reverse_tuple)
                if session:
                    is_reply = True
                else:
                    # Check NAT reverse mapping
                    session = self._nat_sessions.get(forward_tuple)
                    if session:
                        is_reply = True

            # 3. New Session Path
            if not session:
                # SYN flood protection rate check
                if clean_proto == "tcp" and tcp_flags and tcp_flags.get("syn") and not tcp_flags.get("ack"):
                    syn_q = self._syn_rates[src_ip]
                    syn_q.append(now)
                    # Count SYN packets in the last 1 second
                    cutoff = now - 1.0
                    recent_syns = sum(1 for t in syn_q if t > cutoff)
                    if recent_syns > self.syn_rate_limit:
                        self.metric_syn_floods += 1
                        self.metric_drops += 1
                        return "DROP", f"SYN flood rate exceeded ({recent_syns}/s) from {src_ip}", None

                # Table Capacity Check
                if len(self._sessions) >= self.max_connections:
                    self._purge_expired(now)
                    if len(self._sessions) >= self.max_connections:
                        self.metric_drops += 1
                        return "DROP", "Connection table full (resource limit)", None

                # Per-source and per-destination limits
                if self._src_counts[src_ip] >= self.max_per_source:
                    self.metric_drops += 1
                    return "DROP", f"Per-source connection limit reached ({self.max_per_source}) for {src_ip}", None

                if self._dst_counts[dst_ip] >= self.max_per_dest:
                    self.metric_drops += 1
                    return "DROP", f"Per-destination connection limit reached ({self.max_per_dest}) for {dst_ip}", None

                # TCP: Only a clean SYN (without ACK) is allowed to initiate a new session
                if clean_proto == "tcp":
                    if not (tcp_flags and tcp_flags.get("syn") and not tcp_flags.get("ack")):
                        self.metric_invalid += 1
                        self.metric_drops += 1
                        return "DROP", "TCP out of state: Packet without active session", None

                session = Session(self._next_session_id, src_ip, dst_ip, src_port, dst_port, clean_proto)
                self._next_session_id += 1
                self.metric_total_sessions += 1
                self._connection_rate_window.append(now)

                self._sessions[forward_tuple] = session
                self._src_counts[src_ip] += 1
                self._dst_counts[dst_ip] += 1

                if clean_proto == "tcp":
                    session.state = STATE_SYN_SENT
                    session.seq_orig = seq
                    session.timeout = TIMEOUT_SYN_SENT
                elif clean_proto == "udp":
                    session.state = STATE_NEW
                    session.timeout = TIMEOUT_UDP_SINGLE
                elif clean_proto == "icmp":
                    session.state = STATE_NEW
                    session.timeout = TIMEOUT_ICMP

            # 4. State Update for Existing Session
            session.last_seen = now
            if not is_reply:
                session.packets_orig += 1
                session.bytes_orig += payload_len
            else:
                session.packets_reply += 1
                session.bytes_reply += payload_len

            # TCP State Transitions
            if clean_proto == "tcp" and tcp_flags:
                syn = tcp_flags.get("syn", False)
                ack_f = tcp_flags.get("ack", False)
                fin = tcp_flags.get("fin", False)
                rst = tcp_flags.get("rst", False)

                if rst:
                    session.state = STATE_CLOSED
                    session.timeout = 5
                elif is_reply and syn and ack_f and session.state == STATE_SYN_SENT:
                    session.state = STATE_SYN_RECV
                    session.seq_reply = seq
                    session.ack_reply = ack
                    session.timeout = TIMEOUT_SYN_RECV
                elif not is_reply and ack_f and session.state == STATE_SYN_RECV:
                    session.state = STATE_ESTABLISHED
                    session.timeout = TIMEOUT_ESTABLISHED
                elif fin:
                    if session.state in (STATE_ESTABLISHED, STATE_SYN_RECV):
                        session.state = STATE_FIN_WAIT if not is_reply else STATE_CLOSE_WAIT
                        session.timeout = TIMEOUT_FIN_WAIT
                    elif session.state in (STATE_FIN_WAIT, STATE_CLOSE_WAIT):
                        session.state = STATE_TIME_WAIT
                        session.timeout = TIMEOUT_TIME_WAIT

            # UDP State Transitions
            elif clean_proto == "udp":
                if is_reply and session.state == STATE_NEW:
                    session.state = STATE_ESTABLISHED
                    session.timeout = TIMEOUT_UDP_STREAM

            # ICMP State Transitions
            elif clean_proto == "icmp":
                if is_reply:
                    session.state = STATE_ESTABLISHED
                    session.timeout = 5

            return "ALLOW", f"Session #{session.id} ({session.state})", session

    def apply_pat(self, session: Session, gateway_ip: str) -> Tuple[str, int]:
        """Applies stateful Port Address Translation (PAT/Masquerade) to an outbound session."""
        with self.lock:
            pat_port = self._allocate_pat_port()
            session.nat_type = "pat"
            # Translated tuple: (proto, gateway_ip, pat_port, dst_ip, dst_port)
            session.translated_tuple = (session.proto, gateway_ip, pat_port, session.dst_ip, session.dst_port)
            
            # Register reverse return tuple for inbound replies: (proto, dst_ip, dst_port, gateway_ip, pat_port)
            reverse_nat_tuple = (session.proto, session.dst_ip, session.dst_port, gateway_ip, pat_port)
            self._nat_sessions[reverse_nat_tuple] = session
            return gateway_ip, pat_port

    def _purge_expired(self, now: float) -> int:
        """Removes expired sessions from the table."""
        expired_keys = [k for k, s in self._sessions.items() if s.is_expired(now)]
        for k in expired_keys:
            s = self._sessions.pop(k, None)
            if s:
                self._src_counts[s.src_ip] = max(0, self._src_counts[s.src_ip] - 1)
                self._dst_counts[s.dst_ip] = max(0, self._dst_counts[s.dst_ip] - 1)
                # Clean reverse NAT mapping
                if s.translated_tuple:
                    rev = (s.proto, s.dst_ip, s.dst_port, s.translated_tuple[1], s.translated_tuple[2])
                    self._nat_sessions.pop(rev, None)
        return len(expired_keys)

    # ------------------------------------------------------------- Diagnostics & Metrics
    def get_active_connections_count(self) -> int:
        with self.lock:
            return len(self._sessions)

    def get_connection_rate(self) -> float:
        """Calculates new connections per second over the last window."""
        with self.lock:
            if len(self._connection_rate_window) < 2:
                return 0.0
            now = time.time()
            cutoff = now - 5.0
            recent = [t for t in self._connection_rate_window if t > cutoff]
            return round(len(recent) / 5.0, 2)

    def get_drops_count(self) -> int:
        with self.lock:
            return self.metric_drops

    def get_invalid_packets_count(self) -> int:
        with self.lock:
            return self.metric_invalid

    def get_top_talkers(self, limit: int = 10) -> List[Tuple[str, int]]:
        with self.lock:
            sorted_talkers = sorted(self._src_counts.items(), key=lambda x: x[1], reverse=True)
            return sorted_talkers[:limit]

    def get_top_destinations(self, limit: int = 10) -> List[Tuple[str, int]]:
        with self.lock:
            sorted_dests = sorted(self._dst_counts.items(), key=lambda x: x[1], reverse=True)
            return sorted_dests[:limit]

    def list_sessions(self, limit: int = 50) -> List[dict]:
        with self.lock:
            return [s.to_dict() for s in list(self._sessions.values())[:limit]]

StatefulDataplane = StatefulFirewallEngine
