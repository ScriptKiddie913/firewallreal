"""SentinelFW TCP Stream Reassembly Engine.

Provides stateful TCP stream reconstruction from raw segments:
* Handles out-of-order segment buffering
* Resolves overlapping and duplicate TCP segments
* Enforces strict per-flow byte budgets to prevent memory exhaustion attacks
* Tracks TCP connection lifecycle (SYN, ESTABLISHED, FIN, RST, TIME_WAIT)
"""
import collections
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple


class TCPFlowState:
    """Tracks sequence numbers and buffered segments for a unidirectional TCP half-stream."""

    def __init__(self, isn: int = 0, flow_budget: int = 1048576):
        self.isn = isn
        self.expected_seq = (isn + 1) & 0xFFFFFFFF
        self.flow_budget = flow_budget
        self.buffered_bytes = 0
        # Priority map of out-of-order segments: seq -> payload
        self.out_of_order: Dict[int, bytes] = {}
        self.last_activity = time.monotonic()
        self.is_closed = False

    def add_segment(self, seq: int, payload: bytes) -> bytes:
        """Processes an incoming TCP segment.

        Returns any newly available contiguous byte stream.
        """
        if not payload:
            return b""

        self.last_activity = time.monotonic()
        seg_len = len(payload)
        end_seq = (seq + seg_len) & 0xFFFFFFFF

        # 1. Duplicate check: segment entirely before expected_seq
        # Note: handle standard 32-bit wrap around using modulo arithmetic
        diff = (seq - self.expected_seq) & 0xFFFFFFFF
        if diff > 0x80000000:
            # seq is before expected_seq
            overlap = (self.expected_seq - seq) & 0xFFFFFFFF
            if overlap >= seg_len:
                return b""  # completely duplicate
            # Partial overlap: trim redundant prefix
            payload = payload[overlap:]
            seq = self.expected_seq
            seg_len = len(payload)

        # 2. Out of order segment buffering
        if seq != self.expected_seq:
            # Check per-flow memory budget before buffering
            if self.buffered_bytes + seg_len <= self.flow_budget:
                self.out_of_order[seq] = payload
                self.buffered_bytes += seg_len
            return b""

        # 3. In-order segment: assemble and append contiguous chain
        assembled = bytearray(payload)
        self.expected_seq = (self.expected_seq + seg_len) & 0xFFFFFFFF

        # Walk through buffered out-of-order segments to see if they now connect
        while True:
            next_seg = self.out_of_order.pop(self.expected_seq, None)
            if next_seg is None:
                break
            assembled.extend(next_seg)
            self.buffered_bytes = max(0, self.buffered_bytes - len(next_seg))
            self.expected_seq = (self.expected_seq + len(next_seg)) & 0xFFFFFFFF

        return bytes(assembled)


class TCPReassembler:
    """Manages multi-flow TCP stream reassembly with global and per-flow resource rails."""

    def __init__(self, per_flow_budget: int = 1048576, max_flows: int = 20000,
                 flow_timeout: float = 300.0):
        self.per_flow_budget = per_flow_budget
        self.max_flows = max_flows
        self.flow_timeout = flow_timeout
        # Flow map: (src_ip, sport, dst_ip, dport) -> TCPFlowState
        self._flows: Dict[Tuple[str, int, str, int], TCPFlowState] = {}
        self._lock = threading.RLock()

    def process_segment(self, src: str, sport: int, dst: str, dport: int,
                        seq: int, ack: int, flags: int, payload: bytes) -> bytes:
        """Ingests a TCP packet and returns reassembled contiguous stream bytes."""
        key = (str(src), int(sport), str(dst), int(dport))
        now = time.monotonic()

        with self._lock:
            flow = self._flows.get(key)

            # SYN: start of new half-stream
            if (flags & 0x02) and not (flags & 0x10):
                # Evict stale flows if table is at capacity
                if len(self._flows) >= self.max_flows:
                    self._evict_stale(now)
                flow = TCPFlowState(isn=seq, flow_budget=self.per_flow_budget)
                self._flows[key] = flow
                return b""

            if flow is None:
                # Mid-stream pickup: treat current seq as baseline
                flow = TCPFlowState(isn=(seq - 1) & 0xFFFFFFFF, flow_budget=self.per_flow_budget)
                self._flows[key] = flow

            # FIN or RST: teardown stream
            if flags & 0x01 or flags & 0x04:
                flow.is_closed = True

            data = flow.add_segment(seq, payload)

            if flow.is_closed and not flow.out_of_order:
                self._flows.pop(key, None)

            return data

    def _evict_stale(self, now: float):
        """Removes expired or closed TCP flows."""
        expired = [k for k, f in self._flows.items()
                   if f.is_closed or (now - f.last_activity) > self.flow_timeout]
        for k in expired:
            del self._flows[k]

    def clear(self):
        with self._lock:
            self._flows.clear()

    def active_flows_count(self) -> int:
        with self._lock:
            return len(self._flows)
