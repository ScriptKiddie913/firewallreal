"""SentinelFW Advanced C2 & Botnet Detection Engine.

Provides statistical beaconing analysis, inter-arrival time variance detection,
TLS fingerprint anomaly correlation, and dynamic C2_SCORE calculation (0–100).
"""
import collections
import math
import threading
import time
from typing import Dict, List, Optional, Tuple


class StatisticalBeaconDetector:
    """Detects metronomic periodic beaconing by analyzing inter-arrival time variance."""

    def __init__(self, min_samples: int = 5, max_cv: float = 0.22, window_size: int = 50):
        self.min_samples = min_samples
        self.max_cv = max_cv
        self.window_size = window_size
        self._flows: Dict[Tuple[str, str], collections.deque] = collections.defaultdict(lambda: collections.deque(maxlen=window_size))
        self._lock = threading.RLock()

    def record_connection(self, src_ip: str, dst_host: str, timestamp: Optional[float] = None) -> dict:
        """Records connection timestamp and evaluates statistical beaconing metrics."""
        t = timestamp if timestamp is not None else time.time()
        key = (src_ip.strip(), dst_host.strip().lower())

        with self._lock:
            q = self._flows[key]
            q.append(t)

            if len(q) < self.min_samples:
                return {
                    "is_beacon": False,
                    "samples": len(q),
                    "mean_interval": 0.0,
                    "cv": 1.0,
                    "beacon_score": 0,
                }

            # Calculate intervals
            intervals = [q[i] - q[i - 1] for i in range(1, len(q))]
            # Filter zero or negative intervals
            valid_intervals = [i for i in intervals if i > 0.001]
            if len(valid_intervals) < self.min_samples - 1:
                return {"is_beacon": False, "samples": len(q), "mean_interval": 0.0, "cv": 1.0, "beacon_score": 0}

            n = len(valid_intervals)
            mean = sum(valid_intervals) / n
            if mean <= 0.05:  # High-rate burst (e.g. streaming or webpage asset downloads)
                return {"is_beacon": False, "samples": n, "mean_interval": mean, "cv": 1.0, "beacon_score": 0}

            variance = sum((x - mean) ** 2 for x in valid_intervals) / n
            std_dev = math.sqrt(variance)
            cv = std_dev / mean  # Coefficient of Variation

            is_beacon = cv <= self.max_cv
            # Lower CV means higher regularity -> higher beacon score
            beacon_score = max(0, min(100, int((1.0 - cv) * 100))) if is_beacon else int(max(0, (1.0 - cv) * 40))

            return {
                "is_beacon": is_beacon,
                "samples": n,
                "mean_interval": round(mean, 2),
                "std_dev": round(std_dev, 2),
                "cv": round(cv, 3),
                "beacon_score": beacon_score,
            }

    def get_flow_stats(self, src_ip: str, dst_host: str) -> dict:
        """Returns current statistical beacon metrics for a flow without recording a new timestamp."""
        key = (src_ip.strip(), dst_host.strip().lower())
        with self._lock:
            q = self._flows.get(key)
            if not q or len(q) < self.min_samples:
                return {"is_beacon": False, "samples": len(q) if q else 0, "mean_interval": 0.0, "cv": 1.0, "beacon_score": 0}

            intervals = [q[i] - q[i - 1] for i in range(1, len(q))]
            valid_intervals = [i for i in intervals if i > 0.001]
            if len(valid_intervals) < self.min_samples - 1:
                return {"is_beacon": False, "samples": len(q), "mean_interval": 0.0, "cv": 1.0, "beacon_score": 0}

            n = len(valid_intervals)
            mean = sum(valid_intervals) / n
            if mean <= 0.05:
                return {"is_beacon": False, "samples": n, "mean_interval": mean, "cv": 1.0, "beacon_score": 0}

            variance = sum((x - mean) ** 2 for x in valid_intervals) / n
            std_dev = math.sqrt(variance)
            cv = std_dev / mean

            is_beacon = cv <= self.max_cv
            beacon_score = max(0, min(100, int((1.0 - cv) * 100))) if is_beacon else int(max(0, (1.0 - cv) * 40))

            return {
                "is_beacon": is_beacon,
                "samples": n,
                "mean_interval": round(mean, 2),
                "std_dev": round(std_dev, 2),
                "cv": round(cv, 3),
                "beacon_score": beacon_score,
            }

    def clear(self):
        with self._lock:
            self._flows.clear()


class C2RiskScorer:
    """Calculates unified C2_SCORE combining statistical, reputation, and protocol signals."""

    def __init__(self, beacon_detector: Optional[StatisticalBeaconDetector] = None):
        self.beacon_detector = beacon_detector or StatisticalBeaconDetector()

    def evaluate_c2(self, src_ip: str, dst_host: str,
                    reputation_hit: bool = False,
                    dns_tunnel_or_dga: bool = False,
                    suspicious_tld_or_typo: bool = False,
                    rare_destination: bool = False,
                    timestamp: Optional[float] = None) -> dict:
        """Evaluates unified C2 score (0-100) and renders mitigation verdict."""
        if timestamp is not None:
            beacon_stats = self.beacon_detector.record_connection(src_ip, dst_host, timestamp=timestamp)
        else:
            beacon_stats = self.beacon_detector.get_flow_stats(src_ip, dst_host)

        score = 0
        signals = []

        # 1. Statistical beaconing component (up to 45 pts)
        if beacon_stats["is_beacon"]:
            b_pts = int(beacon_stats["beacon_score"] * 0.45)
            score += b_pts
            signals.append(f"Metronomic beaconing detected (interval: {beacon_stats['mean_interval']}s, CV: {beacon_stats['cv']})")

        # 2. Threat intelligence reputation hit (+40 pts)
        if reputation_hit:
            score += 40
            signals.append("Destination matches active threat intelligence IOC")

        # 3. DNS Tunnel or DGA (+35 pts)
        if dns_tunnel_or_dga:
            score += 35
            signals.append("DNS query exhibits tunneling or DGA patterns")

        # 4. Suspicious TLD or typosquatting (+20 pts)
        if suspicious_tld_or_typo:
            score += 20
            signals.append("High-risk TLD or brand typosquatting imitation")

        # 5. Rare external destination (+15 pts)
        if rare_destination:
            score += 15
            signals.append("Rare / low-reputation autonomous system destination")

        total_score = min(100, score)

        # Verdict assignment
        if total_score >= 80:
            action = "QUARANTINE"
            severity = "CRITICAL"
        elif total_score >= 60:
            action = "BLOCK"
            severity = "HIGH"
        elif total_score >= 40:
            action = "ALERT"
            severity = "MEDIUM"
        else:
            action = "ALLOW"
            severity = "LOW"

        return {
            "c2_score": total_score,
            "action": action,
            "severity": severity,
            "signals": signals,
            "beacon_metrics": beacon_stats,
            "src_ip": src_ip,
            "dst_host": dst_host,
        }
