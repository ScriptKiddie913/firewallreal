"""SentinelFW Anomaly Detection and Baseline Engine.

Maintains rolling statistical baselines for system and network traffic metrics
and computes Z-scores to identify statistical outliers and sudden attacks.
"""
import collections
import math
import threading
import time
from typing import Dict, List, Tuple
from .common import STOP, event


class RollingMetric:
    """Maintains running statistical mean and standard deviation for a single metric."""

    def __init__(self, name: str, window_samples: int = 1440):  # default 24h at 1 sample/min
        self.name = name
        self.window = collections.deque(maxlen=window_samples)
        self.count = 0
        self.mean = 0.0
        self.m2 = 0.0  # sum of squares of differences from current mean (Welford's)

    def add(self, value: float):
        val = float(value)
        self.window.append(val)
        self.count += 1
        delta = val - self.mean
        self.mean += delta / min(self.count, len(self.window))
        delta2 = val - self.mean
        self.m2 += delta * delta2

    @property
    def variance(self) -> float:
        if len(self.window) < 2:
            return 1.0  # avoid zero division
        # Recompute accurately from current window
        n = len(self.window)
        m = sum(self.window) / n
        var = sum((x - m) ** 2 for x in self.window) / max(1, n - 1)
        return max(var, 0.001)

    @property
    def std_dev(self) -> float:
        return math.sqrt(self.variance)

    def z_score(self, current_value: float) -> float:
        sd = self.std_dev
        if sd < 0.0001:
            return 0.0
        return (float(current_value) - self.mean) / sd


class BaselineEngine(threading.Thread):
    """Tracks global and per-application baselines and flags anomalous spikes."""

    def __init__(self, cfg=None, conntrack=None, engine=None):
        super().__init__(name="anomaly_engine", daemon=True)
        self.cfg = cfg or {}
        a_cfg = self.cfg.get("anomaly_detection", {})
        self.enabled = a_cfg.get("enabled", True)
        self.alert_sigma = float(a_cfg.get("alert_threshold_sigma", 3.0))
        self.autorespond_sigma = float(a_cfg.get("autorespond_threshold_sigma", 5.0))
        self.conntrack = conntrack
        self.engine = engine
        self._lock = threading.RLock()
        self.metrics: Dict[str, RollingMetric] = {
            "connections_per_minute": RollingMetric("connections_per_minute"),
            "bandwidth_in_kbps": RollingMetric("bandwidth_in_kbps"),
            "bandwidth_out_kbps": RollingMetric("bandwidth_out_kbps"),
            "dns_queries_per_minute": RollingMetric("dns_queries_per_minute"),
            "new_processes_per_minute": RollingMetric("new_processes_per_minute"),
        }
        self._counters = collections.defaultdict(float)
        self._last_tick = time.time()

    def record_counter(self, metric_name: str, increment: float = 1.0):
        """Records an occurrence towards the current minute's total."""
        with self._lock:
            self._counters[metric_name] += increment

    def run(self):
        """1-minute tick evaluation loop."""
        while not STOP.wait(60):
            if not self.enabled:
                continue
            try:
                self.evaluate_tick()
            except Exception as e:
                event("anomaly_eval_error", "low", error=str(e))

    def evaluate_tick(self) -> List[dict]:
        """Calculates Z-scores for the elapsed minute and triggers alerts."""
        anomalies = []
        now = time.time()

        with self._lock:
            snapshot_counters = dict(self._counters)
            self._counters.clear()

            # Enrich from conntrack if available
            if self.conntrack:
                active = self.conntrack.get_active()
                snapshot_counters["connections_per_minute"] = len(active)

            for name, metric in self.metrics.items():
                val = snapshot_counters.get(name, 0.0)
                if len(metric.window) >= 10:  # need minimal training samples
                    z = metric.z_score(val)
                    if z >= self.alert_sigma:
                        sev = "critical" if z >= self.autorespond_sigma else "high"
                        anom = {
                            "metric": name,
                            "value": val,
                            "mean": round(metric.mean, 2),
                            "std_dev": round(metric.std_dev, 2),
                            "z_score": round(z, 2),
                            "severity": sev,
                        }
                        anomalies.append(anom)
                        event(
                            "anomaly_detected",
                            sev,
                            metric=name,
                            val=val,
                            mean=round(metric.mean, 2),
                            sigma=round(z, 2),
                        )
                metric.add(val)

        return anomalies

    def get_baselines(self) -> Dict[str, dict]:
        """Returns baseline stats for each tracked metric."""
        with self._lock:
            return {
                name: {
                    "mean": round(m.mean, 2),
                    "std_dev": round(m.std_dev, 2),
                    "samples": len(m.window),
                }
                for name, m in self.metrics.items()
            }
