"""SentinelFW Anomaly Detection and Baseline Engine.

Features:
* Running statistical baselines (Welford's algorithm) and rolling Z-score evaluation
* Pure stdlib streaming Half-Space Tree (HSTree) online anomaly ensemble
* Labelled precision gate: remains strictly in alert-only mode until precision target is met
* Human-readable, plain language explanations for every detected anomaly
"""
import collections
import math
import random
import threading
import time
from typing import Dict, List, Optional, Tuple
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


class HalfSpaceTreeNode:
    """Node in an online Half-Space Tree streaming ensemble."""

    def __init__(self, depth: int, max_depth: int, feature_bounds: List[Tuple[float, float]], rng: random.Random):
        self.depth = depth
        self.max_depth = max_depth
        self.r_mass = 0.0  # reference window mass
        self.l_mass = 0.0  # latest window mass
        self.left: Optional[HalfSpaceTreeNode] = None
        self.right: Optional[HalfSpaceTreeNode] = None
        self.split_feat = -1
        self.split_val = 0.0

        if depth < max_depth and feature_bounds:
            num_feats = len(feature_bounds)
            self.split_feat = rng.randint(0, num_feats - 1)
            f_min, f_max = feature_bounds[self.split_feat]
            self.split_val = (f_min + f_max) / 2.0

            left_bounds = list(feature_bounds)
            left_bounds[self.split_feat] = (f_min, self.split_val)
            right_bounds = list(feature_bounds)
            right_bounds[self.split_feat] = (self.split_val, f_max)

            self.left = HalfSpaceTreeNode(depth + 1, max_depth, left_bounds, rng)
            self.right = HalfSpaceTreeNode(depth + 1, max_depth, right_bounds, rng)

    def insert(self, point: List[float]):
        self.l_mass += 1.0
        if self.depth < self.max_depth and self.left and self.right:
            val = point[self.split_feat] if self.split_feat < len(point) else 0.0
            if val <= self.split_val:
                self.left.insert(point)
            else:
                self.right.insert(point)

    def score(self, point: List[float]) -> float:
        if self.depth >= self.max_depth or not self.left or not self.right:
            # Score proportional to reference mass and depth
            return self.r_mass * (2 ** self.depth)
        val = point[self.split_feat] if self.split_feat < len(point) else 0.0
        if val <= self.split_val:
            return self.left.score(point)
        return self.right.score(point)

    def update_window(self):
        self.r_mass = self.l_mass
        self.l_mass = 0.0
        if self.left:
            self.left.update_window()
        if self.right:
            self.right.update_window()


class HalfSpaceTreeEnsemble:
    """Ensemble of streaming Half-Space Trees with labelled precision gating."""

    def __init__(self, num_trees: int = 25, max_depth: int = 8,
                 feature_names: Optional[List[str]] = None,
                 initial_bounds: Optional[List[Tuple[float, float]]] = None,
                 precision_threshold: float = 0.90, min_eval_samples: int = 30):
        self.num_trees = num_trees
        self.max_depth = max_depth
        self.feature_names = feature_names or ["conn_rate", "bw_in", "bw_out", "dns_rate", "proc_rate"]
        bounds = initial_bounds or [(0.0, 10000.0) for _ in self.feature_names]
        self.rng = random.Random(42)
        self.trees = [HalfSpaceTreeNode(0, max_depth, bounds, self.rng) for _ in range(num_trees)]

        self.precision_threshold = precision_threshold
        self.min_eval_samples = min_eval_samples
        self.true_positives = 0
        self.false_positives = 0
        self.gate_passed = False
        self.total_evaluated = 0
        self._window_counter = 0

    def update(self, point: List[float]):
        for tree in self.trees:
            tree.insert(point)
        self._window_counter += 1
        # Every 100 observations, cycle reference window
        if self._window_counter >= 100:
            for tree in self.trees:
                tree.update_window()
            self._window_counter = 0

    def anomaly_score(self, point: List[float]) -> float:
        """Computes anomaly score between 0.0 (normal) and 1.0 (highly anomalous)."""
        # Guard against zero or quiescent traffic
        if not point or all(abs(x) < 1e-4 for x in point):
            return 0.0
        # If the ensemble has not yet accumulated reference mass (unprimed), return 0.0
        total_ref_mass = sum(tree.r_mass for tree in self.trees)
        if total_ref_mass < 5.0:
            return 0.0

        raw_scores = [tree.score(point) for tree in self.trees]
        avg_mass = sum(raw_scores) / max(1, len(raw_scores))
        # Inverse mapping: low mass in dense trees indicates outlier
        score = 1.0 / (1.0 + math.log1p(max(0.0, avg_mass)))
        return round(min(1.0, max(0.0, score)), 4)

    def record_feedback(self, is_attack: bool, is_predicted_attack: bool):
        """Records ground truth feedback to advance the labelled precision gate."""
        self.total_evaluated += 1
        if is_predicted_attack:
            if is_attack:
                self.true_positives += 1
            else:
                self.false_positives += 1

        if (self.true_positives + self.false_positives) >= self.min_eval_samples:
            precision = self.true_positives / (self.true_positives + self.false_positives)
            if precision >= self.precision_threshold:
                self.gate_passed = True

    def explain(self, point: List[float], baselines: Dict[str, dict]) -> str:
        """Explains an anomaly in plain human language."""
        explanations = []
        for idx, name in enumerate(self.feature_names):
            val = point[idx] if idx < len(point) else 0.0
            b = baselines.get(name)
            if b:
                mean = b.get("mean", 0.0)
                sd = max(0.001, b.get("std_dev", 1.0))
                diff_sigma = (val - mean) / sd
                if diff_sigma >= 2.5:
                    explanations.append(
                        f"{name} measured {round(val, 1)} (deviated +{round(diff_sigma, 1)}σ from normal mean of {mean})"
                    )

        if not explanations:
            return "Multi-dimensional metric deviation detected across network flows."
        return "Anomaly explained: " + "; ".join(explanations) + "."


class BaselineEngine(threading.Thread):
    """Tracks global and per-application baselines, HSTree model, and flags anomalous spikes."""

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
        self.hstree = HalfSpaceTreeEnsemble(
            num_trees=25,
            max_depth=8,
            feature_names=list(self.metrics.keys()),
        )
        self._counters = collections.defaultdict(float)
        self._last_tick = time.time()

    def record_counter(self, metric_name: str, increment: float = 1.0):
        with self._lock:
            self._counters[metric_name] += increment

    def run(self):
        while not STOP.wait(60):
            if not self.enabled:
                continue
            try:
                self.evaluate_tick()
            except Exception as e:
                event("anomaly_eval_error", "low", error=str(e))

    def evaluate_tick(self) -> List[dict]:
        anomalies = []
        now = time.time()

        with self._lock:
            snapshot_counters = dict(self._counters)
            self._counters.clear()

            if self.conntrack:
                active = self.conntrack.get_active()
                snapshot_counters["connections_per_minute"] = len(active)

            # Build feature point for streaming HSTree model
            point = [float(snapshot_counters.get(name, 0.0)) for name in self.metrics.keys()]
            self.hstree.update(point)
            hst_score = self.hstree.anomaly_score(point)

            for name, metric in self.metrics.items():
                val = snapshot_counters.get(name, 0.0)
                if len(metric.window) >= 10:
                    z = metric.z_score(val)
                    # Trigger metric alert only if there is real activity and significant statistical deviation
                    if (val > 0.0 or metric.mean > 0.0) and z >= self.alert_sigma:
                        sev = "critical" if z >= self.autorespond_sigma else "high"
                        explanation = f"Anomaly explained: {name} measured {round(val, 1)} (deviated +{round(z, 1)}σ from normal mean of {round(metric.mean, 2)})."
                        is_alert_only = not self.hstree.gate_passed

                        anom = {
                            "metric": name,
                            "value": val,
                            "mean": round(metric.mean, 2),
                            "std_dev": round(metric.std_dev, 2),
                            "z_score": round(z, 2),
                            "hst_anomaly_score": hst_score,
                            "severity": sev,
                            "explanation": explanation,
                            "mode": "alert_only" if is_alert_only else "enforcing",
                        }
                        anomalies.append(anom)
                        event(
                            "anomaly_detected",
                            sev,
                            metric=name,
                            val=val,
                            mean=round(metric.mean, 2),
                            sigma=round(z, 2),
                            hst_score=hst_score,
                            explanation=explanation,
                            mode="alert_only" if is_alert_only else "enforcing",
                        )
                metric.add(val)

            # Check for pure multivariate anomaly if no univariate metrics flagged
            if not anomalies and hst_score >= 0.85 and any(snapshot_counters.get(k, 0.0) > 0.0 for k in self.metrics):
                explanation = self.hstree.explain(point, self.get_baselines())
                anom = {
                    "metric": "multivariate_flow",
                    "value": 0.0,
                    "mean": 0.0,
                    "std_dev": 0.0,
                    "z_score": 0.0,
                    "hst_anomaly_score": hst_score,
                    "severity": "high",
                    "explanation": explanation,
                    "mode": "alert_only" if not self.hstree.gate_passed else "enforcing",
                }
                anomalies.append(anom)
                event(
                    "anomaly_detected",
                    "high",
                    metric="multivariate_flow",
                    val=0.0,
                    mean=0.0,
                    sigma=0.0,
                    hst_score=hst_score,
                    explanation=explanation,
                    mode="alert_only" if not self.hstree.gate_passed else "enforcing",
                )

        return anomalies

    def get_baselines(self) -> Dict[str, dict]:
        with self._lock:
            return {
                name: {
                    "mean": round(m.mean, 2),
                    "std_dev": round(m.std_dev, 2),
                    "samples": len(m.window),
                }
                for name, m in self.metrics.items()
            }
