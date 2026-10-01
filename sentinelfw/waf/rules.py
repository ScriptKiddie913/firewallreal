"""SentinelFW WAF Rules Engine — OWASP CRS-Style Inspection & Scoring.

Supports:
* ModSecurity / CRS rule structure: id, name, phase, paranoia_level, targets, pattern, score, action, tags
* Paranoia levels 1 to 4 with progressive rule activation
* Cumulative anomaly scoring with configurable blocking threshold
* Runtime enable/disable of individual rules or rule tags
"""
import json
import re
import threading
from typing import Dict, List, Optional, Tuple, Union
from ..common import event


class WAFRule:
    """Represents a single WAF inspection rule."""

    def __init__(self, id: int, name: str, pattern: str, targets: List[str],
                 score: int = 5, phase: int = 1, paranoia_level: int = 1,
                 action: str = "block", tags: Optional[List[str]] = None,
                 description: str = "", enabled: bool = True, is_regex: bool = True):
        self.id = int(id)
        self.name = str(name).strip()
        self.pattern_raw = pattern
        self.is_regex = bool(is_regex)
        self.pattern = re.compile(pattern, re.IGNORECASE) if is_regex else pattern
        self.targets = [t.upper() for t in targets]
        self.score = int(score)
        self.phase = int(phase)
        self.paranoia_level = int(paranoia_level)
        self.action = str(action).lower()
        self.tags = [str(t).lower() for t in (tags or [])]
        self.description = str(description).strip()
        self.enabled = bool(enabled)

    def matches(self, value: str) -> bool:
        """Checks if the given string value matches this rule's pattern."""
        if not value or not self.enabled:
            return False
        if self.is_regex:
            return bool(self.pattern.search(value))
        return self.pattern_raw.lower() in value.lower()

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "pattern": self.pattern_raw,
            "targets": self.targets,
            "score": self.score,
            "phase": self.phase,
            "paranoia_level": self.paranoia_level,
            "action": self.action,
            "tags": self.tags,
            "description": self.description,
            "enabled": self.enabled,
        }


class WAFRuleEngine:
    """Thread-safe OWASP CRS rule set engine with anomaly scoring."""

    def __init__(self, paranoia_level: int = 1, anomaly_threshold: int = 5):
        self.paranoia_level = max(1, min(4, int(paranoia_level)))
        self.anomaly_threshold = int(anomaly_threshold)
        self._rules: Dict[int, WAFRule] = {}
        self._lock = threading.RLock()

    def add_rule(self, rule_spec: Union[dict, WAFRule]):
        with self._lock:
            if isinstance(rule_spec, WAFRule):
                self._rules[rule_spec.id] = rule_spec
            elif isinstance(rule_spec, dict):
                r = WAFRule(
                    id=rule_spec.get("id"),
                    name=rule_spec.get("name", f"Rule-{rule_spec.get('id')}"),
                    pattern=rule_spec.get("pattern", ""),
                    targets=rule_spec.get("targets", ["REQUEST_URI"]),
                    score=rule_spec.get("score", 5),
                    phase=rule_spec.get("phase", 1),
                    paranoia_level=rule_spec.get("paranoia_level", 1),
                    action=rule_spec.get("action", "block"),
                    tags=rule_spec.get("tags", []),
                    description=rule_spec.get("description", ""),
                    enabled=rule_spec.get("enabled", True),
                    is_regex=rule_spec.get("is_regex", True),
                )
                self._rules[r.id] = r

    def remove_rule(self, rule_id: int) -> bool:
        with self._lock:
            if rule_id in self._rules:
                del self._rules[rule_id]
                return True
            return False

    def toggle_rule(self, rule_id: int, enabled: Optional[bool] = None) -> bool:
        with self._lock:
            if rule_id in self._rules:
                if enabled is None:
                    self._rules[rule_id].enabled = not self._rules[rule_id].enabled
                else:
                    self._rules[rule_id].enabled = bool(enabled)
                return True
            return False

    def set_paranoia_level(self, level: int):
        with self._lock:
            self.paranoia_level = max(1, min(4, int(level)))

    def set_anomaly_threshold(self, threshold: int):
        with self._lock:
            self.anomaly_threshold = max(1, int(threshold))

    def load_rules_from_json(self, data_or_path: Union[str, list]):
        """Loads rules from a JSON filepath, JSON string, or list of dicts."""
        raw_list = []
        if isinstance(data_or_path, list):
            raw_list = data_or_path
        elif isinstance(data_or_path, str):
            if data_or_path.strip().startswith("[") or data_or_path.strip().startswith("{"):
                loaded = json.loads(data_or_path)
                raw_list = loaded if isinstance(loaded, list) else loaded.get("rules", [])
            else:
                from pathlib import Path
                p = Path(data_or_path)
                if p.exists():
                    loaded = json.loads(p.read_text(encoding="utf-8"))
                    raw_list = loaded if isinstance(loaded, list) else loaded.get("rules", [])
        with self._lock:
            for item in raw_list:
                if isinstance(item, dict) and "id" in item:
                    self.add_rule(item)

    def list_rules(self) -> List[dict]:
        with self._lock:
            return [r.to_dict() for r in sorted(self._rules.values(), key=lambda x: x.id)]

    def evaluate(self, targets: Dict[str, Union[str, List[str]]], phase: int = 1) -> Tuple[bool, int, List[dict]]:
        """Evaluates targets against rules matching current phase and paranoia level.

        Returns (should_block: bool, total_anomaly_score: int, matched_rules: list).
        """
        with self._lock:
            matched = []
            total_score = 0
            cur_paranoia = self.paranoia_level
            threshold = self.anomaly_threshold

            for rule in self._rules.values():
                if not rule.enabled or rule.phase != phase:
                    continue
                if rule.paranoia_level > cur_paranoia:
                    continue

                rule_matched = False
                matched_target = ""
                matched_value = ""

                for target_name in rule.targets:
                    val = targets.get(target_name)
                    if not val:
                        continue
                    if isinstance(val, list):
                        for item in val:
                            if rule.matches(str(item)):
                                rule_matched = True
                                matched_target = target_name
                                matched_value = str(item)[:128]
                                break
                    elif rule.matches(str(val)):
                        rule_matched = True
                        matched_target = target_name
                        matched_value = str(val)[:128]

                    if rule_matched:
                        break

                if rule_matched:
                    total_score += rule.score
                    match_record = {
                        "rule_id": rule.id,
                        "rule_name": rule.name,
                        "score": rule.score,
                        "target": matched_target,
                        "value": matched_value,
                        "tags": rule.tags,
                        "action": rule.action,
                    }
                    matched.append(match_record)

            should_block = total_score >= threshold
            return should_block, total_score, matched
