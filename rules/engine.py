"""Rule engine.

Loads detection rules from a YAML file and evaluates them against
normalized events. Adding or changing rules only requires editing the
YAML file - no code changes.

Week 1 implements ``threshold`` rules (count matching events inside a
sliding window per group). ``sequence`` rules are evaluated by the
correlation module (week 2).
"""

from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml


class RuleEngine:
    """Evaluates YAML-defined threshold rules against events."""

    def __init__(self, rules_path: str | Path) -> None:
        """Load rules from a YAML file.

        Args:
            rules_path: Path to the rules YAML file.

        Raises:
            FileNotFoundError: If the rules file does not exist.
        """
        self._rules_path = Path(rules_path)
        with self._rules_path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        self._rules: list[dict[str, Any]] = data.get("rules", [])
        # Sliding window of timestamps per (rule_id, group value).
        self._windows: dict[tuple[str, str], deque[datetime]] = {}
        # Groups that already produced an alert (one alert per burst).
        self._fired: set[tuple[str, str]] = set()

    @property
    def rules(self) -> list[dict[str, Any]]:
        """All rules loaded from the YAML file (enabled or not)."""
        return self._rules

    def evaluate(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        """Evaluate one normalized event against every enabled rule.

        Args:
            event: A normalized event dict (see normalizer).

        Returns:
            A list of alert dicts (empty if no rule matched).
        """
        alerts: list[dict[str, Any]] = []
        for rule in self._rules:
            if not rule.get("enabled", True):
                continue
            if rule.get("type") != "threshold":
                continue  # sequence rules belong to the correlator.
            if not self._matches(rule, event):
                continue
            alert = self._evaluate_threshold(rule, event)
            if alert is not None:
                alerts.append(alert)
        return alerts

    @staticmethod
    def _matches(rule: dict[str, Any], event: dict[str, Any]) -> bool:
        """Check that the event satisfies the rule's match block."""
        match = rule.get("match", {})
        return all(event.get(key) == value for key, value in match.items())

    def _evaluate_threshold(
        self, rule: dict[str, Any], event: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Count events of this group inside the window and compare."""
        condition = rule["condition"]
        window = timedelta(seconds=int(condition["window_seconds"]))
        timestamp = datetime.fromisoformat(event["timestamp"])
        group_value = str(event.get(rule.get("group_by", "source_ip"), ""))
        key = (rule["id"], group_value)

        # Append the event and evict everything outside the window.
        bucket = self._windows.setdefault(key, deque())
        bucket.append(timestamp)
        cutoff = timestamp - window
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()

        count = len(bucket)
        if not self._compare(count, condition["operator"], int(condition["value"])):
            self._fired.discard(key)  # Window dropped below threshold.
            return None
        if key in self._fired:
            return None  # Already alerted for this burst.
        self._fired.add(key)

        context = dict(event)
        context.update({"count": count, "window_seconds": condition["window_seconds"]})
        message = rule["message"].format_map(_SafeContext(context))
        return {
            "rule_id": rule["id"],
            "rule_name": rule["name"],
            "severity": rule["severity"],
            "message": message,
            "timestamp": event["timestamp"],
            "source_ip": event.get("source_ip", ""),
            "event_type": event.get("event_type", ""),
        }

    @staticmethod
    def _compare(count: int, operator: str, value: int) -> bool:
        """Compare a count against a threshold using an operator string."""
        return {
            ">": count > value,
            ">=": count >= value,
            "<": count < value,
            "<=": count <= value,
            "==": count == value,
        }.get(operator, False)


class _SafeContext(dict[str, Any]):
    """Dict that leaves unknown ``{placeholders}`` untouched."""

    def __missing__(self, key: str) -> str:
        return "{" + key + "}"
