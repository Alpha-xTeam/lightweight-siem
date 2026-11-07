"""Unit tests for the rule engine."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from rules.engine import RuleEngine

RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "rules.yaml"


def make_event(
    timestamp: str,
    source_ip: str = "192.168.1.100",
    event_type: str = "failed_login",
    username: str = "admin",
) -> dict[str, Any]:
    """Build a normalized event dict for tests."""
    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "username": username,
        "event_type": event_type,
        "status": "failure" if event_type == "failed_login" else "success",
        "raw_log": "raw",
    }


def test_loads_rules_from_yaml() -> None:
    engine = RuleEngine(RULES_PATH)
    rule_ids = [rule["id"] for rule in engine.rules]
    assert "BRUTE_FORCE_001" in rule_ids
    assert "LOGIN_ESCALATION_001" in rule_ids
    assert len(engine.rules) >= 3


def test_disabled_rules_are_skipped() -> None:
    rules = {
        "rules": [
            {
                "id": "OFF_001",
                "name": "Disabled rule",
                "description": "never fires",
                "enabled": False,
                "type": "threshold",
                "match": {"event_type": "failed_login"},
                "group_by": "source_ip",
                "condition": {
                    "metric": "count",
                    "operator": ">",
                    "value": 0,
                    "window_seconds": 60,
                },
                "severity": "low",
                "message": "should not fire {source_ip}",
            }
        ]
    }
    tmp_rules = RULES_PATH.parent / "_tmp_rules.yaml"
    tmp_rules.write_text(yaml.safe_dump(rules), encoding="utf-8")
    try:
        engine = RuleEngine(tmp_rules)
        alerts = engine.evaluate(make_event("2026-11-07T10:00:00"))
        assert alerts == []
    finally:
        tmp_rules.unlink()


def test_threshold_rule_fires_after_six_failures() -> None:
    """More than 5 failures from one IP inside 60s -> one alert."""
    engine = RuleEngine(RULES_PATH)
    alerts: list[dict[str, Any]] = []
    for second in range(6):
        event = make_event(f"2026-11-07T10:00:{second:02d}")
        alerts.extend(engine.evaluate(event))
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["rule_id"] == "BRUTE_FORCE_001"
    assert alert["severity"] == "high"
    assert alert["source_ip"] == "192.168.1.100"
    assert "192.168.1.100" in alert["message"]


def test_threshold_rule_does_not_fire_below_threshold() -> None:
    """Exactly 5 failures (not more than 5) -> no alert."""
    engine = RuleEngine(RULES_PATH)
    alerts: list[dict[str, Any]] = []
    for second in range(5):
        event = make_event(f"2026-11-07T10:00:{second:02d}")
        alerts.extend(engine.evaluate(event))
    assert alerts == []


def test_window_expires_old_events() -> None:
    """Failures spread beyond the 60s window do not accumulate."""
    engine = RuleEngine(RULES_PATH)
    alerts: list[dict[str, Any]] = []
    for minute in range(6):
        event = make_event(f"2026-11-07T10:{minute:02d}:00")
        alerts.extend(engine.evaluate(event))
    assert alerts == []


def test_groups_are_counted_per_source_ip() -> None:
    """Failures from different IPs are counted separately."""
    engine = RuleEngine(RULES_PATH)
    alerts: list[dict[str, Any]] = []
    for second in range(6):
        ip = "10.0.0.1" if second % 2 == 0 else "10.0.0.2"
        event = make_event(f"2026-11-07T10:00:{second:02d}", source_ip=ip)
        alerts.extend(engine.evaluate(event))
    assert alerts == []


def test_alert_fires_only_once_per_burst() -> None:
    """A long burst of failures produces a single alert, not one per line."""
    engine = RuleEngine(RULES_PATH)
    alerts: list[dict[str, Any]] = []
    for second in range(20):
        event = make_event(f"2026-11-07T10:00:{second:02d}")
        alerts.extend(engine.evaluate(event))
    assert len(alerts) == 1
