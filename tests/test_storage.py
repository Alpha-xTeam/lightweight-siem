"""Unit tests for SQLite storage."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from storage.database import Database


def make_event(timestamp: str = "2026-11-07T10:00:00") -> dict[str, Any]:
    """Build a normalized event dict for tests."""
    return {
        "timestamp": timestamp,
        "source_ip": "192.168.1.100",
        "username": "admin",
        "event_type": "failed_login",
        "status": "failure",
        "raw_log": "raw line",
    }


def make_alert() -> dict[str, Any]:
    """Build an alert dict for tests."""
    return {
        "rule_id": "BRUTE_FORCE_001",
        "rule_name": "SSH Brute Force",
        "severity": "high",
        "message": "Brute force from 192.168.1.100",
        "timestamp": "2026-11-07T10:01:00",
        "source_ip": "192.168.1.100",
        "event_type": "failed_login",
    }


def test_save_and_get_events(tmp_path: Path) -> None:
    db = Database(tmp_path / "test.db")
    db.save_event(make_event())
    db.save_event(make_event(timestamp="2026-11-07T10:00:01"))
    events = db.get_recent_events(limit=10)
    assert len(events) == 2
    assert events[0]["source_ip"] == "192.168.1.100"
    db.close()


def test_recent_events_respects_limit_and_order(tmp_path: Path) -> None:
    db = Database(tmp_path / "test.db")
    for second in range(5):
        db.save_event(make_event(timestamp=f"2026-11-07T10:00:{second:02d}"))
    events = db.get_recent_events(limit=2)
    assert len(events) == 2
    # Newest first.
    assert events[0]["timestamp"] == "2026-11-07T10:00:04"
    assert events[1]["timestamp"] == "2026-11-07T10:00:03"
    db.close()


def test_save_and_get_alerts(tmp_path: Path) -> None:
    db = Database(tmp_path / "test.db")
    db.save_alert(make_alert())
    alerts = db.get_recent_alerts(limit=10)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "BRUTE_FORCE_001"
    assert alerts[0]["severity"] == "high"
    db.close()


def test_empty_database_returns_empty_lists(tmp_path: Path) -> None:
    db = Database(tmp_path / "test.db")
    assert db.get_recent_events() == []
    assert db.get_recent_alerts() == []
    db.close()


def test_database_creates_file(tmp_path: Path) -> None:
    path = tmp_path / "created.db"
    db = Database(path)
    db.close()
    assert path.exists()
