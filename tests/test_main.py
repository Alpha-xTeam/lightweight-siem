"""Integration tests for the main pipeline."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from main import process_line
from rules.engine import RuleEngine
from storage.database import Database

RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "rules.yaml"


def test_process_line_normalizes_stores_and_returns_alerts(tmp_path: Path) -> None:
    """A brute-force burst through process_line yields one alert."""
    db = Database(tmp_path / "test.db")
    engine = RuleEngine(RULES_PATH)
    alerts: list[dict[str, Any]] = []
    for second in range(6):
        line = (
            f"Nov  7 10:00:{second:02d} srv sshd[1002]: "
            "Failed password for admin from 192.168.1.100 port 52235 ssh2"
        )
        alerts.extend(process_line(line, engine, db))
    events = db.get_recent_events()
    assert len(events) == 6
    assert events[0]["event_type"] == "failed_login"
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "BRUTE_FORCE_001"
    db.close()


def test_process_line_skips_unrecognized_lines(tmp_path: Path) -> None:
    """Unknown lines are ignored and no event is stored."""
    db = Database(tmp_path / "test.db")
    engine = RuleEngine(RULES_PATH)
    alerts = process_line("hello world, not an ssh line", engine, db)
    assert alerts == []
    assert db.get_recent_events() == []
    db.close()


def test_alerts_are_persisted(tmp_path: Path) -> None:
    """Alerts produced by the pipeline are saved to the database."""
    db = Database(tmp_path / "test.db")
    engine = RuleEngine(RULES_PATH)
    for second in range(6):
        line = (
            f"Nov  7 10:00:{second:02d} srv sshd[1002]: "
            "Failed password for admin from 192.168.1.100 port 52235 ssh2"
        )
        process_line(line, engine, db)
    stored = db.get_recent_alerts()
    assert len(stored) == 1
    assert stored[0]["severity"] == "high"
    db.close()
