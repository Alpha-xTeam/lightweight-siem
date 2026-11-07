"""SQLite storage.

Stores normalized events and alerts in two tables (events, alerts).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp  TEXT NOT NULL,
    source_ip  TEXT NOT NULL,
    username   TEXT NOT NULL,
    event_type TEXT NOT NULL,
    status     TEXT NOT NULL,
    raw_log    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    rule_id   TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity  TEXT NOT NULL,
    message   TEXT NOT NULL,
    source_ip TEXT NOT NULL
);
"""


class Database:
    """SQLite wrapper for persisting events and alerts."""

    def __init__(self, db_path: str | Path) -> None:
        """Open (or create) the database and ensure the schema exists.

        Args:
            db_path: Path of the SQLite database file.
        """
        self._conn = sqlite3.connect(str(db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def save_event(self, event: dict[str, Any]) -> None:
        """Insert one normalized event.

        Args:
            event: Event dict with timestamp, source_ip, username,
                event_type, status and raw_log keys.
        """
        self._conn.execute(
            "INSERT INTO events (timestamp, source_ip, username, event_type, status, raw_log)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (
                event["timestamp"],
                event["source_ip"],
                event["username"],
                event["event_type"],
                event["status"],
                event["raw_log"],
            ),
        )
        self._conn.commit()

    def save_alert(self, alert: dict[str, Any]) -> None:
        """Insert one alert.

        Args:
            alert: Alert dict with timestamp, rule_id, rule_name,
                severity, message and source_ip keys.
        """
        self._conn.execute(
            "INSERT INTO alerts (timestamp, rule_id, rule_name, severity, message, source_ip)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (
                alert["timestamp"],
                alert["rule_id"],
                alert["rule_name"],
                alert["severity"],
                alert["message"],
                alert["source_ip"],
            ),
        )
        self._conn.commit()

    def get_recent_events(self, limit: int = 50) -> list[dict[str, Any]]:
        """Fetch the newest events, newest first.

        Args:
            limit: Maximum number of rows to return.

        Returns:
            A list of event dicts.
        """
        rows = self._conn.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(row) for row in rows]

    def get_recent_alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        """Fetch the newest alerts, newest first.

        Args:
            limit: Maximum number of rows to return.

        Returns:
            A list of alert dicts.
        """
        rows = self._conn.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(row) for row in rows]

    def count_events_by_type(self) -> dict[str, int]:
        """Count stored events grouped by event_type.

        Returns:
            Mapping of event_type to its count (used by the dashboard).
        """
        rows = self._conn.execute(
            "SELECT event_type, COUNT(*) AS n FROM events GROUP BY event_type"
        ).fetchall()
        return {row["event_type"]: row["n"] for row in rows}

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()
