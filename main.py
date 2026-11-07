"""Lightweight SIEM - entry point.

Pipeline: collector -> normalizer -> rule engine -> storage -> console.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import yaml

from collector.file_tail import tail_file
from normalizer.ssh_normalizer import normalize_line
from rules.engine import RuleEngine
from storage.database import Database

BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config" / "siem.config.yaml"


def load_config(path: Path = CONFIG_PATH) -> dict[str, Any]:
    """Load the SIEM configuration YAML file.

    Args:
        path: Path to the configuration file.

    Returns:
        The configuration as a dict.
    """
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def process_line(line: str, engine: RuleEngine, db: Database) -> list[dict[str, Any]]:
    """Run one raw log line through the pipeline.

    Args:
        line: A raw log line (from the collector).
        engine: The rule engine used to evaluate the event.
        db: The database where events and alerts are stored.

    Returns:
        A list of alerts produced for this line (may be empty).
    """
    event = normalize_line(line)
    if event is None:
        return []
    db.save_event(event)
    alerts = engine.evaluate(event)
    for alert in alerts:
        db.save_alert(alert)
    return alerts


def _print_alert(alert: dict[str, Any]) -> None:
    """Print one alert to the console in a readable format."""
    print(
        f"[ALERT][{alert['severity'].upper()}] {alert['rule_id']}: "
        f"{alert['message']} ({alert['timestamp']})"
    )


def main() -> None:
    """Start the SIEM: tail the log file and process every new line."""
    config = load_config()
    db_path = BASE_DIR / config["storage"]["db_path"]
    log_path = BASE_DIR / config["collector"]["auth_log_path"]
    rules_path = BASE_DIR / "rules" / "rules.yaml"

    db = Database(db_path)
    engine = RuleEngine(rules_path)
    print(f"Lightweight SIEM started. Tailing: {log_path}")
    try:
        for line in tail_file(log_path, from_start=True, poll_interval=0.5):
            for alert in process_line(line, engine, db):
                _print_alert(alert)
    except KeyboardInterrupt:
        print("\nStopping SIEM.")
    finally:
        db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Lightweight SIEM")
    parser.add_argument("--once", action="store_true", help="Process existing lines and exit.")
    args = parser.parse_args()
    if args.once:
        # Process current file content once, then exit (useful for demos/tests).
        config = load_config()
        db = Database(BASE_DIR / config["storage"]["db_path"])
        engine = RuleEngine(BASE_DIR / "rules" / "rules.yaml")
        log_path = BASE_DIR / config["collector"]["auth_log_path"]
        for line in log_path.read_text(encoding="utf-8").splitlines():
            for alert in process_line(line, engine, db):
                _print_alert(alert)
        db.close()
        print("Done (single pass).")
    else:
        main()
