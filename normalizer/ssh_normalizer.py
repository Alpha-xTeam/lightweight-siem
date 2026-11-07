"""SSH log normalizer.

Converts a raw SSH/auth.log line into a unified event dict with keys:
timestamp, source_ip, username, event_type, status, raw_log.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

# Syslog timestamp, e.g. "Nov  7 10:00:02" (no year -> current year).
_SYSLOG_TS = re.compile(r"^([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
# ISO timestamp, e.g. "2022-10-03 15:43:14" (LogHub style).
_ISO_TS = re.compile(r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})")

# SSH message patterns (checked in order).
_ACCEPTED = re.compile(
    r"Accepted (?:password|publickey|keyboard-interactive) for (\S+) from (\S+)"
)
_FAILED = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from (\S+)"
)
_PORT_SCAN = re.compile(r"Did not receive identification string from (\S+)")


def _parse_timestamp(raw_line: str) -> str:
    """Extract and normalize the timestamp of a log line.

    Args:
        raw_line: The raw log line.

    Returns:
        An ISO-8601 timestamp string (``YYYY-MM-DDTHH:MM:SS``).
        If no timestamp is found, the current time is used.
    """
    iso_match = _ISO_TS.match(raw_line)
    if iso_match:
        return iso_match.group(1).replace(" ", "T")
    syslog_match = _SYSLOG_TS.match(raw_line)
    if syslog_match:
        stamp = " ".join(syslog_match.group(1).split())  # Collapse spaces.
        parts = stamp.split()  # e.g. ["Nov", "7", "10:00:02"].
        year = datetime.now().year
        parsed = datetime.strptime(f"{parts[0]} {parts[1]} {year} {parts[2]}", "%b %d %Y %H:%M:%S")
        return parsed.strftime("%Y-%m-%dT%H:%M:%S")
    return datetime.now().strftime("%Y-%m-%dT%H:%M:%S")


def normalize_line(line: str) -> dict[str, Any] | None:
    """Convert one raw SSH log line into a unified event dict.

    Args:
        line: A raw log line (e.g. from auth.log or Syslog).

    Returns:
        A dict with keys ``timestamp``, ``source_ip``, ``username``,
        ``event_type``, ``status`` and ``raw_log``; or ``None`` if the
        line does not match any known SSH pattern.
    """
    line = line.strip()
    if not line:
        return None

    match = _ACCEPTED.search(line)
    if match:
        username, source_ip = match.group(1), match.group(2)
        event_type, status = "successful_login", "success"
    else:
        match = _FAILED.search(line)
        if match:
            username, source_ip = match.group(1), match.group(2)
            event_type, status = "failed_login", "failure"
        else:
            match = _PORT_SCAN.search(line)
            if not match:
                return None
            username, source_ip = "", match.group(1)
            event_type, status = "port_scan", "suspicious"

    return {
        "timestamp": _parse_timestamp(line),
        "source_ip": source_ip,
        "username": username,
        "event_type": event_type,
        "status": status,
        "raw_log": line,
    }
