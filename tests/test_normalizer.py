"""Unit tests for the SSH normalizer."""

from __future__ import annotations

import re

from normalizer.ssh_normalizer import normalize_line

ISO_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")


def test_failed_password_line() -> None:
    line = (
        "Nov  7 10:00:02 srv sshd[1002]: "
        "Failed password for admin from 192.168.1.100 port 52235 ssh2"
    )
    event = normalize_line(line)
    assert event is not None
    assert event["event_type"] == "failed_login"
    assert event["source_ip"] == "192.168.1.100"
    assert event["username"] == "admin"
    assert event["status"] == "failure"
    assert event["raw_log"] == line
    assert ISO_PATTERN.fullmatch(event["timestamp"])


def test_failed_password_for_invalid_user_line() -> None:
    line = (
        "Nov  7 10:00:01 srv sshd[1001]: "
        "Failed password for invalid user admin from 192.168.1.100 port 52234 ssh2"
    )
    event = normalize_line(line)
    assert event is not None
    assert event["event_type"] == "failed_login"
    assert event["username"] == "admin"
    assert event["source_ip"] == "192.168.1.100"


def test_accepted_password_line() -> None:
    line = (
        "Nov  7 10:00:04 srv sshd[1004]: "
        "Accepted password for admin from 192.168.1.100 port 52237 ssh2"
    )
    event = normalize_line(line)
    assert event is not None
    assert event["event_type"] == "successful_login"
    assert event["status"] == "success"
    assert event["username"] == "admin"
    assert event["source_ip"] == "192.168.1.100"


def test_accepted_publickey_line() -> None:
    line = (
        "Nov  7 10:05:00 srv sshd[1005]: "
        "Accepted publickey for deploy from 10.0.0.25 port 49152 ssh2"
    )
    event = normalize_line(line)
    assert event is not None
    assert event["event_type"] == "successful_login"
    assert event["username"] == "deploy"
    assert event["source_ip"] == "10.0.0.25"


def test_port_scan_line() -> None:
    line = "Nov  7 10:02:00 srv sshd[1010]: Did not receive identification string from 10.0.0.77"
    event = normalize_line(line)
    assert event is not None
    assert event["event_type"] == "port_scan"
    assert event["source_ip"] == "10.0.0.77"
    assert event["status"] == "suspicious"


def test_iso_timestamp_from_loghub_style_line() -> None:
    line = (
        "2022-10-03 15:43:14 host sshd[3243]: "
        "Failed password for root from 10.0.0.5 port 22 ssh2"
    )
    event = normalize_line(line)
    assert event is not None
    assert event["timestamp"] == "2022-10-03T15:43:14"


def test_unknown_line_returns_none() -> None:
    assert normalize_line("some random log line with no ssh meaning") is None
