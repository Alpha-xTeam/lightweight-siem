"""Unit tests for the file tail collector."""

from __future__ import annotations

from pathlib import Path

import pytest

from collector.file_tail import _open_log, tail_file


def test_open_log_reads_whole_file_when_from_start(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    log.write_text("line1\nline2\n", encoding="utf-8")
    handle = _open_log(log, from_start=True)
    assert handle.read() == "line1\nline2\n"
    handle.close()


def test_open_log_skips_existing_content_by_default(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    log.write_text("old line\n", encoding="utf-8")
    handle = _open_log(log, from_start=False)
    assert handle.read() == ""
    handle.close()


def test_tail_yields_existing_lines_from_start(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    log.write_text("line1\nline2\n", encoding="utf-8")
    lines = tail_file(log, from_start=True, poll_interval=0.01)
    assert next(lines) == "line1"
    assert next(lines) == "line2"
    lines.close()


def test_tail_yields_lines_appended_after_start(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    log.write_text("", encoding="utf-8")
    lines = tail_file(log, from_start=True, poll_interval=0.01)
    with log.open("a", encoding="utf-8") as handle:
        handle.write("appended line\n")
    assert next(lines) == "appended line"
    lines.close()


def test_tail_raises_when_file_is_missing(tmp_path: Path) -> None:
    lines = tail_file(tmp_path / "missing.log")
    with pytest.raises(FileNotFoundError):
        next(lines)
    lines.close()
