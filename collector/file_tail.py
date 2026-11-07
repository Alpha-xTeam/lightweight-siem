"""File tail collector.

Continuously tails a log file (e.g. auth.log) and yields new lines,
similar to the ``tail -f`` command.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from pathlib import Path
from typing import IO


def _open_log(path: str | Path, from_start: bool = False) -> IO[str]:
    """Open a log file for tailing.

    Args:
        path: Path of the log file to open.
        from_start: If True, position the file pointer at the beginning
            (existing lines are read). If False, jump to the end so only
            newly appended lines are seen (``tail -f`` behaviour).

    Returns:
        The opened text file handle.

    Raises:
        FileNotFoundError: If the file does not exist.
    """
    handle = Path(path).open("r", encoding="utf-8", errors="replace")
    if not from_start:
        handle.seek(0, 2)  # Seek to end of file (SEEK_END).
    return handle


def tail_file(path: str | Path, from_start: bool = False, poll_interval: float = 0.5) -> Iterator[str]:
    """Yield lines from a log file as they are appended.

    The generator blocks until new data arrives, polling the file every
    ``poll_interval`` seconds.

    Args:
        path: Path of the log file to tail.
        from_start: Read existing lines first, then follow new ones.
        poll_interval: Seconds to wait between reads when no new data.

    Yields:
        One log line at a time (without the trailing newline).
    """
    handle = _open_log(path, from_start=from_start)
    try:
        while True:
            line = handle.readline()
            if line:
                yield line.rstrip("\n")
            else:
                time.sleep(poll_interval)
    finally:
        handle.close()
