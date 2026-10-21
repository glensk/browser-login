"""The broker's append-only audit log, bounded by one-step rotation (tp#951).

Every writer appends one JSON line to ``<home>/audit.log``. Once the file has
reached ``AUDIT_ROTATE_BYTES`` the next append first renames it to
``audit.log.1`` (replacing the previous one), so the log keeps at most about
two rotation sizes on disk. ``tail_bytes`` reads across both files, so a read
right after a rotation still sees the recent history.
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path

AUDIT_NAME = "audit.log"
AUDIT_ROTATED_NAME = "audit.log.1"
AUDIT_ROTATE_BYTES = 8 * 1024 * 1024


def append_line(
    home: Path, line: str, *, rotate_bytes: int = AUDIT_ROTATE_BYTES
) -> None:
    """Append ``line`` (newline added when missing) to ``home/audit.log`` (0600),
    rotating the file first when it has reached ``rotate_bytes``."""
    if not line.endswith("\n"):
        line += "\n"
    path = home / AUDIT_NAME
    with contextlib.suppress(FileNotFoundError):
        if path.stat().st_size >= rotate_bytes:
            os.replace(path, home / AUDIT_ROTATED_NAME)
    fd = os.open(str(path), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, line.encode())
    finally:
        os.close(fd)


def _tail(path: Path, limit: int) -> bytes:
    with path.open("rb") as fh:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        fh.seek(max(0, size - limit))
        data = fh.read()
    if size > limit:  # drop the partial first line
        data = data.partition(b"\n")[2]
    return data


def tail_bytes(home: Path, limit: int) -> bytes:
    """The last ``limit`` bytes of the log, continued from ``audit.log.1`` when the
    current file is shorter. ``FileNotFoundError`` when neither exists."""
    current = home / AUDIT_NAME
    rotated = home / AUDIT_ROTATED_NAME
    data = b""
    found = False
    with contextlib.suppress(FileNotFoundError):
        data = _tail(current, limit)
        found = True
    if len(data) < limit:
        with contextlib.suppress(FileNotFoundError):
            data = _tail(rotated, limit - len(data)) + data
            found = True
    if not found:
        raise FileNotFoundError(str(current))
    return data
