"""The broker audit log rotates instead of growing without bound (tp#951)."""

from __future__ import annotations

import json
import stat
from pathlib import Path

from broker import auditlog


def test_append_creates_0600_and_rotates_at_the_limit(tmp_path: Path) -> None:
    for i in range(5):
        auditlog.append_line(tmp_path, json.dumps({"i": i}), rotate_bytes=30)
    current = tmp_path / "audit.log"
    rotated = tmp_path / "audit.log.1"
    assert stat.S_IMODE(current.stat().st_mode) == 0o600
    assert rotated.exists()
    # nothing grows past one line beyond the limit, and only one old file is kept
    assert current.stat().st_size <= 30 + len(json.dumps({"i": 4})) + 1
    assert sorted(p.name for p in tmp_path.glob("audit.log*")) == [
        "audit.log",
        "audit.log.1",
    ]
    lines = (rotated.read_text() + current.read_text()).splitlines()
    assert [json.loads(x)["i"] for x in lines] == sorted(
        json.loads(x)["i"] for x in lines
    )
    assert json.loads(lines[-1]) == {"i": 4}


def test_tail_reads_across_the_rotation(tmp_path: Path) -> None:
    (tmp_path / "audit.log.1").write_text('{"i": 1}\n{"i": 2}\n')
    (tmp_path / "audit.log").write_text('{"i": 3}\n')
    tail = auditlog.tail_bytes(tmp_path, 1024).decode().splitlines()
    assert [json.loads(x)["i"] for x in tail] == [1, 2, 3]


def test_tail_drops_a_partial_first_line_and_raises_when_absent(tmp_path: Path) -> None:
    (tmp_path / "audit.log").write_text('{"i": 1}\n{"i": 2}\n')
    assert auditlog.tail_bytes(tmp_path, 12).decode().splitlines() == ['{"i": 2}']
    empty = tmp_path / "none"
    empty.mkdir()
    try:
        auditlog.tail_bytes(empty, 10)
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("expected FileNotFoundError")
