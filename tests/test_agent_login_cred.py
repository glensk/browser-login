"""tp#991 B5 — agent-login.py's credential section (agent_login_cred.py).

Every branch of the state-file reader and the section, against temp state
files; a sentinel planted in every field that could be displayed (and in
unknown keys) must never be printed. Hermetic: no credctl, no vault.

Run: uv run pytest -q tests/test_agent_login_cred.py
"""

from __future__ import annotations

# pylint: disable=missing-function-docstring,import-error,wrong-import-position
import calendar
import json
import secrets
import sys
import time
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import agent_login_cred as alc  # noqa: E402

SENTINEL = "s3cr3t" + secrets.token_hex(12)
NOW = float(
    calendar.timegm(time.strptime("2026-10-14T12:00:00Z", "%Y-%m-%dT%H:%M:%SZ"))
)


def _ts(delta_s: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(NOW - delta_s))


def _result(cid: str, verdict: str, count: int, **extra: Any) -> dict[str, Any]:
    return {
        "id": cid,
        "verdict": verdict,
        "location_count": count,
        "class": "api-key",
        "master": f"vault:{cid}",
        "master_status": "read",
        "master_detail": SENTINEL,
        "copies": [{"ref": SENTINEL, "kind": "sops", "status": verdict}],
        "ok": verdict == "equal",
        **extra,
    }


def _doc(
    results: list[Any] | None = None,
    *,
    attempt: str = "completed",
    started: float = 600,
    completed: float | None = 300,
    rc: int | None = 0,
    **extra: Any,
) -> dict[str, Any]:
    return {
        "v": 1,
        "manifest_digest": "sha256:" + "0" * 64,
        "attempt": attempt,
        "started_at": _ts(started),
        "completed_at": None if completed is None else _ts(completed),
        "exit": rc,
        "error": SENTINEL if attempt in ("failed", "timeout") else None,
        "results": results if results is not None else [],
        "unknown_key": SENTINEL,
        **extra,
    }


def _write(tmp_path: Path, doc: Any) -> Path:
    path = tmp_path / "check-latest.json"
    path.write_text(doc if isinstance(doc, str) else json.dumps(doc))
    return path


def _lines(tmp_path: Path, doc: Any) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = alc.lines(alc.load(_write(tmp_path, doc)), NOW)
    assert SENTINEL not in json.dumps(out)
    return out


def _marks(out: list[tuple[str, str]]) -> list[str]:
    return [m for m, _t in out]


# ---------------------------------------------------------------------------
# file-level states
# ---------------------------------------------------------------------------


def test_absent_file_is_one_warning(tmp_path: Path) -> None:
    out = alc.lines(alc.load(tmp_path / "nope.json"), NOW)
    assert _marks(out) == [alc.WARN]
    assert "credctl-daily.sh" in out[0][1]


@pytest.mark.parametrize(
    "doc",
    [
        "not json",
        "[]",
        json.dumps({"v": 2, "attempt": "completed"}),
        json.dumps({"v": "1"}),
    ],
)
def test_unusable_file_is_one_warning(tmp_path: Path, doc: str) -> None:
    out = _lines(tmp_path, doc)
    assert _marks(out) == [alc.WARN] and "unknown version" in out[0][1]


@pytest.mark.parametrize(
    "over",
    [
        {"attempt": "running"},
        {"started_at": SENTINEL},
        {"completed_at": SENTINEL},
        {"completed_at": None},  # completed without a time
        {"exit": "0"},
        {"exit": True},
        {"results": {}},
    ],
)
def test_invalid_envelope_fields_are_one_warning(tmp_path: Path, over: dict) -> None:
    out = _lines(tmp_path, {**_doc(), **over})
    assert _marks(out) == [alc.WARN]


def test_started_with_a_completion_time_is_invalid(tmp_path: Path) -> None:
    out = _lines(tmp_path, _doc(attempt="started", completed=10))
    assert _marks(out) == [alc.WARN] and "unknown version" in out[0][1]


# ---------------------------------------------------------------------------
# attempt states
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("attempt", ["failed", "timeout"])
def test_a_failed_run_is_one_failure(tmp_path: Path, attempt: str) -> None:
    out = _lines(tmp_path, _doc(attempt=attempt, rc=124))
    assert _marks(out) == [alc.FAIL]
    assert attempt in out[0][1] and "exit 124" in out[0][1]


def test_a_fresh_started_run_is_in_progress(tmp_path: Path) -> None:
    out = _lines(
        tmp_path, _doc(attempt="started", started=120, completed=None, rc=None)
    )
    assert _marks(out) == [alc.WARN] and "running" in out[0][1]


def test_a_started_run_older_than_an_hour_failed(tmp_path: Path) -> None:
    out = _lines(
        tmp_path, _doc(attempt="started", started=2 * 3600, completed=None, rc=None)
    )
    assert _marks(out) == [alc.FAIL] and "never finished" in out[0][1]


def test_a_stale_run_is_one_warning(tmp_path: Path) -> None:
    out = _lines(tmp_path, _doc(started=40 * 3600, completed=37 * 3600))
    assert _marks(out) == [alc.WARN] and "older than 36 h" in out[0][1]


def test_a_fresh_completed_run_has_no_header_line(tmp_path: Path) -> None:
    assert not _lines(tmp_path, _doc())


# ---------------------------------------------------------------------------
# results
# ---------------------------------------------------------------------------


def test_one_line_per_multi_location_result(tmp_path: Path) -> None:
    results = [
        _result("npm-nixos-admin", "equal", 3),
        _result("groq", "DRIFT", 2),
        _result("elevenlabs", "missing", 2),
        _result("os-password", "unreadable", 2),
        _result("qbittorrent", "uncompared", 2),
        _result("solo", "single", 1),
        _result("solo-equal", "equal", 1),
    ]
    out = _lines(tmp_path, _doc(results))
    by_id = {t.split(" ", maxsplit=1)[0]: (m, t) for m, t in out}
    assert set(by_id) == {
        "npm-nixos-admin",
        "groq",
        "elevenlabs",
        "os-password",
        "qbittorrent",
    }
    assert by_id["npm-nixos-admin"][0] == alc.OK
    assert "all 3 places equal" in by_id["npm-nixos-admin"][1]
    for cid in ("groq", "elevenlabs", "os-password"):
        assert by_id[cid][0] == alc.FAIL
    assert by_id["qbittorrent"][0] == alc.WARN
    assert "check -T qbittorrent" in by_id["qbittorrent"][1]


def test_accepted_uncompared_rows_fold_into_one_quiet_line(tmp_path: Path) -> None:
    """tp#889 R3b: uncompared by design is no warning; unaccepted still is."""
    results = [
        _result("ext-a", "uncompared", 2, accepted_uncompared=True),
        _result("ext-b", "uncompared", 3, accepted_uncompared=True),
        _result("qbittorrent", "uncompared", 2, accepted_uncompared=False),
        _result("legacy", "uncompared", 2),  # flag absent = not accepted
        _result("groq", "DRIFT", 2, accepted_uncompared=True),  # flag ignored
        _result("npm", "equal", 2),
        _result("solo", "uncompared", 1, accepted_uncompared=True),  # one place
    ]
    out = _lines(tmp_path, _doc(results))
    texts = [t for _m, t in out]
    assert not any(t.startswith(("ext-a", "ext-b", "solo")) for t in texts)
    by_id = {t.split(" ", maxsplit=1)[0]: m for m, t in out}
    assert by_id["qbittorrent"] == alc.WARN and by_id["legacy"] == alc.WARN
    assert by_id["groq"] == alc.FAIL and by_id["npm"] == alc.OK
    assert out[-1][0] == alc.QUIET
    assert out[-1][1].startswith("2 accepted as uncompared by design")
    assert _marks(out).count(alc.WARN) == 2


@pytest.mark.parametrize("flag", ["true", 1, None, {"x": SENTINEL}])
def test_a_non_true_accepted_flag_still_warns(tmp_path: Path, flag: Any) -> None:
    results = [_result("odd", "uncompared", 2, accepted_uncompared=flag)]
    assert _marks(_lines(tmp_path, _doc(results))) == [alc.WARN]


def test_only_accepted_rows_leave_no_warning(tmp_path: Path, capsys: Any) -> None:
    results = [
        _result(f"ext-{i}", "uncompared", 2, accepted_uncompared=True) for i in range(5)
    ]
    path = _write(tmp_path, _doc(results))
    alc.print_section(lambda _c, t: t, path=path, now=NOW)
    out = capsys.readouterr().out
    assert alc.WARN not in out and alc.FAIL not in out
    assert "· 5 accepted as uncompared by design" in out
    assert "no credential is stored" not in out
    data = alc.summary(alc.load(path), NOW)
    assert all(r["accepted_uncompared"] for r in data["results"])
    assert len(data["results"]) == 5


@pytest.mark.parametrize(
    "bad",
    [
        {"id": SENTINEL.upper()},
        {"id": "x" * 65},
        {"id": 5},
        {"verdict": SENTINEL},
        {"location_count": "2"},
        {"location_count": True},
        {"location_count": 65},
        {"location_count": -1},
    ],
)
def test_an_invalid_result_is_counted_never_shown(tmp_path: Path, bad: dict) -> None:
    results = [{**_result("good", "equal", 2), **bad}, _result("ok-one", "equal", 2)]
    out = _lines(tmp_path, _doc(results))
    texts = [t for _m, t in out]
    assert any("1 result(s) unreadable" in t for t in texts)
    assert any(t.startswith("ok-one") for t in texts)
    assert not any(t.startswith("good") for t in texts)


def test_a_non_dict_result_is_counted(tmp_path: Path) -> None:
    out = _lines(tmp_path, _doc([SENTINEL, 7]))
    assert out == [(alc.WARN, "2 result(s) unreadable in the state file")]


def test_results_shown_after_a_failed_header(tmp_path: Path) -> None:
    out = _lines(tmp_path, _doc([_result("groq", "DRIFT", 2)], attempt="failed", rc=3))
    assert _marks(out) == [alc.FAIL, alc.FAIL]


# ---------------------------------------------------------------------------
# the section and the -j summary
# ---------------------------------------------------------------------------


def test_print_section(tmp_path: Path, capsys: Any) -> None:
    path = _write(tmp_path, _doc([_result("groq", "equal", 2)]))
    alc.print_section(lambda _c, t: t, path=path, now=NOW)
    out = capsys.readouterr().out
    assert out.startswith("Credentials in two or more places")
    assert "✅ groq — all 2 places equal" in out
    assert SENTINEL not in out


def test_print_section_without_multi_location_results(
    tmp_path: Path, capsys: Any
) -> None:
    path = _write(tmp_path, _doc([_result("solo", "single", 1)]))
    alc.print_section(lambda _c, t: t, path=path, now=NOW)
    assert "no credential is stored in two or more places" in capsys.readouterr().out


def test_summary_holds_validated_fields_only(tmp_path: Path) -> None:
    path = _write(
        tmp_path, _doc([_result("groq", "DRIFT", 2), _result("a", "single", 1)])
    )
    data = alc.summary(alc.load(path), NOW)
    assert data["status"] == "ok" and data["attempt"] == "completed"
    assert data["results"] == [
        {
            "id": "groq",
            "verdict": "DRIFT",
            "location_count": 2,
            "accepted_uncompared": False,
        }
    ]
    assert SENTINEL not in json.dumps(data)


def test_state_path_env_override(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setenv(alc.STATE_ENV, str(tmp_path / "x.json"))
    assert alc.state_path() == tmp_path / "x.json"
    monkeypatch.delenv(alc.STATE_ENV)
    assert alc.state_path() == alc.DEFAULT_STATE


def test_agent_login_overview_prints_the_section() -> None:
    """The wiring in ./agent-login.py: the section follows the keychain list."""
    src = (Path(__file__).resolve().parent.parent / "agent-login.py").read_text()
    keychain = src.index(
        'agent_login_keychain.print_list(_state_path("keychain.json"), _c)\n'
    )
    assert src.index("agent_login_cred.print_section(_c)", keychain) > keychain
    assert 'data["credentials"] = agent_login_cred.summary(' in src
