"""tp#1137: checks.json keeps a bounded history of identity proofs that did
not say ``match``, and ``agent-login.py -H`` / ``-t`` show it.

Hermetic: the state dir is the per-test tmp dir (conftest
`_private_agent_login_state`); no browser, no broker.
"""

from __future__ import annotations

# pylint: disable=protected-access,missing-function-docstring
# pylint: disable=import-error,wrong-import-position
import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import agent_login_state as als  # noqa: E402

_SPEC = importlib.util.spec_from_file_location(
    "agent_login_tp1137", REPO / "agent-login.py"
)
assert _SPEC and _SPEC.loader
al = importlib.util.module_from_spec(_SPEC)
sys.modules["agent_login_tp1137"] = al
_SPEC.loader.exec_module(al)


def _indeterminate(site: str, why: str = "token") -> None:
    al.record_check(
        site,
        None,
        "could not tell which account",
        {
            "phase": "client-proof",
            "code": "identity_indeterminate",
            "detail": why,
            "identity": "indeterminate",
            "identity_why": why,
            "identity_status": 503,
        },
    )


def test_a_transient_indeterminate_survives_the_next_match() -> None:
    _indeterminate("runai-test3")
    al.record_check(
        "runai-test3", True, "logged in", {"phase": "ok", "identity": "match"}
    )
    rec = als.checks()["runai-test3"]
    assert rec["state"] == "ok" and rec["detail"] == ""  # the latest overwrote it
    (entry,) = rec["identity_history"]
    assert entry["identity"] == "indeterminate" and entry["why"] == "token"
    assert entry["status"] == 503 and entry["state"] == "unknown"
    assert entry["code"] == "identity_indeterminate" and entry["at_text"]


def test_match_and_no_proof_add_nothing() -> None:
    als.record_check("s", "ok", "logged in", identity="match")
    als.record_check("s", "ok", "logged in")  # no proof ran
    als.record_check("s", "failed", "NOT logged in")
    assert als.identity_history("s") == []


def test_history_is_bounded_newest_kept() -> None:
    for i in range(als.IDENTITY_HISTORY_MAX + 5):
        als.record_check(
            "s", "unknown", "x", identity="indeterminate", now=1_000_000.0 + i
        )
    hist = als.identity_history("s")
    assert len(hist) == als.IDENTITY_HISTORY_MAX
    assert hist[-1]["at"] == 1_000_000.0 + als.IDENTITY_HISTORY_MAX + 4
    assert hist[0]["at"] == 1_000_005.0


def test_only_fixed_words_and_redacted_detail_are_kept() -> None:
    als.record_check(
        "s",
        "failed",
        "wrong account",
        identity="wrong_account",
        identity_why="Bearer eyJ$$$",
        identity_status=True,  # not an int
        detail="saw a@b.c with token " + "A1b2C3d4" * 8,
    )
    (entry,) = als.identity_history("s")
    assert entry["why"] == "" and entry["status"] is None
    assert "a@b.c" not in entry["detail"] and "A1b2C3d4A1b2" not in entry["detail"]
    assert (
        als.record_check("t", "unknown", "x", identity_why="no token")["identity_why"]
        == "no token"
    )


def test_dash_h_prints_the_history(capsys: pytest.CaptureFixture[str]) -> None:
    _indeterminate("dsm-readonly", why="network")
    al.record_check("github", True, "logged in", {"identity": "match"})
    assert al.identity_history_action("", as_json=False) == 0
    out = capsys.readouterr().out
    assert "dsm-readonly:" in out and "why=network" in out and "http=503" in out
    assert "github" not in out
    assert al.identity_history_action("dsm-readonly", as_json=True) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["dsm-readonly"][0]["why"] == "network"
    assert al.identity_history_action("github", as_json=False) == 0
    assert "no identity proof" in capsys.readouterr().out


def test_dash_t_shows_the_newest_entries(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    for why in ("token", "network", "status", "auth"):
        _indeterminate("runai-test3", why=why)
    monkeypatch.setattr(al, "_test_site", lambda site: 0)
    assert al.run_test("runai-test3") == 0
    out = capsys.readouterr().out
    assert "why=auth" in out and "why=network" in out and "why=token" not in out
    assert "-H runai-test3" in out


def test_parser_has_dash_h() -> None:
    args = al.build_parser().parse_args(["-H"])
    assert args.identity_history == ""
    args = al.build_parser().parse_args(["-H", "x"])
    assert args.identity_history == "x"
    assert al.build_parser().parse_args([]).identity_history is None
