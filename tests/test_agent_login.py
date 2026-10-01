"""Status logic of agent-login.py (no broker, no network)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_PATH = Path(__file__).resolve().parent.parent / "agent-login.py"
_SPEC = importlib.util.spec_from_file_location("agent_login", _PATH)
assert _SPEC and _SPEC.loader
al = importlib.util.module_from_spec(_SPEC)
sys.modules["agent_login"] = al  # dataclasses resolve their module by name
_SPEC.loader.exec_module(al)

KA = next(t for t in al.TARGETS if t.site == "kleinanzeigen")
ANIBIS = next(t for t in al.TARGETS if t.site == "anibis")
TUTTI = next(t for t in al.TARGETS if t.site == "tutti")


def test_ready_when_listed_and_flow_supported() -> None:
    listed = {"kleinanzeigen": {"site": "kleinanzeigen", "refused": False}}
    assert al.classify(KA, listed)[0] == "ready"


def test_two_step_listed_needs_flow() -> None:
    listed = {"anibis": {"site": "anibis", "refused": False}}
    assert al.classify(ANIBIS, listed)[0] == "needs-flow"


def test_refused_missing_unknown_unchecked() -> None:
    listed = {
        "kleinanzeigen": {"site": "kleinanzeigen", "refused": True, "reason": "x"}
    }
    assert al.classify(KA, listed) == ("refused", "x")
    assert al.classify(KA, {})[0] == "missing"
    assert al.classify(TUTTI, {})[0] == "unknown"
    assert al.classify(KA, {}, readable=False)[0] == "unchecked"


def test_overview_broker_down(monkeypatch) -> None:
    monkeypatch.setattr(al, "broker_state", lambda: ("not installed", []))
    data = al.overview()
    assert not data["broker_ok"]
    assert {r["status"] for r in data["rows"]} <= {"unchecked", "unknown"}
