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
RICARDO = next(t for t in al.TARGETS if t.site == "ricardo")
TUTTI = next(t for t in al.TARGETS if t.site == "tutti")
GEIZHALS = next(t for t in al.TARGETS if t.site == "geizhals")


def test_ready_when_listed_and_flow_supported() -> None:
    listed = {"kleinanzeigen": {"site": "kleinanzeigen", "refused": False}}
    assert al.classify(KA, listed)[0] == "ready"


def test_flows() -> None:
    """Kleinanzeigen goes through the broker; the SMG sites (anibis, tutti, Ricardo)
    show a Cloudflare 'are you human' box to headless logins -> manual sessions."""
    assert "two-step" in al.SUPPORTED_FLOWS
    listed = {KA.site: {"site": KA.site, "refused": False}}
    assert KA.flow == "two-step" and al.classify(KA, listed)[0] == "ready"
    for target in (ANIBIS, RICARDO, TUTTI):
        assert target.flow == "manual", target.site
        listed = {target.site: {"site": target.site, "refused": False}}
        assert al.classify(target, listed)[0] == "manual", target.site
        assert target.site in al.MANUAL_START
    assert TUTTI.fill_origin == "https://auth.tutti.ch"


def test_unsupported_flow_needs_flow() -> None:
    odd = al.Target("odd", "Odd", "https://login.odd.example", "magic-link", "n")
    listed = {"odd": {"site": "odd", "refused": False}}
    assert al.classify(odd, listed) == ("needs-flow", "n")


def test_refused_missing_unknown_unchecked() -> None:
    listed = {
        "kleinanzeigen": {"site": "kleinanzeigen", "refused": True, "reason": "x"}
    }
    assert al.classify(KA, listed) == ("refused", "x")
    assert al.classify(KA, {})[0] == "missing"
    assert al.classify(TUTTI, {})[0] == "missing"
    assert al.classify(GEIZHALS, {})[0] == "unknown"
    assert al.classify(KA, {}, readable=False)[0] == "unchecked"


def test_overview_broker_down(monkeypatch) -> None:
    monkeypatch.setattr(al, "broker_state", lambda: ("not installed", []))
    data = al.overview()
    assert not data["broker_ok"]
    assert {r["status"] for r in data["rows"]} <= {"unchecked", "unknown"}


def test_overview_rows_carry_check_url(monkeypatch) -> None:
    sites = [
        {"site": "ricardo", "refused": False, "check_url": "https://r.example/me"},
        {"site": "extra", "refused": False, "check_url": "https://e.example/me"},
    ]
    monkeypatch.setattr(al, "broker_state", lambda: ("running, Bitwarden ok", sites))
    rows = {r["site"]: r for r in al.overview()["rows"]}
    assert rows["ricardo"]["check_url"] == "https://r.example/me"  # broker wins
    assert rows["extra"]["check_url"] == "https://e.example/me"
    assert rows["kleinanzeigen"]["check_url"] == al.DEFAULT_CHECK_URLS["kleinanzeigen"]
    assert rows["geizhals"]["check_url"] == ""
