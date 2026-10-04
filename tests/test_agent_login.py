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
    target = al.Target("shop", "Shop", "https://login.shop.example", "two-step")
    listed = {"shop": {"site": "shop", "refused": False}}
    assert al.classify(target, listed)[0] == "ready"


def test_flows() -> None:
    """The marketplace sites (anibis, tutti, Ricardo, Kleinanzeigen) run on Albert's
    Safari session (Cloudflare 'are you human' box at headless logins);
    Kleinanzeigen keeps the broker as fallback."""
    assert "two-step" in al.SUPPORTED_FLOWS
    for target in (KA, ANIBIS, RICARDO, TUTTI):
        assert target.flow == al.SAFARI_FLOW, target.site
        listed = {target.site: {"site": target.site, "refused": False}}
        assert al.classify(target, listed)[0] == "safari", target.site
    for target in (ANIBIS, RICARDO, TUTTI):
        assert target.site in al.MANUAL_START  # guided login (-g) still possible
    assert KA.fallback == "two-step"
    assert TUTTI.fill_origin == "https://auth.tutti.ch"


def test_unsupported_flow_needs_flow() -> None:
    odd = al.Target("odd", "Odd", "https://login.odd.example", "magic-link", "n")
    listed = {"odd": {"site": "odd", "refused": False}}
    assert al.classify(odd, listed) == ("needs-flow", "n")


def test_refused_missing_unknown_unchecked() -> None:
    listed = {
        "kleinanzeigen": {"site": "kleinanzeigen", "refused": True, "reason": "x"}
    }
    assert al.classify(KA, listed)[0] == "safari"  # listed = consent for Safari
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


def test_wait_for_network_gives_up_quietly(monkeypatch) -> None:
    def no_dns(*_a, **_k):
        raise OSError("no network")

    monkeypatch.setattr(al.socket, "getaddrinfo", no_dns)
    now = [0.0]
    slept: list[float] = []

    def fake_sleep(s: float) -> None:
        slept.append(s)
        now[0] += s

    assert not al.wait_for_network(
        "x.invalid", 60, sleep=fake_sleep, clock=lambda: now[0]
    )
    assert slept and sum(slept) >= 60


def test_check_all_offline_is_quiet(monkeypatch) -> None:
    monkeypatch.setattr(al, "wait_for_network", lambda: False)
    sent: list = []
    monkeypatch.setattr(al, "send_mail", lambda *a: sent.append(a))
    assert al.check_all(mail=True) == 0 and not sent


def test_last_check_roundtrip(tmp_path) -> None:
    f = tmp_path / "last.json"
    al.record_check("anibis", True, "logged in", f)
    al.record_check("tutti", False, "NOT logged in", f)
    checks = al.last_checks(f)
    assert al.check_cell("anibis", checks).startswith("✅ ")
    assert al.check_cell("tutti", checks).startswith("❌ ")
    assert al.check_cell("cscs", checks) == "not checked yet"
