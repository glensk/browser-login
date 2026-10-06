"""Status logic of agent-login.py (no broker, no network)."""

from __future__ import annotations

import importlib.util
import os
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
GEIZHALS = al.Target("geizhals", "geizhals", "", "unknown")


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
    monkeypatch.setattr(al, "broker_state", lambda **_k: ("not installed", []))
    data = al.overview()
    assert not data["broker_ok"]
    statuses = {r["site"]: r["status"] for r in data["rows"]}
    for site, status in statuses.items():  # built-in assisted sites need no broker
        want = {"assisted"} if site in al.ASSISTED_SITES else {"unchecked", "unknown"}
        assert status in want, site


def test_overview_rows_carry_check_url(monkeypatch) -> None:
    sites = [
        {"site": "ricardo", "refused": False, "check_url": "https://r.example/me"},
        {"site": "extra", "refused": False, "check_url": "https://e.example/me"},
    ]
    monkeypatch.setattr(
        al, "broker_state", lambda **_k: ("running, Bitwarden ok", sites)
    )
    rows = {r["site"]: r for r in al.overview()["rows"]}
    assert rows["ricardo"]["check_url"] == "https://r.example/me"  # broker wins
    assert rows["extra"]["check_url"] == "https://e.example/me"
    assert rows["kleinanzeigen"]["check_url"] == al.DEFAULT_CHECK_URLS["kleinanzeigen"]


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


def _row(site: str, status: str, **kw) -> dict:
    return {"site": site, "name": site, "status": status, "detail": "", **kw}


def test_verdict_one_answer_per_login() -> None:
    """✅ only with a complete setup AND a passing last real check."""
    ok = {"cscs": {"ok": True, "at": "t", "how": "logged in"}}
    bad = {"cscs": {"ok": False, "at": "t", "how": "NOT logged in"}}
    assert al.verdict(_row("cscs", "ready"), ok) == (True, "checked t, login broker")
    works, why = al.verdict(_row("cscs", "ready"), bad)
    assert not works and "NOT logged in" in why
    works, why = al.verdict(_row("cscs", "ready"), {})
    assert not works and "-t cscs" in why
    # a setup problem wins over an old passing check
    assert not al.verdict(_row("cscs", "missing"), ok)[0]
    assert al.verdict(_row("x", "unknown"), {}) == (
        False,
        "no Vaultwarden item / login address yet",
    )
    row = _row("tutti", "safari", safari=False, fallback="")
    assert "Safari" in al.verdict(row, {"tutti": {"ok": True, "at": "t"}})[1]


def test_assisted_sites_and_resolve() -> None:
    assert {"anthropic", "openai", "slack", "switch"} <= al.ASSISTED_SITES
    sw = next(t for t in al.TARGETS if t.site == "switch")
    assert al.classify(sw, {}, readable=False)[0] == "assisted"
    assert al.resolve_site("https://auth.cscs.ch") == "cscs"
    assert al.resolve_site("https://auth.cscs.ch/") == "cscs"
    assert al.resolve_site("CSCS") == "cscs"
    assert al.resolve_site("nope") == "nope"


def test_broker_state_uses_recent_snapshot(monkeypatch, tmp_path) -> None:
    """The overview reads the snapshot; only `fresh` (or none/stale) asks the broker."""
    calls: list[bool] = []

    def live(*, fresh):
        calls.append(fresh)
        return "running, Bitwarden readable", [{"site": "cscs"}]

    monkeypatch.setattr(al, "_broker_state_live", live)
    monkeypatch.setattr(al, "SOCKET", str(tmp_path))  # "exists"
    assert al.broker_state()[1] == [{"site": "cscs"}]  # no snapshot yet → live
    assert al.broker_state()[1] == [{"site": "cscs"}]  # snapshot
    assert calls == [False]
    al.broker_state(fresh=True)
    assert calls == [False, True]


def test_agent_summary_lists_both_sides() -> None:
    rows = [
        _row("cscs", "ready", flow="cscs"),
        _row("anthropic", "assisted", flow=al.ASSISTED_FLOW),
        _row("geizhals", "unknown"),
    ]
    checks = {
        "cscs": {"ok": True, "at": "t", "how": "logged in"},
        "anthropic": {"ok": True, "at": "t", "how": "logged in as a@b.ch"},
    }
    text = al.agent_summary({"rows": rows, "broker_ok": True}, checks)
    assert "- ✅ cscs (`cscs`): login broker" in text
    assert "a@b.ch" in text
    assert "- ❌ geizhals: no Vaultwarden item / login address yet" in text
    assert "browser.py login <site>" in text


def test_snapshot_plist() -> None:
    plist = al.snapshot_plist()
    assert "<string>com.albert.agent-login-snapshot</string>" in plist
    assert "<string>-S</string>" in plist
    assert "<key>StartInterval</key>" in plist and "<true/>" in plist


def test_safari_state_keeps_last_readable(monkeypatch) -> None:
    good = {"anibis": {"safari": True, "safari_expires": "2099-01-01"}}
    monkeypatch.setattr(al, "safari_sessions", lambda sites: good)
    assert al.safari_state(["anibis"]) == good
    bad = {"anibis": {"safari": None, "safari_error": "no access"}}
    monkeypatch.setattr(al, "safari_sessions", lambda sites: bad)
    assert al.safari_state(["anibis"]) == good  # the last readable state


def test_expired_safari_session_fails() -> None:
    row = _row("tutti", "safari", safari=True, safari_expires="2001-01-01")
    works, why = al.verdict(row, {"tutti": {"ok": True, "at": "t"}})
    assert not works and "expired" in why


def test_private_claude_lives_in_its_own_instance(monkeypatch) -> None:
    """anthropic-private runs every browser.py call in the `private` instance."""
    seen: list[str] = []
    monkeypatch.setattr(
        sys.modules["agent_login_claude"], "browser_mode", lambda: "headless"
    )
    monkeypatch.delenv("CLAUDE_BROWSER_INSTANCE", raising=False)
    with al.site_instance("anthropic-private"):
        seen.append(os.environ["CLAUDE_BROWSER_INSTANCE"])
    with al.site_instance("anthropic"):
        seen.append(os.environ["CLAUDE_BROWSER_INSTANCE"])
    assert seen == ["private", ""]
    assert "CLAUDE_BROWSER_INSTANCE" not in os.environ


def test_smartsheet_is_a_broker_site() -> None:
    target = next(t for t in al.TARGETS if t.site == "smartsheet")
    assert target.fill_origin == "https://app.smartsheet.com"
    assert al.classify(target, {})[0] == "missing"
    listed = {"smartsheet": {"site": "smartsheet", "refused": False}}
    assert al.classify(target, listed)[0] == "ready"


def test_keychain_parse_names_only() -> None:
    """Readable = decrypt trusts the security CLI and apple-tool: may read;
    secret-looking names are masked."""
    import agent_login_keychain as kc  # pylint: disable=import-outside-toplevel

    def item(svce: str, apps: str, partition: str = "apple-tool:") -> str:
        return (
            'keychain: "/x/login.keychain-db"\nclass: "genp"\nattributes:\n'
            f'    "acct"<blob>="albert"\n    "svce"<blob>="{svce}"\n'
            "access: 3 entries\n    entry 0:\n"
            "        authorizations (6): decrypt derive export_clear\n"
            f"        applications{apps}\n"
            "    entry 1:\n        authorizations (1): partition_id\n"
            f"        description: {partition}\n        applications: <null>\n"
        )

    text = (
        item("EPFL_VPN_PASSWORD", " (1):\n            0: /usr/bin/security (OK)")
        + item("prompting-item", " (0):")
        + item("other-team", ": <null>", "teamid:ABC")
        + item("Xq7#pL9vT2", " (1):\n            0: /usr/bin/security (OK)")
    )
    got = {i["service"]: i["readable"] for i in kc.parse_dump(text)}
    assert got == {
        "EPFL_VPN_PASSWORD": True,
        kc.MASKED: True,
        "prompting-item": False,
        "other-team": False,
    }
