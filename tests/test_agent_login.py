"""Status logic of agent-login.py (no broker, no network)."""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

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
    # built-in assisted sites need no broker; eduid-sso sites fall back to assisted
    no_broker = al.ASSISTED_SITES | al.EDUID_SSO_SITES
    for site, status in statuses.items():
        want = {"assisted"} if site in no_broker else {"unchecked", "unknown"}
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
    assert {"anthropic", "openai", "slack"} <= al.ASSISTED_SITES
    assert "switch" not in al.ASSISTED_SITES  # tp#821: the broker logs it in
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


def test_keychain_names_without_broker_are_strict(monkeypatch) -> None:
    """No secret broker: only ENV_STYLE / colon names survive."""
    import agent_login_keychain as kc  # pylint: disable=import-outside-toplevel

    monkeypatch.setattr(kc, "_scrub_client", lambda: None)
    got = kc.mask_known_secrets(["EPFL_VPN_PASSWORD", "gh:github.com", "plainword"])
    assert got == ["EPFL_VPN_PASSWORD", "gh:github.com", kc.MASKED]


def test_agents_file_lists_injectable_secrets_by_name_only(
    monkeypatch, tmp_path
) -> None:
    """tp#816 E2: `-S` puts the secret-run items (ids + field names) into the
    agents file, never a value — against a real broker on a fixture vault."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import secret_fixtures as sf  # pylint: disable=import-outside-toplevel

    pw, token, seed = sf.sentinel(), sf.sentinel(), sf.totp_seed()
    items = [
        sf.secret_item(
            "GitHub",
            pw,
            fields={"agent_secret_fields": "api_token", "api_token": token},
            totp=seed,
        ),
        sf.secret_item("Refused", "abc"),
    ]
    vpath = sf.write_vault(tmp_path / "v.json", items)
    monkeypatch.setenv("AGENT_LOGIN_STATE_FILE", str(tmp_path / "state" / "last.json"))
    with sf.sockdir() as d:
        brk = sf.make_broker(
            tmp_path / "h", vpath, allow_uid=os.getuid(), keeper_sock=None
        )
        with sf.serving(brk, str(d / "b.sock"), os.getuid()) as path:
            monkeypatch.setattr(al, "SOCKET", path)
            note, rows = al.agent_login_secrets.secrets_state(
                al.broker_request, tmp_path / "state", fresh=True
            )
    assert note == "ok"
    data = {"rows": [], "broker_ok": True}
    written = al.write_agent_summary(data).read_text()  # reads the snapshot
    assert "## Secrets agents can inject" in written
    assert "- `github`: password, api_token (+ TOTP: `-o`)" in written
    assert "refused" not in written.lower().split("## secrets", 1)[1]
    for value in (pw, token, seed):
        assert value not in written
    assert rows and rows[0]["id"] == "github"
    snapshot = (tmp_path / "state" / "secrets.json").read_text()
    for value in (pw, token, seed):
        assert value not in snapshot


def test_secret_rows_are_sanitised_again() -> None:
    rows = al.agent_login_secrets.clean_rows(
        [
            {"id": "pw=hunter2!", "fields": ["ok", "a\tb"], "has_totp": True},
            {"id": "gone", "refused": True},
        ]
    )
    assert rows == [{"id": "item-1", "fields": ["ok", "field-2"], "has_totp": True}]
    assert al.agent_login_secrets.summary_lines([]) == []


SWITCH = next(t for t in al.TARGETS if t.site == "switch")
_READABLE = "running, Bitwarden readable"


def test_switch_is_eduid_sso_through_the_broker() -> None:
    """tp#821: switch logs in via the broker's `eduid` item + the SSO click."""
    assert SWITCH.flow == al.EDUID_SSO_FLOW and SWITCH.broker_site == "eduid"
    assert al.EDUID_SSO_FLOW in al.SUPPORTED_FLOWS
    eduid = {"eduid": {"site": "eduid", "refused": False}}
    assert al.classify(SWITCH, eduid)[0] == "ready"
    # no / refused eduid item: the window flow, i.e. your own session
    assert al.classify(SWITCH, {})[0] == "assisted"
    refused = {"eduid": {"site": "eduid", "refused": True, "reason": "x"}}
    status, detail = al.classify(SWITCH, refused)
    assert status == "assisted" and "-g switch" in detail
    assert al.classify(SWITCH, eduid, readable=False)[0] == "assisted"


def test_overview_switch_row_reads_the_eduid_item(monkeypatch) -> None:
    sites = [{"site": "eduid", "refused": False, "fill_origins": ["https://x"]}]
    monkeypatch.setattr(al, "broker_state", lambda **_k: (_READABLE, sites))
    row = {r["site"]: r for r in al.overview()["rows"]}["switch"]
    assert row["status"] == "ready" and row["in_bitwarden"]
    assert row["check_url"] == al.DEFAULT_CHECK_URLS.get("switch", "")


def _fake_run(calls: list):
    class _Res:
        returncode = 0

    def run(cmd, **_kw):
        calls.append(cmd[2:])
        return _Res()

    return run


def _no_assisted_check(site: str):
    raise AssertionError(f"assisted_check({site}) must not run")


def test_run_test_switch_logs_in_when_the_broker_has_eduid(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setenv("AGENT_LOGIN_STATE_FILE", str(tmp_path / "last.json"))
    sites = [{"site": "eduid", "refused": False}]
    monkeypatch.setattr(al, "broker_state", lambda **_k: (_READABLE, sites))
    calls: list = []
    monkeypatch.setattr(al.subprocess, "run", _fake_run(calls))
    monkeypatch.setattr(al, "assisted_check", _no_assisted_check)
    assert al.run_test("switch") == 0
    assert calls == [["login", "switch"], ["logged-in", "switch"]]
    assert al.last_checks(tmp_path / "last.json")["switch"]["ok"]


def test_run_test_switch_only_checks_without_eduid(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("AGENT_LOGIN_STATE_FILE", str(tmp_path / "last.json"))
    monkeypatch.setattr(al, "broker_state", lambda **_k: (_READABLE, []))
    calls: list = []
    monkeypatch.setattr(al.subprocess, "run", _fake_run(calls))
    monkeypatch.setattr(al, "assisted_check", lambda s: (False, "NOT logged in"))
    assert al.run_test("switch") == 2
    assert not calls  # no `browser.py login`: it would wait for a human


def test_guided_switch_is_the_window_login(monkeypatch) -> None:
    seen: list[str] = []

    def fake_assisted_login(site: str) -> int:
        seen.append(site)
        return 0

    monkeypatch.setattr(al, "assisted_login", fake_assisted_login)
    assert al.manual_login("switch") == 0 and seen == ["switch"]
    assert "-g switch" in al.safari_fix("switch")


def test_check_all_starts_a_down_browser(monkeypatch) -> None:
    """A down shared Chromium is started before any site is checked."""
    monkeypatch.setattr(al, "wait_for_network", lambda: True)
    state: dict[str, str | None] = {"mode": None}
    calls: list[tuple[str, ...]] = []

    def fake_browser(*args: str, quiet: bool = False) -> int:
        del quiet
        calls.append(args)
        state["mode"] = "headless"
        return 0

    monkeypatch.setattr(al, "_browser", fake_browser)
    monkeypatch.setattr(al, "browser_mode", lambda: state["mode"])
    monkeypatch.setattr(
        al, "overview", lambda: {"broker_ok": True, "broker": "ok", "rows": []}
    )
    assert al.check_all() == 0
    assert calls == [("up", "--headless")]


def test_check_all_browser_wont_start(monkeypatch) -> None:
    """Browser stays down: ONE failure (and one mail), no per-site verdicts."""
    monkeypatch.setattr(al, "wait_for_network", lambda: True)
    monkeypatch.setattr(al, "_browser", lambda *a, quiet=False: 1)
    monkeypatch.setattr(al, "browser_mode", lambda: None)
    monkeypatch.setattr(al, "overview", pytest.fail)
    monkeypatch.setattr(al, "record_check", pytest.fail)
    sent: list = []
    monkeypatch.setattr(al, "send_mail", lambda *a: sent.append(a))
    assert al.check_all(mail=True) == 1
    assert len(sent) == 1 and "does not start" in sent[0][0]


def test_check_all_browser_dies_mid_run(monkeypatch) -> None:
    """The browser dies after the first site: the run stops, later sites keep
    their previous verdict instead of being recorded as logged out."""
    monkeypatch.setattr(al, "wait_for_network", lambda: True)
    ups = iter([True, True, False])
    monkeypatch.setattr(al, "ensure_browser_up", lambda: next(ups))
    rows = [{"site": s, "status": "ready"} for s in ("a", "b", "c")]
    monkeypatch.setattr(
        al, "overview", lambda: {"broker_ok": True, "broker": "ok", "rows": rows}
    )
    seen: list[str] = []

    def ensure(site: str) -> tuple[bool, str]:
        seen.append(site)
        return True, "x"

    monkeypatch.setattr(al, "ensure_logged_in", ensure)
    monkeypatch.setattr(al, "record_check", lambda *a, **k: None)
    assert al.check_all() == 1
    assert seen == ["a"]
