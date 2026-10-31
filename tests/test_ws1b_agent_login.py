"""WS1b client side: `agent-login.py -L` (the Safari pipeline around the step
machine), the on-demand state, the refresh pass, the assisted tri-state and
its 2-run mail rule, LaunchAgents, the toolchain lines, the new Safari import
rules, and browser.py's Notion verdict, guided-login event and built-in
import transaction.

Hermetic: the state dir and cache dirs are per-test temp dirs (conftest);
browser.py runs, Safari's cookie file, safari.py and launchctl are stubs.
No credential-shaped literals.
"""

from __future__ import annotations

# pylint: disable=missing-function-docstring,import-error,wrong-import-position
# pylint: disable=protected-access,too-many-lines,redefined-outer-name,unused-argument
import contextlib
import hashlib
import json
import os
import secrets
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from playwright.sync_api import Error as PlaywrightError

sys.path[:0] = [
    str(Path(__file__).resolve().parent.parent),
    str(Path(__file__).resolve().parent),
]

from ws3_fixtures import load_script  # noqa: E402

import agent_login_jobs as jobs  # noqa: E402
import agent_login_safari as alsafari  # noqa: E402
import agent_login_state as als  # noqa: E402
import agent_login_toolchain as tc  # noqa: E402
from broker import safari_cookies as sc  # noqa: E402

browser = load_script("browser_ws1b_test", "bin/browser.py")
al = load_script("agent_login_ws1b_test", "agent-login.py")


@pytest.fixture(autouse=True)
def _cache_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    cache = tmp_path / "browser-cache"
    cache.mkdir()
    monkeypatch.setenv("CLAUDE_BROWSER_CACHE_DIR", str(cache))
    monkeypatch.setattr(browser, "LOGIN_LOG_DIR", cache / "login-log")
    monkeypatch.delenv(alsafari.SCHEDULED_ENV, raising=False)
    return cache


def _run(rc: int | None, result: dict | None = None) -> jobs.BrowserRun:
    return jobs.BrowserRun(rc, rc is None, "", 0.1, result)


def _cookie(site: str, name: str, value: str | None = None) -> sc.Cookie:
    domain = sc.rule(site).domains[0]
    return sc.Cookie(
        domain=f".{domain}",
        name=name,
        value=value if value is not None else secrets.token_hex(8),
        path="/",
        expires=time.time() + 86400 * 30,
        secure=True,
        http_only=True,
    )


# ---------------------------------------------------------------------------
# -L: the pipeline
# ---------------------------------------------------------------------------


@pytest.fixture
def pipeline(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Stub every outside effect of `-L`; the dict records what happened."""
    log: dict[str, Any] = {
        "imports": [],
        "drive": 0,
        "probe": (2, {"code": "logged_out"}),
    }
    monkeypatch.setattr(al, "probe", lambda site, quiet=True: log["probe"])
    monkeypatch.setattr(al, "_safari_jar", lambda site: (log.get("jar", []), None))

    def fake_import(site: str, agent: bool) -> jobs.BrowserRun:
        log["imports"].append(agent)
        return _run(log.get("import_rc", 0), {"phase": "ok", "code": "ok"})

    def fake_drive(site: str, recipe: alsafari.Recipe) -> alsafari.Outcome:
        log["drive"] += 1
        out: alsafari.Outcome = log.get("outcome") or alsafari.Outcome(
            0, "ok", credential=True, steps=["login"]
        )
        return out

    monkeypatch.setattr(al, "_import_run", fake_import)
    monkeypatch.setattr(al, "_drive_safari", fake_drive)
    monkeypatch.setattr(al, "_wait_flush", lambda site, before: True)
    monkeypatch.setattr(al, "configured_instance", lambda site: "")
    monkeypatch.setattr(alsafari, "interactive_gate", lambda: log.get("gate"))
    return log


def test_l_refuses_on_an_unattended_mac(pipeline: dict) -> None:
    for reason in ("console_locked", "albert_idle", "idle_unknown"):
        pipeline["gate"] = reason
        assert al.safari_login_action("galaxus-de") == 3
    assert pipeline["drive"] == 0 and not pipeline["imports"]


@pytest.mark.parametrize(
    ("rc", "code"),
    [
        (2, "internal"),
        (2, "unknown"),
        (2, ""),
        (124, "timeout"),
        (al.KILLED_RC, "killed"),
        (2, "indeterminate"),
        (2, "access_gated"),
        (2, "identity_indeterminate"),
        (2, "wrong_account"),  # not Notion: no import proof handles it
    ],
)
def test_l_goes_on_only_from_a_definite_logged_out(
    pipeline: dict, rc: int, code: str
) -> None:
    pipeline["probe"] = (rc, {"code": code})
    assert al.safari_login_action("galaxus-de") == 2
    assert pipeline["drive"] == 0 and not pipeline["imports"]


def test_l_notion_also_goes_on_from_another_account(pipeline: dict) -> None:
    pipeline["probe"] = (2, {"code": "wrong_account"})
    pipeline["jar"] = [_cookie("notion", "token_v2")]
    assert al.safari_login_action("notion") == 0
    assert pipeline["imports"] == [False]


@pytest.mark.parametrize("rc", [75, 124, 125, None])
def test_l_stops_when_the_import_timed_out_or_was_busy(
    pipeline: dict, monkeypatch: pytest.MonkeyPatch, rc: int | None
) -> None:
    pipeline["jar"] = [_cookie("notion", "token_v2")]
    monkeypatch.setattr(al, "_import_run", lambda site, agent: _run(rc, None))
    assert al.safari_login_action("notion") in (2, 75)
    assert pipeline["drive"] == 0  # never followed by a Safari login (N5)


def test_l_import_after_a_login_without_steps_is_a_copy(pipeline: dict) -> None:
    pipeline["outcome"] = alsafari.Outcome(0, "ok")  # no step ran (N4)
    assert al.safari_login_action("galaxus-de") == 0
    assert pipeline["imports"] == [False]


def test_l_reports_a_failed_undo(
    pipeline: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    pipeline["jar"] = [_cookie("notion", "token_v2")]
    monkeypatch.setattr(
        al,
        "_import_run",
        lambda site, agent: _run(
            2, {"phase": "client-proof", "code": "indeterminate", "undo": "failed"}
        ),
    )
    assert al.safari_login_action("notion") == 2
    assert "UNDO FAILED" in al.last_checks()["notion"]["how"]


def test_l_says_quarantined_only_when_it_was_written(
    pipeline: dict, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    pipeline["outcome"] = alsafari.Outcome(2, "recipe_stuck", credential=True)

    def broken(*_a: Any, **_k: Any) -> None:
        raise als.StateError("locked")

    monkeypatch.setattr(als, "quarantine", broken)
    assert al.safari_login_action("galaxus-de") == 2
    out = capsys.readouterr().out
    assert "could NOT be written" in out and "quarantined (" not in out


def test_l_refuses_inside_a_launchagent(
    pipeline: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(alsafari.SCHEDULED_ENV, "1")
    assert al.safari_login_action("galaxus-de") == 2
    assert pipeline["drive"] == 0 and not pipeline["imports"]


def test_l_every_launchagent_plist_marks_itself_scheduled() -> None:
    for _label, text, _what in jobs.agent_plists():
        assert f"<key>{jobs.SCHEDULED_ENV}</key>" in text
    assert "<integer>21600</integer>" in jobs.refresh_plist()
    assert "<string>-R</string>" in jobs.refresh_plist()


def test_l_does_nothing_when_the_shared_browser_is_logged_in(pipeline: dict) -> None:
    pipeline["probe"] = (0, {"phase": "ok", "code": "ok"})
    assert al.safari_login_action("galaxus-de") == 0
    assert pipeline["drive"] == 0 and not pipeline["imports"]


@pytest.mark.parametrize(
    "code", ["indeterminate", "identity_indeterminate", "access_gated"]
)
def test_l_stops_when_the_free_check_cannot_tell(pipeline: dict, code: str) -> None:
    pipeline["probe"] = (2, {"code": code})
    assert al.safari_login_action("notion") == 2
    assert pipeline["drive"] == 0 and not pipeline["imports"]


def test_l_imports_a_session_safari_already_holds(pipeline: dict) -> None:
    pipeline["jar"] = [_cookie("notion", "token_v2")]
    assert al.safari_login_action("notion") == 0
    assert pipeline["imports"] == [False] and pipeline["drive"] == 0
    rec = al.last_checks()["notion"]
    assert rec["state"] == "ok" and rec["route"] == "safari-import"


def test_l_logs_safari_in_then_imports_as_an_agent_login(pipeline: dict) -> None:
    assert al.safari_login_action("galaxus-de") == 0
    assert pipeline["drive"] == 1 and pipeline["imports"] == [True]
    assert al.last_checks()["galaxus-de"]["route"] == "safari-login"


def test_l_failure_after_a_credential_step_quarantines(pipeline: dict) -> None:
    pipeline["outcome"] = alsafari.Outcome(2, "recipe_stuck", credential=True)
    assert al.safari_login_action("galaxus-de") == 2
    assert als.quarantined("galaxus-de") is not None
    # a second run is refused until the audited release
    assert al.safari_login_action("galaxus-de") == 2
    assert pipeline["drive"] == 1
    assert al.release_action("galaxus-de") == 0
    assert als.quarantined("galaxus-de") is None


def test_l_albert_stop_is_exit_4_and_no_quarantine(pipeline: dict) -> None:
    pipeline["outcome"] = alsafari.Outcome(4, "needs_albert_captcha")
    assert al.safari_login_action("galaxus-de") == 4
    assert als.quarantined("galaxus-de") is None
    rec = al.last_checks()["galaxus-de"]
    assert rec["code"] == "needs_albert_captcha" and rec["phase"] == "safari-source"


def test_l_vault_locked_is_the_agents_fix_not_albert(pipeline: dict) -> None:
    """tp#1082: a locked vault tab is no stop of Albert's — exit 2, no
    quarantine, and the text names the agent's own fixes."""
    pipeline["outcome"] = alsafari.Outcome(2, "vault_locked")
    assert al.safari_login_action("galaxus-de") == 2
    assert als.quarantined("galaxus-de") is None
    rec = al.last_checks()["galaxus-de"]
    assert rec["code"] == "vault_locked"
    row = {"site": "galaxus-de", "flow": al.SAFARI_FLOW, "status": "safari"}
    why = al._summary_reason(row, "failed", {"galaxus-de": rec})
    assert "~/.local/libexec/vault-touchid unlock-safari -a main" in why
    assert "needs Albert" not in why


def test_l_stops_when_the_import_lacks_an_expected_account(
    pipeline: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    pipeline["jar"] = [_cookie("notion", "token_v2")]
    monkeypatch.setattr(
        al,
        "_import_run",
        lambda site, agent: _run(
            2, {"phase": "precheck", "code": "identity_unconfigured"}
        ),
    )
    assert al.safari_login_action("notion") == 2
    assert pipeline["drive"] == 0  # a Safari login cannot fix it
    assert al.last_checks()["notion"]["code"] == "identity_unconfigured"


def test_l_unknown_site_and_dry_run(
    pipeline: dict, capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert al.safari_login_action("no-such-site") == 2
    pipeline["jar"] = [_cookie("notion", "token_v2")]
    pipeline["probe"] = (0, {})
    monkeypatch.setattr(al, "probe", lambda *a, **k: pytest.fail("probed"))
    assert al.safari_login_action("notion", dry_run=True) == 0
    out = capsys.readouterr().out
    assert "import it first" in out and "safari.py lacks" in out
    assert "interactive gate open" in out
    # read-only: no import, no record, no Safari
    assert not pipeline["imports"] and pipeline["drive"] == 0
    assert "notion" not in al.last_checks()


def test_l_ricardo_logs_safari_in_without_import(pipeline: dict) -> None:
    assert al.safari_login_action("ricardo") == 0
    assert pipeline["drive"] == 1 and not pipeline["imports"]


def test_l_one_safari_login_at_a_time() -> None:
    with al.safari_login_lock() as first:
        assert first
        with al.safari_login_lock(wait_s=0.2) as second:
            assert not second


def test_l_cli_combinations(monkeypatch: pytest.MonkeyPatch) -> None:
    combos = [["-n"], ["-L", "notion", "-c"], ["-L", "notion", "-R"]]
    combos += [
        ["-L", "notion", flag, "notion"]
        for flag in ("-t", "-g", "-p", "-Q", "-D", "-E")
    ]
    for argv in combos:
        monkeypatch.setattr(sys, "argv", ["agent-login.py", *argv])
        with pytest.raises(SystemExit) as exc:
            al.main()
        assert exc.value.code == 2


# ---------------------------------------------------------------------------
# texts agents read
# ---------------------------------------------------------------------------


def test_agents_md_tells_agents_to_run_l_not_to_ask_albert() -> None:
    """SF2: the header promises `-L` only for the sites `agent_route` routes
    (no unconditional promise), and says what exit 3 means."""
    data = {"rows": [], "broker_ok": True, "broker": "running"}
    text = al.agent_summary(data, {})
    assert "-L <site>" not in text
    assert "ask Albert to run `agent-login.py -g <site>`" in text
    # claude.ai's magic link needs no safari.py: routed even with no features
    rows = [
        {"site": s, "name": s, "status": "assisted", "flow": al.ASSISTED_FLOW}
        for s in ("anthropic", "notion")
    ]
    header = al._route_header(rows)
    assert header.startswith("for anthropic run `agent-login.py -L <site>` yourself")
    assert (
        "exit 3 = the Mac is locked or idle: retry later, do not ask Albert" in header
    )
    # tp#1082: a locked vault is no longer Albert's stop — the agent unlocks
    assert "or a locked vault are his" not in header
    assert "a locked vault is NOT his" in header
    assert "`~/.local/libexec/vault-touchid unlock-safari -a main` yourself" in header
    assert "for the other sites on Albert's session" in header
    assert header in al.agent_summary({**data, "rows": rows}, {})


def test_route_header_and_hints_follow_agent_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    notion = {"site": "notion", "status": "assisted", "flow": al.ASSISTED_FLOW}
    galaxus = {"site": "galaxus", "status": "safari", "flow": al.SAFARI_FLOW}
    live = {**galaxus, "safari": True, "safari_expires": "2099-01-01"}
    # no safari.py features: notion is Albert's; galaxus only with a live session
    assert not al.agent_route("notion", notion)
    assert (
        al.route_hint("notion", notion)
        == " — your own login: ./agent-login.py -g notion"
    )
    assert not al.agent_route("galaxus", galaxus)
    assert al.route_hint("galaxus", galaxus) == (
        " — Albert logs in in Safari, then ./agent-login.py -t galaxus"
    )
    assert al.agent_route("galaxus", live)
    assert al.route_hint("galaxus", live) == (
        " — an agent imports Albert's existing Safari session: ./agent-login.py -L galaxus"
    )
    assert not al.agent_route("galaxus", {**live, "safari_expires": "2000-01-01"})
    assert not al.agent_route("galaxus", {**live, "safari": "yes"})
    assert "galaxus" in al._route_header([notion, live])
    assert "notion" not in al._route_header([notion, live]).split(" run ")[0]
    # every feature: the recipe drives Safari itself
    monkeypatch.setenv(alsafari.FEATURES_ENV, ALL_FEATURES)
    assert al.agent_route("notion", notion)
    assert al.route_hint("notion", notion) == (
        " — an agent renews it: ./agent-login.py -L notion (Albert's Safari)"
    )
    assert al.route_hint("anthropic") == (
        " — an agent renews it: ./agent-login.py -L anthropic (magic link)"
    )
    assert al._route_header([notion]).startswith("for notion run")
    # a row whose site id is not a valid id never reaches the header
    bad = {**notion, "site": "bad id;rm"}
    assert al._route_header([bad]).startswith("for the other sites")


def test_check_only_gate_text_follows_agent_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = {"site": "galaxus", "status": "safari", "flow": al.SAFARI_FLOW}
    assert al.check_only_gate(row) == (
        "manual_import",
        "the Safari import runs by hand only — ./agent-login.py -t galaxus",
    )
    live = {**row, "safari": True, "safari_expires": "2099-01-01"}
    code, why = al.check_only_gate(live) or ("", "")
    assert code == "manual_import"
    assert (
        "an agent imports Albert's existing Safari session: ./agent-login.py -L galaxus"
        in why
    )
    assert "(a plain import: -t galaxus)" in why
    monkeypatch.setenv(alsafari.FEATURES_ENV, ALL_FEATURES)
    code, why = al.check_only_gate(row) or ("", "")
    assert "an agent renews it: ./agent-login.py -L galaxus (Albert's Safari)" in why


ALL_FEATURES = ",".join(
    sorted(set().union(*(r.features() for r in alsafari.RECIPES.values())))
)


def test_failed_rows_promise_l_only_with_safari_py_features(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = {"site": "notion", "flow": al.ASSISTED_FLOW, "status": "assisted"}
    # conftest: no safari.py features → the old wording (S2)
    assert "-g notion" in al._summary_reason(row, "failed", {})
    assert "-L galaxus-de" not in al.safari_fix("galaxus-de")
    monkeypatch.setenv(alsafari.FEATURES_ENV, ALL_FEATURES)
    assert "-L notion" in al._summary_reason(row, "failed", {})
    checks = {"notion": {"code": "needs_albert_push"}}
    assert "push approval" in al._summary_reason(row, "failed", checks)
    assert "-L galaxus-de" in al.safari_fix("galaxus-de")
    # claude.ai needs no safari.py: the magic link
    monkeypatch.setenv(alsafari.FEATURES_ENV, "none")
    assert "-L anthropic" in al.safari_fix("anthropic")


def test_a_quarantined_row_names_the_release(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(alsafari.FEATURES_ENV, ALL_FEATURES)
    row = {
        "site": "galaxus-de",
        "flow": al.SAFARI_FLOW,
        "status": "safari",
        "quarantine": {"phase": "safari-source", "at_text": "now"},
    }
    assert "./agent-login.py -Q galaxus-de" in al._summary_reason(row, "failed", {})


def test_galaxus_de_is_a_safari_target() -> None:
    target = next(t for t in al.TARGETS if t.site == "galaxus-de")
    assert target.flow == al.SAFARI_FLOW
    assert al.manual_import("galaxus-de")  # never imported by the daily run


def test_assisted_failure_keeps_wrong_account() -> None:
    failed: list = []
    al._record_assisted("notion", False, "x", {"code": "wrong_account"}, failed)
    assert al.last_checks()["notion"]["code"] == "wrong_account"
    al._record_assisted("notion", False, "x", {"code": "indeterminate"}, failed)
    assert al.last_checks()["notion"]["code"] == "logged_out"


def test_missing_safari_session_is_a_flag_not_a_setup_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(alsafari.FEATURES_ENV, ALL_FEATURES)
    row = {
        "site": "galaxus-de",
        "name": "Galaxus DE",
        "status": "safari",
        "safari": False,
        "fallback": "",
    }
    assert al._setup_problem(row) is None
    assert "renew: ./agent-login.py -L galaxus-de" in al._row_flags(row)


# ---------------------------------------------------------------------------
# on demand (myfritz)
# ---------------------------------------------------------------------------


def _row(site: str, **kw: Any) -> dict:
    base = {
        "site": site,
        "name": site,
        "status": "extra",
        "flow": "one-page",
        "instance": "",
        "stage": "pending",
    }
    base.update(kw)
    return base


def test_on_demand_row_is_never_stale(monkeypatch: pytest.MonkeyPatch) -> None:
    old = time.time() - 5 * 86400
    als.record_check("myfritz", "ok", "logged in", now=old)
    state, why = al.row_state(_row("myfritz"), als.checks())
    assert state == "on-demand" and "on demand" in why
    line = al._summary_line(_row("myfritz"), als.checks())
    assert line is not None and "browser.py login myfritz" in line[1]


def test_check_all_skips_on_demand_and_drops_its_legacy_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    als.record_check("myfritz", "failed", "NOT logged in")
    assert "myfritz" in als.read(als.LEGACY_FILE)
    monkeypatch.setattr(al, "ensure_logged_in", lambda *a, **k: pytest.fail("checked"))
    failed: list = []
    assert al._check_row(_row("myfritz"), failed, lambda: True)
    assert not failed and "myfritz" not in als.read(als.LEGACY_FILE)


# ---------------------------------------------------------------------------
# assisted tri-state + the 2-run mail rule
# ---------------------------------------------------------------------------


def test_invalid_streak_counts_runs_an_hour_apart() -> None:
    t0 = time.time()
    rec = als.record_check("notion", "failed", "x", run_id="a", now=t0)
    assert rec["invalid_streak"] == 1
    rec = als.record_check("notion", "failed", "x", run_id="a", now=t0 + 7200)
    assert rec["invalid_streak"] == 1  # same run
    rec = als.record_check("notion", "failed", "x", run_id="b", now=t0 + 60)
    assert rec["invalid_streak"] == 1  # too soon
    rec = als.record_check("notion", "unknown", "x", run_id="c", now=t0 + 3700)
    assert rec["invalid_streak"] == 1  # unknown keeps it
    rec = als.record_check("notion", "failed", "x", run_id="d", now=t0 + 3700)
    assert rec["invalid_streak"] == 2
    rec = als.record_check("notion", "ok", "x", run_id="e", now=t0 + 9000)
    assert rec["invalid_streak"] == 0


def test_first_invalid_is_reprobed_and_mailed_only_on_the_second_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    answers = iter(
        [
            (False, "NOT logged in", {"code": "logged_out"}),
            (False, "NOT logged in", {"code": "logged_out"}),
        ]
    )
    monkeypatch.setattr(al, "assisted_probe", lambda site: next(answers))
    failed: list = []
    deferred: list[str] = []
    al._check_assisted_row("notion", failed, deferred)
    assert deferred == ["notion"] and "notion" not in al.last_checks()
    al.recheck_deferred(deferred, failed)
    assert al.last_checks()["notion"]["invalid_streak"] == 1
    assert not failed  # one failed run: no mail yet


def test_reprobe_that_passes_records_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(al, "assisted_probe", lambda site: (True, "logged in", None))
    failed: list = []
    al.recheck_deferred(["notion"], failed)
    assert al.last_checks()["notion"]["state"] == "ok" and not failed


def test_tristate_indeterminate_is_could_not_tell(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    res = {"phase": "client-proof", "code": "indeterminate", "server": "indeterminate"}
    monkeypatch.setattr(al, "guided_busy", lambda: None)
    monkeypatch.setattr(al, "run_browser", lambda *a, **k: _run(2, res))
    ok, how, got = al._assisted_check("notion")
    assert ok is None and "could not tell" in how and got == res


# ---------------------------------------------------------------------------
# refresh pass
# ---------------------------------------------------------------------------


def test_refresh_pass_touches_only_refreshable_default_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rows = [
        _row("npm-nixos", session_refresh="npm-jwt"),
        _row("calibre"),
        _row("npm-admin", session_refresh="npm-jwt", instance="admin"),
    ]
    monkeypatch.setattr(al, "daily_loaded", lambda: True)
    monkeypatch.setattr(al, "wait_for_network", lambda **k: True)
    monkeypatch.setattr(al, "ensure_browser_up", lambda: True)
    monkeypatch.setattr(al, "_browser", lambda *a, **k: 0)
    monkeypatch.setattr(al, "overview", lambda: {"rows": rows})
    probed: list[str] = []

    def fake_probe(site: str, quiet: bool = True) -> tuple[int, dict]:
        probed.append(site)
        return 0, {"session_left_s": 3600}

    monkeypatch.setattr(al, "probe", fake_probe)
    monkeypatch.setattr(
        al, "refresh_step", lambda site, check, how: f"{how} (token renewed)"
    )
    monkeypatch.setattr(al, "row_instance", lambda row: row["instance"])
    assert al.refresh_pass() == 0
    assert probed == ["npm-nixos"]
    assert "npm-nixos" not in al.last_checks()  # records nothing


def test_refresh_pass_is_off_while_the_daily_job_is(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(al, "daily_loaded", lambda: False)
    monkeypatch.setattr(al, "wait_for_network", lambda **k: pytest.fail("ran"))
    assert al.refresh_pass() == 0


# ---------------------------------------------------------------------------
# LaunchAgents: one transaction
# ---------------------------------------------------------------------------


def test_install_rolls_back_every_agent_on_a_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(jobs, "_plist_path", lambda label: tmp_path / f"{label}.plist")
    (tmp_path / f"{jobs.SNAPSHOT_LABEL}.plist").write_text("old snapshot")
    calls: list[tuple[str, ...]] = []

    def fake(*args: str) -> int:
        calls.append(args)
        if args[0] == "print":
            return 0 if args[1].endswith(jobs.SNAPSHOT_LABEL) else 113
        if args[0] == "bootstrap" and jobs.REFRESH_LABEL in args[-1]:
            return 5
        return 0

    monkeypatch.setattr(jobs, "_launchctl", fake)
    assert jobs.install_daily() == 1
    assert not (tmp_path / f"{jobs.LAUNCH_LABEL}.plist").exists()
    assert not (tmp_path / f"{jobs.REFRESH_LABEL}.plist").exists()
    assert (tmp_path / f"{jobs.SNAPSHOT_LABEL}.plist").read_text() == "old snapshot"
    # the snapshot agent was loaded before: it is loaded again
    assert any(c[0] == "bootstrap" and jobs.SNAPSHOT_LABEL in c[-1] for c in calls[-3:])


def test_install_rolls_back_a_failed_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agents = tmp_path / "LaunchAgents"
    agents.mkdir()
    monkeypatch.setattr(jobs, "_plist_path", lambda label: agents / f"{label}.plist")
    monkeypatch.setattr(jobs, "_launchctl", lambda *a: 113 if a[0] == "print" else 0)
    real = Path.write_text

    def write(self: Path, text: str, **kw: Any) -> int:
        if jobs.REFRESH_LABEL in self.name:
            raise OSError(28, "No space left on device")
        return real(self, text, **kw)

    monkeypatch.setattr(Path, "write_text", write)
    assert jobs.install_daily() == 1
    assert not any(agents.iterdir())  # every new plist went again


# tp#1468 B3: the every-minute Access team-cookie sweep


def test_access_sweep_plist_runs_sweep_access_every_minute_in_background() -> None:
    plists = {label: text for label, text, _what in jobs.agent_plists()}
    text = plists[jobs.ACCESS_SWEEP_LABEL]
    assert "<string>com.albert.browser-access-sweep</string>" in text
    assert str(jobs.BROWSER_PY) in text
    args = "".join(f"<string>{a}</string>" for a in ("sweep-access", "-A", "-q", "-S"))
    assert args in text.replace("\n", "").replace(" ", "")
    assert "<key>StartInterval</key>\n    <integer>60</integer>" in text
    assert "<key>RunAtLoad</key>\n    <false/>" in text
    assert "<key>ProcessType</key>\n    <string>Background</string>" in text
    assert "<key>LowPriorityIO</key>\n    <true/>" in text
    log = f"{Path.home()}/Library/Logs/com.albert.browser-access-sweep.log"
    assert text.count(f"<string>{log}</string>") == 2  # stdout + stderr
    # the priority keys are this job's alone
    for label, other in plists.items():
        if label != jobs.ACCESS_SWEEP_LABEL:
            assert "ProcessType" not in other and "LowPriorityIO" not in other


def test_access_sweep_plist_is_valid_plist() -> None:
    import plistlib  # pylint: disable=import-outside-toplevel

    doc = plistlib.loads(jobs.access_sweep_plist().encode())
    assert doc["Label"] == jobs.ACCESS_SWEEP_LABEL
    assert doc["ProgramArguments"][1:] == [
        str(jobs.BROWSER_PY),
        "sweep-access",
        "-A",
        "-q",
        "-S",
    ]
    assert doc["StartInterval"] == 60 and doc["RunAtLoad"] is False
    assert doc["ProcessType"] == "Background" and doc["LowPriorityIO"] is True
    assert doc["EnvironmentVariables"][jobs.SCHEDULED_ENV] == "1"


def test_uninstall_removes_the_access_sweep(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(jobs, "_plist_path", lambda label: tmp_path / f"{label}.plist")
    booted: list[str] = []

    def fake(*args: str) -> int:
        booted.append(args[-1])
        return 0

    monkeypatch.setattr(jobs, "_launchctl", fake)
    for label, text, _what in jobs.agent_plists():
        (tmp_path / f"{label}.plist").write_text(text)
    assert jobs.uninstall_daily() == 0
    assert not list(tmp_path.glob("*.plist"))
    assert any(b.endswith(jobs.ACCESS_SWEEP_LABEL) for b in booted)


def test_install_rolls_back_when_the_access_sweep_itself_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The NEW job fails to bootstrap: every agent goes back to its old plist
    and load state; the sweep's own plist (none before) is gone again."""
    monkeypatch.setattr(jobs, "_plist_path", lambda label: tmp_path / f"{label}.plist")
    labels = [label for label, _t, _w in jobs.agent_plists()]
    assert labels[-1] == jobs.ACCESS_SWEEP_LABEL
    old = [label for label in labels if label != jobs.ACCESS_SWEEP_LABEL]
    for label in old:
        (tmp_path / f"{label}.plist").write_text(f"old {label}")
    calls: list[tuple[str, ...]] = []

    def fake(*args: str) -> int:
        calls.append(args)
        if args[0] == "print":
            return 113 if args[1].endswith(jobs.ACCESS_SWEEP_LABEL) else 0
        if args[0] == "bootstrap" and jobs.ACCESS_SWEEP_LABEL in args[-1]:
            return 5
        return 0

    monkeypatch.setattr(jobs, "_launchctl", fake)
    assert jobs.install_daily() == 1
    assert not (tmp_path / f"{jobs.ACCESS_SWEEP_LABEL}.plist").exists()
    for label in old:
        assert (tmp_path / f"{label}.plist").read_text() == f"old {label}"
    fail = max(
        i
        for i, c in enumerate(calls)
        if c[0] == "bootstrap" and jobs.ACCESS_SWEEP_LABEL in c[-1]
    )
    reloaded = {Path(c[-1]).stem for c in calls[fail + 1 :] if c[0] == "bootstrap"}
    assert reloaded == set(old)  # every agent loaded before is loaded again


def test_print_plist_prints_every_agent(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["agent-login.py", "-P"])
    assert al.main() == 0
    out = capsys.readouterr().out
    for label, _text, _what in jobs.agent_plists():
        assert f"<string>{label}</string>" in out


# ---------------------------------------------------------------------------
# toolchain
# ---------------------------------------------------------------------------


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_vault_touchid_stale_after_an_upgrade(tmp_path: Path) -> None:
    py = tmp_path / "Cellar/python@3.14/3.14.4/bin/python3.14"
    py.parent.mkdir(parents=True)
    py.write_bytes(b"old")
    node = tmp_path / "Cellar/node/26.1/bin/node"
    node.parent.mkdir(parents=True)
    node.write_bytes(b"node")
    swift = tmp_path / "Common.swift"
    swift.write_bytes(b"let x = 1")
    stamp = tmp_path / "vault-touchid.stamp"
    stamp.write_text(
        f"{tc.STAMP_HEADER} — release\n{_sha(py)}  {py}\n{_sha(node)}  {node}\n"
        f"{_sha(swift)}  {swift}\n"
    )
    assert tc.vault_touchid_finding(stamp, links={}) is None
    swift.write_bytes(b"let x = 2")  # ANY pinned file counts (N1)
    found = tc.vault_touchid_finding(stamp, links={})
    assert found is not None and "1 other pinned file(s) changed" in found.what
    py.write_bytes(b"new")
    found = tc.vault_touchid_finding(stamp, links={}, build=Path("/x/build.sh"))
    assert found is not None and "python3 changed" in found.what
    assert found.line().endswith("fix: /x/build.sh") and found.level == "fail"
    stamp.write_text("# something else\n")
    found = tc.vault_touchid_finding(stamp, links={})
    assert found is not None and found.unknown and found.level == "unknown"


def _dist(site: Path, name: str, version: str, direct: bool = False) -> None:
    d = site / f"{name.replace('-', '_')}-{version}.dist-info"
    d.mkdir(parents=True)
    (d / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
    )
    if direct:
        (d / "direct_url.json").write_text("{}")


def _sites(tmp_path: Path) -> tuple[Path, Path]:
    old = tmp_path / "Library/Python/3.14/lib/python/site-packages"
    new = tmp_path / "Library/Python/3.15/lib/python/site-packages"
    new.mkdir(parents=True)
    return old, new


def test_user_site_resync_pins_versions(tmp_path: Path) -> None:
    old, new = _sites(tmp_path)
    _dist(old, "Foo-Bar", "1.2")
    _dist(old, "local-thing", "0.1", direct=True)
    _dist(old, "kept", "3.0")
    _dist(new, "kept", "3.1")
    found = tc.user_site_finding(new)
    assert found is not None and found.level == "fail"  # a fresh minor version
    assert "foo-bar==1.2" in found.fix and "local-thing" not in found.fix
    assert "local-thing" in found.what and "kept" not in found.fix


def test_user_site_gap_is_a_warning_after_14_days_and_ignorable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    old, new = _sites(tmp_path)
    _dist(old, "Foo-Bar", "1.2")
    _dist(old, "gone-on-purpose", "2.0")
    later = time.time() + 15 * 86400
    found = tc.user_site_finding(new, now=later)
    assert found is not None and found.level == "warn" and found.unknown
    assert found.line().startswith("⚠️")
    monkeypatch.setenv(tc.USER_SITE_IGNORE_ENV, "foo_bar,Gone-On-Purpose")
    assert tc.user_site_finding(new) is None


def test_user_site_ambiguous_versions_are_never_pinned(tmp_path: Path) -> None:
    old, new = _sites(tmp_path)
    _dist(old, "twice", "1.0")
    (old / "Twice-2.0.dist-info").mkdir()
    (old / "Twice-2.0.dist-info" / "METADATA").write_text("Name: Twice\nVersion: 2.0\n")
    found = tc.user_site_finding(new)
    assert found is not None and "twice==" not in found.fix and "twice" in found.what


# ---------------------------------------------------------------------------
# Safari import rules
# ---------------------------------------------------------------------------


def test_builtin_rules_and_session_patterns() -> None:
    assert sc.importable_site("notion") and sc.importable_site("galaxus-de")
    assert not sc.importable_site("github")
    assert sc.is_session_cookie("__Secure-next-auth.session-token.0", "openai")
    assert not sc.is_session_cookie("oai-did", "openai")
    assert sc.has_session("slack", [_cookie("slack", "d")])
    assert not sc.has_session("slack", [_cookie("slack", "b")])
    assert "notion" not in sc.SAFARI_SITES  # login/logged-in keep their own flow


def test_session_fingerprint_sees_a_rotated_value() -> None:
    a = _cookie("notion", "token_v2", value="a" * 8)
    b = sc.Cookie(**{**a.__dict__, "value": "b" * 8})
    assert sc.session_fingerprint("notion", [a]) != sc.session_fingerprint(
        "notion", [b]
    )
    assert sc.session_fingerprint("notion", [a]) == sc.session_fingerprint(
        "notion", [a]
    )
    assert "a" * 8 not in sc.session_fingerprint("notion", [a])


# ---------------------------------------------------------------------------
# browser.py: tri-state checks, Notion verdict, events, built-in import
# ---------------------------------------------------------------------------


class FakePage:
    """Enough of a Playwright page for the tri-state checks."""

    def __init__(
        self,
        url: str,
        *,
        raise_on_goto: bool = False,
        challenged: bool = False,
        creds: dict | None = None,
        has_invite: bool = True,
        session: object = None,
    ) -> None:
        self.url = url
        self.raise_on_goto = raise_on_goto
        self.challenged = challenged
        self.creds = creds
        self.has_invite = has_invite
        self.session = session  # what CHATGPT_SESSION_JS answers
        jar = [{"name": "d", "value": secrets.token_hex(4), "domain": ".slack.com"}]
        self.context = SimpleNamespace(cookies=lambda *a: jar)

    def goto(self, _url: str, **_kw: Any) -> None:
        if self.raise_on_goto:
            raise PlaywrightError("net::ERR_TIMED_OUT")

    def wait_for_timeout(self, _ms: float) -> None:
        return None

    def evaluate(self, js: str, *args: Any) -> Any:
        if js == browser.CHALLENGE_JS:
            return self.challenged
        if js == browser.CHATGPT_SESSION_JS:
            if isinstance(self.session, Exception):
                raise self.session
            return self.session
        return self.creds

    def wait_for_selector(self, _sel: str, **_kw: Any) -> None:
        if not self.has_invite:
            raise PlaywrightError("timeout")


@pytest.mark.parametrize(
    ("page", "state"),
    [
        # the session endpoint decides (SF3), never the landing URL
        (FakePage("https://chatgpt.com/", session="invalid"), "invalid"),
        (FakePage("https://chatgpt.com/admin/members", session="invalid"), "invalid"),
        (FakePage("https://auth.openai.com/log-in", session="valid"), "valid"),
        (FakePage("https://chatgpt.com/", session="indeterminate"), "indeterminate"),
        (FakePage("https://chatgpt.com/", session=None), "indeterminate"),
        (
            FakePage("https://chatgpt.com/", session=PlaywrightError("closed")),
            "indeterminate",
        ),
        (FakePage("x", raise_on_goto=True, session="valid"), "indeterminate"),
    ],
)
def test_chatgpt_state(page: FakePage, state: str) -> None:
    assert browser._chatgpt_state(page) == state


class ChallengedChatgpt(FakePage):
    """chatgpt.com behind a Cloudflare "Just a moment..." page that clears
    after `clear_s` of (fake) time; `wait_for_timeout` advances the clock."""

    def __init__(self, clear_s: float, clock: list[float], session: str) -> None:
        super().__init__("https://chatgpt.com/", session=session)
        self.clear_s = clear_s
        self.clock = clock
        self.session_asked = False

    def wait_for_timeout(self, ms: float) -> None:
        self.clock[0] += ms / 1000

    def evaluate(self, js: str, *args: Any) -> Any:
        if js == browser.CHALLENGE_JS:
            return self.clock[0] < self.clear_s
        if js == browser.CHATGPT_SESSION_JS:
            self.session_asked = True
        return super().evaluate(js, *args)


@pytest.mark.parametrize(
    ("clear_s", "session", "state", "asked"),
    [
        # the interstitial clears by itself (2026-10-13: ~3 s) → the session
        # endpoint decides, logged in or not
        (4.0, "valid", "valid", True),
        (4.0, "invalid", "invalid", True),
        # never clears (a real block) → cannot tell, the endpoint is not asked
        (999.0, "valid", "indeterminate", False),
    ],
)
def test_chatgpt_state_waits_for_a_challenge_to_clear(
    monkeypatch: pytest.MonkeyPatch,
    clear_s: float,
    session: str,
    state: str,
    asked: bool,
) -> None:
    clock = [0.0]
    monkeypatch.setattr(browser.time, "monotonic", lambda: clock[0])
    page = ChallengedChatgpt(clear_s, clock, session)
    assert browser._chatgpt_state(page) == state
    assert page.session_asked is asked
    # bounded: the 1.5 s settle + at most CHALLENGE_CLEAR_WAIT_S of polling
    assert clock[0] <= 1.5 + browser.CHALLENGE_CLEAR_WAIT_S + 1.0


def test_openai_identity_waits_for_a_challenge_to_clear(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [0.0]
    monkeypatch.setattr(browser.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(browser, "_eval_enum", lambda *_a: "match")
    page = ChallengedChatgpt(5.0, clock, "valid")
    assert browser._openai_identity(page, {"expected_workspace_id": "W1"}) == "match"
    clock[0] = 0.0
    stuck = ChallengedChatgpt(999.0, clock, "valid")
    assert (
        browser._openai_identity(stuck, {"expected_workspace_id": "W1"})
        == "indeterminate"
    )


def test_chatgpt_session_probe_shape() -> None:
    js = browser.CHATGPT_SESSION_JS
    assert '"/api/auth/session"' in js and "AbortController" in js
    assert 'Object.keys(j).length === 0) return "invalid"' in js
    assert "j.user" in js and "innerText" not in js


@pytest.mark.parametrize(
    ("page", "state"),
    [
        (FakePage("https://swiss-data-science.slack.com/signin"), "invalid"),
        (FakePage("x", raise_on_goto=True), "indeterminate"),
        (FakePage("https://app.slack.com/client", challenged=True), "indeterminate"),
        (FakePage("https://app.slack.com/client", creds=None), "indeterminate"),
        (
            FakePage(
                "https://app.slack.com/client", creds={"token": "t", "domain": "d"}
            ),
            "valid",
        ),
    ],
)
def test_slack_state(
    monkeypatch: pytest.MonkeyPatch, page: FakePage, state: str
) -> None:
    monkeypatch.setattr(browser, "SLACK_BOOT_WAIT_S", 0.0)  # no boot wait here
    assert browser._slack_state(page) == state


class SlowSlack(FakePage):
    """A Slack client that writes its localConfig_v2 only after `boot_s` of
    (fake) time; `wait_for_timeout` advances the fake clock."""

    def __init__(self, boot_s: float, clock: list[float]) -> None:
        super().__init__(
            "https://app.slack.com/client", creds={"token": "t", "domain": "d"}
        )
        self.boot_s = boot_s
        self.clock = clock
        self.waits = 0

    def wait_for_timeout(self, ms: float) -> None:
        self.waits += 1
        self.clock[0] += ms / 1000

    def evaluate(self, js: str, *args: Any) -> Any:
        if js == browser.CHALLENGE_JS:
            return False
        return self.creds if self.clock[0] >= self.boot_s else None


@pytest.mark.parametrize(
    ("boot_s", "state"), [(12.0, "valid"), (25.0, "indeterminate")]
)
def test_slack_state_polls_for_the_client_boot(
    monkeypatch: pytest.MonkeyPatch, boot_s: float, state: str
) -> None:
    """SF3: a client that boots slowly after a cookie import is polled for up
    to SLACK_BOOT_WAIT_S (20 s) — in the proof and in the post-copy check,
    which both go through `_slack_state`."""
    clock = [0.0]
    monkeypatch.setattr(browser.time, "monotonic", lambda: clock[0])
    page = SlowSlack(boot_s, clock)
    assert browser.SLACK_BOOT_WAIT_S == 20.0
    assert browser._slack_state(page) == state
    assert page.waits <= browser.SLACK_BOOT_WAIT_S / browser.SLACK_BOOT_POLL_S + 1
    seen: list[str] = []

    def fake_state(_page: Any) -> str:
        seen.append("x")
        return state

    monkeypatch.setattr(browser, "_slack_state", fake_state)
    browser._slack_identity(page, {"expected_team_id": "T", "expected_user_id": "U"})
    browser._slack_logged_in(page)
    assert seen == ["x", "x"]


@pytest.mark.parametrize(
    ("state", "rc", "code"),
    [
        ("valid", 0, None),
        ("invalid", 2, "logged_out"),
        ("indeterminate", 2, "indeterminate"),
    ],
)
def test_builtin_checks_record_real_codes(
    monkeypatch: pytest.MonkeyPatch, state: str, rc: int, code: str | None
) -> None:
    monkeypatch.setattr(browser, "_background_page_run", lambda *a: state)
    for cmd in (browser.cmd_slack_logged_in, browser.cmd_openai_logged_in):
        browser._result_begin("logged-in", "x", None)
        assert cmd(9) == rc
        assert browser._RESULT.get("code") == code


@pytest.mark.parametrize(
    ("server", "sidebar", "on_login", "verified", "verdict"),
    [
        ("valid", False, False, True, "valid"),
        ("invalid", False, True, True, "invalid"),
        ("invalid", True, False, True, "indeterminate"),
        ("invalid", True, False, False, "valid"),  # S11: before L0, kept ✅
        ("indeterminate", True, False, True, "valid"),
        ("indeterminate", False, True, True, "invalid"),
        ("indeterminate", False, False, True, "indeterminate"),
    ],
)
def test_notion_verdict(
    server: str, sidebar: bool, on_login: bool, verified: bool, verdict: str
) -> None:
    assert browser.notion_verdict(server, sidebar, on_login, verified)[0] == verdict


def test_notion_server_probe_is_bounded_and_picks_the_sessions_user() -> None:
    js = browser.NOTION_SERVER_JS
    assert "AbortController" in js and 'redirect: "manual"' in js
    # the user id comes from the context's cookies (p.mine), never document.cookie
    assert "p.mine" in js and "all.length === 1" in js
    assert "document.cookie" not in js
    # before L0 only a 401 is "invalid" (S11)
    assert 'r.status === 401 || (p.verified && r.type === "opaqueredirect")' in js
    assert "innerText" not in js


def test_identity_probes_return_enums_only() -> None:
    for js in (browser.SLACK_IDENTITY_JS, browser.OPENAI_IDENTITY_JS):
        assert "AbortController" in js and "innerText" not in js
    assert (
        "j.team_id === want.team && j.user_id === want.user"
        in browser.SLACK_IDENTITY_JS
    )
    assert "account_id" in browser.OPENAI_IDENTITY_JS


def test_guided_event_is_recorded_once(monkeypatch: pytest.MonkeyPatch) -> None:
    began = time.time() - 1
    browser._record_guided_event("Notion", began)
    browser._record_guided_event("notion", began)  # already logged since `began`
    modes = [e["mode"] for e in browser._load_login_events("notion")]
    assert modes == ["guided"]
    assert "guided" in browser.ASSISTED_MODES


def test_login_stats_do_not_count_copies(capsys: pytest.CaptureFixture) -> None:
    browser._record_login_event("tutti", "safari-import")
    browser._record_login_event("tutti", "safari-agent")
    browser._print_login_stats("x", browser._load_login_events("tutti"))
    out = capsys.readouterr().out
    assert "1 real login(s)" in out and "1 session cop(ies)" in out


def _overrides(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, data: dict) -> None:
    path = tmp_path / "overrides.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    os.chmod(path, 0o600)
    monkeypatch.setenv("AGENT_LOGIN_SAFARI_OVERRIDES", str(path))


def test_builtin_expected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    values, why = browser._builtin_expected("notion")
    assert not values and "expected_email" in why
    _overrides(
        tmp_path,
        monkeypatch,
        {
            "slack": {"expected_team_id": "T1"},
            "notion": {"notion_probe_verified": True},
        },
    )
    values, why = browser._builtin_expected("slack")
    assert not values and "expected_user_id" in why
    assert browser._notion_probe_verified()
    _overrides(
        tmp_path,
        monkeypatch,
        {"slack": {"expected_team_id": "T1", "expected_user_id": "U1"}},
    )
    assert browser._builtin_expected("slack") == (
        {"expected_team_id": "T1", "expected_user_id": "U1"},
        "",
    )
    assert not browser._notion_probe_verified()
    # OpenAI: the workspace id is required, the account e-mail optional (NIT)
    _overrides(tmp_path, monkeypatch, {"openai": {"expected_workspace_id": "W1"}})
    assert browser._builtin_expected("openai") == ({"expected_workspace_id": "W1"}, "")
    _overrides(
        tmp_path,
        monkeypatch,
        {"openai": {"expected_workspace_id": "W1", "expected_email": "a@example.org"}},
    )
    assert browser._builtin_expected("openai") == (
        {"expected_workspace_id": "W1", "expected_email": "a@example.org"},
        "",
    )


def test_openai_identity_passes_the_optional_email(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent: list[Any] = []

    def fake_enum(_page: Any, _js: str, arg: Any) -> str:
        sent.append(arg)
        return "match"

    monkeypatch.setattr(browser, "_eval_enum", fake_enum)
    page = FakePage("https://chatgpt.com/")
    assert browser._openai_identity(page, {"expected_workspace_id": "W1"}) == "match"
    want = {"expected_workspace_id": "W1", "expected_email": "a@example.org"}
    browser._openai_identity(page, want)
    assert sent == [
        {"workspace": "W1", "email": ""},
        {"workspace": "W1", "email": "a@example.org"},
    ]
    js = browser.OPENAI_IDENTITY_JS
    assert "want.email" in js and "sj.user.email" in js and "toLowerCase" in js


def test_notion_user_id_comes_from_the_context_jar() -> None:
    """NIT: the session's user id is read with `context.cookies()` (it may be
    HttpOnly), never from document.cookie; no other cookie value is kept."""
    page = FakePage("https://app.notion.com/")
    jar = [
        {"name": "token_v2", "value": secrets.token_hex(4)},
        {"name": "notion_user_id", "value": "user-1"},
    ]
    page.context = SimpleNamespace(cookies=lambda *a: jar)
    assert browser._notion_user_id(page) == "user-1"
    page.context = SimpleNamespace(cookies=lambda *a: [])
    assert browser._notion_user_id(page) == ""

    def broken(*_a: Any) -> list:
        raise PlaywrightError("closed")

    page.context = SimpleNamespace(cookies=broken)
    assert browser._notion_user_id(page) == ""


def test_notion_identity_hands_the_jar_user_to_the_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args: list[dict] = []

    class Probe(FakePage):
        def evaluate(self, js: str, *a: Any) -> Any:
            assert js == browser.NOTION_SERVER_JS
            args.append(a[0])
            return {"server": "valid", "identity": "match"}

    page = Probe("https://app.notion.com/")
    monkeypatch.setattr(browser, "_notion_user_id", lambda p: "user-1")
    assert browser._notion_identity(page, {"expected_email": "a@example.org"}) == (
        "match"
    )
    assert args == [{"expected": "a@example.org", "verified": True, "mine": "user-1"}]


def test_tristate_sites_cover_every_builtin_import() -> None:
    assert al.TRISTATE_SITES == frozenset({"notion", "slack", "openai"})
    assert set(sc.SAFARI_BUILTIN) <= al.TRISTATE_SITES


@pytest.fixture
def builtin(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """`_import_builtin` with every browser effect stubbed; `log` records the
    order of what touched the shared jar."""
    log: dict[str, Any] = {
        "order": [],
        "before": "invalid",
        "after": "valid",
        "verdict": "match",
    }
    cookie = _cookie("slack", "d")
    monkeypatch.setattr(browser, "_safari_site_cookies", lambda site: ([cookie], 0))
    expected = {"expected_team_id": "T1", "expected_user_id": "U1"}
    monkeypatch.setattr(browser, "_builtin_expected", lambda site: (expected, ""))
    monkeypatch.setattr(browser, "_registry_register", lambda *a, **k: lambda: None)

    @contextlib.contextmanager
    def lease(_purpose: str):
        log["lease"] = True
        yield "nonce"
        log["lease"] = False

    monkeypatch.setattr(browser, "_interaction_lease", lease)

    def state(port: int, site: str, exp: dict) -> str:
        assert log["lease"]
        key = "after" if "replace" in log["order"] else "before"
        log["order"].append(f"state:{key}")
        return str(log[key])

    def prove(port: int, site: str, cookies: Any, exp: dict) -> str:
        assert log["lease"] and "replace" not in log["order"]  # S6: jar untouched
        log["order"].append("prove")
        return str(log["verdict"])

    def replace(port: int, site: str, cookies: Any) -> int:
        log["order"].append("replace")
        return 1

    def clear_storage(port: int, site: str) -> bool:
        log["order"].append("clear_storage")
        return True

    def clear(port: int, site: str) -> bool:
        log["order"].append("undo")
        return bool(log.get("undo_ok", True))

    monkeypatch.setattr(browser, "_builtin_state", state)
    monkeypatch.setattr(browser, "_builtin_prove_isolated", prove)
    monkeypatch.setattr(browser, "_builtin_replace", replace)
    monkeypatch.setattr(browser, "_builtin_clear_storage", clear_storage)
    monkeypatch.setattr(browser, "_builtin_clear", clear)
    return log


def test_builtin_import_proves_in_isolation_then_commits(builtin: dict) -> None:
    assert browser._import_builtin(9, "slack", dry_run=False, agent=True) == 0
    assert builtin["order"] == [
        "state:before",
        "prove",
        "clear_storage",  # Slack's token store first (S8)
        "replace",
        "state:after",
    ]
    assert [e["mode"] for e in browser._load_login_events("slack")] == ["safari-agent"]


@pytest.mark.parametrize("verdict", ["mismatch", "logged_out", "indeterminate"])
def test_builtin_import_never_touches_the_jar_without_a_match(
    builtin: dict, verdict: str
) -> None:
    builtin["verdict"] = verdict
    assert browser._import_builtin(9, "slack", dry_run=False, agent=False) == 2
    assert builtin["order"] == ["state:before", "prove"]
    assert browser._load_login_events("slack") == []


@pytest.mark.parametrize("before", ["valid", "indeterminate"])
def test_builtin_import_refuses_a_working_or_undecided_session(
    builtin: dict, before: str
) -> None:
    builtin["before"] = before
    rc = browser._import_builtin(9, "slack", dry_run=False, agent=False)
    assert rc == (0 if before == "valid" else 2)
    assert builtin["order"] == ["state:before"]  # S7: nothing proven, nothing replaced


@pytest.mark.parametrize("undo_ok", [True, False])
def test_builtin_import_undoes_a_session_the_shared_browser_rejects(
    builtin: dict, undo_ok: bool
) -> None:
    builtin["after"] = "invalid"
    builtin["undo_ok"] = undo_ok
    assert browser._import_builtin(9, "slack", dry_run=False, agent=False) == 2
    assert builtin["order"][-1] == "undo"
    assert browser._RESULT.get("undo") == ("done" if undo_ok else "failed")


def test_builtin_import_needs_an_expected_account(
    builtin: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(browser, "_builtin_expected", lambda site: ({}, "none"))
    assert browser._import_builtin(9, "slack", dry_run=False, agent=False) == 2
    assert not builtin["order"]
    assert browser._RESULT.get("code") == "identity_unconfigured"


def test_no_credential_literals_in_this_file() -> None:
    text = Path(__file__).read_text(encoding="utf-8")
    assert "pass" + "word=" not in text.replace(" ", "")
    assert os.environ.get(alsafari.SCHEDULED_ENV) is None
    assert json.loads("{}") == {}
