"""Headless by default (tp#836 Phase 2): desired mode, headed lease, preflight.

The invariant under test: the shared browser is headless unless a live HEADED
LEASE exists, held by a guided login (`agent-login.py -g SITE`). These tests pin
the pieces that enforce it — `up` always headless, `switch headed` only for the
lease holder, lease liveness (heartbeat, dead pid, pid reuse), the preflight
revert decision, `login`'s "needs Albert" exit, `_bring_to_front`'s skip rule,
the launch flags (no `--remote-allow-origins`), the native-UI profile prefs and
agent-login's guided window (lease → switch headed → switch headless).

Hermetic: every state file lives in tmp_path (conftest `_private_mode_state`),
the browser and `ps` are stubbed where they would be reached; nothing talks to
the live shared browser.

Run: uv run --no-sync pytest tests/test_headless_default.py -q
"""

from __future__ import annotations

# Tests reach into browser.py's private helpers on purpose (it is a script, not
# a package, so there is no public API).
# pylint: disable=protected-access,missing-function-docstring,import-error
# pylint: disable=redefined-outer-name,unused-argument,duplicate-code
import contextlib
import importlib.util
import json
import os
import sys
import time
import types
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
PORT = 59333


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


browser = _load("browser_headless_test", _REPO / "bin" / "browser.py")
sys.path.insert(0, str(_REPO))
import agent_login_jobs as jobs  # noqa: E402  # pylint: disable=wrong-import-position

LSTART = "Thu Oct  8 10:00:00 2026"


@pytest.fixture
def cache(tmp_path, monkeypatch):
    """A private CACHE_DIR; `ps` answers LSTART for our own pid only."""
    monkeypatch.setattr(browser, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(browser, "LIFECYCLE_FILE", tmp_path / "lifecycle.json")
    monkeypatch.setattr(browser, "PROFILE_DIR", tmp_path / "profile")
    monkeypatch.setattr(browser, "PID_FILE", tmp_path / "browser.pid")
    monkeypatch.setattr(
        browser, "_proc_lstart", lambda pid: LSTART if pid == os.getpid() else None
    )
    return tmp_path


def _lease_rec(**over) -> dict:
    rec = {
        "owner_nonce": "n" * 32,
        "pid": os.getpid(),
        "pid_start_time": LSTART,
        "site": "anthropic",
        "started": "2026-10-08T10:00:00+0200",
        "heartbeat": time.time(),
    }
    rec.update(over)
    return rec


def _write_lease(rec: dict) -> None:
    browser.MAINTENANCE_FILE.parent.mkdir(parents=True, exist_ok=True)
    browser.MAINTENANCE_FILE.write_text(json.dumps(rec), encoding="utf-8")


# --- desired mode -------------------------------------------------------------


def test_desired_mode_defaults_to_headless(cache):
    assert not browser.DESIRED_MODE_FILE.exists()
    assert browser._desired_mode() == "headless"
    assert browser._desired_mode_state().startswith("headless (no file")
    browser._desired_mode_write()
    data = json.loads(browser.DESIRED_MODE_FILE.read_text(encoding="utf-8"))
    assert data == {"mode": "headless"}
    assert browser._desired_mode_state() == "headless"


def test_desired_mode_ignores_a_stray_headed(cache):
    browser.DESIRED_MODE_FILE.parent.mkdir(parents=True, exist_ok=True)
    browser.DESIRED_MODE_FILE.write_text('{"mode": "headed"}', encoding="utf-8")
    assert browser._desired_mode() == "headless"
    assert "not allowed" in browser._desired_mode_state()


@pytest.mark.parametrize("argv", [["up"], ["up", "-H"], ["up", "--headless"]])
def test_up_flag_is_a_no_op_and_env_is_ignored(cache, monkeypatch, argv):
    monkeypatch.setenv("CLAUDE_BROWSER_HEADLESS", "0")
    monkeypatch.setattr(sys, "argv", ["browser.py", *argv])
    args = browser.parse_args()
    launched: list[bool] = []
    monkeypatch.setattr(browser, "_browser_mode", lambda port: None)
    monkeypatch.setattr(browser, "_gate_acquire", lambda kind, wait: 7)
    monkeypatch.setattr(browser, "_gate_release", lambda fd: None)

    def launch(port, headless):
        launched.append(headless)
        return 0

    monkeypatch.setattr(browser, "_launch_and_record", launch)
    assert browser._dispatch(args, PORT) == 0
    assert launched == [True]


def test_up_reverts_a_headed_browser_without_lease(cache, monkeypatch):
    switched: list[tuple] = []
    monkeypatch.setattr(browser, "_browser_mode", lambda port: "headed")

    def switch(port, target, force=False, gate_wait_s=None, revert=False):
        assert revert
        switched.append((target, gate_wait_s))
        return 0

    monkeypatch.setattr(browser, "cmd_switch", switch)
    assert browser.cmd_up(PORT) == 0
    assert switched == [("headless", browser.PREFLIGHT_GATE_WAIT_S)]


def test_up_leaves_a_guided_login_alone(cache, monkeypatch, capsys):
    _write_lease(_lease_rec())
    monkeypatch.setattr(browser, "_browser_mode", lambda port: "headed")
    monkeypatch.setattr(
        browser, "cmd_switch", lambda *a, **k: pytest.fail("must not switch")
    )
    assert browser.cmd_up(PORT) == 0
    assert "HEADED inside a guided login" in capsys.readouterr().out


# --- switch headed -------------------------------------------------------------


def test_switch_headed_refused_without_lease(cache, monkeypatch, capsys):
    monkeypatch.setattr(
        browser, "_browser_mode", lambda port: pytest.fail("no CDP before the check")
    )
    assert browser.cmd_switch(PORT, "headed") == 2
    err = capsys.readouterr().err
    assert "headed mode only inside a guided login: agent-login.py -g <site>" in err


def test_switch_headed_refused_with_a_foreign_nonce(cache, monkeypatch):
    _write_lease(_lease_rec())
    monkeypatch.setenv(browser.MAINTENANCE_ENV, "x" * 32)
    monkeypatch.setattr(browser, "_browser_mode", lambda port: "headless")
    assert browser.cmd_switch(PORT, "headed") == 2


def test_switch_headed_allowed_for_the_lease_holder(cache, monkeypatch, capsys):
    _write_lease(_lease_rec())
    monkeypatch.setenv(browser.MAINTENANCE_ENV, "n" * 32)
    monkeypatch.setattr(browser, "_browser_mode", lambda port: "headed")
    monkeypatch.setattr(browser, "_heal_running_record", lambda port, mode: False)
    assert browser.cmd_switch(PORT, "headed") == 0
    assert "already in HEADED" in capsys.readouterr().out


def test_switch_headless_needs_no_lease_and_records_the_desire(cache, monkeypatch):
    monkeypatch.setattr(browser, "_browser_mode", lambda port: "headless")
    monkeypatch.setattr(browser, "_heal_running_record", lambda port, mode: False)
    assert browser.cmd_switch(PORT, "headless") == 0
    assert browser._desired_mode_state() == "headless"


def _switch_env(monkeypatch, on_gate):
    """cmd_switch with the gate, shutdown and launch stubbed; `on_gate` runs
    while the (fake) gate is being acquired — what happens while we wait."""
    calls: list[str] = []

    def gate(kind, wait):
        on_gate()
        return 7

    monkeypatch.setattr(browser, "_gate_acquire", gate)
    monkeypatch.setattr(browser, "_gate_release", lambda fd: None)
    monkeypatch.setattr(browser, "_unknown_clients_verdict", lambda port: None)

    def shutdown(port, rec):
        calls.append("shutdown")
        return True

    def launch(port, headless):
        calls.append("launch")
        return 0

    monkeypatch.setattr(browser, "_shutdown_browser", shutdown)
    monkeypatch.setattr(browser, "_launch_and_record", launch)
    return calls


def test_revert_waiting_on_the_gate_spares_a_new_guided_login(cache, monkeypatch):
    """Revert queued behind the gate; meanwhile a guided login takes the lease
    and the browser is headed → the revert must do nothing."""
    monkeypatch.setattr(browser, "_browser_mode", lambda port: "headed")
    calls = _switch_env(monkeypatch, lambda: _write_lease(_lease_rec()))
    assert browser._revert_headed(PORT, "`eval`") == 0
    assert not calls
    assert any(
        e["event"] == "revert_skipped" and e["reason"] == "lease"
        for e in _journal_events()
    )


def test_switch_rechecks_the_mode_under_the_gate(cache, monkeypatch):
    modes = iter(["headed", "headless"])  # another switch got there first
    monkeypatch.setattr(browser, "_browser_mode", lambda port: next(modes))
    calls = _switch_env(monkeypatch, lambda: None)
    assert browser.cmd_switch(PORT, "headless") == 0
    assert not calls


def test_switch_without_change_meanwhile_does_switch(cache, monkeypatch):
    monkeypatch.setattr(browser, "_browser_mode", lambda port: "headed")
    monkeypatch.setattr(browser, "_lifecycle_transition", lambda *a: {})
    calls = _switch_env(monkeypatch, lambda: None)
    assert browser.cmd_switch(PORT, "headless", revert=True) == 0
    assert calls == ["shutdown", "launch"]


# --- lease liveness ------------------------------------------------------------


@pytest.mark.parametrize(
    ("over", "state"),
    [
        ({}, "live"),
        ({"age": 40}, "live"),  # sleep/wake: pid alive = live
        ({"age": 119}, "live"),
        ({"age": 121}, "hung owner"),
        ({"pid": 999_999_9}, "dead pid"),
        ({"pid_start_time": "Mon Jan  1 00:00:00 2024"}, "pid reused"),
        ({"pid": "12"}, "invalid"),
        ({"owner_nonce": ""}, "invalid"),
        ({"heartbeat": None}, "invalid"),
    ],
)
def test_lease_state(cache, over, state):
    over = dict(over)
    age = over.pop("age", None)
    rec = _lease_rec(**over)
    if age is not None:  # relative to NOW, not to collection time
        rec["heartbeat"] = time.time() - age
    assert browser._headed_lease_state(rec) == state


def test_lease_state_none_and_live_record(cache):
    assert browser._headed_lease_state(None) == "none"
    assert browser._headed_lease_live() is None
    _write_lease(_lease_rec())
    live = browser._headed_lease_live()
    assert live is not None and live["site"] == "anthropic"


def test_lease_held_needs_the_matching_nonce(cache, monkeypatch):
    _write_lease(_lease_rec())
    assert not browser._headed_lease_held()  # no env
    monkeypatch.setenv(browser.MAINTENANCE_ENV, "x" * 32)
    assert not browser._headed_lease_held()
    monkeypatch.setenv(browser.MAINTENANCE_ENV, "n" * 32)
    assert browser._headed_lease_held()
    _write_lease(_lease_rec(heartbeat=time.time() - 200))
    assert not browser._headed_lease_held()  # hung owner = not held


def test_headed_lease_context_writes_exports_and_releases(cache, monkeypatch):
    monkeypatch.setattr(browser, "MAINTENANCE_HEARTBEAT_S", 0.05)
    with browser._headed_lease("slack") as nonce:
        assert os.environ[browser.MAINTENANCE_ENV] == nonce
        rec = json.loads(browser.MAINTENANCE_FILE.read_text(encoding="utf-8"))
        assert rec["owner_nonce"] == nonce and rec["site"] == "slack"
        assert rec["pid"] == os.getpid() and rec["pid_start_time"] == LSTART
        first = rec["heartbeat"]
        assert browser._headed_lease_held()
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            time.sleep(0.05)
            cur = json.loads(browser.MAINTENANCE_FILE.read_text(encoding="utf-8"))
            if cur["heartbeat"] > first:
                break
        assert cur["heartbeat"] > first, "heartbeat thread never refreshed"
    assert browser.MAINTENANCE_ENV not in os.environ
    assert not browser.MAINTENANCE_FILE.exists()


def test_headed_lease_refuses_a_second_live_owner(cache):
    _write_lease(_lease_rec())
    with pytest.raises(browser.HeadedLeaseBusy):
        with browser._headed_lease("openai"):
            pass
    assert json.loads(browser.MAINTENANCE_FILE.read_text())["site"] == "anthropic"


def test_lease_state_ps_failure_is_live(cache, monkeypatch):
    """A `ps` hiccup on a live owner pid never ends the lease."""
    monkeypatch.setattr(browser, "_proc_lstart", lambda pid: None)
    assert browser._headed_lease_state(_lease_rec()) == "live"
    old = _lease_rec(heartbeat=time.time() - 121)
    assert browser._headed_lease_state(old) == "hung owner"


def test_headed_lease_needs_a_start_time(cache, monkeypatch):
    monkeypatch.setattr(browser, "_proc_lstart", lambda pid: None)
    with pytest.raises(browser.HeadedLeaseError, match="start time"):
        with browser._headed_lease("slack"):
            pass
    assert not browser.MAINTENANCE_FILE.exists()


def test_heartbeat_survives_a_write_error(cache, monkeypatch, capsys):
    monkeypatch.setattr(browser, "MAINTENANCE_HEARTBEAT_S", 0.02)
    real = browser._json_write_atomic
    fails = {"n": 0}

    def flaky(path, data):
        if path == browser.MAINTENANCE_FILE and fails["n"] < 2:
            fails["n"] += 1
            raise OSError(28, "No space left on device")
        real(path, data)

    with browser._headed_lease("slack"):
        first = json.loads(browser.MAINTENANCE_FILE.read_text())["heartbeat"]
        monkeypatch.setattr(browser, "_json_write_atomic", flaky)
        deadline = time.monotonic() + 3
        cur = first
        while time.monotonic() < deadline and cur <= first:
            time.sleep(0.05)
            cur = json.loads(browser.MAINTENANCE_FILE.read_text())["heartbeat"]
        assert fails["n"] == 2 and cur > first, "heartbeat gave up after an OSError"
    assert capsys.readouterr().err.count("heartbeat failed") == 1  # logged once


def test_unique_tmp_names_differ(tmp_path):
    target = tmp_path / "Preferences"
    assert browser._unique_tmp(target) != browser._unique_tmp(target)
    assert browser._unique_tmp(target).parent == tmp_path


def test_headed_lease_takes_over_a_stale_one(cache):
    _write_lease(_lease_rec(heartbeat=time.time() - 200))
    with browser._headed_lease("openai") as nonce:
        assert nonce != "n" * 32
    assert not browser.MAINTENANCE_FILE.exists()


def test_headed_lease_release_is_compare_before_release(cache, capsys):
    with browser._headed_lease("notion"):
        _write_lease(_lease_rec(owner_nonce="f" * 32))  # somebody rewrote it
    assert browser.MAINTENANCE_FILE.exists()  # a foreign lease is left alone
    assert "rewritten by owner ffffffff" in capsys.readouterr().err


# --- preflight -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("cmd", "mode", "live", "want"),
    [
        ("eval", "headed", False, "revert"),
        ("open", "headed", False, "revert"),
        ("login", "headed", False, "revert"),
        ("register-exec", "headed", False, "revert"),
        ("slack-session", "headed", False, "revert"),
        ("doctor", "headed", False, None),  # recovery tools never revert
        ("close-hung", "headed", False, None),
        ("close", "headed", False, None),
        ("eval", "headed", True, None),
        ("eval", "headless", False, None),
        ("eval", None, False, None),
        ("status", "headed", False, None),
        ("journal", "headed", False, None),
        ("down", "headed", False, None),
        ("switch", "headed", False, None),
        ("up", "headed", False, None),
    ],
)
def test_preflight_action(cmd, mode, live, want):
    assert browser._preflight_action(cmd, mode, live) == want


def test_preflight_reverts_before_the_command(cache, monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(browser, "_browser_mode", lambda port: "headed")
    monkeypatch.setattr(browser, "_journal_parent_chain", lambda: [])

    def revert(port, why):
        calls.append(why)
        return 0

    monkeypatch.setattr(browser, "_revert_headed", revert)
    assert browser._preflight("eval", PORT) is None
    assert calls == ["`eval`"]


def test_preflight_failed_revert_warns_and_journals(cache, monkeypatch, capsys):
    monkeypatch.setattr(browser, "_browser_mode", lambda port: "headed")
    monkeypatch.setattr(browser, "_journal_parent_chain", lambda: [])
    monkeypatch.setattr(browser, "_revert_headed", lambda port, why: 1)
    assert browser._preflight("open", PORT) is None
    err = capsys.readouterr().err
    assert err.count("❌") == 1
    assert "headed without lease — revert failed: switch headless exit 1" in err
    assert _journal_events()[-1]["event"] == "revert_failed"


def test_failing_revert_still_runs_the_command(cache, monkeypatch):
    ran: list[str] = []
    monkeypatch.setattr(sys, "argv", ["browser.py", "--cdp-port", str(PORT), "token"])
    monkeypatch.setattr(browser, "_browser_mode", lambda port: "headed")
    monkeypatch.setattr(browser, "_journal_parent_chain", lambda: [])
    monkeypatch.setattr(browser, "_revert_headed", lambda port, why: 1)

    def token(port):
        ran.append("token")
        return 0

    monkeypatch.setattr(browser, "cmd_token", token)
    assert browser.main() == 0
    assert ran == ["token"]


def test_preflight_skips_while_a_transition_is_in_flight(cache, monkeypatch):
    browser._lifecycle_write("switching", "headless", port=PORT)
    monkeypatch.setattr(browser, "_browser_mode", lambda port: "headed")
    monkeypatch.setattr(
        browser, "_revert_headed", lambda port, why: pytest.fail("no revert")
    )
    assert browser._preflight("eval", PORT) is None
    assert _journal_events()[-1]["event"] == "revert_skipped"


def test_preflight_revert_leaves_stdout_empty(cache, monkeypatch, capfd):
    """Nothing the revert prints — Python or a child process — reaches stdout."""
    monkeypatch.setattr(browser, "_browser_mode", lambda port: "headed")
    monkeypatch.setattr(browser, "_journal_parent_chain", lambda: [])

    def noisy_switch(port, target, force=False, gate_wait_s=None, revert=False):
        print("✓ Switched to HEADLESS.")
        os.system("echo child-process-output")  # noqa: S605  # fd 1 of a child
        return 0

    monkeypatch.setattr(browser, "cmd_switch", noisy_switch)
    browser._preflight("slack-session", PORT)
    print('{"token": "json"}')  # the command's own stdout still works after
    out, err = capfd.readouterr()
    assert out == '{"token": "json"}\n'
    assert "Switched to HEADLESS" in err and "child-process-output" in err


def test_preflight_skips_status_without_cdp(cache, monkeypatch):
    monkeypatch.setattr(
        browser, "_browser_mode", lambda port: pytest.fail("status must not probe")
    )
    assert browser._preflight("status", PORT) is None


def test_preflight_keeps_a_guided_login(cache, monkeypatch):
    _write_lease(_lease_rec())
    monkeypatch.setattr(browser, "_browser_mode", lambda port: "headed")
    monkeypatch.setattr(
        browser, "_revert_headed", lambda port, why: pytest.fail("no revert")
    )
    assert browser._preflight("eval", PORT) is None


def test_revert_headed_is_journaled(cache, monkeypatch, tmp_path):
    monkeypatch.setattr(
        browser,
        "cmd_switch",
        lambda port, target, force=False, gate_wait_s=None, revert=False: 0,
    )
    assert browser._revert_headed(PORT, "`eval`") == 0
    journal = Path(os.environ["CLAUDE_BROWSER_JOURNAL_FILE"])
    events = [
        json.loads(line) for line in journal.read_text(encoding="utf-8").splitlines()
    ]
    assert [(e["event"], e["phase"]) for e in events] == [
        ("revert_headed", "start"),
        ("revert_headed", "end"),
    ]
    assert events[1]["result"] == 0


# --- login never opens a human flow --------------------------------------------


def test_guided_login_refused_without_lease(cache, monkeypatch, capsys):
    monkeypatch.setattr(browser, "_browser_mode", lambda port: "headed")
    assert not browser._guided_login_allowed(PORT, "slack", "Slack")
    assert "needs Albert: agent-login.py -g slack" in capsys.readouterr().err


def test_guided_login_allowed_only_headed_under_the_lease(cache, monkeypatch):
    _write_lease(_lease_rec())
    monkeypatch.setenv(browser.MAINTENANCE_ENV, "n" * 32)
    monkeypatch.setattr(browser, "_browser_mode", lambda port: "headed")
    assert browser._guided_login_allowed(PORT, "notion", "Notion")
    monkeypatch.setattr(browser, "_browser_mode", lambda port: "headless")
    assert not browser._guided_login_allowed(PORT, "notion", "Notion")


def test_openai_login_exits_needs_albert(cache, monkeypatch, capsys):
    @contextlib.contextmanager
    def owned(port, *, prepare=None):  # the fresh owned tab (tp#845)
        yield object()

    monkeypatch.setattr(browser, "_connect", pytest.fail)  # never a picked tab
    monkeypatch.setattr(browser, "_owned_background_page", owned)
    monkeypatch.setattr(browser, "_chatgpt_logged_in", lambda page: False)
    monkeypatch.setattr(browser, "_browser_mode", lambda port: "headless")
    monkeypatch.setattr(
        browser, "_interaction_lease", lambda name: pytest.fail("no human flow")
    )
    assert browser.cmd_openai_login(PORT) == browser.NEEDS_ALBERT_RC == 4
    assert "needs Albert: agent-login.py -g openai" in capsys.readouterr().err


# --- bring_to_front ------------------------------------------------------------


@pytest.mark.parametrize(
    ("mode", "held", "want"),
    [
        ("headed", True, None),
        ("headless", True, "headless"),
        (None, True, "headless"),
        ("headed", False, "no-lease"),
        ("headless", False, "no-lease"),
    ],
)
def test_bring_to_front_skip(mode, held, want):
    assert browser._bring_to_front_skip(mode, held) == want


class _Page:
    url = "https://chatgpt.com/auth/login?state=secret"

    def __init__(self):
        self.raised = 0

    def bring_to_front(self):
        self.raised += 1


def _journal_events() -> list[dict]:
    journal = Path(os.environ["CLAUDE_BROWSER_JOURNAL_FILE"])
    return [
        json.loads(line) for line in journal.read_text(encoding="utf-8").splitlines()
    ]


def test_bring_to_front_without_lease_is_a_journaled_no_op(cache, monkeypatch):
    monkeypatch.setattr(
        browser, "_browser_mode", lambda port: pytest.fail("no CDP without a lease")
    )
    page = _Page()
    browser._bring_to_front(page, "login openai", PORT)
    assert page.raised == 0
    (rec,) = _journal_events()
    assert (rec["event"], rec["skipped"], rec["origin"]) == (
        "bring_to_front",
        "no-lease",
        "https://chatgpt.com",
    )


def test_bring_to_front_headless_under_lease_is_skipped(cache, monkeypatch):
    _write_lease(_lease_rec())
    monkeypatch.setenv(browser.MAINTENANCE_ENV, "n" * 32)
    monkeypatch.setattr(browser, "_browser_mode", lambda port: "headless")
    page = _Page()
    browser._bring_to_front(page, "doctor", PORT)
    assert page.raised == 0
    assert _journal_events()[0]["skipped"] == "headless"


def test_bring_to_front_raises_inside_a_guided_login(cache, monkeypatch):
    _write_lease(_lease_rec())
    monkeypatch.setenv(browser.MAINTENANCE_ENV, "n" * 32)
    monkeypatch.setattr(browser, "_browser_mode", lambda port: "headed")
    page = _Page()
    browser._bring_to_front(page, "login openai", PORT)
    assert page.raised == 1
    assert "skipped" not in _journal_events()[0]


def test_token_and_slack_session_never_raise():
    src = (_REPO / "bin" / "browser.py").read_text(encoding="utf-8")
    assert '_bring_to_front(page, "token")' not in src
    assert '_bring_to_front(page, "slack-session")' not in src
    assert browser._JOURNAL_RAISING_CMDS == frozenset({"doctor"})


# --- launch flags + native-UI prefs ----------------------------------------------


def _launch(monkeypatch, headless: bool) -> list[str]:
    seen: list[list[str]] = []
    monkeypatch.setattr(browser, "_launch_guard", lambda port: None)
    monkeypatch.setattr(browser, "_chromium_binary", lambda: "/x/Chrome")
    monkeypatch.setattr(browser, "_headless_user_agent", lambda binary: "UA/1")

    def launch(binary, flags, headless=False):
        seen.append(flags)
        return 4242

    monkeypatch.setattr(browser, "_launch_browser", launch)
    monkeypatch.setattr(browser, "_is_up", lambda port: True)
    monkeypatch.setattr(browser, "_record_running", lambda port, mode, pid, nonce: pid)
    assert browser._launch_and_record(PORT, headless) == 0
    return seen[0]


def test_launch_flags_drop_remote_allow_origins(cache, monkeypatch):
    flags = _launch(monkeypatch, headless=True)
    assert not any(f.startswith("--remote-allow-origins") for f in flags)
    assert "--deny-permission-prompts" in flags
    assert "--headless=new" in flags and "--user-agent=UA/1" in flags
    headed = _launch(monkeypatch, headless=False)
    assert not any(f.startswith("--remote-allow-origins") for f in headed)
    assert "--headless=new" not in headed


def test_launch_writes_the_native_ui_prefs(cache, monkeypatch):
    prefs = browser.PROFILE_DIR / "Default" / "Preferences"
    prefs.parent.mkdir(parents=True)
    prefs.write_text(json.dumps({"keep": {"me": 1}, "download": {"x": 2}}))
    _launch(monkeypatch, headless=True)
    data = json.loads(prefs.read_text())
    assert data["keep"] == {"me": 1} and data["download"]["x"] == 2
    cs = data["profile"]["default_content_setting_values"]
    assert cs == {
        "notifications": 2,
        "geolocation": 2,
        "media_stream_camera": 2,
        "media_stream_mic": 2,
    }
    assert data["download"]["default_directory"] == str(browser.DOWNLOAD_DIR)
    assert data["download"]["prompt_for_download"] is False
    assert browser.DOWNLOAD_DIR.is_dir()


def test_unparsable_prefs_are_left_untouched(cache, monkeypatch, capsys):
    prefs = browser.PROFILE_DIR / "Default" / "Preferences"
    prefs.parent.mkdir(parents=True)
    prefs.write_text("[1, 2]")
    _launch(monkeypatch, headless=True)  # the launch itself still happens
    assert prefs.read_text() == "[1, 2]"
    assert "profile prefs not applied" in capsys.readouterr().err


# --- agent-login's guided window ---------------------------------------------------


@pytest.fixture
def guided_env(monkeypatch):
    log: list[tuple] = []
    rc: dict[tuple, list[int]] = {}

    owner: dict[str, str | None] = {"nonce": "nonce"}

    class FakeBrowserModule:
        @staticmethod
        def _headed_lease_live():
            return {"owner_nonce": owner["nonce"]} if owner["nonce"] else None

        @staticmethod
        @contextlib.contextmanager
        def _maintenance(site, mode, force=False):
            assert mode == "A"
            log.append(("lease", site))
            if force:
                log.append(("force",))
            try:
                yield types.SimpleNamespace(nonce="nonce")
            finally:
                log.append(("release", site))

    def fake_browser(*args, quiet=False, **_kw):
        log.append(args)
        codes = rc.get(args)
        return codes.pop(0) if codes else 0

    monkeypatch.setattr(jobs, "_browser_module", lambda: FakeBrowserModule)
    monkeypatch.setattr(jobs, "_browser", fake_browser)
    monkeypatch.setattr(jobs, "browser_mode", lambda: "headed")
    monkeypatch.setattr(jobs.time, "sleep", lambda s: None)
    return log, rc, owner


def test_guided_window_order(guided_env):
    log, _rc, _owner = guided_env
    with jobs.guided_window("anibis") as win:
        log.append(("work",))
    assert win.restored
    assert log == [
        ("lease", "anibis"),
        ("switch", "headed"),
        ("work",),
        ("switch", "headless"),
        ("release", "anibis"),
    ]


def test_guided_window_passes_force_to_the_transaction(guided_env):
    log, _rc, _owner = guided_env
    with jobs.guided_window("slack", force=True):
        pass
    assert log[:2] == [("lease", "slack"), ("force",)]


def test_guided_window_failed_switch_back_is_loud_and_retried(guided_env, capsys):
    log, rc, _owner = guided_env
    rc[("switch", "headless")] = [1, 1]
    with jobs.guided_window("slack") as win:
        pass
    assert not win.restored
    assert log.count(("switch", "headless")) == 2
    out = capsys.readouterr().out
    assert "attempt 1/2" in out and "still HEADED" in out


def test_guided_window_retry_succeeds(guided_env):
    log, rc, _owner = guided_env
    rc[("switch", "headless")] = [1, 0]
    with jobs.guided_window("slack") as win:
        pass
    assert win.restored and log.count(("switch", "headless")) == 2


def test_guided_window_failed_switch_headed_raises_and_reverts(guided_env):
    log, rc, _owner = guided_env
    rc[("switch", "headed")] = [1]
    with pytest.raises(RuntimeError, match="switch headed failed"):
        with jobs.guided_window("notion"):
            pytest.fail("the block must not run")
    assert ("switch", "headless") in log and log[-1] == ("release", "notion")


def test_guided_window_hides_on_error_inside(guided_env):
    log, _rc, _owner = guided_env
    with pytest.raises(ValueError):
        with jobs.guided_window("openai"):
            raise ValueError("boom")
    assert log[-2:] == [("switch", "headless"), ("release", "openai")]


def test_guided_window_leaves_another_owners_window_alone(guided_env, capsys):
    log, _rc, owner = guided_env
    with jobs.guided_window("slack") as win:
        owner["nonce"] = "someone-else"
    assert win.restored
    assert ("switch", "headless") not in log
    assert "another guided login holds the headed lease" in capsys.readouterr().out


def test_guided_window_hides_when_no_lease_is_left(guided_env):
    log, _rc, owner = guided_env
    with jobs.guided_window("slack"):
        owner["nonce"] = None
    assert ("switch", "headless") in log


def test_browser_module_systemexit_becomes_runtimeerror(monkeypatch):
    monkeypatch.setenv("CLAUDE_BROWSER_INSTANCE", "no-such-instance")
    with pytest.raises(RuntimeError, match="cannot load"):
        jobs._browser_module()


def test_browser_module_loads_the_real_lease(tmp_path, monkeypatch):
    monkeypatch.setenv("CLAUDE_BROWSER_CACHE_DIR", str(tmp_path))
    mod = jobs._browser_module()
    assert mod.MAINTENANCE_FILE == tmp_path / "maintenance.json"
    assert callable(mod._headed_lease)
