"""Local Network privacy (tp#1663): launch context, terminal relaunch, LAN probe.

A browser cold-started by a LaunchAgent job is its own macOS "responsible
process" and gets no Local Network grant (ERR_ADDRESS_UNREACHABLE for every
LAN host but the gateway). Pinned here: `_launch_context` (launchd vs
interactive), `_browser_launchd_rooted`, `up` refusing a launchd cold start
(exit 75), a terminal `up` relaunching a launchd-rooted browser, `switch`
refusing in a launchd context, the relaunch path through `cmd_switch`, and
doctor's LAN probe.

Hermetic: the responsible-PID lookup, `ps`, the gate, shutdown and launch are
stubbed; no real browser is launched, no network is touched.

Run: uv run --no-sync pytest tests/test_launch_context.py -q
"""

from __future__ import annotations

# pylint: disable=protected-access,missing-function-docstring,import-error
# pylint: disable=redefined-outer-name,unused-argument,duplicate-code
# pylint: disable=too-few-public-methods
import importlib.util
import os
import sys
from pathlib import Path

import pytest
from playwright.sync_api import Error as PlaywrightError
from ports import unused_port

_REPO = Path(__file__).resolve().parent.parent
PORT = unused_port()
ITERM = "/Applications/iTerm.app/Contents/MacOS/iTerm2"
PY = "/usr/bin/python3"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


browser = _load("browser_launch_context_test", _REPO / "bin" / "browser.py")


@pytest.fixture
def cache(tmp_path, monkeypatch):
    monkeypatch.setattr(browser, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(browser, "LIFECYCLE_FILE", tmp_path / "lifecycle.json")
    monkeypatch.setattr(browser, "PROFILE_DIR", tmp_path / "profile")
    monkeypatch.setattr(browser, "PID_FILE", tmp_path / "browser.pid")
    monkeypatch.delenv(browser.SCHEDULED_ENV, raising=False)
    return tmp_path


def _world(monkeypatch, *, resp: dict[int, int], exe: dict[int, str], ctty=False):
    """Stub the responsible-PID lookup, `ps -o comm=` and the ctty check."""
    monkeypatch.setattr(browser, "_responsible_pid", resp.get)
    monkeypatch.setattr(browser, "_proc_exe", exe.get)
    monkeypatch.setattr(browser, "_has_ctty", lambda: ctty)


# --- _launch_context -----------------------------------------------------------


def test_scheduled_env_is_a_launchd_context(cache, monkeypatch):
    monkeypatch.setenv(browser.SCHEDULED_ENV, "1")
    _world(monkeypatch, resp={os.getpid(): 3234}, exe={3234: ITERM})
    assert "AGENT_LOGIN_SCHEDULED" in str(browser._launch_context())


def test_terminal_app_responsible_is_interactive(cache, monkeypatch):
    _world(monkeypatch, resp={os.getpid(): 3234}, exe={3234: ITERM})
    assert browser._launch_context() is None


def test_unknown_responsible_is_interactive(cache, monkeypatch):
    _world(monkeypatch, resp={}, exe={})
    assert browser._launch_context() is None


def test_non_app_responsible_without_tty_is_launchd(cache, monkeypatch):
    me = os.getpid()
    _world(monkeypatch, resp={me: me}, exe={me: PY})
    reason = browser._launch_context()
    assert reason is not None and "launchd" in reason and "python3" in reason


def test_non_app_responsible_with_tty_is_interactive(cache, monkeypatch):
    me = os.getpid()
    _world(monkeypatch, resp={me: me}, exe={me: "/usr/sbin/sshd"}, ctty=True)
    assert browser._launch_context() is None


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
def test_responsible_pid_resolves_for_this_process():
    assert isinstance(browser._responsible_pid(os.getpid()), int)


# --- _browser_launchd_rooted ---------------------------------------------------


def test_browser_its_own_responsible_is_launchd_rooted(cache, monkeypatch):
    monkeypatch.setattr(browser, "_find_root_pids", lambda port: [500])
    _world(monkeypatch, resp={500: 500}, exe={})
    assert "own responsible" in str(browser._browser_launchd_rooted(PORT))


def test_browser_under_iterm_is_fine(cache, monkeypatch):
    monkeypatch.setattr(browser, "_find_root_pids", lambda port: [500])
    _world(monkeypatch, resp={500: 3234}, exe={3234: ITERM})
    assert browser._browser_launchd_rooted(PORT) is None


def test_browser_under_a_non_app_is_launchd_rooted(cache, monkeypatch):
    monkeypatch.setattr(browser, "_find_root_pids", lambda port: [500])
    _world(monkeypatch, resp={500: 77}, exe={77: PY})
    assert "no app" in str(browser._browser_launchd_rooted(PORT))


@pytest.mark.parametrize("roots", [[], [500, 501]])
def test_browser_rooted_unknown_without_exactly_one_root(cache, monkeypatch, roots):
    monkeypatch.setattr(browser, "_find_root_pids", lambda port: roots)
    _world(monkeypatch, resp={500: 500, 501: 501}, exe={})
    assert browser._browser_launchd_rooted(PORT) is None


# --- up ------------------------------------------------------------------------


def _no_launch(monkeypatch):
    monkeypatch.setattr(
        browser, "_gate_acquire", lambda *a: pytest.fail("no gate in launchd")
    )
    monkeypatch.setattr(
        browser, "_launch_and_record", lambda *a: pytest.fail("must not launch")
    )


def test_up_refuses_a_launchd_cold_start(cache, monkeypatch, capsys):
    monkeypatch.setattr(browser, "_browser_mode", lambda port: None)
    monkeypatch.setattr(browser, "_launch_context", lambda: "a launchd job")
    _no_launch(monkeypatch)
    assert browser.cmd_up(PORT) == browser.BUSY_RC == 75
    err = capsys.readouterr().err
    assert "launchd context" in err and "browser.py up" in err


def test_up_cold_starts_when_interactive(cache, monkeypatch):
    monkeypatch.setattr(browser, "_browser_mode", lambda port: None)
    monkeypatch.setattr(browser, "_launch_context", lambda: None)
    monkeypatch.setattr(browser, "_gate_acquire", lambda kind, wait: 7)
    monkeypatch.setattr(browser, "_gate_release", lambda fd: None)
    launched: list[bool] = []

    def launch(port, headless):
        launched.append(headless)
        return 0

    monkeypatch.setattr(browser, "_launch_and_record", launch)
    assert browser.cmd_up(PORT) == 0
    assert launched == [True]


def _up_running(monkeypatch, *, rooted, context):
    monkeypatch.setattr(browser, "_browser_mode", lambda port: "headless")
    monkeypatch.setattr(browser, "_heal_running_record", lambda port, mode: False)
    monkeypatch.setattr(browser, "_browser_launchd_rooted", lambda port: rooted)
    monkeypatch.setattr(browser, "_launch_context", lambda: context)


def test_terminal_up_relaunches_a_launchd_rooted_browser(cache, monkeypatch):
    _up_running(monkeypatch, rooted="pid 5 is its own", context=None)
    calls: list[dict] = []

    def revert_tx(port, **kw):
        calls.append(kw)
        return 0

    monkeypatch.setattr(browser, "_revert_tx", revert_tx)
    assert browser.cmd_up(PORT) == 0
    assert calls and calls[0]["relaunch"] is True


def test_launchd_up_reuses_a_running_browser(cache, monkeypatch, capsys):
    """The scheduled job finds the browser up: reuse it, never relaunch."""
    _up_running(monkeypatch, rooted="pid 5 is its own", context="a launchd job")
    monkeypatch.setattr(browser, "_revert_tx", lambda *a, **k: pytest.fail("no"))
    assert browser.cmd_up(PORT) == 0
    captured = capsys.readouterr()
    assert "already up" in captured.out
    assert "no Local Network access" in captured.err


def test_terminal_up_leaves_a_terminal_rooted_browser(cache, monkeypatch, capsys):
    _up_running(monkeypatch, rooted=None, context=None)
    monkeypatch.setattr(browser, "_revert_tx", lambda *a, **k: pytest.fail("no"))
    assert browser.cmd_up(PORT) == 0
    assert "already up" in capsys.readouterr().out


def test_failed_relaunch_with_browser_still_up_keeps_up_contract(
    cache, monkeypatch, capsys
):
    _up_running(monkeypatch, rooted="pid 5 is its own", context=None)
    monkeypatch.setattr(browser, "_revert_tx", lambda port, **kw: 1)
    assert browser.cmd_up(PORT) == 0
    assert "relaunch not done" in capsys.readouterr().err


def test_failed_relaunch_leaving_it_down_fails(cache, monkeypatch):
    _up_running(monkeypatch, rooted="pid 5 is its own", context=None)
    monkeypatch.setattr(browser, "_revert_tx", lambda port, **kw: 1)
    monkeypatch.setattr(browser, "_browser_mode", lambda port: None)
    assert browser._relaunch_from_terminal(PORT, "why") == 1


# --- switch ---------------------------------------------------------------------


def test_switch_refuses_in_a_launchd_context(cache, monkeypatch, capsys):
    monkeypatch.setattr(browser, "_launch_context", lambda: "a launchd job")
    monkeypatch.setattr(
        browser, "_browser_mode", lambda port: pytest.fail("nothing touched")
    )
    assert browser.cmd_switch(PORT, "headless", revert=True) == browser.BUSY_RC
    assert "relaunching (switch)" in capsys.readouterr().err


def _switch_env(monkeypatch, rooted):
    calls: list[str] = []
    monkeypatch.setattr(browser, "_launch_context", lambda: None)
    monkeypatch.setattr(browser, "_browser_mode", lambda port: "headless")
    monkeypatch.setattr(browser, "_browser_launchd_rooted", lambda port: rooted)
    monkeypatch.setattr(browser, "_gate_acquire", lambda kind, wait: 7)
    monkeypatch.setattr(browser, "_gate_release", lambda fd: None)
    monkeypatch.setattr(browser, "_unknown_clients_verdict", lambda port: None)
    monkeypatch.setattr(browser, "_lifecycle_transition", lambda *a: {})

    def stop(port, rec):
        calls.append("stop")
        return True

    def launch(port, headless):
        calls.append("launch")
        return 0

    monkeypatch.setattr(browser, "_shutdown_browser", stop)
    monkeypatch.setattr(browser, "_launch_and_record", launch)
    return calls


def test_switch_relaunch_stops_and_relaunches_same_mode(cache, monkeypatch, capsys):
    calls = _switch_env(monkeypatch, rooted="pid 5 is its own")
    assert browser.cmd_switch(PORT, "headless", revert=True, relaunch=True) == 0
    assert calls == ["stop", "launch"]
    assert "Relaunched HEADLESS from this terminal" in capsys.readouterr().out


def test_switch_relaunch_stands_down_when_relaunched_meanwhile(cache, monkeypatch):
    calls = _switch_env(monkeypatch, rooted=None)
    assert browser.cmd_switch(PORT, "headless", revert=True, relaunch=True) == 0
    assert not calls


def test_plain_switch_same_mode_still_a_no_op(cache, monkeypatch, capsys):
    calls = _switch_env(monkeypatch, rooted="pid 5 is its own")
    assert browser.cmd_switch(PORT, "headless") == 0
    assert not calls
    assert "already in HEADLESS" in capsys.readouterr().out


# --- doctor LAN probe ----------------------------------------------------------


class _Resp:
    def __init__(self, status: int) -> None:
        self.status = status


class _Page:
    def __init__(self, result) -> None:
        self.result = result
        self.urls: list[str] = []

    def goto(self, url, timeout=None, wait_until=None):
        self.urls.append(url)
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


def _lan(monkeypatch, reachable=True):
    monkeypatch.delenv(browser.LAN_PROBE_ENV, raising=False)
    monkeypatch.setattr(browser, "_lan_host_reachable", lambda url: reachable)


def test_lan_probe_ok(monkeypatch, capsys):
    _lan(monkeypatch)
    log: list[str] = []
    page = _Page(_Resp(200))
    browser._doctor_lan(log, page)
    assert log == ["ok"]
    assert page.urls == [browser.LAN_PROBE_DEFAULT_URL]
    out = capsys.readouterr().out
    assert "✅ LAN probe" in out and "/healthz" not in out  # origin only


def test_lan_probe_address_unreachable_fails_with_hint(monkeypatch, capsys):
    _lan(monkeypatch)
    log: list[str] = []
    err = PlaywrightError("page.goto: net::ERR_ADDRESS_UNREACHABLE at https://x/")
    browser._doctor_lan(log, _Page(err))
    assert log == ["fail"]
    out = capsys.readouterr().out
    assert "Local Network privacy" in out and "browser.py up" in out


def test_lan_probe_off_lan_is_a_warning_without_navigation(monkeypatch):
    _lan(monkeypatch, reachable=False)
    log: list[str] = []
    page = _Page(_Resp(200))
    browser._doctor_lan(log, page)
    assert log == ["warn"] and not page.urls


def test_lan_probe_disabled_by_env(monkeypatch):
    monkeypatch.setenv(browser.LAN_PROBE_ENV, "off")
    log: list[str] = []
    page = _Page(_Resp(200))
    browser._doctor_lan(log, page)
    assert log == ["ok"] and not page.urls


def test_doctor_launch_context_flags_a_launchd_rooted_browser(monkeypatch, capsys):
    monkeypatch.setattr(browser, "_browser_launchd_rooted", lambda port: "own")
    log: list[str] = []
    browser._doctor_launch_context(log, PORT)
    assert log == ["fail"]
    assert "❌ launch context" in capsys.readouterr().out
