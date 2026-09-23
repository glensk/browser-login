"""Unit tests for `browser.py down` (tp#187).

`down` needs the client gate exclusively, and every registered CDP client holds
it shared for its whole lifetime — so a long-lived client (the Playwright MCP
server behind `register-exec`) used to make `down` refuse forever, even when
the browser was already gone and only a stale lifecycle record was left. These
tests pin the fix: a record no browser stands behind is cleared without the
gate, and ``force`` stops a live browser without waiting for the drain.

Everything runs against a throwaway CACHE_DIR; the browser itself is stubbed
(`_is_up`, `_find_root_pids`, `_shutdown_browser`), so the live shared browser
is never touched.

Run: python3 -m pytest tests/ -q     (from the repo root)
"""

from __future__ import annotations

# Tests reach into browser.py's private helpers on purpose (it is a script, not
# a package, so there is no public API).
# pylint: disable=protected-access,missing-function-docstring,import-error
# pylint: disable=redefined-outer-name,unused-argument
import importlib.util
import sys
import time
from pathlib import Path

import pytest

_BROWSER_PY = Path(__file__).resolve().parent.parent / "bin" / "browser.py"
PORT = 59222


def _load_browser_module():
    """Import bin/browser.py as a module (it has no module-level playwright import)."""
    spec = importlib.util.spec_from_file_location("browser_down_test", _BROWSER_PY)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["browser_down_test"] = mod
    spec.loader.exec_module(mod)
    return mod


browser = _load_browser_module()


class Env:
    """The stubbed world: is the browser up, and what did `down` shut down."""

    def __init__(self) -> None:
        self.up = False
        self.roots: list[int] = []
        self.shutdowns = 0

    def shutdown(self, port: int, stopping: dict) -> bool:
        del port, stopping
        self.shutdowns += 1
        self.up = False
        self.roots = []
        return True


@pytest.fixture
def env(tmp_path, monkeypatch):
    clients = tmp_path / "clients"
    monkeypatch.setattr(browser, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(browser, "PROFILE_DIR", tmp_path / "profile")
    monkeypatch.setattr(browser, "PID_FILE", tmp_path / "browser.pid")
    monkeypatch.setattr(browser, "LIFECYCLE_FILE", tmp_path / "lifecycle.json")
    monkeypatch.setattr(browser, "CLIENTS_DIR", clients)
    monkeypatch.setattr(browser, "REGISTRY_GATE", clients / ".registry.lock")
    monkeypatch.setattr(browser, "REGISTRY_EX_WAIT_S", 0.3)
    monkeypatch.setattr(browser, "REGISTRY_UP_WAIT_S", 0.2)
    e = Env()
    monkeypatch.setattr(browser, "_is_up", lambda port: e.up)
    monkeypatch.setattr(browser, "_find_root_pids", lambda port: list(e.roots))
    monkeypatch.setattr(browser, "_shutdown_browser", e.shutdown)
    monkeypatch.setattr(browser, "_unknown_clients_verdict", lambda port: None)
    monkeypatch.setattr(browser, "_browser_mode", lambda port: "headed")
    monkeypatch.setattr(browser, "_proc_lstart", lambda pid: None)
    monkeypatch.setattr(browser, "_validated_root_pid", lambda rec: None)
    return e


@pytest.fixture
def client():
    """A registered long-lived CDP client holding the gate shared."""
    release = browser._registry_register("playwright-mcp", "MCP server", PORT)
    yield
    release()


def _write(state: str, age_s: float = 0.0, pid: int | None = 999_999) -> dict:
    rec: dict = browser._lifecycle_write(state, "headed", pid=pid, port=PORT)
    if age_s:
        rec["iso"] = time.strftime(
            "%Y-%m-%dT%H:%M:%S%z", time.localtime(time.time() - age_s)
        )
        browser.LIFECYCLE_FILE.write_text(browser.json.dumps(rec), encoding="utf-8")
    return rec


def test_stale_running_record_cleared_despite_registered_client(env, client, capsys):
    _write("running")
    browser.PID_FILE.write_text("999999\n", encoding="utf-8")
    t0 = time.monotonic()
    assert browser.cmd_down(PORT) == 0
    assert time.monotonic() - t0 < 1.0
    assert not browser.LIFECYCLE_FILE.exists()
    assert not browser.PID_FILE.exists()
    assert env.shutdowns == 0
    assert "stale lifecycle record cleared" in capsys.readouterr().out


def test_fresh_starting_record_not_cleared_by_early_path(env, client):
    _write("starting")
    assert browser.cmd_down(PORT) == 1  # gated path: the client does not drain
    assert browser._lifecycle_read()["state"] == "starting"


def test_dead_switching_record_cleared(env, client):
    _write("switching", age_s=browser.TRANSITION_STALE_S + 60)
    assert browser.cmd_down(PORT) == 0
    assert not browser.LIFECYCLE_FILE.exists()


def test_live_browser_registered_client_refuses_without_force(env, client, capsys):
    env.up, env.roots = True, [4242]
    rec = _write("running", pid=4242)
    assert browser.cmd_down(PORT) == 1
    err = capsys.readouterr().err
    assert "--force" in err
    assert "playwright-mcp" in err
    assert env.shutdowns == 0
    assert browser._lifecycle_read() == rec


def test_live_browser_registered_client_force_stops(env, client, capsys):
    env.up, env.roots = True, [4242]
    _write("running", pid=4242)
    assert browser.cmd_down(PORT, force=True) == 0
    assert env.shutdowns == 1
    assert not browser.LIFECYCLE_FILE.exists()
    err = capsys.readouterr().err
    assert "--force" in err
    assert "playwright-mcp" in err


def test_force_refuses_fresh_transition(env, client, capsys):
    env.up, env.roots = True, [4242]
    _write("switching", pid=4242)
    assert browser.cmd_down(PORT, force=True) == 1
    assert env.shutdowns == 0
    assert "'switching' transition is in flight" in capsys.readouterr().err
    assert browser._lifecycle_read()["state"] == "switching"


def test_no_record_nothing_running(env, capsys):
    assert browser.cmd_down(PORT) == 0
    assert capsys.readouterr().out.strip() == "Stopped (or was not running)."
    assert env.shutdowns == 0


def test_live_browser_no_clients_stops_normally(env):
    env.up, env.roots = True, [4242]
    _write("running", pid=4242)
    assert browser.cmd_down(PORT) == 0
    assert env.shutdowns == 1
    assert not browser.LIFECYCLE_FILE.exists()


def test_parser_down_force_flag(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["browser.py", "down", "-f"])
    assert browser.parse_args().force is True
    monkeypatch.setattr(sys, "argv", ["browser.py", "down"])
    assert browser.parse_args().force is False
