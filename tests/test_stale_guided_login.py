"""agent-login.py -S backstop: a guided login whose owner AND watchdog died.

`agent_login_jobs.recover_stale_guided_login` reads browser.py's maintenance
record from a temp CLAUDE_BROWSER_CACHE_DIR (never the live cache) and runs
`browser.py maintenance-watchdog` through a FAKE `run_browser` — no Chrome,
no real browser.py subprocess.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))
_PATH = _REPO / "agent-login.py"
_SPEC = importlib.util.spec_from_file_location("agent_login", _PATH)
assert _SPEC and _SPEC.loader
al = importlib.util.module_from_spec(_SPEC)
sys.modules["agent_login"] = al
_SPEC.loader.exec_module(al)
jobs = sys.modules["agent_login_jobs"]

NONCE = "abcdef0123456789" + "f" * 48  # the full owner token: never printed


class _FakeRuns:
    """`run_browser` stand-in; optionally clears the record like the watchdog."""

    def __init__(self, cache: Path, rc: int | None = 0, clear: bool = True) -> None:
        self.cache, self.rc, self.clear = cache, rc, clear
        self.calls: list[tuple[tuple[str, ...], float | None]] = []

    def __call__(self, *args, timeout_s, capture=False, quiet=False):
        del capture, quiet
        self.calls.append((args, timeout_s))
        if self.clear and self.rc == 0:
            (self.cache / "maintenance.json").unlink(missing_ok=True)
        return jobs.BrowserRun(self.rc, self.rc is None, "", 0.1)


@pytest.fixture(name="cache")
def fixture_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("CLAUDE_BROWSER_CACHE_DIR", str(tmp_path))
    monkeypatch.delenv("CLAUDE_BROWSER_INSTANCE", raising=False)
    monkeypatch.delenv("CLAUDE_BROWSER_CDP_PORT", raising=False)
    return tmp_path


def _dead_pid() -> int:
    proc = subprocess.Popen(  # pylint: disable=consider-using-with
        [sys.executable, "-c", "pass"]
    )
    proc.wait()
    return proc.pid


def _lstart(pid: int) -> str:
    out = subprocess.run(
        ["ps", "-o", "lstart=", "-p", str(pid)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return out.strip()


def _write(cache: Path, **over) -> None:
    rec = {
        "owner_nonce": NONCE,
        "pid": _dead_pid(),
        "pid_start_time": "Thu Jan  1 00:00:00 2026",
        "site": "slack",
        "mode": "A",
        "state": "active",
        "owned_targets": [],
        "paused": [],
        "watchdog_pid": _dead_pid(),
        "started": time.time() - 30,
        "heartbeat": time.time() - 20,
    }
    rec.update(over)
    (cache / "maintenance.json").write_text(json.dumps(rec), encoding="utf-8")


def _run(monkeypatch, fake: _FakeRuns, capsys) -> tuple[str | None, str]:
    monkeypatch.setattr(jobs, "run_browser", fake)
    out = jobs.recover_stale_guided_login()
    printed = capsys.readouterr()
    return out, printed.out + printed.err


def test_no_record_does_nothing(cache, monkeypatch, capsys):
    fake = _FakeRuns(cache)
    out, printed = _run(monkeypatch, fake, capsys)
    assert out is None and not fake.calls and not printed


def test_live_record_is_never_touched(cache, monkeypatch, capsys):
    me = os.getpid()
    _write(cache, pid=me, pid_start_time=_lstart(me), heartbeat=time.time())
    fake = _FakeRuns(cache)
    out, _ = _run(monkeypatch, fake, capsys)
    assert out is None and not fake.calls
    assert (cache / "maintenance.json").exists()


def test_stale_record_with_live_watchdog_is_left_to_it(cache, monkeypatch, capsys):
    _write(cache, watchdog_pid=os.getpid())
    fake = _FakeRuns(cache)
    out, _ = _run(monkeypatch, fake, capsys)
    assert out is None and not fake.calls


def test_stale_record_with_reused_watchdog_pid_is_recovered(cache, monkeypatch, capsys):
    _write(cache, watchdog_pid=os.getpid(), watchdog_start_time="Thu Jan  1 2026")
    fake = _FakeRuns(cache)
    out, _ = _run(monkeypatch, fake, capsys)
    assert out is not None and len(fake.calls) == 1


def test_malformed_watchdog_pid_is_unsure_and_does_nothing(cache, monkeypatch, capsys):
    _write(cache, watchdog_pid="123")
    fake = _FakeRuns(cache)
    out, _ = _run(monkeypatch, fake, capsys)
    assert out is None and not fake.calls


def test_no_watchdog_pid_waits_for_an_old_heartbeat(cache, monkeypatch, capsys):
    _write(cache, watchdog_pid=None)
    fake = _FakeRuns(cache)
    out, _ = _run(monkeypatch, fake, capsys)
    assert out is None and not fake.calls  # a just-spawned watchdog may exist
    _write(cache, watchdog_pid=None, heartbeat=time.time() - 600)
    out, _ = _run(monkeypatch, fake, capsys)
    assert out is not None and out.startswith("✅") and len(fake.calls) == 1


def test_dead_watchdog_runs_the_recovery_once_bounded(cache, monkeypatch, capsys):
    _write(cache)
    fake = _FakeRuns(cache)
    out, printed = _run(monkeypatch, fake, capsys)
    assert len(fake.calls) == 1
    args, timeout_s = fake.calls[0]
    assert args[:4] == ("--cdp-port", "9222", "maintenance-watchdog", "-n")
    assert args[4] == NONCE[:16] and NONCE.startswith(args[4])
    assert timeout_s is not None and 0 < timeout_s <= 300
    assert timeout_s == jobs.browser_timeout("maintenance-watchdog")
    assert out is not None and out.startswith("✅") and "slack" in out
    assert NONCE[:16] not in out and NONCE[:16] not in printed


def test_recovery_failures_are_one_red_line(cache, monkeypatch, capsys):
    for rc, clear, needle in (
        (None, False, "killed"),
        (1, False, "exit 1"),
        (0, False, "still in place"),
    ):
        _write(cache)
        fake = _FakeRuns(cache, rc=rc, clear=clear)
        out, printed = _run(monkeypatch, fake, capsys)
        assert out is not None and out.startswith("❌") and needle in out
        assert "\n" not in out
        assert NONCE[:8] not in out and NONCE[:8] not in printed


def test_snapshot_prints_the_outcome_before_the_overview(cache, monkeypatch, capsys):
    _write(cache)
    order: list[str] = []
    fake = _FakeRuns(cache)

    def fake_run(*args, **kw):
        order.append("recover")
        return fake(*args, **kw)

    def fake_overview(fresh=False):
        del fresh
        order.append("overview")
        return {"broker_ok": True}

    monkeypatch.setattr(jobs, "run_browser", fake_run)
    monkeypatch.setattr(al, "overview", fake_overview)
    monkeypatch.setattr(
        al.agent_login_secrets, "secrets_state", lambda *a, **k: ("", [])
    )
    monkeypatch.setattr(al, "write_agent_summary", lambda data=None: None)
    monkeypatch.setattr(al.agent_login_keychain, "refresh", lambda *a, **k: None)
    monkeypatch.setattr(sys, "argv", ["agent-login.py", "-S"])
    assert al.main() == 0
    printed = capsys.readouterr().out
    assert order == ["recover", "overview"]
    assert printed.startswith("✅") and NONCE[:8] not in printed


@pytest.mark.parametrize(
    "case",
    [
        ("private", None, None, "9223"),  # the instance whose record it read
        ("", "9351", None, "9351"),  # $CLAUDE_BROWSER_CDP_PORT, like browser.py
        ("private", None, 9351, "9351"),  # the record's own port wins
        ("", None, "9351", "9222"),  # a malformed port is ignored
    ],
)
def test_recovery_runs_against_the_records_instance_port(
    cache, monkeypatch, capsys, case
):
    """Never an implicit 9222: the watchdog acts on the port of the record's
    instance (or on the port the record names)."""
    instance, env_port, rec_port, want = case
    if instance:
        monkeypatch.setenv("CLAUDE_BROWSER_INSTANCE", instance)
    if env_port:
        monkeypatch.setenv("CLAUDE_BROWSER_CDP_PORT", env_port)
    _write(cache, **({} if rec_port is None else {"port": rec_port}))
    fake = _FakeRuns(cache)
    out, _ = _run(monkeypatch, fake, capsys)
    assert out is not None and out.startswith("✅")
    args, _timeout = fake.calls[0]
    assert args[:3] == ("--cdp-port", want, "maintenance-watchdog")
