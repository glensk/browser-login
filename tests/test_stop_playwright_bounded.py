"""`_stop_playwright_bounded` really stops the driver, bounded (tp#1659).

Sync Playwright is bound to its creating thread: the old daemon-thread stop
hit `greenlet.error: Cannot switch to a different thread`, swallowed it, left
the Node driver alive and the thread's asyncio loop "running" (every later
`sync_playwright()` in the process refused). Pinned here:

* a normal stop ends the driver and a fresh `sync_playwright().start()` works;
* a stop that hangs (the driver never sees stdin EOF) returns within its
  bound, the driver is killed and Playwright can start again;
* an outer SIGALRM handler and its armed itimer survive the stop;
* an object with only `.stop()` (a test fake) never makes it raise.

Only the Playwright driver starts (no Chromium, no CDP port). Every test kills
a driver it left alive in a `finally`; a `faulthandler` backstop ends a run
that wedges anyway.

Run: uv run pytest -q tests/test_stop_playwright_bounded.py   (from the repo root)
"""

from __future__ import annotations

# pylint: disable=protected-access,missing-function-docstring,import-error
import contextlib
import faulthandler
import importlib.util
import logging
import os
import signal
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from pw_bound import PwHolder

_BROWSER_PY = Path(__file__).resolve().parent.parent / "bin" / "browser.py"
BACKSTOP_S = 120  # one test: two driver starts and one bounded stop


def _load_browser_module() -> Any:
    """Import bin/browser.py as a module (no module-level playwright import)."""
    spec = importlib.util.spec_from_file_location("browser_stop_pw_test", _BROWSER_PY)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["browser_stop_pw_test"] = mod
    spec.loader.exec_module(mod)
    return mod


browser = _load_browser_module()


@pytest.fixture(autouse=True)
def _backstop() -> Iterator[None]:
    faulthandler.dump_traceback_later(BACKSTOP_S, exit=True)
    try:
        yield
    finally:
        faulthandler.cancel_dump_traceback_later()


def _driver_proc(holder: PwHolder) -> Any:
    """The asyncio process object of the holder's Node driver."""
    return holder.manager._connection._transport._proc


def _gone(proc: Any, pid: int) -> bool:
    """The driver exited (Playwright saw it, or the pid no longer exists)."""
    if proc.returncode is not None:
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    return False


def _wait_gone(proc: Any, pid: int, within_s: float) -> bool:
    end = time.monotonic() + within_s
    while not _gone(proc, pid):
        if time.monotonic() > end:
            return False
        time.sleep(0.05)
    return True


@contextlib.contextmanager
def _driver() -> Iterator[tuple[PwHolder, Any, int]]:
    """A started driver-only Playwright; killed (and its loop unwound) in a
    `finally` when the code under test left it alive."""
    holder = PwHolder(launch=False)
    holder.ensure()
    proc = _driver_proc(holder)
    pid = int(proc.pid)
    try:
        yield holder, proc, pid
    finally:
        if not _gone(proc, pid):
            holder.kill()


def _restart_works() -> None:
    """A fresh `sync_playwright().start()` in this thread succeeds."""
    fresh = PwHolder(launch=False)
    try:
        fresh.ensure()
        assert fresh.pw is not None
    finally:
        fresh.stop("fresh stop")


def test_stop_kills_driver_and_allows_restart() -> None:
    with _driver() as (holder, proc, pid):
        browser._stop_playwright_bounded(holder.pw, wait_s=5)
        assert _wait_gone(proc, pid, 2.0), "driver still alive after the stop"
        assert proc.returncode is not None
    _restart_works()


def test_hung_stop_is_bounded_and_killed(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING, logger="asyncio")
    with _driver() as (holder, proc, pid):
        # The driver never sees stdin EOF: `wait_until_stopped` waits forever.
        holder.manager._connection._transport.request_stop = lambda: None
        t0 = time.monotonic()
        browser._stop_playwright_bounded(holder.pw, wait_s=2)
        took = time.monotonic() - t0
        assert took < 5, f"stop took {took:.1f}s"
        assert _wait_gone(proc, pid, 2.0), "driver still alive after the stop"
    _restart_works()
    # The killed driver was reaped before its loop closed: no asyncio noise
    # ("Loop ... is closed", "Unknown child process", "Task was destroyed").
    noise = [r.getMessage() for r in caplog.records if r.name == "asyncio"]
    assert not noise, noise


def test_outer_sigalrm_restored() -> None:
    fired: list[int] = []

    def sentinel(signum: int, _frame: Any) -> None:
        fired.append(signum)

    old = signal.signal(signal.SIGALRM, sentinel)
    signal.setitimer(signal.ITIMER_REAL, 60)
    try:
        with _driver() as (holder, _proc, _pid):
            browser._stop_playwright_bounded(holder.pw, wait_s=5)
        assert signal.getsignal(signal.SIGALRM) is sentinel
        left, _interval = signal.getitimer(signal.ITIMER_REAL)
        assert 0 < left <= 60
        assert not fired
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


def test_fake_pw_never_raises() -> None:
    calls: list[str] = []

    class _Fake:  # pylint: disable=too-few-public-methods
        def stop(self) -> None:
            calls.append("stop")

    assert browser._stop_playwright_bounded(_Fake(), wait_s=1) is None
    assert calls == ["stop"]
