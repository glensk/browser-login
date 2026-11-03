"""A bounded Playwright lifecycle for tests (tp#1655): no launching test can
wedge the run.

A main-thread SIGALRM bound interrupts the dispatcher's `select()` (and
`time.sleep`) and raises `PlaywrightStall`. A stall marks the owning
`PwHolder` dead: from then on no sync call reaches that instance (it would
spin at 100 % CPU in `_sync_base`), only a SIGKILL of its own driver tree.
`faulthandler.dump_traceback_later(exit=True)` is the last resort for a stall
the signal cannot reach.

Used by tests/test_ws5_client_s2.py and tests/test_ws5_client_s2_cdp.py; each
module wraps `bound_test` in its own autouse fixture.
"""

from __future__ import annotations

# pylint: disable=import-outside-toplevel  # playwright only when a test needs it
import asyncio
import contextlib
import faulthandler
import os
import signal
import subprocess
import time
from collections.abc import Iterator
from types import FrameType
from typing import Any

import pytest
from chromium_page import chromium_available

TEST_BOUND_S = 90  # one launching test: setup, body and teardown
HOLDER_BOUND_S = 60  # a holder's own start and stop
BACKSTOP_S = 600  # faulthandler: dump every stack and exit
_REFIRE_S = 10  # a stalled bound fires again (breaks a dead instance's spin)


class PlaywrightStall(BaseException):
    """A bound ran out. A BaseException, so no `except Exception` (the code
    under test, the storage tab) swallows it."""


class BoundState:  # pylint: disable=too-few-public-methods
    """The innermost armed bound: its phase, whether it fired, and every
    phase that stalled so far (a test's bound reads its own slice). `holder`
    is the instance a stall marks dead (None: no instance is tracked)."""

    phase = ""
    fired = False
    stalls: list[str] = []
    holder: PwHolder | None = None


def chrome_mark() -> pytest.MarkDecorator:
    """Skip a launching test when Playwright's Chromium is missing; with
    `WS5_REQUIRE_CHROME=1` a missing Chromium fails collection instead."""
    available = chromium_available()
    if not available and os.environ.get("WS5_REQUIRE_CHROME") == "1":
        pytest.fail(
            "WS5_REQUIRE_CHROME=1 but Playwright Chromium is missing", pytrace=False
        )
    return pytest.mark.skipif(not available, reason="Playwright Chromium missing")


def _in_playwright(frame: FrameType | None) -> bool:
    while frame is not None:
        if f"{os.sep}playwright{os.sep}" in frame.f_code.co_filename:
            return True
        frame = frame.f_back
    return False


def _on_alarm(_signum: int, frame: FrameType | None) -> None:
    """SIGALRM in the main thread. The first fire marks the tracked instance
    dead and raises; a re-fire raises only inside Playwright code (a later
    sync call on the dead instance spins in `_sync_base`)."""
    if not BoundState.fired:
        BoundState.fired = True
        BoundState.stalls.append(BoundState.phase)
        if BoundState.holder is not None:
            BoundState.holder.dead = True
        raise PlaywrightStall(f"Playwright lifecycle hung in {BoundState.phase}")
    if _in_playwright(frame):
        raise PlaywrightStall(f"Playwright lifecycle hung in {BoundState.phase}")


@contextlib.contextmanager
def bounded(seconds: float, phase: str) -> Iterator[None]:
    """Arm a `seconds` SIGALRM bound named `phase`; an outer bound is
    restored afterwards with what is left of it."""
    old_handler = signal.signal(signal.SIGALRM, _on_alarm)
    old_left, _interval = signal.getitimer(signal.ITIMER_REAL)
    old_phase, old_fired = BoundState.phase, BoundState.fired
    start = time.monotonic()
    BoundState.phase, BoundState.fired = phase, False
    signal.setitimer(signal.ITIMER_REAL, seconds, _REFIRE_S)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        BoundState.phase, BoundState.fired = old_phase, old_fired
        if old_left:
            left = max(old_left - (time.monotonic() - start), 0.001)
            signal.setitimer(signal.ITIMER_REAL, left, _REFIRE_S)
        signal.signal(signal.SIGALRM, old_handler)


def set_phase(phase: str) -> None:
    """Rename the innermost bound (a fixture moves from setup to call to
    teardown)."""
    BoundState.phase = phase


@contextlib.contextmanager
def tracking(holder: PwHolder | None) -> Iterator[None]:
    """`holder` is the instance a stall marks dead while inside."""
    old = BoundState.holder
    BoundState.holder = holder
    try:
        yield
    finally:
        BoundState.holder = old


def bound_test(
    request: pytest.FixtureRequest, seconds: float = TEST_BOUND_S
) -> Iterator[None]:
    """The body of a module's autouse fixture: every `launches_chrome` test
    runs under a `seconds` (default 90 s) main-thread bound. A stall fails that test
    (`Playwright lifecycle hung in <phase>`) and the tracked instance's
    driver is killed; the next test relaunches it."""
    if request.node.get_closest_marker("launches_chrome") is None:
        yield
        return
    # pytest's own faulthandler_timeout re-arms (and cancels) the one
    # faulthandler timer per test: the backstop is armed here, per test.
    faulthandler.dump_traceback_later(BACKSTOP_S, exit=True)
    before = len(BoundState.stalls)
    with bounded(seconds, "setup"):
        yield
    stalled = BoundState.stalls[before:]
    if stalled:
        holder = BoundState.holder
        if holder is not None and holder.dead:
            holder.kill()
        pytest.fail(f"Playwright lifecycle hung in {stalled[0]}")


def _descendants(pid: int) -> list[int]:
    """Every descendant of `pid` (a `pgrep -P` walk from `pid` only)."""
    found = subprocess.run(
        ["pgrep", "-P", str(pid)],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    ).stdout.split()
    kids = [int(k) for k in found if k.isdigit()]
    for kid in list(kids):
        kids += _descendants(kid)
    return kids


def kill_tree(pid: int) -> None:
    """SIGKILL the driver `pid` and its descendants (its Chromium). The tree
    is read before the first kill: an orphan's parent is no longer `pid`."""
    for victim in [pid, *_descendants(pid)]:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.kill(victim, signal.SIGKILL)


def _driver_pid(manager: Any) -> int | None:
    """The Node driver's pid, from Playwright's own transport."""
    try:
        return int(manager._connection._transport._proc.pid)
    except (AttributeError, TypeError, ValueError):
        return None


def _dispatcher(manager: Any) -> Any:
    """The instance's dispatcher greenlet (None before it exists)."""
    return getattr(getattr(manager, "_connection", None), "_dispatcher_fiber", None)


def _is_timeout(exc: BaseException) -> bool:
    """Playwright's own TimeoutError (the 30 s launch timeout)."""
    try:
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
    except ImportError:
        return False
    return isinstance(exc, PlaywrightTimeoutError)


class PwHolder:
    """One driver (and, with `launch`, one headless Chromium). `dead` is set
    by a stall: from then on no sync call reaches this instance, only a kill
    of its driver."""

    def __init__(self, launch: bool = True) -> None:
        self.launch = launch
        self.manager: Any = None
        self.pw: Any = None
        self.browser_: Any = None
        self.pid: int | None = None
        self.dead = False
        self.starts = 0

    def _start(self) -> None:
        from playwright.sync_api import sync_playwright

        self.starts += 1
        self.manager = sync_playwright()
        self.pw = self.manager.start()
        self.pid = _driver_pid(self.manager)
        if self.launch:
            self.browser_ = self.pw.chromium.launch(headless=True, timeout=30_000)

    def _usable(self) -> bool:
        """Not marked dead, and its dispatcher greenlet still runs (a sync
        call on a finished dispatcher spins forever)."""
        dispatcher = _dispatcher(self.manager)
        return not self.dead and dispatcher is not None and not dispatcher.dead

    def _live(self) -> bool:
        if self.pw is None or not self._usable():
            return False
        return not self.launch or (
            self.browser_ is not None and self.browser_.is_connected()
        )

    def ensure(self) -> Any:
        """The live browser (None without `launch`); a dead or disconnected
        instance is killed and relaunched. A launch that stalls or times
        out is killed and retried once; a second failure ends the run."""
        if self._live():
            return self.browser_
        phase = "relaunch" if self.starts > 0 else "launch"
        if self.manager is not None:
            self.kill()
        for attempt in (1, 2):
            try:
                with bounded(HOLDER_BOUND_S, phase):
                    self._start()
                return self.browser_
            except BaseException as exc:  # pylint: disable=broad-exception-caught
                failed = self.dead or _is_timeout(exc)
                self.kill()
                if not failed:
                    raise
                if attempt == 2:
                    pytest.exit(f"Playwright cannot start: {phase}", returncode=1)
                phase = f"{phase} retry"
        raise AssertionError("unreachable")

    def kill(self) -> None:
        """SIGKILL this instance's driver tree; no sync call on it."""
        pid = self.pid or _driver_pid(self.manager)
        if pid is not None:
            kill_tree(pid)
        # A dispatcher greenlet still suspended inside its loop keeps that
        # loop "running" for this thread, and every new sync_playwright()
        # refuses. Unwind it (GreenletExit runs asyncio's own cleanup).
        dispatcher = _dispatcher(self.manager)
        if dispatcher is not None and not dispatcher.dead:
            with contextlib.suppress(Exception):
                dispatcher.throw()
        loop = getattr(self.manager, "_loop", None)
        if loop is not None and not loop.is_running():
            with contextlib.suppress(Exception):
                loop.close()
        # Every sync call leaves its loop set as this thread's running loop
        # (`_sync_base._sync`); a new sync_playwright() would adopt it.
        if loop is not None and asyncio._get_running_loop() is loop:
            asyncio._set_running_loop(None)
        self.manager = self.pw = self.browser_ = None
        self.pid = None
        self.dead = False

    def stop(self, phase: str = "module teardown") -> None:
        """A clean close (browser, then driver) under its own bound, else a
        kill."""
        if self.manager is None:
            return
        if not self._usable():
            self.kill()
            return
        try:
            with bounded(HOLDER_BOUND_S, phase):
                if self.browser_ is not None:
                    self.browser_.close()
                self.pw.stop()
        except BaseException:  # pylint: disable=broad-exception-caught
            stalled = self.dead
            self.kill()
            if not stalled:
                raise
            pytest.fail(f"Playwright lifecycle hung in {phase}")
        self.manager = self.pw = self.browser_ = None
        self.pid = None


def module_holder() -> Iterator[PwHolder]:
    """The body of a module-scoped `_pw` fixture: the module's shared
    instance (started on first use), tracked for the whole module."""
    holder = PwHolder()
    with tracking(holder):
        try:
            yield holder
        finally:
            holder.stop()
