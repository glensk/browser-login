# PLAN: a bounded Playwright stop that actually stops (tp#1659)

- Item: tp#1659 (follow-up of tp#1655)
- Overseer session: 0f33deca-4332-40a7-8fe2-a03b66cfef7c
- Repo: home/browser-login — `bin/browser.py` is LIVE (consumers exec it)
- Status: planned, not started

## Root cause (verified 2026-11-03, Playwright 1.60.0 in `.venv`)

`bin/browser.py:5629` `_stop_playwright_bounded(pw, wait_s=5.0)` runs `pw.stop()` in a
daemon thread under `contextlib.suppress(Exception)` and joins it for `wait_s`.
Callers: `bin/browser.py:5617` (`_connect`, after `connect_over_cdp` raised
`PlaywrightTimeoutError`, before `BrowserAttachTimeout`) and `bin/browser.py:6995`
(`_doctor_probe_cleanup`). The instance comes from `sync_playwright().start()` at
`bin/browser.py:5608`, on the caller's (main) thread.

Sync Playwright is bound to its creating thread. `pw.stop` is
`PlaywrightContextManager.__exit__`
(`playwright/sync_api/_context_manager.py`), which:

1. sets `_exit_was_called = True`,
2. calls `Connection.stop_sync()`: `transport.request_stop()` (sets `_stopped`, closes
   the driver's stdin writer — an asyncio call from a foreign thread), then
   `self._dispatcher_fiber.switch()`, which raises
   `greenlet.error: Cannot switch to a different thread`.

The suppress swallows that error. So the thread returns at once, the "bound" never
bounds anything, and the instance is left half-stopped.

A throwaway probe (scratch dir, driver only plus one headless throwaway Chromium, never
port 9222) gave these results:

| case | swallowed error | driver alive 3 s later | loop closed | later main-thread `pw.stop()` | new `sync_playwright().start()` |
|---|---|---|---|---|---|
| main-thread `pw.stop()` (control) | none | no | yes | — | OK |
| attach timeout (silent listener, 2 s) then `_stop_playwright_bounded` | `greenlet.error: Cannot switch to a different thread` | **yes** | no | no-op in 0.00 s, driver **still alive** | — |
| launch + `browser.close()` (doctor-like) then `_stop_playwright_bounded` | same | **yes** | no | no-op, driver **still alive** | — |
| `_stop_playwright_bounded` then restart | same | — | — | — | **fails**: "using Playwright Sync API inside the asyncio loop" |
| attach timeout then main-thread `pw.stop()` (control) | none | no (stop took 0.08 s) | yes | — | — |
| `_stop_playwright_bounded`, then the process exits | same | driver exits with its parent (stdin EOF) | — | — | — |

Consequences:

- The Node driver is never stopped. It lives until the process exits.
- `_exit_was_called` is set, so even a later correct main-thread `pw.stop()` does
  nothing.
- The thread's running loop stays set (the dispatcher greenlet is still suspended
  inside `run_until_complete`). Every later `sync_playwright()` in that process
  therefore fails.
- A stop that really hangs has no bound at all: the cross-thread call errors out before
  it can hang, and nothing replaces it.

Today's impact is small (priority low stays right). Both callers end the process soon
after: `BrowserAttachTimeout` goes to `main` and exit 1, and doctor's probe is its last
Playwright use. The function is still wrong, though, and it poisons any future caller
that reconnects in the same process.

## Fix design

Rewrite `_stop_playwright_bounded` in place, keeping its signature
`(pw: Any, wait_s: float = 5.0) -> None`. It stops the instance on the calling thread
under a main-thread bound and falls back to killing the driver pid. The model is
`tests/pw_bound.py` (`bounded`, `kill_tree`, `_driver_pid`, `PwHolder.kill`), but the
production code is self-contained: `bin/browser.py` must not import from `tests/`.

1. **Driver pid first.** Read `pw._impl_obj._connection._transport._proc.pid` before
   anything else, in a `try` that tolerates `AttributeError/TypeError/ValueError`
   (None: there is no kill fallback, so the clean stop is all we can do).
2. **Clean stop on the calling thread.** `pw.stop()` with `contextlib.suppress(Exception)`.
   - On the main thread, with `signal.SIGALRM` available: arm a SIGALRM
     `setitimer(ITIMER_REAL, wait_s)` whose handler raises a private
     `_PlaywrightStopStall(BaseException)`. Save the previous handler and any outer
     itimer and restore both in a `finally`, as `pw_bound.bounded` does. browser.py
     uses no SIGALRM today (grep), and `LoginDeadline` is a watchdog thread that calls
     `os._exit`, so they do not conflict.
   - Off the main thread (no signal possible): call `pw.stop()` unbounded. Sync
     Playwright can only be stopped from its own thread anyway. Builder: audit that
     both callers run on the main thread and note the result in the docstring.
3. **Kill fallback.** If the stop stalled, or the driver pid is still alive after it
   (poll up to 1 s), SIGKILL the driver and its `pgrep -P` descendants. Read the tree
   before the first kill. Guard: never signal the shared browser's pid (from the
   lifecycle record) or our own pid. With `connect_over_cdp` the shared Chromium is
   not a descendant of the driver, but the guard makes that impossible to get wrong.
4. **Unwind after a stall** (copy of `PwHolder.kill`). Throw into a dispatcher
   greenlet that is not yet dead (suppressed). Close the loop if it is no longer
   running. Clear `asyncio._set_running_loop(None)` when it is still this instance's
   loop. Then a later `sync_playwright()` in the same process works again.
5. **Docstring** states the thread rule and the kill fallback. Drop the "daemon thread"
   wording and the now-unused `threading` usage in this function (threading stays
   imported for the others).

**What callers see:** nothing changes in the contract. The function returns None, never
raises an `Exception` (a `KeyboardInterrupt` still propagates), and takes at most about
`wait_s + 1 s`. A normal stop takes about 0.1 s. Afterwards the driver is gone and the
thread can start Playwright again. `_connect` still raises `BrowserAttachTimeout` and
`_doctor_probe_cleanup` still never raises.

Out of scope: the 13 plain `pw.stop()` call sites (`bin/browser.py:5947`, `6106`,
`6741`, `11953`, …). They stop on the main thread correctly and are only unbounded. See
the questions.

## Live-install safety

`bin/browser.py` is executed by consumers at any moment. It is never edited in place.

1. Worktree: `git -C /Users/albert/obsidian/42-Git/home/browser-login worktree add
   /Users/albert/obsidian/42-Git/home/browser-login/.worktrees.noindex/stop-pw-bounded
   -b stop-pw-bounded`. All edits and tests happen there.
2. Base check: record `shasum -a 256 bin/browser.py` of the live file at worktree
   creation. Immediately before install, re-hash. If it differs, rebase the worktree on
   the new main and re-run the tests first (other agents land browser.py changes
   often).
3. Install: the change lands on main through `ai.py push` from the worktree branch
   merge (overseer). If the live checkout has to be updated separately: `cp
   bin/browser.py bin/browser.py.bak-tp1659`, then `cp <worktree>/bin/browser.py
   bin/.browser.py.tp1659.tmp` and `mv bin/.browser.py.tp1659.tmp bin/browser.py` (same
   dir, atomic). Keep mode +x.
4. Smoke after install: `bin/browser.py -h` exits 0. `browser.py doctor` runs only
   against a DISPOSABLE instance
   (`CLAUDE_BROWSER_CACHE_DIR=<tmp> browser.py --cdp-port <free port> up`, doctor, `down`),
   never 9222/9223.
5. Rollback: `mv bin/browser.py.bak-tp1659 bin/browser.py` (atomic), or revert the
   commit. Delete the `.bak` once the smoke passes and one real consumer run is clean.

## Boxes

- [ ] B1 Worktree + base hash; audit that both callers (`bin/browser.py:5617`, `:6995`) run on the main thread
- [ ] B2 New test file `tests/test_stop_playwright_bounded.py` (see Verification); confirm it FAILS on the unchanged `bin/browser.py`
- [ ] B3 Rewrite `_stop_playwright_bounded` per the fix design (driver pid, main-thread SIGALRM bound with save/restore, kill fallback with shared-browser guard, unwind + running-loop reset, docstring)
- [ ] B4 Lint per AGENTS.md (`ruff format`, `ruff check`, `mypy bin/browser.py`, `uv run pylint bin/browser.py`); targeted tests green: the new file plus `tests/test_connect_hang.py`
- [ ] B5 Live install (base re-hash, .bak, atomic mv), `-h` smoke, disposable-instance `doctor`; rollback ready

## Verification

New `tests/test_stop_playwright_bounded.py`. It loads `bin/browser.py` the way
`tests/test_connect_hang.py:55` does (`spec_from_file_location`). It starts only the
Playwright driver (`sync_playwright().start()`, no Chromium launch, no CDP port), so no
Chrome is launched. If the conftest `CLAUDE_BROWSER_TEST_NO_LAUNCH` guard or the
`launches_chrome` convention calls for it, mark it accordingly and wrap it in
`pw_bound.bound_test`. Every test kills its driver pid in a `finally`.

1. `test_stop_kills_driver_and_allows_restart`: start pw, take the driver pid, call
   `browser._stop_playwright_bounded(pw, wait_s=5)`. Assert the driver pid is gone
   within 2 s, and that a fresh `sync_playwright().start()` then succeeds (stop it).
   **Old code:** the driver stays alive, and the restart raises "using Playwright Sync
   API inside the asyncio loop". FAIL.
2. `test_hung_stop_is_bounded_and_killed`: start pw and monkeypatch its
   `_impl_obj._connection._transport.request_stop` to a no-op. The driver then never
   sees stdin EOF and `wait_until_stopped` would wait forever. Call
   `_stop_playwright_bounded(pw, wait_s=2)`. Assert it returns in under 5 s, the driver
   pid is gone, and a fresh `sync_playwright().start()` succeeds. **Old code:** returns
   at once with the driver alive. FAIL.
3. `test_outer_sigalrm_restored`: arm an outer `setitimer` and a sentinel handler,
   call the stop, and assert the handler is back and the timer is still armed. Both
   are restored, so this one also passes on old code; it is the regression guard for
   the new bound.

Commands (in the worktree):
`run-quiet uv run pytest tests/test_stop_playwright_bounded.py tests/test_connect_hang.py -q`.
Before B3, the same command must show tests 1 and 2 failing.
