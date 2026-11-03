# PLAN: a bounded Playwright stop that actually stops (tp#1659)

- Item: tp#1659 (follow-up of tp#1655)
- Overseer session: 0f33deca-4332-40a7-8fe2-a03b66cfef7c
- Repo: home/browser-login — `bin/browser.py` is LIVE (consumers exec it)
- Status: planned, debated (Opus adversary, 2026-11-03), not started

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
under a main-thread bound and falls back to killing the driver pid only when the stop
stalled. The model is `tests/pw_bound.py` (`bounded`, `kill_tree`, `_driver_pid`,
`PwHolder.kill`), but the production code is self-contained: `bin/browser.py` must not
import from `tests/`.

Internals are read from fixed sources (no guessing): `conn = pw._impl_obj._connection`,
`proc = conn._transport._proc`, `fiber = conn._dispatcher_fiber`, `loop = conn._loop`.
Every read of these internals (pid, returncode, fiber, loop) sits in a `try` that
tolerates `AttributeError/TypeError/ValueError`, so a fake `pw` with only `.stop()` (as
in `tests/test_connect_hang.py:399-428`) still works and the function never raises.

1. **Driver handle first.** Read `proc` and its pid before anything else (None when the
   internals are missing: then there is no kill fallback, only the clean stop).
2. **Clean stop on the calling thread.**
   - On the main thread (`threading.current_thread() is threading.main_thread()`) with
     `signal.SIGALRM` available: save the previous SIGALRM handler and any outer
     itimer, install a handler that raises a private `_PlaywrightStopStall(BaseException)`
     only while a module-level "stopping" flag is set, and arm
     `setitimer(ITIMER_REAL, wait_s)`. Structure (late-alarm safe):
     `try: pw.stop() except _PlaywrightStopStall: stalled = True except Exception: pass
     finally: clear the flag, then disarm and restore handler + outer itimer`, with the
     disarm itself also wrapped in `except _PlaywrightStopStall` so an alarm racing the
     disarm cannot escape. browser.py uses no SIGALRM today (grep), and `LoginDeadline`
     is a watchdog thread that calls `os._exit`, so they do not conflict.
   - Off the main thread (no signal possible): call `pw.stop()` unbounded under
     `contextlib.suppress(Exception)`. Sync Playwright can only be stopped from its own
     thread anyway.
3. **Kill fallback — only on a stall.** Kill only when `_PlaywrightStopStall` fired, or
   when `proc.returncode is None` after the stop (the asyncio process object, never a
   bare pid probe: after a clean stop the driver is reaped and its pid may be reused).
   Then read the `pgrep -P` tree of the driver pid first, SIGKILL the driver and its
   descendants, never our own pid, and reap with `os.waitpid(pid, WNOHANG)` (suppressed).
   No shared-browser guard: with `connect_over_cdp` the shared Chromium is not a
   descendant of the driver, and a lifecycle-record read would add an I/O failure mode
   to a cleanup that must never raise.
4. **Unwind after a stall** (copy of `PwHolder.kill`). Throw into `fiber` if it is not
   yet dead (suppressed). If `loop` is no longer running: cancel its pending tasks
   (`asyncio.all_tasks(loop)`) and close it (suppressed), so no "Task was destroyed but
   it is pending" / "Event loop is closed" noise reaches stderr. Clear
   `asyncio._set_running_loop(None)` when it is still this instance's loop. Then a later
   `sync_playwright()` in the same process works again. The whole unwind is wrapped in
   the same tolerant `try`.
5. **Docstring** states the thread rule, the late-alarm handling and the stall-only kill
   fallback. Drop the "daemon thread" wording and the now-unused `threading.Thread`
   usage in this function (threading stays imported for the others).

**What callers see:** nothing changes in the contract. The function returns None, never
raises an `Exception` or `_PlaywrightStopStall` (a `KeyboardInterrupt` still
propagates), and takes at most about `wait_s` plus the kill. A normal stop takes about
0.1 s. Afterwards the driver is gone and the thread can start Playwright again.
`_connect` still raises `BrowserAttachTimeout` and `_doctor_probe_cleanup` still never
raises.

Out of scope (overseer decision, 2026-11-03): the 13 plain `pw.stop()` call sites
(`bin/browser.py:5947`, `6106`, `6741`, `11953`, …). They stop on the main thread
correctly and are only unbounded. No follow-up item unless one is seen hanging.

## Live-install safety

`bin/browser.py` is executed by consumers at any moment. It is never edited in place.

1. Worktree (gitignored path): `git -C /Users/albert/obsidian/42-Git/home/browser-login
   worktree add
   /Users/albert/obsidian/42-Git/home/browser-login/.claude/worktrees.noindex/stop-pw-bounded
   -b stop-pw-bounded`. All edits and tests happen there; run `uv sync` once in the
   worktree (it builds its own `.venv`).
2. Base check: record `shasum -a 256 bin/browser.py` of the live file at worktree
   creation. Immediately before landing, re-hash. If it differs, rebase the worktree on
   the new main and re-run the tests first (other agents land browser.py changes
   often).
3. Land: one path only — the worktree branch is merged to main through `ai.py push`
   (overseer), and the live checkout is the main checkout that receives it. No
   separate cp/mv/.bak install.
4. Smoke after landing: `bin/browser.py -h` exits 0. `browser.py doctor` runs only
   against a DISPOSABLE instance
   (`CLAUDE_BROWSER_CACHE_DIR=<tmp> browser.py --cdp-port <free port> up`, doctor, `down`),
   never 9222/9223.
5. Rollback: `git revert` of the landing commit via `ai.py push`.

## Boxes

- [x] B1 Worktree (`.claude/worktrees.noindex/stop-pw-bounded`, `uv sync`) + base hash; audit that every `_connect` call site (`grep -n "_connect(" bin/browser.py`, about 15) and `_doctor_probe_cleanup` run on the main thread, including under `LoginDeadline`, and that no `threading.Thread` target reaches `_connect`; record the result in the docstring
- [x] B2 New test file `tests/test_stop_playwright_bounded.py` (see Verification); confirm tests 1 and 2 FAIL on the unchanged `bin/browser.py`
- [x] B3 Rewrite `_stop_playwright_bounded` per the fix design (named internals, tolerant reads, main-thread SIGALRM bound with flag + late-alarm-safe disarm + save/restore, stall-only kill via `returncode`, unwind with task cancel + running-loop reset, docstring)
- [ ] B4 Lint per AGENTS.md (`ruff format`, `ruff check`, `mypy bin/browser.py`, `uv run pylint bin/browser.py`); targeted tests green: the new file plus `tests/test_connect_hang.py` (its doctor test at `:404` with `_FakePw` is the regression for tolerant reads)
- [ ] B5 Land via `ai.py push` (base re-hash first), `-h` smoke, disposable-instance `doctor`; rollback = `git revert`

## Verification

New `tests/test_stop_playwright_bounded.py`. It loads `bin/browser.py` the way
`tests/test_connect_hang.py:55` does (`spec_from_file_location`). It starts only the
Playwright driver (`sync_playwright().start()`, no Chromium launch, no CDP port), so no
Chrome is launched. If the conftest `CLAUDE_BROWSER_TEST_NO_LAUNCH` guard or the
`launches_chrome` convention calls for it, mark it accordingly and wrap it in
`pw_bound.bound_test`. Every test kills its driver pid in a `finally`.

1. `test_stop_kills_driver_and_allows_restart`: start pw, take the driver pid, call
   `browser._stop_playwright_bounded(pw, wait_s=5)`. Assert the driver process has
   exited within 2 s (`proc.returncode is not None`), and that a fresh
   `sync_playwright().start()` then succeeds (stop it). **Old code:** the driver stays
   alive, and the restart raises "using Playwright Sync API inside the asyncio loop".
   FAIL.
2. `test_hung_stop_is_bounded_and_killed`: start pw and monkeypatch its
   `_impl_obj._connection._transport.request_stop` to a no-op. The driver then never
   sees stdin EOF and `wait_until_stopped` would wait forever. Call
   `_stop_playwright_bounded(pw, wait_s=2)`. Assert it returns in under 5 s without
   raising, the driver pid is gone, and a fresh `sync_playwright().start()` succeeds.
   **Old code:** returns at once with the driver alive. FAIL.
3. `test_outer_sigalrm_restored`: arm an outer `setitimer` and a sentinel handler,
   call the stop, and assert the handler is back and the timer is still armed. Both
   are restored, so this one also passes on old code; it is the regression guard for
   the new bound.
4. `test_fake_pw_never_raises`: pass an object with only a `.stop()` method; the
   function returns None. Guards the tolerant internal reads.

Before B3, run the same tests in the worktree (its own path in place of the repo root)
and confirm tests 1 and 2 fail. The block below is the post-landing check against the
main checkout. It is not strict-eligible: pytest and mypy execute repository code
(the change is runtime behaviour of a Playwright driver, which only a test can
observe); the exec tier runs them.

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff check bin/browser.py tests/test_stop_playwright_bounded.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest tests/test_stop_playwright_bounded.py tests/test_connect_hang.py -q
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run mypy bin/browser.py
```

## Debate outcome (Opus adversary)

Critic: fresh Opus subagent, 2026-11-03, 1 round (Codex refused: `debate_seat_unknown`).
Verdict: sound-with-fixes. No objection rejected, so no round 2.

1. [major] Post-stop pid liveness probe could SIGKILL a reused pid — accepted: kill only on a stall or `proc.returncode is None`; the 1 s pid poll is dropped.
2. [major] Verification lacked the fenced `cd <root> && …` block — accepted: added a ```` ```commands ```` block against the repo root; worktree pre-B3 run kept as prose.
3. [major] A late SIGALRM between `pw.stop()` returning and the disarm could escape as BaseException — accepted: flag-gated handler, stall caught inside the `try`, disarm also guarded.
4. [minor] B1 audited only 2 lines though `_connect` serves ~15 call sites — accepted: B1 audits every `_connect` call site and thread targets; explicit main-thread check stays.
5. [minor] `_FakePw` in `tests/test_connect_hang.py:399-428` reaches the function — accepted: every internal read and the unwind are tolerant; new test 4 plus B4 naming the doctor test.
6. [minor] Unwind sources were unnamed — accepted: `conn._transport._proc`, `conn._dispatcher_fiber`, `conn._loop` named in the design.
7. [minor] Closing the loop with a pending transport task leaks stderr noise; driver left a zombie — accepted: cancel pending tasks before `loop.close()`, `waitpid(WNOHANG)` after the kill.
8. [minor] Worktree path not gitignored; fresh worktree needs `uv sync` — accepted: path moved to `.claude/worktrees.noindex/`, `uv sync` noted.
9. [minor] Separate cp/mv/.bak install collides with the git landing — accepted: single landing path via `ai.py push`, rollback `git revert`.
10. [minor] Shared-browser pid guard is scope creep and adds an I/O failure mode — accepted: guard dropped, own-pid check kept.

Overseer decision folded in: the 13 plain `pw.stop()` call sites stay out of scope (they stop correctly, only unbounded).
