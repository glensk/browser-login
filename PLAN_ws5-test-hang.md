# PLAN: make tests/test_ws5_client_s2.py finish deterministically (tp#1655)

> **Resume here.** Status: root-caused (medium confidence, see below), planned, and the plan
> has been critiqued and reconciled (see the Debate outcome section). Nothing is built. Next
> box: B1. Tests only: no change to `bin/browser.py` or any other live file, so the code needs
> no worktree, but only one writer works in the repo at a time.

## Session

Ticket: tp#1655
Session: 0f33deca-4332-40a7-8fe2-a03b66cfef7c (cause + plan)
Origin: found while building tp#1643 B7-B9; it hangs the same way on base d61cdc8.

## Goal

Every run of `uv run pytest tests/test_ws5_client_s2.py` finishes. When a Playwright step
stalls, that one test fails with a stack and the session carries on. The test does not
wedge the run. With the cause fixed, a clean run shows 47 passed, and the full
browser-login suite can finish again.

## Root cause

**The per-test Playwright lifecycle, with no bound on any of its steps.** Every
`launches_chrome` test starts its own Node driver and a fresh headless Chromium, then tears
both down again:

- `chrome` fixture, `tests/test_ws5_client_s2.py:266-303`: `sync_playwright()` ->
  `pw.chromium.launch()` -> `new_context()` / `route()` / `new_page()` ... `chromium.close()`
  -> driver stop (12 tests).
- `storage_chrome` fixture, `:1194-1244`: the same cycle (7 tests).
- `cdp_chromium`, `:1427-1511`: one `sync_playwright()` only to read `executable_path`, then
  another `sync_playwright()` + `connect_over_cdp()` for each `on_page` call.
- `_chromium_installed()` at import, `:219-233`: one more driver cycle.

That adds up to about 22 driver start/stop cycles and 19 Chromium launch/close cycles per
run. None of these lifecycle calls has a timeout. `new_context`, `new_page`, `route`,
`Browser.close()` and the driver stop wait forever; `launch` falls back to Playwright's
180 s default. When one step of a cycle never returns, the test running that cycle hangs,
which is why the hang moves from run to run. The other test files that call
`tests/chromium_page.py:routed_context` once per test pay the same cost. This file has the
most cycles (47 tests, 21 of them launching).

### Evidence (2026-11-03, Python 3.14.4, playwright 1.60.0, greenlet 3.5.3, Darwin 27.2)

Run 1 (whole file): `test_a_foreign_storage_token_session_is_cleared_by_one_check[navidrome]`
never finished (test 41/47). The outer `timeout 150` fired before
`faulthandler_timeout=45` could dump.

Run 2 (`-m launches_chrome`, `faulthandler_timeout=25`): hung in
`test_unclear_answers_never_pass[case4]` (the 8th launching test, a different one). The
complete dump shows exactly two threads:

```
Thread [asyncio-waitpid-0]          # the driver's child watcher, blocked in os.waitpid
  asyncio/unix_events.py:931 _do_waitpid
Thread (main)                       # the Playwright dispatcher greenlet, idle
  selectors.py:548 select
  asyncio/base_events.py:2019 _run_once
  asyncio/base_events.py:706 run_until_complete
  playwright/sync_api/_context_manager.py:56 greenlet_main
```

What the dump proves:

1. The main greenlet is suspended in a synchronous Playwright call and waits for an answer
   the driver never sends. The dispatcher has nothing to read (`select`), and the driver
   process is still alive (its `waitpid` thread has not returned). faulthandler cannot show
   the suspended main greenlet, so the dump does not pin the exact call yet (B1).
2. **The dump has no `FakeBroker` thread.** That thread (`serve_forever`, started at `:146`)
   is alive for the whole test body. So the hang is not in the test body (the broker proof,
   the routed fetch, `page.evaluate`). It is in fixture setup (`sync_playwright` start,
   `launch`, `new_context`, `route`, `new_page`) or in teardown (`chromium.close()`, or
   `PlaywrightContextManager.__exit__` -> `Connection.stop_sync` at
   `playwright/_impl/_connection.py:316-320`, which waits for the driver to exit via
   `PipeTransport.run` -> `await self._proc.communicate()` at
   `playwright/_impl/_transport.py:137-170`).
3. Nothing outlived the timed-out runs. No `run-driver`, headless shell or temp-profile
   Chromium was left afterwards; only the live shared browser on 9222 was running, and it
   was untouched.

Caveat (critic): run 2's 25 s dump came before Playwright's 30 s default timeouts. A dumped
"hang" could therefore be a call that would have timed out by itself. The idle-dispatcher
frame also cannot tell "a pending call with no reply" from "the driver does not exit after
stdin closes". B1 settles both questions.

Confidence: **high** that the hang is in the per-test Chromium/driver lifecycle (setup or
teardown), and that the moving location comes from the number of cycles. **Medium** on which
single call it is. B1 pins it.

Ruled out:

- The broker socket: a Unix socket in a tmp dir, created per test and closed in
  `make_broker`.
- Port reuse: only `cdp_chromium` binds a port, and these hangs happened outside it.
- The `LoginDeadline` and watchdog threads: none appear in the dump.
- The shared browser: `_connect` is patched or never reached in the fixtures that hung.

## Design

1. **Pin the call (B1).** Run once with Playwright's own logging (`DEBUG=pw:api,pw:browser`
   and `-s`, so the driver's stderr reaches the log file) and with
   `faulthandler_timeout=200`, which is above every Playwright default. The last `pw:api`
   line that shows a start but no finish is the stuck call. All B1 needs is the class:
   launch-side or close-side. If the first run does not hang, a second run is allowed (the
   two-run cap). If neither run hangs, the class stays unknown and B5 applies both branches.
2. **Bound in the main thread, never wedge (B2).** Add an autouse fixture, scoped to the
   module's `launches_chrome` tests, that arms `signal.setitimer(ITIMER_REAL, 90)` with a
   SIGALRM handler that raises `PlaywrightStall(phase)`. The signal interrupts the
   dispatcher's `select()` (the frame in the dump) and also `time.sleep`. The exception
   reaches the test, which fails with a real stack. Teardown disarms the timer (`setitimer(…, 0)`).
   `faulthandler.dump_traceback_later(600, exit=True)`, armed once per session in a
   `pytest_configure`-style module hook, is the final backstop: even a stall the signal
   cannot reach ends the process with a stack. Keep `[tool.pytest.ini_options]
   faulthandler_timeout = 120` in `pyproject.toml`, which makes every future hang dump
   stacks.
   - **After a stall the Playwright instance is dead.** Once an exception has left
     `greenlet_main`, any later sync call on that instance spins at 100 % CPU in
     `_sync_base.py:102-113` (`while not task.done(): dispatcher_fiber.switch()`). So the
     handler sets `dead = True` on the owning holder. Teardown then makes **no** sync API
     call on that instance (no `ctx.close()`, no `browser.close()`, no `pw.stop()`). It
     SIGKILLs the driver by its own pid (`pw._impl_obj._connection._transport._proc.pid`,
     resolved when the instance starts) and that pid's descendants (`pgrep -P` walk from
     that pid only, never from the pytest pid, never by name). The test then fails via
     `pytest.fail(f"Playwright lifecycle hung in {phase}")`, whatever exception was raised
     on the way out.
   - Never use `bin/browser.py:_stop_playwright_bounded` as a model. It calls `pw.stop()` from a
     daemon thread, which greenlet refuses ("cannot switch to a different thread"). The
     error is swallowed, so only `request_stop` takes effect. A sync Playwright call cannot
     be moved to another thread at all.
3. **One browser per module, a fresh context per test (B3).** This reduces how often a
   stall happens; it is not the fix. B2 and B5 are the fix. A module-scoped holder `_pw`
   owns one `sync_playwright()` and one `chromium.launch(headless=True, timeout=30_000)`. It
   arms the same SIGALRM bound (60 s) around its own setup and its own teardown, because the
   function-scoped bound does not cover module-scoped setup and teardown. `chrome` and
   `storage_chrome` keep their contracts and monkeypatches, but they use
   `browser_.new_context()` and close the context in `finally`. Isolation stays the same:
   cookies, localStorage, routes and service workers all live per context. Before each test
   `_pw` checks `not dead and browser_.is_connected()`. If the check fails, it kills the old
   instance as in 2 and starts a fresh one. A single stall therefore fails one test, not
   every test after it. If the relaunch stalls too, the run ends with `pytest.exit("Playwright
   cannot start: <phase>")`.
4. **Drop the extra driver cycles (B4).**
   - `_chromium_installed()` reuses `tests/chromium_page.py:chromium_available` (cached,
     called once per run).
   - `cdp_chromium` takes `executable_path` from `_pw` instead of running its own
     `sync_playwright()`.
   - `on_page` attaches through `_pw`'s `chromium.connect_over_cdp()` instead of a nested
     `sync_playwright()`.
   - Code under test that calls the real `_connect` (the cdp tests) starts its own
     `sync_playwright()` while `_pw` is alive. Check in B4 that this nesting works. If it
     does not, move the two `cdp_chromium` tests to their own module
     (`tests/test_ws5_client_s2_cdp.py`) with no `_pw`, still under the B2 bound.
   - With `WS5_REQUIRE_CHROME=1` set, Chromium being unavailable fails at collection instead
     of skipping. Without that flag, a missing Chromium would skip all 21 launching tests and
     verification would still pass.
5. **Targeted fix (B5)**, chosen by B1:
   - Close-side (`Browser.close` / driver stop): close in the order `ctx.close()`, then
     `browser_.close()`, then `pw.stop()`, all under the main-thread bound. On a stall, kill
     the driver pid as in 2. In-test `page.close()` calls stay, because they run against a
     live browser.
   - Launch-side (`launch` / `new_context` / `new_page`): `launch(timeout=30_000)`. On
     `TimeoutError` or a stall, kill the half-started driver tree as in 2 and retry the
     module launch once.
   - Class unknown (neither B1 run hung): apply both branches.
   - Neither class (the log names a call in the test body): stop and report to the overseer
     before changing any test logic.

Out of scope (overseer decision, 2026-11-03): the other test files that use
`tests/chromium_page.py:routed_context` once per test. They get the shared-browser fix only
through a follow-up tp item, and only if B6's full suite shows a hang there.

Follow-up candidate (overseer to file, not built here): production
`bin/browser.py:_stop_playwright_bounded` probably does nothing on a sync instance (see 2).

## Boxes

- [x] B1 Instrumented run: `DEBUG=pw:api,pw:browser timeout 300 uv run pytest
      tests/test_ws5_client_s2.py -x -s -m launches_chrome -p no:cacheprovider -o
      faulthandler_timeout=200 > /tmp/ws5-b1.log 2>&1`. Allow a second run only if the
      first does not hang. Record the stuck call and its class (launch-side, close-side, or
      unknown) in the Root cause section; the overseer edits the plan.
- [x] B2 Add the main-thread SIGALRM bound fixture (90 s, autouse for `launches_chrome`).
      Add the `dead` flag, the teardown that makes no sync call on a dead instance, and the
      driver-pid kill (the pid comes from Playwright's transport, then a `pgrep -P` walk
      from that pid only). The test fails with `pytest.fail("Playwright lifecycle hung in
      <phase>")`. Add the session backstop `faulthandler.dump_traceback_later(600,
      exit=True)`. Add `[tool.pytest.ini_options] faulthandler_timeout = 120` to
      `pyproject.toml`. This makes `pyproject.toml` the inifile for the whole suite;
      confirm that `uv run pytest --collect-only -q` still collects the same number of
      tests as before the change.
- [x] B3 Add a module-scoped `_pw` holder (one driver, one headless Chromium,
      `launch(timeout=30_000)`), with its own 60 s bound around setup and teardown and a
      relaunch when the browser is disconnected or dead. Port `chrome` and `storage_chrome`
      to a fresh context per test, closed in `finally`.
- [x] B4 Switch `_chromium_installed` to `chromium_page.chromium_available`. Make
      `cdp_chromium` reuse `_pw` for `executable_path` and `connect_over_cdp`. Check that a
      nested `_connect` works; if it does not, split the cdp tests into
      `tests/test_ws5_client_s2_cdp.py`. Add the `WS5_REQUIRE_CHROME=1` collection failure.
- [x] B5 Apply the targeted fix for B1's class (Design 5; class unknown = both branches).
- [x] B6 Verification below is green. Lint is clean.

## Verification

```
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff format --check /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws5_client_s2.py
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff check /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws5_client_s2.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run --project /Users/albert/obsidian/42-Git/home/browser-login mypy /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws5_client_s2.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run --project /Users/albert/obsidian/42-Git/home/browser-login pylint /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws5_client_s2.py
cd /Users/albert/obsidian/42-Git/home/browser-login && env WS5_REQUIRE_CHROME=1 timeout 300 uv run --project /Users/albert/obsidian/42-Git/home/browser-login pytest -v -rs -p no:cacheprovider /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws5_client_s2.py
```

Each line is `cd <repo> && <argv>` (tp verify grammar). Strict-eligible: no. The block runs
mypy, pylint and pytest, because the ticket's whole claim is that the test file completes.
Checks the block cannot express:

- The pytest line runs at most twice (no repeat loops). Both runs must show 47 passed, 0
  skipped. Record the wall time.
- Watchdog proof, one throwaway test, no load. A fixture monkeypatches a lifecycle call
  (`browser_.close`) to `time.sleep(10**6)`. Within about 90 s the test fails with the
  "Playwright lifecycle hung in teardown" message. The next test still passes on a
  relaunched `_pw`, and no core is pegged (check `ps -o %cpu -p <pytest pid>` once while it
  runs). Delete the throwaway test after the check.
- Leftover check, specific to this run: record the pytest process's descendant pids at
  session finish (in a temporary print inside a `pytest_sessionfinish` hook in the
  throwaway test). The list must be empty. `pgrep -fl run-driver` is not a valid check,
  because Playwright MCP and browser.py clients start their own drivers.
- Full suite once: `timeout 1800 nice -n 15 uv run pytest -q -p no:cacheprovider` reaches
  its summary line. Report any other file that hangs to the overseer as a follow-up item
  (scope note above).
- `git diff --stat` touches only `tests/test_ws5_client_s2.py` and `pyproject.toml`, plus
  `tests/test_ws5_client_s2_cdp.py` if B4 split it.

## Debate outcome (Opus adversary)

Codex refused at round 0 (`debate_seat_unknown`: no allowed seat had a fresh five-hour
reading), so the debate fell back to the Opus critique.
Critic: fresh Opus subagent, 2026-11-03, 1 round (verdict `unsound`; no objection rejected,
so no round 2).

1. [blocker] After a driver kill, any later sync call spins at 100 % CPU (`_sync_base.py:102-113`). Accepted: added the `dead` flag; teardown makes no sync call on a dead instance and only kills the driver pid (Design 2, B2).
2. [blocker] The `time.sleep(10**6)` watchdog proof cannot pass with a child-kill watchdog. Accepted: the bound is now SIGALRM in the main thread, which interrupts `time.sleep`. The proof also checks that the next test passes and no core is pegged.
3. [major] "The kill is the only bound" is false; a main-thread signal interrupts `select()`. Accepted: a SIGALRM fixture replaces the threading.Timer kill, plus a `faulthandler.dump_traceback_later(exit=True)` backstop.
4. [major] The function-scoped watchdog does not cover the module-scoped `_pw` setup and teardown. Accepted: `_pw` arms its own 60 s bound around both; the session backstop covers anything left.
5. [major] `_stop_playwright_bounded` cannot work on a sync instance (a cross-thread greenlet switch). Accepted: the plan now forbids it as a model; the production no-op is listed as a follow-up candidate for the overseer.
6. [major] B3 only reduces the odds of a hang, and B1 might not reproduce. Accepted: the goal is reworded (every run finishes; a stall fails one test). B1 may use the second run, and an unknown class applies both B5 branches.
7. [major] One shared browser lets a single kill cascade into every later test. Accepted: `_pw` checks `is_connected()` and `dead`, relaunches, and calls `pytest.exit` if the relaunch also stalls.
8. [minor] `pgrep -P <pytest pid>` also matches `cdp_chromium`'s Chromium. Accepted: the driver pid comes from Playwright's transport, and the walk starts from that pid only.
9. [minor] A killed driver raises "Connection closed while reading from the driver", not `TargetClosedError`. Accepted: the fixture converts any exception raised during a stall into `pytest.fail("Playwright lifecycle hung in <phase>")`.
10. [minor] Verification passes even if every launching test skips. Accepted: `WS5_REQUIRE_CHROME=1` fails collection instead of skipping; the run uses `-rs` and expects 0 skipped.
11. [minor] `pgrep -fl run-driver` also matches other clients' drivers. Accepted: replaced by a descendant-pid check at session finish.
12. [minor] A new pytest table makes `pyproject.toml` the suite's inifile, and mypy was missing from verification. Accepted: B2 checks the collection count; mypy is added to the Verification block.
