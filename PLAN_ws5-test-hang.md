# PLAN: make tests/test_ws5_client_s2.py finish deterministically (tp#1655)

> **Resume here.** Status: root-caused (medium confidence, see below) and planned, nothing
> built. Next box: B1. Tests only: no change to `bin/browser.py` or any live file, so no
> worktree is needed for the code, but one writer per repo.

## Session

Ticket: tp#1655
Session: 0f33deca-4332-40a7-8fe2-a03b66cfef7c (cause + plan)
Origin: found while building tp#1643 B7-B9; it hangs equally on base d61cdc8.

## Goal

`uv run pytest tests/test_ws5_client_s2.py` finishes (pass or fail) on every run, and the
full browser-login suite can complete again. A Playwright step that does hang fails its
test with a stack instead of wedging the session.

## Root cause

**The per-test Playwright lifecycle, with no bound on any of its steps.** Every
`launches_chrome` test starts its own Node driver plus a fresh headless Chromium and tears
both down again:

- `chrome` fixture, `tests/test_ws5_client_s2.py:266-303`: `sync_playwright()` ->
  `pw.chromium.launch()` -> `new_context()` / `route()` / `new_page()` ... `chromium.close()`
  -> driver stop (12 tests).
- `storage_chrome` fixture, `:1194-1244`: the same cycle (7 tests).
- `cdp_chromium`, `:1427-1511`: one `sync_playwright()` only to read `executable_path`,
  then a further `sync_playwright()` + `connect_over_cdp()` per `on_page` call.
- `_chromium_installed()` at import, `:219-233`: one more driver cycle.

That is about 22 driver start/stop cycles and 19 Chromium launch/close cycles per run. None
of those lifecycle calls has a timeout: `new_context`, `new_page`, `route`,
`Browser.close()` and the driver stop wait forever (`launch` has Playwright's 180 s
default). When one cycle's step never returns, the test that drew it hangs, so the
location moves from run to run. The browser-login suite pays the same cost in the other
files that use `tests/chromium_page.py:routed_context` per test; this file has the most
cycles (47 tests, 21 of them launching).

### Evidence (2026-11-03, Python 3.14.4, playwright 1.60.0, greenlet 3.5.3, Darwin 27.2)

Run 1 (whole file): `test_a_foreign_storage_token_session_is_cleared_by_one_check[navidrome]`
never finished (test 41/47). The outer `timeout 150` fired before
`faulthandler_timeout=45` could dump.

Run 2 (`-m launches_chrome`, `faulthandler_timeout=25`): hung in
`test_unclear_answers_never_pass[case4]` (8th launching test, a different one). The
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

1. The main greenlet is suspended in a synchronous Playwright call, waiting for an answer
   that the driver never sends. The dispatcher has nothing to read
   (`select`), and the driver process is still alive (its `waitpid` thread has not
   returned). faulthandler cannot show the suspended main greenlet, so the exact call
   is not pinned yet (B1).
2. **No `FakeBroker` thread** (`serve_forever`, started at `:146` and alive for the whole
   test body) is in the dump. So the hang is not in the test body (the broker proof,
   the routed fetch, `page.evaluate`). It is in fixture setup (`sync_playwright`
   start, `launch`, `new_context`, `route`, `new_page`) or teardown (`chromium.close()`,
   `PlaywrightContextManager.__exit__` -> `Connection.stop_sync`
   (`playwright/_impl/_connection.py:316-320`), which waits for the driver to exit
   via `PipeTransport.run` -> `await self._proc.communicate()`
   (`playwright/_impl/_transport.py:137-170`)).
3. Nothing outlived the timed-out runs: no `run-driver`, headless shell or temp-profile
   Chromium was left over afterwards (only the live shared browser on 9222, untouched).

The repo already treats an unbounded Playwright stop as a known hazard: production
`_connect` bounds it with `_stop_playwright_bounded` (`bin/browser.py:5428`). The tests
have no equivalent.

Confidence: **high** that the hang is in the per-test Chromium/driver lifecycle (setup or
teardown) and that its moving location comes from the number of cycles. **Medium** on
which single call it is (`Browser.close()` / driver stop vs. launch-side). B1 pins it
with one instrumented run before B3 commits to a final teardown.

Ruled out: the broker socket (Unix socket in a tmp dir, per test, closed in
`make_broker`); port reuse (only `cdp_chromium` binds a port, and these hangs happened
outside it); `LoginDeadline` / watchdog threads (none in the dump); the shared browser
(`_connect` is patched or not reached in the hung fixtures).

## Design

1. **Pin the call (B1).** One run with Playwright's own logging
   (`DEBUG=pw:api,pw:browser`, `-s` so the driver's stderr reaches the log file), and
   the file-level `faulthandler_timeout`. The last `pw:api` line that shows a start but no
   finish is the stuck call. Only the classification matters: launch-side or close-side.
2. **Never wedge (B2).** `[tool.pytest.ini_options] faulthandler_timeout = 120` in
   `pyproject.toml`, so every future hang dumps stacks. Add a module-local autouse
   watchdog fixture for the launching tests (a `threading.Timer`, 90 s, cancelled in
   teardown). On fire it SIGKILLs this pytest process's own Playwright children (the
   `run-driver` node processes and the Chromium processes whose parent is that driver,
   found with `pgrep -P`, never by name, never the shared browser on 9222-9225). The
   pending sync call then gets `TargetClosedError`, and the test fails with a message
   instead of hanging. A sync Playwright call cannot be moved to another thread
   (greenlet-bound), so the kill is the only bound.
3. **One browser per module, a fresh context per test (B3).** A module-scoped fixture
   `_pw` owns one `sync_playwright()` and one `chromium.launch(headless=True)`.
   `chrome` and `storage_chrome` keep their contracts and monkeypatches but use
   `browser_.new_context()` and close the context in `finally`. Isolation stays the same,
   because cookies, localStorage, routes and service workers are all per context. That
   turns about 19 launch/close cycles into 1, so a rare lifecycle stall becomes about 20x
   less likely per run. Module teardown closes the browser bounded. If B1 showed a
   close-side hang, it kills the Chromium process tree (pid from
   `new_browser_cdp_session().send("SystemInfo.getProcessInfo")`, type `browser`) after
   a 10 s grace, then stops the driver.
4. **Drop the extra driver cycles (B4).** `_chromium_installed()` reuses
   `tests/chromium_page.py:chromium_available` (cached, once per run). `cdp_chromium`
   takes `executable_path` from `_pw` instead of its own `sync_playwright()`. `on_page`
   attaches through `_pw`'s `chromium.connect_over_cdp()` instead of a nested
   `sync_playwright()`. Code under test that calls the real `_connect` (cdp tests) starts
   its own `sync_playwright()` while `_pw` is alive. Verify in B4 that this nesting
   works. If it does not, the two `cdp_chromium` tests move to their own module
   (`tests/test_ws5_client_s2_cdp.py`) with no `_pw`.
5. **Targeted fix (B5)**, chosen by B1:
   - Close-side (`Browser.close` / driver stop): close order is `ctx.close()` -> bounded
     browser close as in 3. In-test `page.close()` calls stay, because they run against a
     live browser.
   - Launch-side (`launch` / `new_context` / `new_page`): pass `timeout=30_000` to
     `launch`, and retry the module-level launch once on `TimeoutError`, killing the
     half-started process tree first.
   - Neither (the log names a call in the test body): stop and report to the overseer
     before changing any test logic.

Out of scope: the same per-test pattern in the other `routed_context` users
(`tests/chromium_page.py`). Note it as a follow-up item if B6's full suite shows a hang
there.

## Boxes

- [ ] B1 Instrumented single run: `DEBUG=pw:api,pw:browser timeout 300 uv run pytest
      tests/test_ws5_client_s2.py -x -s -m launches_chrome -p no:cacheprovider -o
      faulthandler_timeout=60 > /tmp/ws5-b1.log 2>&1`. Record the stuck Playwright call,
      launch-side or close-side, in this plan's Root cause section (overseer edits the
      plan). One run; if it does not hang, note it and continue with B2-B4 (they do not
      depend on the result).
- [ ] B2 `pyproject.toml`: `[tool.pytest.ini_options] faulthandler_timeout = 120`. Add a
      module-local watchdog fixture in `tests/test_ws5_client_s2.py` (90 s, kills only this
      process's Playwright child tree via `pgrep -P`, cancelled in teardown, test fails
      with "Playwright lifecycle hung in <phase>").
- [ ] B3 Module-scoped `_pw` fixture (one driver, one headless Chromium). Port `chrome` and
      `storage_chrome` to a fresh context per test, closed in `finally`. Bounded module
      teardown.
- [ ] B4 `_chromium_installed` -> `chromium_page.chromium_available`. `cdp_chromium`
      reuses `_pw` for `executable_path` and `connect_over_cdp`. Check that a nested
      `_connect` works; if not, split the cdp tests into
      `tests/test_ws5_client_s2_cdp.py`.
- [ ] B5 Targeted fix per B1's classification (Design 5).
- [ ] B6 Verification below is green. Lint is clean.

## Verification

```
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff format --check /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws5_client_s2.py
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff check /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws5_client_s2.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run --project /Users/albert/obsidian/42-Git/home/browser-login pylint /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws5_client_s2.py
cd /Users/albert/obsidian/42-Git/home/browser-login && timeout 300 uv run --project /Users/albert/obsidian/42-Git/home/browser-login pytest -v -p no:cacheprovider /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws5_client_s2.py
```

Each line is `cd <repo> && <argv>` (tp verify grammar). Notes the block cannot express:

- The pytest line runs twice at most (no repeat loops): 47 passed both times, wall time
  recorded (expected well under the old per-test-launch time).
- Watchdog proof (one targeted test, no load): a throwaway test whose fixture
  monkeypatches `chromium.close` to `time.sleep(10**6)` fails within about 90 s with the
  watchdog message, and the session continues. Delete it after the check.
- `pgrep -fl run-driver` after the runs: no leftover driver, and no Chromium outside the
  live instances.
- Full suite once: `timeout 1800 nice -n 15 uv run pytest -q -p no:cacheprovider` reaches
  its summary line. Report any other file that hangs as a follow-up item.
- `git diff --stat` touches only `tests/test_ws5_client_s2.py`, `pyproject.toml` (and
  `tests/test_ws5_client_s2_cdp.py` if B4 split it).
