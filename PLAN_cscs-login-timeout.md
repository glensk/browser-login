# Plan: tp#843 — bound every unattended `browser.py login` (CSCS first) so it cannot hang after the broker said "login ok"

## Session

Resume: `c --resume 7d725bed-5c4e-4909-82fc-dd9a58934d10`

## Context

**Problem.** 2026-10-08 16:06: `browser.py login cscs` (pid 98267, the agent-login `-c`
run) got the broker's "login ok" at 16:06:50, then stalled; it was killed after ~11.5 min
(`li` log: `cscs: NOT logged in (browser.py login exit -15)`). Nothing bounds it at either
level:

- **Inside browser.py:** the sync Playwright calls `page.evaluate`, `page.close`,
  `CDPSession.send`, `browser.close`, `pw.stop` take no timeout. `_broker_request` resets
  its socket timeout on every `recv`, so a broker that dribbles data stretches it without
  limit.
- **In the runner:** `agent-login.py` (`ensure_logged_in`, `run_test`),
  `agent_login_jobs.py` (`_browser`, `browser_mode`) and `agent_login_claude.py` call
  `subprocess.run` with no timeout.
- **Side effects while hung:** it held the interaction lease (`_broker_write_storage`
  runs inside `_interaction_lease`) and the gate shared, so `switch`, `down` and every
  other interactive login were blocked for 11.5 min.

**Evidence (journal `~/.cache/claude-browser/journal.jsonl`).** pid 98267 registered 5
times (one per `_connect`):

- 43.713 / 44.380 — `_broker_logged_in` pre-check;
- 45.952 — cookie injection + broker request;
- 50.303 / 50.667 — `_broker_write_storage` → `_background_page_run` (createTarget,
  then adopt).

No 6th attach (verify probe), no unregister, no `login phase=end` ⇒ the stall is in
**phase 2 of `_background_page_run` during the storage write**. The storage tab sat on
the Keycloak form ⇒ `add_init_script` + `goto` ran and the portal SPA redirected ⇒ the hang
is after `goto`. The second Keycloak tab is `logged-in cscs` (pid 97907, `cmd_token`),
reused via `_pick_page` at 16:06:41 (tp#845).

**Root-cause hypotheses, ranked:**

1. ~50 % — unbounded `page.evaluate` in `verify` racing the SPA's portal → auth.cscs.ch
   redirect; Playwright awaited an execution context that never settled.
2. ~30 % — unbounded `page.close()` in `_background_page_run`'s `finally` awaiting a close
   ack while the tab navigates (fits "tab still open").
3. ~10 % — `browser.close()`/`pw.stop()` hang after a suppressed close error.
4. ~5 % — `wait_for_load_state` ignoring its 10 s timeout.

Ruled out: `_switch_page_by_target` (the tab would still be on `about:blank`). The
Keycloak bounce itself is separate and intermittent; a retry with a 240 s outer timeout
succeeded in 65 s. The step breadcrumbs below name the call that hangs next time.

**Chosen design — two layers.**

- **Inner (browser.py):** a command-scoped `LoginDeadline` with a watcher thread that
  hard-exits (same idea as `_eval_watchdog_fire`; sync Playwright calls cannot be
  cancelled).
  - Armed at the **top** of `cmd_login`, before `_resolve_site` (which already calls the
    broker), for **every** `login`/`cscs-login`.
  - Exception: a process carrying a live guided-maintenance owner nonce
    (`_maint_owner()`). Guided children inherit `$CLAUDE_BROWSER_MAINTENANCE` from
    `_maintenance`/`guided_window`, so a human-waiting flow (e.g. the 5-min SWITCH wait)
    is never bounded.
  - Unattended builtin flows already return `NEEDS_ALBERT_RC` instead of waiting for a
    human (tp#836), so bounding them is safe. Arming follows maintenance ownership, not
    the kind of site.
  - Only this layer knows the process's owned target ids: it closes them over raw CDP
    under one cleanup budget, confirms by re-listing, journals, and exits.
- **Outer (runner):** a per-call subprocess timeout derived from the **same** env var
  (inner + 90 s) — the last resort when the inner layer itself fails. An outer kill is
  reported as its own status (never 124) and is never retried.

**Exit codes.**

- **124 `LOGIN_TIMEOUT_RC`** — timed out, every owned tab confirmed closed.
- **125 `LOGIN_TIMEOUT_DIRTY_RC`** — timed out, owned-tab cleanup not confirmed.
- Not 75 — 75 means a guided login owns the browser; callers skip it and never mail, so a
  recurring hang would go silent. Not 4 — that would wrongly send Albert to `-g`. Not 2 —
  indistinguishable from "not logged in".
- The runner retries only after a 124, and only once a bounded `logged-in` check fails.

**Why Verification runs tests, mypy, pylint:** the change adds a thread, a hard-exit
path, lock ordering and cleanup budgets, exercisable safely only with fakes (fake CDP
server, fake broker socket, `CLAUDE_BROWSER_TEST_NO_LAUNCH` — never the live 9222
browser, never a real Chrome). mypy/pylint are this repo's documented gates (AGENTS.md);
`test_guided_login.py` runs because `_close_owned_targets` gains a budget.

## Steps

- [x] **0. Worktree.** All work in a git worktree — AGENTS.md forbids editing
      `bin/browser.py` in place while consumers exec it.
- [x] **1. Constants (`bin/browser.py`).**
  - Generalise `_connect_timeout_s` into `_positive_seconds(raw, default)` (finite > 0,
    else the default); keep the old name as an alias.
  - `LOGIN_TIMEOUT_S = _positive_seconds($CLAUDE_BROWSER_LOGIN_TIMEOUT_S, 300)` —
    `BROKER_TIMEOUT_S` (180 s) is the longest legitimate single wait; ≈ 4.6× the observed
    65 s.
  - `LOGGED_IN_TIMEOUT_S = 120` (2 attaches + one background page).
  - `BG_PAGE_STEP_S = CONNECT_TIMEOUT_S + 60` (= 90): raw create 5 + attach ≤ 30 + goto 15
    - load 10 + fn ≈ 10 + raw close 5, rounded up.
  - `DEADLINE_CLEANUP_S = 15`.
  - `LOGIN_TIMEOUT_RC = 124`, `LOGIN_TIMEOUT_DIRTY_RC = 125`, commented next to
    `BUSY_RC`/`NEEDS_ALBERT_RC` and in the broker exit-code block (~l. 8707).
- [x] **2. `class LoginDeadline`** — command-scoped; no module-level mutable sets.
  - Fields: `lock`, `armed`, `generation`, `firing`, `port`, `cmd`, `site`, `t0`,
    `owned: set[str]`, `step: str`, and a stack of absolute deadlines (overall + nested
    steps).
  - Methods:
    - `add_owned(tid)` / `drop_owned(tid)` under the lock; each also journals
      `owned_target op=add|close tid=…`, so an outer kill leaves a trace;
    - `step_to(label)`;
    - `push(seconds, scope)` / `pop()` as a context manager for step deadlines.
  - **One daemon watcher thread** polling every 0.25 s — no `Timer` objects to cancel.
    Under the lock it checks `armed`, a matching `generation` and
    `now >= min(deadlines)`, sets `firing = True` and snapshots `owned`; only then does it
    run the fire procedure (step 3).
  - `disarm()`: under the lock, `armed = False`, `generation += 1`. If `firing` is
    already set, the main thread waits on an Event (the fire decided first and will exit).
    After `disarm()` returns, a hard exit is impossible.
  - One accessor, `_active_deadline()`, lets helpers deep in the call stack
    (`_background_page_run`, `_broker_login`, `cmd_token`) call `step_to`/`add_owned`;
    without an active instance they are no-ops.
- [x] **3. Fire procedure** (watcher thread, never raises):
  1. stderr: `❌ {cmd} {site}: no progress after {s:g}s in step {step} (a Playwright call
     never returned)`;
  2. `_close_owned_targets(port, snapshot, budget_s=DEADLINE_CLEANUP_S,
     journal_event="watchdog")` (step 5);
  3. journal `watchdog` with `command`, `site`, `scope`, `step`, `timeout_s`,
     `elapsed_ms`, `owned`, `closed`, `confirmed`;
  4. journal `login phase=end result=124|125 reason=timeout duration_ms=…`
     (`_journaled_dispatch`'s `finally` does not run after `os._exit`);
  5. flush, then `_hard_exit(124 if confirmed else 125)` — a thin `os._exit` wrapper
     tests can patch.

  Registry/gate/lease flocks die with the process; `_registry_live_clients` reaps the
  leftover file.
- [x] **4. Arm in `cmd_login` and `cmd_logged_in`.**
  - `cmd_login`, at the very top (before the Safari check and `_resolve_site`):
    `with _login_deadline(port, "login", site_name, LOGIN_TIMEOUT_S)` unless
    `_maint_owner()`.
  - Its `finally` (success, failure, exception): `disarm()`, then a command-scope final
    cleanup of any still-owned ids (`_close_owned_targets(..., budget_s=
    DEADLINE_CLEANUP_S)`), with a ⚠ line if any remain.
  - `cmd_logged_in`: the same with `LOGGED_IN_TIMEOUT_S` — bounds `cmd_token`'s unbounded
    `_scan_token` evaluate on `logged-in cscs`.
  - `login-cscs-assisted` and `assisted-login` are human-only (they need a TTY) and stay
    unarmed; comment the reason.
- [x] **5. `_close_owned_targets(port, ids, *, budget_s=30.0,
      journal_event="maintenance")` — budgeted and confirming.**
  - One monotonic deadline; each `_cdp_get`/`_cdp_close_target` gets `min(3.0, left)`.
  - Keeps the keep-alive rule (never close the last page).
  - After closing, **re-list `/json/list`**; return `(gone, confirmed)`, where
    `confirmed` = no owned id still listed.
  - Update the maintenance callers (~l. 10103, 10148, 10401, 10565) to keep their old
    behaviour with an explicit budget.
- [x] **6. Harden `_background_page_run`.**
  - **Phase 1 (create):** resolve `_browser_ws_url(port)`, then
    `_cdp_create_background_target(ws_url, start, 5.0)` (raw CDP, bounded), replacing the
    Playwright `new_browser_cdp_session().send(...)` and the first `_connect` entirely;
    `add_owned(tid)` **immediately**.
  - The **whole helper** runs inside `push(BG_PAGE_STEP_S, "background_page")`: attach,
    `_switch_page_by_target`, prepare, goto, load, fn, teardown.
  - Breadcrumbs: `step_to("bg:create" | "bg:adopt" | "bg:prepare" | "bg:goto" |
    "bg:load" | "bg:fn" | "bg:close" | "bg:teardown")`.
  - `finally`: close by owned id with `_cdp_close_target(port, tid, 5.0)` (replaces
    `page.close()`/`_switch_close_target`); `drop_owned(tid)` only once a re-list confirms
    it gone, otherwise it stays owned for step 4's command-scope cleanup.
- [x] **7. Breadcrumbs.** `_broker_login`: `broker:precheck`, `broker:request`,
      `broker:cookies`, `broker:storage`, `broker:verify`, `broker:after`. `cmd_token`:
      `token:pick`, `token:goto`, `token:scan`. `_resolve_site`: `resolve`.
- [x] **8. One monotonic deadline in `_broker_request`:**
      `deadline = monotonic() + timeout`; before connect, send and every `recv`,
      `sock.settimeout(max(0.01, deadline - now))`; when exhausted, raise
      `BrokerUnavailable("login broker did not answer within {timeout:g}s")`. Also covers
      `_broker_sites` (60 s).
- [x] **9. Runner helper (`agent_login_jobs.py`).**
  - `@dataclass BrowserRun(rc: int | None, killed: bool, stdout: str, elapsed_s: float)`.
  - `run_browser(*args, timeout_s: float | None, capture: bool = False,
    quiet: bool = False) -> BrowserRun` — `timeout_s` is **required, keyword-only, no
    default**; `None` = no timeout, allowed only for human-guided calls.
  - On `subprocess.TimeoutExpired` (`subprocess.run` SIGKILLs browser.py only;
    `_security_run` children live in their own session and are untouched — tp#504) →
    `killed=True, rc=None`.
  - `_browser(*args, quiet=False, timeout_s)` (also required) returns `run.rc`, or
    `KILLED_RC = -9` after an outer kill (never `BUSY_RC`).
  - Budgets, from `browser_timeout(cmd)`:
    - `login` = `_positive_seconds(env CLAUDE_BROWSER_LOGIN_TIMEOUT_S, 300) + 90` (parser
      duplicated, with a parity test against browser.py's; the 90 s margin covers
      interpreter start, venv bootstrap, the 15 s cleanup and slack);
    - `logged-in` = 120 + 90 = 210;
    - `status` = 30; `up`/`switch` = 120; `down`/`open` = 60; `eval -t 30` = 60.
  - `browser_mode()` → `run_browser("status", timeout_s=30, capture=True)`; a killed run
    counts as down/unknown (None).
- [x] **10. Route every call site explicitly.**
  - **Unattended (bounded):**
    - `agent-login.py`: `ensure_logged_in` (`logged-in`/`login`), `run_test`
      (`login`/`logged-in`), `_assisted_check`/`_claude_check` (`logged-in`),
      `ensure_browser_up` (`status`/`up`);
    - `agent_login_claude.py`: `up`/`down`/`open`/`eval`;
    - `agent_login_jobs.py`: `hide_window` (`switch headless`) and `guided_window`'s
      `switch headed`.
  - **Human-guided (`timeout_s=None`):** the `_browser("login", browser_site(site))`
    inside `guided_window` (agent-login.py ~l. 848) and the `assisted-login` argv runner
    (~l. 751).
  - Replace the raw `subprocess.run([... BROWSER_PY ...])` calls (agent-login.py ~l. 677,
    683, 873; agent_login_claude.py ~l. 71) with `run_browser`.
- [x] **11. Retry/reporting (`ensure_logged_in`, `run_test`).**
  - **124:** run the bounded `logged-in`; if it passes → `logged in (after an inner
    timeout)`; else `ensure_logged_in` retries `login` **once**, `run_test` does not.
  - **125 (dirty):** no retry; report `NOT logged in (browser.py login timed out after
    Ns; owned tabs may remain — see browser.py journal, event owned_target)`.
  - **Outer kill:** no retry; report `… killed by the runner after Ns (inner watchdog
    failed)`.
  - Both go into the failure mail.
  - Worst case 2 × (inner + cleanup) + 2 × check ≈ 17 min — bounded and journaled,
    unlike the old unbounded hang. 124/125 are never `BUSY_RC`.
- [x] **12. Docs.**
  - README exit table: `124 | timed out; owned tabs closed; retried once by agent-login`
    and `125 | timed out; tab cleanup unconfirmed; not retried`.
  - README env list (~l. 107): `CLAUDE_BROWSER_LOGIN_TIMEOUT_S` — default 300, finite
    > 0; runner timeout = value + 90; never applied to a guided login.
  - `.env.example`: the same variable under "shared browser", same wording.
  - AGENTS.md bullet next to tp#693: "every unattended `login`/`logged-in` runs under a
    `LoginDeadline` (tp#843): armed unless the process owns a live maintenance record;
    raw-CDP create/close of owned targets; exit 124/125; runner calls pass an explicit
    `timeout_s` (None only for guided calls)".
- [x] **13. Tests — new `tests/test_login_timeout.py`** (no Chrome, ever).
  - a) In-process `_background_page_run`, a fake attach whose `evaluate` blocks,
    `BG_PAGE_STEP_S=0.3`, `_hard_exit` patched → 124 within 2 s; the fake
    `_cdp_close_target` called with the owned tid; journal `watchdog step=bg:fn` and
    `login end result=124`.
  - b) Phase-1 hang: the fake raw create stalls past the budget → no target leaks, fires
    on `bg:create`.
  - c) Raw close fails and the re-list still shows the tid → **125**, `confirmed=false`.
  - d) Normal path: tid closed by raw CDP, no `page.close()`, owned set empty; a failed
    close on the normal path is retried by the `cmd_login` `finally` cleanup.
  - e) Race: `disarm()` concurrent with expiry, 200 iterations → `_hard_exit` never
    called after `disarm()` returned.
  - f) Arming: `login switch`, `login cscs`, a builtin and a broker site are armed without
    a nonce; with `$CLAUDE_BROWSER_MAINTENANCE` matching a live fake record none is;
    `login-cscs-assisted` never is.
  - g) `_broker_request` against a fake Unix-socket broker dribbling 1 byte/s →
    `BrokerUnavailable` within timeout + 1 s; the deadline is armed before
    `_resolve_site` (a stalled `sites` exits 124 at the login deadline).
  - h) Fake-CDP CLI subprocess (FakeCdp moved from `test_connect_hang.py` to a shared
    `tests/fake_cdp.py`; `LOGIN_BROKER_SOCKET` → a fake broker whose `sites` lists an
    https check URL): the real `browser.py login fakesite` registers and creates a target
    on the fake, which is marked silent so the attach stalls;
    `CLAUDE_BROWSER_CONNECT_TIMEOUT_S=60`, `CLAUDE_BROWSER_LOGIN_TIMEOUT_S=3` → rc 124
    within 3 + 15 + 10 s; the fake recorded `Target.closeTarget` for that tid and no
    longer lists it; `_registry_live_clients() == []`; the gate and `INTERACTION_LOCK`
    flock exclusively without blocking.
  - i) A subprocess holding `_interaction_lease` + a registration arms
    `LoginDeadline(0.5)` and blocks → rc 124, lease and gate free, registration reaped.
  - j) Env parsing: invalid/≤ 0/NaN/inf → 300; parity between browser.py's and
    agent_login_jobs's parser.
- [x] **14. Tests — extend `tests/test_agent_login.py`.**
  - AST: parse agent-login.py, agent_login_jobs.py, agent_login_claude.py — every
    `subprocess.run`/`Popen` whose argv references `BROWSER_PY` sits inside
    `run_browser`; every `_browser(...)`/`run_browser(...)` call passes `timeout_s=`
    explicitly; only the two guided call sites of step 10 pass `None`.
  - Budgets: env 600 → login timeout 690; default 390; `logged-in` 210; `status` 30.
  - Status handling: `TimeoutExpired` → `killed`, no retry, "killed by the runner"
    wording; 124 + failing check → exactly one retry; 124 + passing check → logged in, no
    retry; 125 → no retry; `browser_mode()` returns None when killed.
- [ ] **15. Deploy.** Merge the worktree; `browser.py -h`; one real `./agent-login.py -t
      cscs`; read `browser.py journal` for the `step` breadcrumbs.
- [ ] **16. Out of scope (separate tp items):** `cmd_token`'s URL-based tab pick
      (`_pick_page` — tp#845); the intermittent Keycloak bounce after injecting the bundle
      is still unexplained.

## Implementation notes (steps 0–14, deviations from the text above)

- Step 1: `_positive_seconds` already names the argparse type, so the env
  parser is `_env_seconds(raw, default)` (`_connect_timeout_s` stays as an
  alias); the runner's copy is `agent_login_jobs.env_seconds` (written
  differently on purpose — pylint's duplicate-code — parity pinned by a
  hypothesis test).
- Step 6: phase 1 still registers a client (`_registry_register`, plus
  `_ensure_page_target`) BEFORE the raw create, like `open -N`: the dropped
  first `_connect` was also the registration that makes a guided login's
  record refuse us before we touch its browser. The close goes through
  `_close_owned_targets(port, [tid], budget_s=5.0, journal_event=None)`
  (raw `_cdp_close_target` + keep-alive rule + confirming re-list).
  Playwright detaches (`bg:teardown`) before the raw close (`bg:close`).
  The attached part is its own helper, `_background_page_attached`.
- Step 5: `journal_event=None` = no journal line; an unreachable browser whose
  port refuses connections is down (every id gone, confirmed — the old
  behaviour), any other failure is unconfirmed. Maintenance callers pass
  `MAINT_CLOSE_BUDGET_S = 30`.
- Step 7: every `step_to` is journaled as a `login_step` event (step 15 reads
  the breadcrumbs from the journal).
- Step 10: `assisted_login_argv` returns only the browser.py arguments, so
  `assisted_login_cmd` runs through `_browser(..., timeout_s=None)`.
- Step 14: the AST rule is per function — any function that spawns a
  subprocess and names `BROWSER_PY` must be `run_browser`.
- Step 13h: the target is not marked silent — `FakeCdp` never answers
  page-session commands, so every Playwright attach stalls anyway.
  `FakeCdp` gained a `create_stall` knob (13b).
- Incidental: `tests/test_login_viewer.py::_record` now writes atomically — the
  relay polls the record from a worker thread, and a read between
  `write_text`'s truncate and write made the success test flaky.

## Debate

Codex (gpt-5.6-sol) round 1, 11 objections, all accepted; the judge converged.

- **O1:** `timeout_s` is a required keyword with no default; only the two guided call
  sites pass `None`; the AST test enforces it (steps 9, 10, 14).
- **O2:** arming is keyed to `_maint_owner()`, not the kind of site — switch, cscs,
  builtin and broker logins are all armed, guided children never (steps 4, 13f).
- **O3:** armed before `_resolve_site`; one monotonic deadline in `_broker_request`; a
  dribbling-broker test (steps 4, 8, 13g).
- **O4:** the outer timeout derives from the same env var + a 90 s margin covering the
  15 s cleanup; env 600 → 690; the inner deadline covers the whole command (steps 1, 9,
  14).
- **O5:** phase 1 uses the bounded raw-CDP `_cdp_create_background_target`; the tid is
  owned immediately; the step deadline covers the whole helper incl. teardown (steps 6,
  13b).
- **O6:** `_close_owned_targets` has one aggregate budget and re-lists to confirm; a
  `finally` cleanup runs on success, failure and timeout; unconfirmed → 125 (steps 3, 4,
  5, 13c, 13d).
- **O7:** a command-scoped `LoginDeadline` (lock, generation, `firing`) replaces the
  globals; no `Timer`-cancel races; a 200-iteration race test (steps 2, 13e).
- **O8:** `BrowserRun` separates inner 124/125 from an outer kill; retry only after 124 +
  a failed bounded check; a kill or 125 is never retried; worst case bounded ≈ 17 min
  (steps 9, 11).
- **O9:** `browser_mode()`, `ensure_browser_up` and the `agent_login_claude.py` calls go
  through `run_browser`; the AST test enforces it (steps 9, 10, 14).
- **O10:** a fake-CDP CLI test with a registered client and a real target proves 124,
  target closed, registry reaped, gate and lease free; plus phase-1, failed-close, race
  and guided tests (step 13).
- **O11:** `CLAUDE_BROWSER_LOGIN_TIMEOUT_S` (default, valid range, runner = value + 90)
  documented in the README env list and `.env.example`, plus the exit-table rows
  (step 12).

## Verification

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff format --check bin/ tests/ agent-login.py agent_login_jobs.py agent_login_claude.py && ruff check bin/ tests/ agent-login.py agent_login_jobs.py agent_login_claude.py
cd /Users/albert/obsidian/42-Git/home/browser-login && mypy bin/browser.py && uv run pylint bin/browser.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests/test_login_timeout.py tests/test_agent_login.py tests/test_connect_hang.py tests/test_guided_login.py tests/test_broker_spa_and_switch_eduid.py tests/test_login_broker.py tests/test_journal.py
cd /Users/albert/obsidian/42-Git/home/browser-login && bin/browser.py -h
```
