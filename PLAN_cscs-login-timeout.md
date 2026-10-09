# Plan: tp#843 — bound `browser.py login cscs` so it cannot hang after the broker said "login ok"

## Session

Resume: `c --resume 7d725bed-5c4e-4909-82fc-dd9a58934d10`

## Context

**Problem.** 2026-10-08 16:06: `browser.py login cscs` (pid 98267, the agent-login `-c` run)
got the broker's "login ok" at 16:06:50, then stalled; it was killed after ~11.5 min
(`li` log: `cscs: NOT logged in (browser.py login exit -15)`). Nothing bounds it at either
level: inside browser.py the sync Playwright calls `page.evaluate`, `page.close`,
`CDPSession.send`, `browser.close`, `pw.stop` take no timeout; in the runner
`agent-login.py ensure_logged_in`/`run_test` and `agent_login_jobs._browser` call
`subprocess.run` with no timeout. While hung it held the interaction lease
(`_broker_write_storage` runs inside `_interaction_lease`) and the gate shared — every
`switch`/`down`/other interactive login blocked for the whole stall.

**Evidence (journal `~/.cache/claude-browser/journal.jsonl`).** pid 98267 registered 5
times (one per `_connect`): 43.713/44.380 (`_broker_logged_in` pre-check), 45.952 (cookie
injection + broker request), 50.303/50.667 (`_broker_write_storage` →
`_background_page_run`: createTarget, then adopt). No 6th attach (verify probe), no
unregister, no `login phase=end` → the stall is in **phase 2 of `_background_page_run`
during the storage write**. The storage tab sat on the Keycloak form ⇒ `add_init_script` +
`goto` ran and the portal SPA then redirected to Keycloak ⇒ the hang is after `goto`. The
second Keycloak tab is the one `logged-in cscs` (pid 97907, `cmd_token`) reused via
`_pick_page` at 16:06:41 (tp#845).

**Root-cause hypotheses, ranked:**

1. ~50 % — unbounded `page.evaluate(_BROKER_STORAGE_CHECK_JS)` in `verify` racing the SPA's
   portal → auth.cscs.ch redirect; Playwright awaited an execution context that never
   settled (`evaluate` has no timeout parameter).
2. ~30 % — unbounded `page.close()` in `_background_page_run`'s `finally` awaiting a close
   ack while the tab navigates (fits "tab still open").
3. ~10 % — `browser.close()`/`pw.stop()` teardown hang after a suppressed close error.
4. ~5 % — `wait_for_load_state` ignoring its 10 s timeout.

Ruled out: `_switch_page_by_target`'s `CDPSession.send` (the tab would still be on
`about:blank`). Why the injected session bounced to Keycloak at all is a separate,
intermittent issue, not this ticket. A retry with a 240 s outer timeout succeeded in 65 s.

**Chosen design — two layers.**

- **Inner (browser.py):** a hard wall-clock deadline on a timer thread, the same pattern
  as `cmd_eval`'s `_eval_watchdog_fire`, because sync Playwright calls cannot be
  cancelled. It is the only layer that knows this process's owned target ids, so it can
  close them over raw CDP (`_cdp_close_target`), journal the exact step, and `os._exit`.
  Flocks (registry/gate/lease) die with the process; `_registry_live_clients` reaps the
  leftover file (`test_eval_watchdog_exits_at_its_deadline_while_the_attach_is_stuck`
  proves it).
- **Outer (runner):** a per-site `subprocess` timeout in the runner — last resort for
  hangs the inner layer cannot see (stuck interpreter, a hang outside the armed scope).

**Exit code 124** (the GNU `timeout` convention), new `LOGIN_TIMEOUT_RC`:

- not 75 — 75 means a guided login owns the browser; callers skip it and never mail, so a
  recurring hang would go silent;
- not 4 — that would wrongly send Albert to `-g`;
- not 2 — indistinguishable from "not logged in".

124 lets the runner retry once (the evidence says retries succeed) and lets the failure
mail say "timed out". The deadline is armed **only for the broker (and Safari) flows**:
assisted/guided logins wait for a human and stay unbounded.

**Why Verification runs tests, mypy and pylint:** the change touches the exit path, a
thread and cleanup ordering, which can only be exercised safely with fakes (never the
live 9222 browser, no real Chrome); mypy/pylint are this repo's documented gates
(AGENTS.md).

## Steps

- [ ] **0. Worktree.** All work in a git worktree — AGENTS.md forbids editing
      `bin/browser.py` in place while consumers exec it.
- [ ] **1. Constants in `bin/browser.py`** next to `EVAL_TIMEOUT_S`/`CONNECT_TIMEOUT_S`.
      Generalise `_connect_timeout_s` into `_positive_seconds(raw, default)` and keep the
      old name as a thin alias (the `test_connect_hang` env test still passes).
  - `LOGIN_TIMEOUT_S = _positive_seconds($CLAUDE_BROWSER_LOGIN_TIMEOUT_S, 300)` —
    `BROKER_TIMEOUT_S` (180 s) is the longest legitimate single wait; pre-check + storage
    write + verify + token add tens of seconds in practice; ≈ 4.6× the observed 65 s.
  - `BG_PAGE_STEP_S = 45` — goto 15 + load 10 + `cscs_portal_ready` 8 + one evaluate +
    5 s raw close ≈ 40 s.
  - `LOGIN_TIMEOUT_RC = 124`, with a comment line next to `BUSY_RC`/`NEEDS_ALBERT_RC` and
    in the broker exit-code comment block (~l. 8707).
- [ ] **2. Owned-target registry + step breadcrumbs.**
  - Module-level `_OWNED_TIDS: set[str]` and `_STEP: list[str]` (last step label).
  - Helper `_step(label)`, called before each Playwright call:
    - `_background_page_run`: `bg:adopt`, `bg:prepare`, `bg:goto`, `bg:load`, `bg:fn`,
      `bg:close`, `bg:teardown`;
    - `_broker_login`: `broker:request`, `broker:cookies`, `broker:storage`,
      `broker:verify`, `broker:after`;
    - `cmd_token`: `token:pick`, `token:goto`, `token:scan`.
  - This is the root-cause instrument for the next occurrence: the journal names the call
    that hung.
- [ ] **3. `_deadline(seconds, scope)` context manager** — a stack of daemon
      `threading.Timer`s, cancelled on exit; nested use allowed (step deadline inside the
      login deadline). On fire, `_deadline_fire(scope, seconds)` runs on the timer thread,
      never raises, and does in order:
  1. stderr: `❌ {cmd} {site}: no progress after {s:g}s in step {step} (a Playwright call
     never returned) — owned tabs closed; retry: browser.py login {site}`;
  2. close every id in `_OWNED_TIDS` via `_close_owned_targets`, extended with a
     `journal_event` kwarg (default `"maintenance"`) that logs `watchdog` here. Raw CDP:
     `/json/list` + `_cdp_close_target` (3 s each); keeps the never-close-the-last-page
     keep-alive; never touches a tab it does not own (the reused `cmd_token` tab stays);
  3. journal `watchdog` with `command`, `site`, `scope`, `step`, `timeout_s`,
     `elapsed_ms`, `owned`, `closed`;
  4. login commands also journal `login phase=end result=124 reason=timeout
     duration_ms=…` (`_journaled_dispatch`'s `finally` does not run after `os._exit`);
  5. flush, then `_hard_exit(LOGIN_TIMEOUT_RC)` — a thin `os._exit` wrapper tests can
     patch.

  Cleanup is capped at ~10 s overall (`_close_owned_targets` gets the remaining budget).
- [ ] **4. Arm in `cmd_login`.** Wrap `site.login(port)` in
      `with _deadline(LOGIN_TIMEOUT_S, "login")` only when `is_broker` (or
      `_safari_login`). Builtin/assisted/guided flows stay unarmed; comment the reason.
- [ ] **5. Harden `_background_page_run`.**
  - After `Target.createTarget` returns `tid`: `_OWNED_TIDS.add(tid)` (phase 1 already
    holds it).
  - Wrap phase 2 (after the second `_connect`) in `_deadline(BG_PAGE_STEP_S,
    "background_page")`.
  - In `finally`, replace `page.close()`/`_switch_close_target` (unbounded Playwright CDP)
    with `_cdp_close_target(port, tid, 5.0)` by owned id; discard `tid` from
    `_OWNED_TIDS` only on success.
  - Keep `browser.close()`/`pw.stop()` (covered by the step deadline).

  This kills hypothesis 2 and bounds 1/3/4 to 45 s instead of forever. The `logged-in`
  probes share the helper and get the same bound.
- [ ] **6. Runner — `agent_login_jobs.py`.**
  - `TIMEOUT_RC = 124`; `LOGIN_RUN_TIMEOUT_S = 360` (inner 300 + 60 for venv bootstrap,
    interpreter start and the ≤ 10 s watchdog cleanup); `CHECK_RUN_TIMEOUT_S = 150`
    (`logged-in`: 2 attaches ≤ 60 + 45 s step + slack).
  - `run_browser(args, *, timeout_s, capture=False) -> tuple[int, str]` catches
    `subprocess.TimeoutExpired` (`subprocess.run` then SIGKILLs browser.py only;
    `_security_run` children live in their own session and are never touched — tp#504
    rule) and maps it to `TIMEOUT_RC`.
  - `_browser()` gains `timeout_s` (default `CHECK_RUN_TIMEOUT_S`).
- [ ] **7. Runner — `agent-login.py`.**
  - `ensure_logged_in`: `login` via `run_browser(..., LOGIN_RUN_TIMEOUT_S, capture=True)`;
    on 124 run `login` once more (one retry, then stop), then the positive check. Failure
    text: `NOT logged in (browser.py login timed out after 300s, retried once)`.
  - `run_test`: same bound, same 124 wording, no retry.
  - 124 is **never** `BUSY_RC`. `assisted_login` (`-g`, human at the keyboard) stays
    unbounded.
- [ ] **8. Docs.** README exit table row `124 | timed out: a step never returned; owned
      tabs closed; retry later (agent-login retries once)`. AGENTS.md one-line bullet next
      to tp#693: "an unattended login is bounded (tp#843): `_deadline` + raw-CDP close of
      owned targets + exit 124; never arm it for a human-waiting flow".
- [ ] **9. Tests — new `tests/test_login_timeout.py`.** No Chrome: fake pw/browser/page,
      `_hard_exit` patched, journal at `CLAUDE_BROWSER_JOURNAL_FILE` in `tmp_path`.
  - a) `_background_page_run` with a fake page whose `evaluate` blocks on an Event the
    patched `_hard_exit` sets; `BG_PAGE_STEP_S=0.2` → exit 124 within 2 s;
    `_cdp_close_target` (faked) called with the owned tid; journal `watchdog` with
    `step == "bg:fn"` and `login end result=124`.
  - b) Normal path closes by tid over raw CDP: no `page.close()` call; `_OWNED_TIDS` empty
    afterwards.
  - c) `cmd_login` arms the deadline for a broker site, not for a builtin/assisted site
    (spy on `_deadline`).
  - d) Fire with no owned tabs and the browser down → no exception, still 124.
  - e) Subprocess (`python -I` loading browser.py) arms `_deadline(0.5, "login")` and
    blocks → rc 124, journal lines, `_registry_live_clients()` reaps the registration
    (the real `os._exit` path, as test_connect_hang's eval-watchdog test).
  - f) `CLAUDE_BROWSER_LOGIN_TIMEOUT_S` parsing: invalid/≤0/NaN → 300.
- [ ] **10. Tests — extend `tests/test_agent_login.py`** with fake `subprocess.run`s
      raising `TimeoutExpired`:
  - `timeout=` passed for `login` (360) and `logged-in` (150);
  - a timeout is retried exactly once, then reported "timed out" (not busy);
  - 124 then a passing check → logged in;
  - `run_test` maps a timeout to 124.
- [ ] **11. Deploy.** Merge the worktree; `browser.py -h`; one real `./agent-login.py -t
      cscs`; read `browser.py journal` for the step breadcrumbs.
- [ ] **12. Out of scope (separate tp items):** `cmd_token` still picks tabs by URL
      (`_pick_page` — tp#845); the intermittent Keycloak bounce after injecting the bundle
      is still unexplained.

## Verification

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff format --check bin/ tests/ agent-login.py agent_login_jobs.py && ruff check bin/ tests/ agent-login.py agent_login_jobs.py
cd /Users/albert/obsidian/42-Git/home/browser-login && mypy bin/browser.py && uv run pylint bin/browser.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests/test_login_timeout.py tests/test_agent_login.py tests/test_connect_hang.py tests/test_broker_spa_and_switch_eduid.py tests/test_journal.py tests/test_login_broker.py
cd /Users/albert/obsidian/42-Git/home/browser-login && bin/browser.py -h
```
