# Plan: tp#845 — logged-in checks and logins use only tabs they own (target id), never a tab picked by URL

## Session

Resume: `c --resume 7d725bed-5c4e-4909-82fc-dd9a58934d10`

## Context

**Order.** Implement AFTER tp#843 (`PLAN_cscs-login-timeout.md`) has landed and use its
names:

- `LoginDeadline` (`add_owned`/`drop_owned`/`step_to`/`push`, via `_active_deadline()`);
- `BG_PAGE_STEP_S`, `DEADLINE_CLEANUP_S`, exit 124/125, `_hard_exit`;
- `_cdp_create_background_target(ws_url, url, 5.0)`, `_cdp_close_target(port, tid, 5.0)`;
- the budgeted, confirming `_close_owned_targets(port, ids, *, budget_s, journal_event)
  -> (gone, confirmed)`;
- `run_browser(*args, timeout_s, capture, quiet) -> BrowserRun` and
  `browser_timeout(cmd)` (agent_login_jobs.py).

Line numbers below are from HEAD 83106c7 and will shift after tp#843.

**Problem.** `_pick_page(browser, substr)` (bin/browser.py:4717) returns the first tab
whose URL contains `substr`; with no match it falls back to *any* content tab
(`content[-1]`), and the site flows then `goto` it. AGENTS.md (tp#786): consumers own tabs
by target id.

**Evidence.**

- (a) `login cscs` → `_pick_portal_page` → `_pick_page("cscs.ch")` found no CSCS tab, fell
  back to openai-team's leftover ChatGPT tab and navigated it.
- (b) During the tp#836 renewal test, `logged-in anthropic/openai` navigated other
  clients' tabs.
- (c) tp#844: a leftover "ChatGPT - Admin | Members" tab.
- (d) `logged-in cscs` (= `cmd_token`) and `logged-in biopolwifi` bypass
  `_logged_in_page_check`, so they pick a tab even during a guided login.
- (e) `_close_stale_cscs_tabs` closes any tab whose URL contains `auth.cscs.ch`,
  including other clients' tabs.

**Ownership model — three kinds of target.**

1. **Maintenance-owned** — the guided login's `tx.owned`; unchanged.
2. **In-process ephemeral** — the whole lifecycle stays inside one process
   (`_owned_background_page` / `_background_page_run`); recorded in a per-process ledger
   so a crash can be reaped.
3. **Public `open -N` handoffs** — the creator exits and the caller owns the tid; NOT
   ledgered (a pid ledger would reap a live handed-off tab).

**Session premise (corrected).** Cookies and localStorage are scoped by domain/origin
and partition, and shared between tabs of the same browser context. A fresh tab sees the
session only if `Target.createTarget` lands in the default context. Invariants:
`createTarget` never gets a `browserContextId`; no `new_context()` on these paths; the UA
launch flag (AGENTS.md "Headless = plain Chrome UA") is untouched.

**Inventory**

| Function : line                                                  | Now                                                                  | Becomes                                                                                                                                                                 |
| :--------------------------------------------------------------- | :------------------------------------------------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `_logged_in_page_check` :7665 (anthropic, openai, slack, test site) | picked tab unless a maintenance record or `PROBE_BACKGROUND_ENV`     | always `_background_page_run(port, "about:blank", _broker_probe_viewport, check)`; drop `url_substr` and the env branch                                                |
| `cmd_token` :5930 (= `logged-in cscs`)                           | `_pick_portal_page`, `goto`, `_close_stale_cscs_tabs`                | `_background_page_run(port, "about:blank", None, fn)`; `fn`: `goto PORTAL_PROFILE_URL`; Keycloak → 2, else `_capture_and_cache_token`; lease-free as today              |
| `cmd_cscs_login` :6714-6778                                      | pick + close stale ×3                                                | owned `about:blank` tab → `_interaction_lease` → `goto` portal; the retry stays in that tab; token captured from it                                                     |
| `_pick_portal_page` :5885, `_close_stale_cscs_tabs` :5900        | pick / close by URL                                                  | **delete**                                                                                                                                                              |
| `cmd_anthropic_login` :7594, `cmd_openai_login` :7770, `cmd_slack_login` :7954 | substring pick, probe, `goto`                          | owned blank tab; warm probe outside the lease (as today); cold path: lease, then `goto` in the same tab                                                                |
| `cmd_slack_session` :8015                                        | pick + `goto`                                                        | `_background_page_run`; `fn` = check + `_slack_session_from_page`                                                                                                      |
| `cmd_biopolwifi_login` :8074 / `_logged_in` :8144                | pick + `goto`; logged-in ignores maintenance                         | login: owned blank tab → lease → `goto`; logged-in: `_logged_in_page_check`; error lines via `_tab_hint`                                                                |
| `cmd_switch_login` :8532, `cmd_notion_login` :9565               | substring pick / focusing `ctx.new_page()`, left open                | owned blank tab → lease → `goto` → `_bring_to_front` (only under the mode-A lease); closed in `finally`                                                                 |
| `_test_site_logged_in` :9738 `probe:"pick"`                      | picks by origin                                                      | branch removed; fixture key dropped                                                                                                                                     |
| `_background_page_run` :8881 (after tp#843)                      | raw create, adopt, raw close, in `push(BG_PAGE_STEP_S)`              | `_owned_background_page` under `push(BG_PAGE_STEP_S)` (context exit included); `goto`/`fn` inside                                                                      |
| `claude_account_email` (agent_login_claude.py:68)                | `eval --url claude.ai`, else plain `open` (leaves a tab)              | `run_browser("eval-fresh", "-t", "30", "https://claude.ai/", JS, timeout_s=browser_timeout("eval-fresh"), capture=True)`                                               |
| `claude_login_by_hand` (agent_login_claude.py:91)                | plain `open https://claude.ai/login`, polls `eval --url`, leaves a tab | `run_browser("login", "anthropic", "-e", want, timeout_s=None)` inside `guided_window`: browser.py owns the tab, activates it under the headed lease, polls `/api/account` on it, closes it |
| `_eval_attached` :4993 (`eval --url`)                            | `_pick_page(..., require_match=True)`                                | **keep** (documented CLI), renamed `_match_page`; evaluates only, never navigates; the no-`--url` default skips `#owned-` marker tabs                                    |
| `open -N` handoffs (`_open_new_raw` :4828, `_guided_open_owned` :9834, external tools) | caller owns the tid                              | **unchanged, not ledgered**; a reap pass never touches them                                                                                                            |
| `cmd_open -r` :4859, blank reuse :4867                           | navigates an existing tab                                            | out of scope; `-r` help "manual use; tools use -N"; follow-up tp for blank-tab reuse; `_is_blank` does not treat `about:blank#owned-…` as blank                         |
| doctor probe :5676                                               | own unique probe URL                                                 | keep; doctor also reports orphan ledgers (read-only ⚠)                                                                                                                 |
| **new `eval-fresh URL JS`** (`-t/--timeout S`, `-h`)             | —                                                                    | create → readyState `complete` (≤ 15 s) → evaluate → close, in one ledgered process armed by a `LoginDeadline`; exit 0/1/75; http(s) only                               |
| **new `reap-owned`** (`-n/--dry-run`, `-h`)                      | —                                                                    | coordinated reaper of proven-dead owners' ledgers (Steps)                                                                                                               |
| **new `login -e/--expect-account EMAIL`**                        | —                                                                    | anthropic only (else exit 2); assisted only (no magic-link auto path); waits ≤ 15 min until `/api/account` email == EMAIL                                               |

**Cost.**

- One extra short-lived background tab + one attach per check (tp#843 already made
  create raw).
- claude/chatgpt/slack checks already `goto` their surface — no extra page loads.
- CSCS/Biopol lose the "already-settled tab" shortcut: one cold SPA load each.
- Sessions unaffected (the default-context invariant).
- Check tabs get the 1280×720 probe viewport; login tabs do not.

**Why Verification runs tests, mypy, pylint:** AGENTS.md makes ruff/mypy/pylint the gates
for bin/browser.py; crash boundaries, flocks, concurrency, BUSY/75 and lease ordering are
safe to exercise only with fakes. conftest's `CLAUDE_BROWSER_TEST_NO_LAUNCH=1` blocks a
real Chrome; `-m "not launches_chrome"` skips the opt-in disposable-browser tests.
`test_login_timeout.py` must stay green because `_background_page_run` is rebuilt on its
deadline.

## Steps

- [ ] **0. Worktree, after tp#843 has merged** (AGENTS.md forbids editing bin/browser.py
      in place).
- [ ] **1. Owned-tab ledger** (`bin/browser.py`, next to the maintenance helpers).
  - File `<CACHE_DIR>/owned/<pid>.json`: `{pid, pid_start_time, entries: [{marker,
    tid|null, parent|null, created}]}`.
  - The owner creates the file and takes and holds its flock for its whole life, before
    the first entry is written.
  - `_owned_ledger()` — a lazy per-process singleton: `pending(marker)`,
    `bind(marker, tid)`, `add_children(parent, tids)`, `drop(tids)`.
  - Every write runs under an in-process lock + the file flock and uses
    `_json_write_atomic`; the tp#843 watcher thread goes through the same lock.
  - `_owner_state(path)` is tri-state:
    - `live` — flock held, or pid alive with a matching `_proc_lstart`;
    - `dead` — flock free and (pid gone or start time differs);
    - `unknown` — anything unreadable.
- [ ] **2. `@contextmanager _owned_background_page(port, *, prepare=None)`** — no body
      deadline (human logins wait). In order:
  1. `release = _registry_register(...)` — `SystemExit(75)` propagates, so
     `createTarget` is never sent;
  2. `marker = secrets.token_hex(16)`; `ledger.pending(marker)`;
  3. `tid = _cdp_create_background_target(ws, f"about:blank#owned-{marker}", 5.0)` —
     payload keys exactly `url` and `background`. On None: re-list; marker listed → bind
     and close it; otherwise drop the pending entry;
  4. `ledger.bind(marker, tid)`; `_active_deadline().add_owned(tid)`;
  5. `_connect`; `_page_by_target(browser, tid)` (renamed from `_switch_page_by_target`,
     alias kept);
  6. `prepare(page)`;
  7. `yield page` — still on the marker URL; callers navigate only after this;
  8. `finally`: one `Target.getTargets` snapshot → transitive closure of
     `type=="page"` descendants via `openerId` → record them (`ledger.add_children` +
     `add_owned`) → `_close_owned_targets(port, leaves_first + [tid],
     budget_s=DEADLINE_CLEANUP_S, journal_event="owned_tab")` → drop only confirmed-gone
     tids (the rest stay for tp#843's command-scope cleanup or a reaper) →
     `browser.close()`, `pw.stop()`, `release()`.

  Catch `Exception` only, never `BaseException`; `SystemExit` is re-raised.
  `page.close()` is never called.
- [ ] **3. `_background_page_run(port, url, prepare, fn)`** = `with
      dl.push(BG_PAGE_STEP_S, "background_page"): with _owned_background_page(...) as
      page:` → `goto url` (15 s) → load (10 s) → `fn`. Keep tp#843's `step_to`
      breadcrumbs (+ `bg:ledger`). Returns None on `Exception`; `SystemExit` passes
      through. `_with_background_page` and `_with_prepared_background_page` stay as
      wrappers.
- [ ] **4. Checks.** `_logged_in_page_check(port, check)` as in the inventory
      (`_guided_probe` may keep setting `PROBE_BACKGROUND_ENV`; no effect now).
      `cmd_token` and `cmd_slack_session` as in the inventory; run directly (not via
      `cmd_logged_in`) they arm `LoginDeadline(LOGGED_IN_TIMEOUT_S)`.
      `cmd_biopolwifi_logged_in` → `_logged_in_page_check`.
- [ ] **5. Logins.**
  - cscs, biopolwifi, switch-window, notion: `with _owned_background_page(port) as page:`
    → `_interaction_lease` → first non-blank `goto`.
  - anthropic, openai, slack: warm probe in the owned tab before the lease; cold path →
    lease → `goto`.
  - Delete `_pick_portal_page`, `_close_stale_cscs_tabs`, the `probe:"pick"` branch and
    `_pick_page`; add `_match_page` (eval only).
- [ ] **6. `login -e/--expect-account EMAIL`** (`cmd_anthropic_login(port, expect=…)`):
      requires `_guided_login_allowed`; pre-fills EMAIL; `_bring_to_front` on the owned
      page; polls `fetch("/api/account")` in that page every 10 s for ≤ 900 s; 0 on a
      match; a different account → exit 2 with the email masked to its domain.
- [ ] **7. `eval-fresh`.** Parser `-t/--timeout`, `-h`; `cmd_eval_fresh` arms
      `LoginDeadline(timeout)` and calls `_background_page_run`; `fn` polls
      `document.readyState === "complete"` for ≤ 15 s, then `page.evaluate`, and prints
      JSON like `eval`. JS error / not ready → ❌ exit 1; deadline → 124/125.
- [ ] **8. `reap-owned` (`-n/--dry-run`).**
  1. Register (a foreign maintenance → 75); take `_interaction_lease("reap-owned")`.
  2. Non-blocking global `<CACHE_DIR>/owned-reaper.lock`; if held: "another reaper is
     running", exit 0.
  3. Per ledger: claim only `dead` owners (non-blocking flock, kept).
  4. One `Target.getTargets` snapshot: resolve pending markers by the exact URL
     `about:blank#owned-<marker>`; add transitive page descendants to the claimed ledger
     BEFORE closing; close leaves first via `_close_owned_targets` (keep-alive rule);
     re-list; drop the confirmed tids.
  5. Delete the file only when empty (otherwise it stays claimable); delete dead owners'
     orphaned `*.tmp`.
  6. Journal `reap_owned owner=… closed=… left=…`; exit 0 when nothing is left, else 1.

  Internal `_reap_owned(port, coordinated=True)` is also called from the maintenance
  transaction start, `_guided_a`'s `finally` (it holds the lease; strangers get 75) and
  `cmd_maintenance_watchdog` (gate exclusive). Never from `_preflight`, never from
  `status`.
- [ ] **9. Doctor:** a read-only "owned-tab ledgers" line; each `dead`/`unknown` ledger →
      ⚠ with the hint "browser.py reap-owned". It never closes anything.
- [ ] **10. Runner** (agent_login_jobs.py, agent_login_claude.py, agent-login.py).
  - `browser_timeout`: `eval-fresh` = 60, `reap-owned` = 60.
  - `claude_account_email` and `claude_login_by_hand` as in the inventory;
    `claude_account_email` validates that the last stdout line is JSON (else None) and
    drops the old `open` fallback.
  - After `BrowserRun.killed` and at the start of the daily `-c` run:
    `run_browser("reap-owned", timeout_s=browser_timeout("reap-owned"))`.
  - tp#843's AST allowlist for `timeout_s=None` gains the `login anthropic -e` call
    inside `guided_window`.
- [ ] **11. Tests — new `tests/test_owned_tabs_tp845.py`** (fakes).
  - Checks with no record (logged-in anthropic, openai, slack, biopolwifi, token, plus
    slack-session): `_connect` outside the helper → `pytest.fail`; the helper received the
    viewport `prepare`.
  - Logins: a fake owned page whose ctx `.pages` raises; for cscs/biopolwifi the first
    non-blank `goto` sees the fake lease held; for every login cleanup runs even when the
    flow raises.
  - BUSY: with a foreign live record, the checks, `token`, biopolwifi and `eval-fresh`
    exit exactly 75 and the fake CDP got no `Target.createTarget`.
  - createTarget payload keys `{url, background}`; no `new_context`.
  - Popup closure: nested popups closed leaves-first; unrelated pages and
    iframe/worker targets untouched; `page.close()` never called.
  - `login -e`: match → 0; mismatch → 2 without the raw email.
  - `eval-fresh`: not-ready → 1; JS error → 1; deadline → 124.
  - AST guard: `_match_page` called only from `_eval_attached`; the deleted names are
    gone; no `browserContextId` literal.
  - Opt-in `launches_chrome`: a cookie + origin localStorage seeded in one target are
    readable from a fresh owned target; the marker URL round-trips in `/json/list`.
- [ ] **12. Tests — new `tests/test_owned_ledger.py`.**
  - O9 crash points: kill after the CDP reply but before the tid write; kill with only
    the temp file written → both reaped by marker, nothing else touched.
  - O10: owner flock held → live even when the fake `ps` says dead; `ps` failure →
    unknown → not reaped; pid reuse → dead.
  - Two concurrent reapers → exactly one acts.
  - A failed close keeps the tid; a reaper killed mid-pass leaves a claimable file.
  - Orphaned nested popups closed leaves-first.
  - An `open -N` tid survives a reap pass after its creator exited.
  - `reap-owned` under a foreign record → 75; `-n` closes nothing; `status` and
    `_preflight` never call `_reap_owned`.
- [ ] **13. Update existing tests.**
  - `test_tab_selection.py` → `_match_page`; delete the site-flow fallback test.
  - Replace `_pick_page`/`_pick_portal_page` fakes with a fake
    `_owned_background_page`/`_background_page_run`: `test_token_verify.py` env fixture,
    `test_credentials.py` `_cscs_login_env`, `test_magic_link_flow.py:291`,
    `test_headless_default.py:528`.
  - `test_guided_login.py`: keep :588; add "no record → still background"; drop
    `probe:"pick"` (:913); extend the SIGKILL E2E to a mode-A builtin login child (its
    ledger is reaped in `_guided_a`'s `finally`).
  - `test_agent_login.py`: `eval-fresh` via `run_browser` (open failure, non-JSON
    output, rc 1, kill → None); the `claude_login_by_hand` argv; `reap-owned` after a
    kill.
  - `test_login_timeout.py` (tp#843): `_background_page_run` still fires 124 inside the
    helper and still closes over raw CDP.
- [ ] **14. Docs.**
  - README: Quick start (`eval --url` "evaluates only, never navigates"; `eval-fresh`;
    `reap-owned`; `login -e`); every logged-in/login row → "fresh owned background tab,
    closed again"; the ledger, reaping, and "`status` is never destructive"; exit-table
    notes for `reap-owned` 0/1/75.
  - AGENTS.md: tp#786 bullet — in-repo flows obey it too, `_match_page` is reserved for
    `eval --url`; guided-login sentence — fresh tabs always, not only while a record
    lives; new bullet "Owned-tab ledger (tp#845)" — three ownership kinds, two-phase
    marker, tri-state liveness, reaping only via `reap-owned`/the maintenance
    transaction/the watchdog, never `_preflight`/`status`.
- [ ] **15. Deploy.** `browser.py doctor` on a disposable instance; on live: `logged-in
      openai`, then `reap-owned -n` and `status` show no leftover chatgpt tab (tp#845
      acceptance). File the follow-up tp for `open` blank-tab reuse.

## Debate

Codex gpt-5.6-sol, 2 rounds, every objection accepted; the judge converged.

- **O1** — `claude_login_by_hand` is in the inventory → `login anthropic -e EMAIL` on an
  owned, activated, closed tab (steps 6, 10).
- **O2** — Ledger only for single-process lifecycles; `open -N` handoffs are not
  ledgered; Claude account detection uses `eval-fresh` (steps 1, 7; handoff test in
  step 12).
- **O3** — `_owned_background_page` has no body deadline; `_background_page_run` keeps
  tp#843's `push(BG_PAGE_STEP_S)` around the context exit; raw-CDP close only;
  `test_login_timeout.py` in Verification.
- **O4** — Snapshot before the root closes; transitive page-only closure; leaves first;
  nested/unrelated/iframe tests (steps 2, 11).
- **O5** — Tabs are created on the marker `about:blank`; cscs/biopol/switch/notion
  navigate only under the lease; a test pins the lease at the first non-blank `goto`.
- **O6** — Registration before `createTarget`; `SystemExit` never caught; 75 tests with
  no `createTarget` (steps 2, 11).
- **O7** — Premise corrected; default-context invariant; payload test + an opt-in
  `launches_chrome` storage test; UA untouched.
- **O8** — The agent side uses tp#843's `run_browser(capture=True, timeout_s=…)`;
  readiness inside `eval-fresh`; failure/malformed/timeout tests.
- **O9** — Two-phase pending marker → bind tid → navigate; the reaper resolves pending
  entries by exact marker; two crash-point tests.
- **O10** — Per-ledger flock held for the owner's lifetime; global reaper lock;
  tri-state liveness; only proven-dead owners reaped.
- **O11** — No reaping in `_preflight`; `reap-owned` registers and takes the lease;
  maintenance start, `_guided_a` and the watchdog reap under exclusive coordination.
- **O12** — `status` untouched; acceptance via `reap-owned -n`; doctor's ⚠ is read-only.
- **O13** — Descendants recorded before closing; a failed close keeps the tid and the
  file stays claimable; journaled; crash/concurrency/popup tests.

## Verification

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff format --check bin/ tests/ agent-login.py agent_login_jobs.py agent_login_claude.py && ruff check bin/ tests/ agent-login.py agent_login_jobs.py agent_login_claude.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run mypy bin/browser.py && uv run pylint bin/browser.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q -m "not launches_chrome" tests/test_owned_tabs_tp845.py tests/test_owned_ledger.py tests/test_login_timeout.py tests/test_tab_selection.py tests/test_token_verify.py tests/test_credentials.py tests/test_magic_link_flow.py tests/test_headless_default.py tests/test_guided_login.py tests/test_agent_login.py tests/test_broker_spa_and_switch_eduid.py tests/test_switch_site.py tests/test_login_broker.py tests/test_connect_hang.py tests/test_journal.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run python bin/browser.py -h && uv run python bin/browser.py eval-fresh -h && uv run python bin/browser.py reap-owned -h && uv run python bin/browser.py login -h
```
