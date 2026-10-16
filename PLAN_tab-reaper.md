# Plan: tp#1109 — tab ownership, keep pins and an idle-tab reaper for the shared Chromium

## Session

Resume: `c --resume ecfca613-110e-4fd3-83ca-87e5ed4522d9`

## Context

The shared agent Chromium (CDP 9222; instances 9223/9224/9225) ran 2 d 21 h with ~19
page tabs that finished agent sessions left behind (ad-heavy pages, admin pages): ~3.1 GB,
84 % CPU, typing lag on a 16 GB Mac. Nothing closes a tab that its opener forgot; nothing
records which session opened which tab. Some tabs are legitimately long-lived
(an `app.straiv.io` tab an agent re-uses) and must never be reaped while needed.

Existing machinery this builds on (AGENTS.md): `open -N` handoffs (caller owns the tid,
never ledgered), the owned-tab ledger (`<cache>/owned/*.json`, `reap-owned`), the
maintenance record (guided login → BUSY 75), `_registry_register` (client gate),
`_interaction_lease`, raw CDP helpers (`_cdp_ws_call`, `_cdp_close_target`,
`_cdp_create_background_target`), `close`'s per-close re-list + last-tab keep-alive
(`_close_one`), `_tab_hint`/`_target_label` (origins only in output), `_journal`.
LaunchAgents live in `agent_login_jobs.agent_plists()` (installed as one transaction by
`agent-login.py --install-daily`).

## Design

**State file** `<CACHE_DIR>/tabs.json` (per instance; 0600; written with
`_json_write_atomic` under an flock on `<CACHE_DIR>/tabs.lock`, bounded wait, best
effort — a state write failure never fails the command that triggered it):

```json
{"v": 1,
 "targets": {"<tid>": {"created": 1760000000.0, "via": "open",
                       "opener": {"session": "<CLAUDE_CODE_SESSION_ID|CODEX_…|null>",
                                  "cwd": "/abs", "pid": 123, "tool": "claude"},
                       "last_used": 1760000000.0, "keep": false,
                       "first_seen": 1760000000.0, "url_h": "<sha256[:16] of url>",
                       "last_change": 1760000000.0, "last_attached": null}},
 "keep_origins": ["https://app.straiv.io"]}
```

No raw URL is stored (only a hash for change detection); origins in `keep_origins` are
what the caller pinned. Entries whose tid is absent from a SUCCESSFUL listing are pruned.

**Opener identity**: `CLAUDE_CODE_SESSION_ID` (Claude Code), else `CODEX_SESSION_ID` /
`CODEX_COMPANION_SESSION_ID` if set, else null; `cwd` = `os.getcwd()`; `pid` = the
nearest ancestor that is the agent process when cheap (`CLAUDE_PID`), else `os.getppid()`;
`tool` = first non-shell `comm` of `_journal_parent_chain()` when already computed, else
`AI_AGENT`'s prefix, else `?`.

**Idle** of a page target = `now - max(created, last_used, last_change, last_attached,
timeOrigin)`, where `timeOrigin` = `performance.timeOrigin` read by a read-only
`Runtime.evaluate` on the target's own websocket (the time its current document was
created — gives a real age for tabs never seen before). `last_attached` = the last sample
in which `Target.getTargets` reported `attached: true` (some CDP client — Playwright MCP,
an eval — is attached; Playwright attaches to every page while connected). A target whose
probe did not answer has NO idle value → never reaped (hung tabs are `close-hung`'s job).

**Reap rule** — a page target is closed only if ALL hold:

1. browser up, no live maintenance record, registration succeeded (75 → skip, exit 0),
   interaction lease taken within its wait (else skip, exit 0);
2. `type == "page"`, URL is http(s) (never `about:`, `chrome:`, `devtools:`, blank
   keep-alives, `#owned-` markers);
3. not in any owned-tab ledger whose owner is `live` or `unknown`, and not in the live
   maintenance record's `owned_targets`;
4. not pinned (`keep: true`) and its origin not in `keep_origins`;
5. `attached` is false in a `Target.getTargets` read taken right before ITS close, and
   its URL hash unchanged since the decision sample (else `skipped (changed)`);
6. idle ≥ threshold (`-I/--idle-hours`, default env `CLAUDE_BROWSER_TAB_IDLE_H`, 2 h;
   floor 0.25 h);
7. it is not the last page target (the reaper never needs the keep-alive path: it
   leaves the last page alone).

At most `-m/--max` (default 20) closes per run; one overall deadline (60 s).
Every close is journaled (`tab_reaped`, origin + id8 + idle s + opener session) and
printed origin-only (`_target_label`).

## Steps

- [ ] B1 **State module + recording.** `_tabstate_*` helpers in `bin/browser.py`
      (load/locked update/prune/opener identity). Record on `_open_new_raw` (creation,
      opener, `via: open`), `eval -T` and `eval --url` (`last_used`; for `--url` the tid
      via `Target.getTargetInfo` on the page's CDP session, best effort), and
      `eval-fresh` not at all (ephemeral, ledgered). `register-exec` adds `session` and
      `cwd` to its registry `extra` (shown by `clients` and `tabs`). Tests with
      `CLAUDE_BROWSER_CACHE_DIR` temp dirs + fake CDP.
- [ ] B2 **`browser.py tabs`** (`-A/--all-instances`, `-j/--json`, `-f/--full-urls`,
      `-n/--no-probe`): for each up instance one `Target.getTargets` + per-target
      `timeOrigin` probe (shared budget, `_probe_targets`-style threads), updates the
      state's observations (first_seen / url_h / last_change / last_attached), prints a
      table: id8, opener (session8 + cwd basename | `mcp~<sid8>` hint | `unknown`), age
      (created or first_seen, `≥` when first_seen), loaded (timeOrigin age), idle,
      `keep`/`attached`/`owned` flags, title → origin. Header lists live registered
      clients with their session. `-A` re-execs itself per instance
      (`CLAUDE_BROWSER_INSTANCE=…`) because CACHE_DIR/registry are per instance.
      Registers as a client; takes no lease; closes nothing. The `mcp~<sid8>` hint:
      a target first seen while exactly one live `register-exec` client with a session
      exists and no `open` recorded it.
- [ ] B3 **`browser.py keep`**: `keep TARGET…` (a full tid, a unique ≥ 8-char tid
      prefix, or a URL substring that matches exactly one page — else refuses listing
      the candidates origin-only), `-o/--origin ORIGIN` (pin every tab of that origin,
      normalised scheme://host[:port]), `-r/--release` (undo either form), `-l/--list`.
      Also `open -k/--keep` pins at creation. Pins of gone tids are pruned with the
      entry; origin pins persist until released.
- [ ] B4 **`browser.py reap-idle`** (`-n/--dry-run`, `-I/--idle-hours H`,
      `-m/--max N`, `-A/--all-instances`, `-q/--quiet`): the reap rule above, built on
      `_registry_register` → `_interaction_lease("reap-idle", wait_s=30)` → per-close
      fresh `Target.getTargets` + `_cdp_close_target`. Dry run prints `would close:` and
      every skip reason count; takes no lease. `-A` re-execs per up instance; a down
      instance is skipped silently (never launched). Tests: fake CDP with attached /
      pinned / owned / blank / last-tab / changed-URL / unanswered-probe cases; one
      `launches_chrome` test on a disposable instance that opens two tabs, ages them via
      `-I 0.25` + a backdated state entry and a monkeypatched clock, and reaps only the
      unpinned one.
- [ ] B5 **LaunchAgent** `com.albert.browser-tab-reaper` in `agent_login_jobs.agent_plists()`
      (generalise `launchagent_plist` to take the script path): every 15 min,
      `browser.py reap-idle -A -q`, own log, `RunAtLoad false`. Install with
      `agent-login.py --install-daily` (the existing one-transaction installer).
- [ ] B6 **Docs + live acceptance.** README section "Tabs: who opened what, keep pins,
      the idle reaper"; AGENTS.md convention bullet (reaping only via `reap-idle` /
      `reap-owned` / `close`, rule summary; agents that need a long-lived tab run
      `browser.py keep`). Live: `tabs -A` and `reap-idle -A -n` against the live browser
      (read-only), a real `reap-idle` only after the dry run lists nothing unexpected,
      LaunchAgent loaded and its first run logged.

## Verification

Targeted test files only (no load generators, no suite loops); the one
`launches_chrome` test runs on a disposable instance.

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff format --check bin/ agent_login_jobs.py && ruff check bin/ agent_login_jobs.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run mypy bin/browser.py agent_login_jobs.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pylint bin/browser.py agent_login_jobs.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests/test_tab_reaper.py tests/test_owned_tabs_tp845.py tests/test_cdp_client_detection.py tests/test_agent_login.py
cd /Users/albert/obsidian/42-Git/home/browser-login && bin/browser.py tabs -h && bin/browser.py keep -h && bin/browser.py reap-idle -h
```

## Decisions / assumptions

- Attached = in use (conservative): while a Playwright MCP is connected every tab reads
  `attached`, so nothing is reaped until it disconnects + the idle threshold. Accepted
  per the ticket's "never while a CDP client is attached".
- Blank / non-http(s) tabs are never reaped (cheap; avoid fighting `open -N` handoffs
  and the last-tab keep-alive).
