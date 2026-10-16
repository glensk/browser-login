# Plan: tp#1109 — tab ownership, keep pins and an idle-tab reaper for the shared Chromium

## Session

Resume: `c --resume ecfca613-110e-4fd3-83ca-87e5ed4522d9`

## Context

The shared agent Chromium (CDP 9222; instances 9223/9224/9225) ran 2 d 21 h with ~19
page tabs that finished agent sessions left behind (ad-heavy pages, admin pages): ~3.1 GB,
84 % CPU, typing lag on a 16 GB Mac. Nothing closes a tab its opener forgot, and nothing
records which session opened which tab. Some tabs are legitimately long-lived (an
`app.straiv.io` tab an agent re-uses) and must never be reaped while needed.

Builds on (AGENTS.md): `open -N` handoffs (caller owns the tid, never ledgered), the
owned-tab ledger (`<cache>/owned/*.json`, `_page_descendants`, `reap-owned`), the
maintenance record (guided login → BUSY 75), the registry gate (`_gate_acquire`, shared
for clients, exclusive for `switch`/`down`), `_unknown_cdp_clients`, `_interaction_lease`,
the raw CDP helpers (`_cdp_ws_call`, `_cdp_close_target`), `_target_label` /
`_tab_hint` / `_tab_title` (origins only in output), `_journal`. LaunchAgents live in
`agent_login_jobs.agent_plists()` (one-transaction installer `agent-login.py
--install-daily`).

Plan reconciled with a Codex debate (gpt-5.6-sol, converged in round 1, 14 objections
accepted; ledger in the session scratchpad).

## Design

**State file** `<CACHE_DIR>/tabs.json` per instance, mode 0600, `{"v": 1, "targets":
{tid: entry}, "keep_origins": [origin, …]}`. Entry: `created` (browser.py created it),
`via` (`open`), `opener` (`session`, `cwd`, `pid`, `tool`), `last_used`, `keep`,
`first_seen`, `url_h` (full sha256 hex of the URL without its fragment — no raw URL is
ever stored), `last_change`. Every update is read-merge-write under an flock on
`<CACHE_DIR>/tabs.lock` (bounded wait) with `_json_write_atomic`. A missing file is
empty; an unreadable / malformed / unknown-version file makes the reaper refuse (exit 1)
and `tabs` warn. Pins (`keep`, `open -k`, release) are durable writes — a failure is
exit 1; activity and observation writes are best effort with a stderr warning. Prune
only entries absent from a successful snapshot AND whose `created`/`first_seen` is older
than that snapshot's start.

**Opener identity**: session = `CLAUDE_CODE_SESSION_ID`, else `CLAUDE_SESSION_ID`, else
`CODEX_SESSION_ID`, else null; `cwd` = `os.getcwd()`; `pid` = `CLAUDE_PID` if set, else
`os.getppid()`; `tool` = `AI_AGENT`'s first token or `?`. Tabs created by anything else
(Playwright MCP, raw clients) show opener `unknown`; `tabs`' header lists live registered
clients (register-exec now records `session` + `cwd` in its registry `extra`).

**Idle** of a page target = `now - max(created, last_used, last_change, first_seen)`
— local accounting only: browser.py creation, `open`/`eval -T`/`eval --url` activity,
and an observed URL change (fragment-less hash differs from the last sample).
`performance.timeOrigin` (read by `tabs` over the target websocket) is a diagnostic
"loaded" column only; the reaper sends no `Runtime.evaluate`. `attached` from
`Target.getTargets` is an instantaneous close veto, never activity.

**Reap rule** (`reap-idle`; a page target is closed only if ALL hold):

1. browser up; no maintenance record file at all (live, dead or unreadable → exit 75:
   a dead record is the watchdog's); the registry gate taken EXCLUSIVELY (bounded
   wait; held by any live client such as a register-exec MCP → exit 75) without
   self-registering; `_unknown_cdp_clients` returns an empty list (None or any client →
   75); maintenance re-checked; then `_interaction_lease("reap-idle")` (timeout → 1).
2. `type == "page"` and the URL is http(s) (never `about:`, `chrome:`, `devtools:`, blank
   keep-alives, `#owned-` markers).
3. not in any owned ledger: marker entries resolved via the listing, descendants
   expanded with `_page_descendants`; any ledger whose owner is `unknown` → refuse the
   run (exit 1).
4. not pinned (`keep`) and its origin not in `keep_origins`.
5. idle ≥ threshold (`-I/--idle-hours`, default env `CLAUDE_BROWSER_TAB_IDLE_H`, 2 h,
   floor 0.25 h).
6. right before ITS close, holding `tabs.lock`: a fresh `Target.getTargets` says
   `attached: false`, the fragment-less URL hash equals the decision sample's (else
   `skipped (changed)`), the pin state re-read says unpinned.
7. it is not the last page target of the BROWSER (tp#317: zero pages break every
   `connect_over_cdp`). A sole tab of an invisible headless window may be closed — its
   window goes with it — because headless `_cdp_create_background_target` puts every
   browser.py tab in its own `newWindow`; a per-window rule would forbid reaping every
   such tab. Headed mode never reaps (rule 1: a mode-A guided login is a maintenance
   record).

At most `-m/--max` closes per run (default 20), one overall deadline (60 s). Each
close is journaled (`tab_reaped`: origin, id8, idle_s, opener session — never a raw URL
or cwd) and printed origin-only via `_target_label`. `-n/--dry-run` is a pure read: no
gate, no lease, persists nothing, prints `would close:` plus skip-reason counts.
`-A/--all-instances` runs one subprocess child per known instance whose CDP port answers
(never launches one), `-A` dropped from the child argv, rows labelled by instance, exit
aggregated by severity 1 > 75 > 0.

## Steps

- [ ] B1 **State module + recording.** `_tabstate_*` helpers in `bin/browser.py`
      (locked load/merge/write, prune rule, opener identity, version check). Record on
      `_open_new_raw` (creation, opener, `via: open`), `eval -T` and `eval --url`
      (`last_used`; for `--url` the tid via `Target.getTargetInfo` on the page's CDP
      session, best effort). `register-exec` adds `session` + `cwd` to its registry
      `extra`. Tests (`tests/test_tab_reaper.py`): env precedence, malformed state,
      stale-snapshot prune, concurrent merge.
- [ ] B2 **`browser.py tabs`** (all up instances by default; `-1/--this-instance`,
      `-j/--json`, `-f/--full-urls`, `-n/--no-probe`): per instance one
      `Target.getTargets` + a bounded concurrent `performance.timeOrigin` probe
      (skipped with `-n`), records observations (first_seen, url_h, last_change), and
      prints instance, id8, opener (session8 + cwd basename | `unknown`), age
      (`created`, or `≥` + first_seen), loaded, idle, flags (`keep`, `attached`,
      `owned`), title → origin. JSON origin-only unless `-f`. Header: live registered
      clients with session. Registers; no lease; closes nothing.
- [ ] B3 **`browser.py keep`**: `keep TID…` (a full tid or a unique ≥ 8-char prefix;
      ambiguous/none → exit 2, candidates listed origin-only), `-o/--origin ORIGIN`
      (canonical scheme://host[:port]; userinfo/path refused), `-r/--release` (either
      form), `-l/--list`. `open -k/--keep` pins at creation (pin failure: prints
      `target=`, exit 1). Durable writes under `tabs.lock`.
- [ ] B4 **`browser.py reap-idle`** (`-n/--dry-run`, `-I/--idle-hours H`, `-m/--max N`,
      `-A/--all-instances`, `-q/--quiet`) implementing the reap rule. Tests with the
      fake CDP: attached veto, pinned tid / origin, owned marker-only ledger + popup
      descendant, unknown ledger owner, maintenance debris, blank / non-http, last page,
      changed URL, keep-vs-close under the lock, exclusive gate refused by a registered
      client and by an unknown client, dry run persists nothing, MCP-created tab shows
      `unknown`. One `launches_chrome` test on a disposable instance: two
      `open -N` tabs (each its own headless window), one pinned, state backdated, real
      reap closes only the unpinned one and `eval-fresh` still attaches afterwards.
- [ ] B5 **LaunchAgent** `com.albert.browser-tab-reaper` in `agent_plists()`
      (`launchagent_plist` gains a `script` parameter): every 15 min,
      `browser.py reap-idle -A -q`, own log, `RunAtLoad false`. Installed with
      `agent-login.py --install-daily`.
- [ ] B6 **Docs + live acceptance.** README section "Tabs: who opened what, keep pins,
      the idle reaper"; AGENTS.md bullet (reaping only via `reap-idle` / `reap-owned` /
      `close`; agents that need a long-lived tab run `browser.py keep`). Live: `tabs`
      and `reap-idle -A -n` against the live browsers (read-only); the LaunchAgent
      loaded and its first run logged.

## Verification

The block is not strict-eligible on purpose: AGENTS.md makes mypy, pylint and the
pytest suites with fakes the gates for `bin/browser.py` (coordination, flocks and the
close path can only be exercised safely that way), so a permissioned reviewer runs
lines 2-5. Targeted files only; no load generators, no suite loops.

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff format --check bin/ agent_login_jobs.py && ruff check bin/ agent_login_jobs.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run mypy bin/browser.py agent_login_jobs.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pylint bin/browser.py agent_login_jobs.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests/test_tab_reaper.py tests/test_owned_tabs_tp845.py tests/test_cdp_client_detection.py tests/test_agent_login.py tests/test_ws1b_agent_login.py tests/test_safari_cookies.py
cd /Users/albert/obsidian/42-Git/home/browser-login && bin/browser.py tabs -h && bin/browser.py keep -h && bin/browser.py reap-idle -h
```

## Acceptance

- A1 (agent; headless): run `browser.py tabs`. PASS: every page tab of every up instance listed with opener, age, idle; tabs opened via `browser.py open` show their session.
- A2 (agent; headless): run `browser.py reap-idle -A -n`. PASS: exit 0, no pinned / attached / owned tab listed under `would close:`.
- A3 (agent; headless): `launchctl print gui/$(id -u)/com.albert.browser-tab-reaper` and its log. PASS: loaded, at least one run logged without ❌.

## Decisions / assumptions

- Attached is a veto, not activity; and a live registered client (any register-exec
  Playwright MCP) holds the gate shared, so the reaper skips (75) while one is
  connected. Stale tabs then wait until that session ends.
- "Never the last tab of a window" is implemented as "never the last page of the
  browser" (rule 7 reason).
- Blank / non-http(s) tabs are never reaped.
