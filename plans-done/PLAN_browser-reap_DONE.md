# Plan: tp#1759 — shared agent Chromium never piles up (orphan markers, blank tabs, MCP orphans)

## Session

Ticket: tp#1759
Resume: `c --resume 08414911-7a01-4f35-bfb8-aff656e45e2b`

## Context

2026-11-06 09:16: the shared Chrome for Testing (CDP 9222, PID 70933, up since
2026-11-03 20:07) held 8 page targets in 7 windows: 4 `about:blank#owned-<hex>` tabs, one
`about:blank` + one `chrome://newtab/` (startup window, with the One Google Bar iframe
`ogs.google.com`), plus http(s) work tabs; renderers from Nov 3-5 alive; the 31 Chrome
processes of the box summed ~1.85 GB RSS (incl. a second, unrelated Chromium launched
09:22), the shared root ~62 min CPU + GPU ~39 min. Three `npm exec @playwright/mcp@0.0.76
--cdp-endpoint http://localhost:9222` servers ran, all three with a LIVE claude parent.

What already exists (do not rebuild):

- **Owner metadata** (lever 1) is done: `_owned_background_page` writes a two-phase
  ledger `<cache>/owned/<pid>-<rand>.json` (pid + `pid_start_time` + entries with
  marker/tid/created) under a lifetime flock; `_owner_state` is tri-state.
- **`reap-owned`** closes tabs of proven-DEAD ledgers — but runs only by hand and from the
  guided-login transaction/watchdog, never on a timer.
- **`reap-idle`** (tp#1109) + LaunchAgent `com.albert.browser-tab-reaper` (every 15 min,
  `reap-idle -A -q`, defined in `agent_login_jobs.agent_plists()`, installed by
  `agent-login.py --install-daily`) closes idle http(s) tabs; its log shows it working.
  It never touches `about:`/`chrome:` tabs or owned markers.

Gaps found (read-only probes, 2026-11-06):

1. The 4 orphan markers have **no ledger at all** (`<cache>/owned/` held only one live
   ledger) and their tids appear in neither journal file, so `reap-owned` cannot see them
   and `reap-idle` skips them (non-http). They are never navigated (still on the marker).
   Likely cause: `_create_owned_target` drops the pending entry when `createTarget` gives
   no reply within 5 s AND `_marker_target` does not list the tab yet — the tab appears
   later with nobody owning it. (Six `owned_tab … confirmed:false` closes in the journal
   show the close path is slow under load too.)
2. Blank/NTP tabs are never trimmed (startup window opens `chrome://newtab/` with Google
   widgets because no start URL is passed).
3. No windows exist without a page: in headless every browser.py tab is its own
   `newWindow`, so a window goes with its last page — "empty extra windows" reduces to
   closing orphan/blank pages (verified with `Browser.getWindowForTarget`; the
   `browser_ui` omnibox/toolbar targets belong to no reportable window and die with it).
4. Every page reads `attached: true` while a Playwright MCP is connected (it auto-attaches
   to all targets), so `attached` cannot be the veto for the new marker/blank rules.
5. Nothing kills playwright-mcp servers whose claude parent died.
6. tp#1663: a launchd context never cold-starts the browser (Local Network privacy).

## Out of scope v1

- **Idle stop** (old lever 4 / old B5) is dropped: the SWITCH portal cookie is a
  browser-session cookie (`bin/browser.py` ~10265-10268), so any stop logs it out, while
  console-balance runs hourly (`-R` every 6 h) and the switch status check every 30 min —
  the browser is never idle long enough, and when it stops, launchd cannot cold-start it
  again (tp#1663). It would either never fire or log people out.

## Design

**Marker v2 (owner in the URL).** New markers are `p<pid>-<h12>-<hex16>`
(`about:blank#owned-p123-0a1b2c3d4e5f-…`), `h12` = the first 12 hex digits of sha256 of
the owner's RAW `_proc_lstart` string — exactly the value the ledger stores as
`pid_start_time` (no epoch conversion). An orphan's owner is then provable from the URL
alone, even with no ledger: dead = pid gone, or `sha256(_proc_lstart(pid))[:12] != h12`;
`_proc_lstart` failing = unknown (never closed). When the owner's own lstart is unknown at
creation, the marker falls back to the legacy 32-hex form. Legacy 32-hex markers stay
recognised. The ledger FILE format (fields, stem naming, `pid_start_time`) is unchanged,
so `_caller_ledger_tids`, `_owned_ledger_tids` and `_reap_owned` need no format change
(tp#1765 invariant).

**Create fix (lighter option, objection 5).** No keep-pending: when `createTarget` gives no
reply, `_create_owned_target` polls `_marker_target` for up to 5 s more (late reply →
bind + close as today); only if the tab still is not listed is the entry dropped. A tab
that appears even later carries a v2 marker naming its owner, so the orphan rule reaps it
once that owner is dead (legacy-marker processes are covered by the 10 min grace).

**Orphan marker rule** (in `_reap_owned`, so all owned-tab reaping stays in one place,
same reaper lock + interaction lease; journal `orphan_marker`): from one target snapshot,
THEN the ledger references (markers + tids of every ledger in `<cache>/owned/`, any
state, incl. unknown and `.<stem>.json.*.tmp` files), a page whose URL is exactly
`about:blank#owned-<marker>` and that no ledger names by marker or tid is closed when:

- v2 marker: its owner is dead (pid gone or lstart hash differs) — never when the pid lives
  with the same start, never when `ps` fails;
- legacy marker: its tabs.json `first_seen` is ≥ `ORPHAN_MARKER_GRACE_S` (10 min) ago —
  the pending entry is always written before `createTarget`, so a ledger-less marker that
  old has no owner;
- right before the close, a fresh snapshot still shows it on the exact marker URL and more
  than one page (never the last page of the browser, tp#317).
An unreadable ledger directory or file stops this rule (fail closed, exit 1). Closes share
`ORPHAN_CLOSE_BUDGET_S` (10 s).

**Observation pass (objection 4).** `_reap_owned` first records `first_seen` (and `url_h`)
for every marker and blank page in tabs.json under `tabs.lock` — `setdefault` only, no
pruning, never touching `opener`/`created`/`via` — whatever the gate or unknown-client
state, so legacy markers and blanks age even when `reap-idle` is skipped (75). Dry run:
on a deep copy, nothing written.

**Blank trim rule** (objection 2): a blank page is one whose RAW URL is exactly
`about:blank` or `chrome://newtab/` and `_is_owned_marker(url)` is false. Excluded: every
tid any ledger names (roots and page descendants: `_owned_ledger_tids`; None = unreadable
→ trim nothing, exit 1), pinned tabs, the last page. Blanks beyond ONE are closed when
idle (`_tab_idle_s`: created / last_used / last_change / first_seen) ≥ `BLANK_GRACE_S`
(30 min); the survivor is the oldest observed one, `about:blank` preferred over the NTP.
Full trim only when `_unknown_cdp_clients(port) == []`; otherwise (an MCP or other socket,
or no lsof → None) only the NTP and the startup blank are trimmed. The startup blank is
the page `_launch_and_record` records in tabs.json as `via: "startup"` once CDP is up
(`_opened_by_caller` requires `via == "open"`, so this proves no ownership). Plus launch
with `about:blank` as the start URL so no NTP/One Google Bar is created. Closes share
`BLANK_CLOSE_BUDGET_S` (5 s), each after a fresh re-check (still blank, same url_h, > 1
page).

**MCP orphan rule** (objection 3): from one `ps -axo pid,ppid,lstart,command` snapshot,
group the `npm exec @playwright/mcp…` / `node …playwright-mcp…` processes whose command
has `--cdp-endpoint` on THIS instance's port (`localhost`/`127.0.0.1`) by their top
npm/node ancestor. The ONLY orphan criterion: that top process has ppid 1. No name
allow-list of parents — a live parent of any name spares the group. Kill the group
(top + descendants): SIGTERM, 3 s, SIGKILL; pid + raw lstart re-checked before each
signal (no pid-reuse kills). Never anything without `--cdp-endpoint` to this port. MCP
kills run from the timer only (never from the `reap -o` after `up`). Budget
`MCP_REAP_BUDGET_S` (5 s).

**`browser.py reap`** (new umbrella; all flags short+long, `-h`): runs per instance, in
order, each step with its own budget: `reap-owned` dead owners (`REAP_CLOSE_BUDGET_S`,
30 s) + orphan markers (10 s) → blank trim (5 s) → `reap-idle` (unchanged rules;
`REAP_IDLE_DEADLINE_S` 8 s + gate 2 s + lease 3 s) → MCP orphans (5 s): ≈ 63 s; overall
deadline `REAP_TOTAL_S` = 75 s, a step not started before it is reported skipped. Each step
is wrapped so a `SystemExit` (e.g. a guided login's 75 from `_registry_register`) is
reported as "skipped" with rc 75, never aborting the following steps; `reap-idle`'s 75
(client registered) is likewise "skipped", not an error. Flags: `-n/--dry-run` (pure read,
prints `would close:` / `would kill:`), `-A/--all-instances` (same fan-out as
`reap-idle -A`, never launches one), `-q/--quiet` (only actions and ❌),
`-I/--idle-hours` (passed to reap-idle), `-o/--orphans-only` (owned + orphan markers
only: the cheap pass for `up`; no MCP kills). Output ✅/❌ lines, origins only
(`_target_label`), exit aggregated 1 > 75 > 0.

**Hook into `up`** (objection 10): after a successful `up` (already-running or fresh),
spawn `browser.py reap -o -q` detached (`start_new_session`, stdout/err to the journal
log), so `up` never waits on it — at most once per 10 min per instance, rate-limited by
the stamp file `<cache>/reap-after-up.stamp` (mtime). Not from `_preflight`/`status`
(convention kept).

**Timer** (Albert, 2026-11-06, fixed): the existing label `com.albert.browser-tab-reaper`
switches its args from `reap-idle -A -q` to `reap -A -q` AND its interval from 15 min to
**2 h** (`StartInterval` 7200); no second timer. The cleanup after each use (owned-tab close
on exit, `reap -o` after `up`) stays; the 2-h timer only catches what that misses. Same
log; reinstalled by bootout + bootstrap of that one label (as in tp#1109 B5).

**Ledger/tabs.json invariants** (tp#1765, landed browser-login 09a9407: `close -i` skips the
lease for caller-owned tabs):

- `_caller_ledger_tids` reads ledger files exactly as `_owned_ledger_tids` and `_reap_owned`
  do; any ledger-format change (fields, stem naming, `pid_start_time`) updates all three
  together, with a shared test. Marker v2 changes only the marker string, not the format.
- tabs.json `opener` + `created` + `via` now prove ownership for `close -i`: any reaper pass
  that prunes or rewrites tabs.json leaves these fields unchanged for live tabs.
- Deleting a dead owner's ledger is safe (the close fast path just turns off for that owner).

**Lighter launch** (lever 5): add Playwright's own default set for a headless agent browser
that does not affect logins: `--disable-background-networking`,
`--disable-component-update`, `--disable-default-apps`, `--disable-sync`,
`--disable-features=Translate,MediaRouter,OptimizationHints,NtpOneGoogleBar` (exact list
verified against `chrome://version` of chromium-1248). NOT `--renderer-process-limit`
(site isolation/stability — see Questions). Measure on a disposable instance (RSS sum +
CPU after 10 min idle with the same 3 test tabs) with and without the flags.

## Steps

- [x] B1 **Marker v2 + create fix.** `_new_owned_marker()`, `_marker_owner(marker)` →
      (pid, lstart hash) | None, `_marker_owner_state(marker)` → live/dead/unknown;
      `_create_owned_target` late-reply poll (5 s), no keep-pending (lighter option of
      objection 5: rely on marker v2). Tests: marker round trip, hash = raw-lstart hash
      (no epoch), legacy marker → None, lstart unknown → legacy form, late listing within
      the poll is bound and closed.
- [x] B2 **Orphan marker rule + observation pass** in `_reap_owned` (pure
      `_orphan_markers(snapshot, ledger_refs, observed, now, pid_state)`), reported in
      `reap-owned` output. Tests: v2 dead/live/reused pid, `ps` failure spared, legacy
      within/after grace, marker named by a ledger of any state (incl. tmp file),
      unreadable ledger stops, last-page veto, URL changed before close, dry run writes
      nothing, "reap-idle skipped (75), legacy marker still aged".
- [x] B3 **Blank trim** (pure `_blank_extras(pages, state, owned, restricted, now)`) +
      `about:blank` start URL + `via: "startup"` record at launch. Tests: keeps exactly
      one, prefers about:blank, grace, pinned, last page, ledger root and child excluded,
      marker URL and `about:blank#x` never blank, unknown client → only NTP + startup
      blank, lsof None → restricted.
- [x] B4 **MCP orphans** (pure `_mcp_orphans(ps_rows, port)`, kill with pid+lstart
      re-check). Tests: ppid-1 group killed, live non-claude parent spared, live claude
      parent spared, other port spared, `localhost` vs `127.0.0.1`, npm+node pair as one
      group, pid reuse between signals.
- [x] B5 **`browser.py reap`** umbrella (flags above, per-step budgets, SystemExit → 75
      skipped, -A fan-out, dry run pure read, severity aggregation) + detached rate-limited
      `reap -o -q` after `up`. Tests with the fake CDP: dry run persists/closes nothing,
      `-o` skips blank/idle/MCP, SystemExit in one step does not stop the next, exit
      aggregation, stamp file limits the spawn to once per 10 min.
- [x] B6 **Launch flags**: add the set above; disposable-instance measurement
      before/after (`CLAUDE_BROWSER_CACHE_DIR=<tmp> browser.py --cdp-port <free> up`,
      own profile, no real cookies); `doctor` on that instance.
- [x] B7 **Timer**: `agent_plists()` reaper args → `reap -A -q`, `TAB_REAPER_INTERVAL_S`
      (`StartInterval`) 900 → 7200 (2 h, Albert's decision); test of the generated plist;
      reload of that one label (bootout + bootstrap gui/<uid>).
- [x] B8 **Docs**: README "Tabs: who opened what…" section (+ `reap`, MCP orphans, idle
      stop out of scope), `docs/AGENTS_REFERENCE.md` "Owned-tab ledger" / "Idle-tab
      reaper" bullets (reaping now also via `reap`; orphan-marker and blank rules),
      AGENTS.md hard-rule line "Nothing closes a real tab outside …" gains `reap`.
- [x] B9 **Live rollout** (9222): `reap -A -n` dry run, review list; first real run with
      `-o` only (dead-owner tabs + v2-dead markers); legacy orphan markers only after the
      go below; before/after windows/tabs/RSS recorded in the ticket; LaunchAgent reloaded
      and its first run logged without ❌.
  ↳ evidence 2026-11-06: reaper LaunchAgent reloaded 2026-11-06 15:11 CET with reap -A -q / 7200 s; reap -A -n dry run: 0 to close/kill (only default instance up); first launchd run (kickstart) exit 0, quiet log; 9222 before/after 1 page, 11 procs, 4 renderers; legacy-marker path not exercised (no markers present)

## Verification

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff format --check bin/browser.py agent_login_jobs.py
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff check bin/browser.py agent_login_jobs.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run mypy bin/browser.py agent_login_jobs.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pylint bin/browser.py agent_login_jobs.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests/test_browser_reap_tp1759.py tests/test_tab_reaper.py tests/test_owned_tabs_tp845.py tests/test_owned_ledger.py tests/test_connect_hang.py tests/test_agent_login.py
cd /Users/albert/obsidian/42-Git/home/browser-login && bin/browser.py reap -h
cd /Users/albert/obsidian/42-Git/home/browser-login && bin/browser.py reap-owned -h
```

(`tests/test_down.py` is not needed: with idle stop out of scope nothing uses the `down`
internals.)

## Acceptance

- A1 (agent; headless): `browser.py reap -A -n` on the live browser. PASS: exit 0; only
  orphan markers / extra blanks / dead-parent MCPs listed; no http(s) tab younger than the
  idle threshold, no pinned tab, no live-ledger tab.
- A2 (agent; headless): after the real run, `/json/list`. PASS: no `#owned-` page without
  a live ledger; ≤ 1 blank page; window count = page count.
- A3 (agent; headless): `launchctl print gui/<uid>/com.albert.browser-tab-reaper` + log.
  PASS: args `reap -A -q`, interval 7200 s, one run logged without ❌.
- A4 (agent; headless): `browser.py logged-in switch` and `logged-in cscs` after the
  rollout. PASS: exit 0 (no reaper step stopped the browser or dropped a session).

## Decisions / assumptions

- Lever 1 needs no new metadata store: the tp#845 ledger already records pid + start time;
  marker v2 only covers the ledger-less orphan case.
- "Close empty extra windows" = close orphan/blank pages (a headless window dies with its
  last page; no page-less windows exist).
- No idle stop in v1 (see Out of scope v1).
- `reap-idle` keeps its own rules unchanged; `reap` only orchestrates it.
- Objection 5: the lighter option (no keep-pending; marker v2 + late-reply poll).

## Questions for Albert

- Close the 4 existing LEGACY orphan markers (no ledger, no pid in the URL, ≥ 10 min old)
  in the first real run? Recommendation: yes — no process can own a marker without a ledger.
- Skip `--renderer-process-limit` (would merge sites into shared renderers; stability and
  isolation cost)? Recommendation: skip.

## Debate outcome (Opus adversary)

Critic: fresh Opus subagent, 2026-11-06, 1 round. VERDICT sound-with-fixes; Codex could
not debate it.

1. [blocker] Idle stop logs out the SWITCH browser-session cookie / never fires —
   ACCEPTED: old B5 dropped; "Out of scope v1" note added; idle-stop flags, acceptance
   items and questions removed; boxes renumbered (B6-B10 → B5-B9).
2. [major] Blank trim too loose — ACCEPTED: raw URL exactly `about:blank` /
   `chrome://newtab/` and not an owned marker; every ledger tid (roots + children)
   excluded; full trim only when `_unknown_cdp_clients(port) == []`, else only the NTP
   and the startup blank (`via: "startup"`, recorded at launch).
3. [major] MCP orphan rule by name allow-list — ACCEPTED: the only criterion is ppid 1 of
   the group's top npm/node process, pid + lstart re-checked before each signal; test with
   a live non-claude parent that must be spared.
4. [major] Legacy markers never age when reap-idle is skipped — ACCEPTED: B2's own
   observation pass under `tabs.lock`, independent of gate/unknown clients; test
   "reap-idle skipped (75), legacy marker still aged".
5. [major] Keep-pending leaves entries forever — ACCEPTED, lighter option chosen: no
   keep-pending; marker v2 + 5 s late-reply poll (B1).
6. [minor] 15 s overall deadline inconsistent with the step budgets — ACCEPTED: per-step
   budgets (30 + 10 + 5 + 13 + 5 s ≈ 63 s), overall `REAP_TOTAL_S` 75 s.
7. [minor] A step's SystemExit kills the umbrella — ACCEPTED: each step wrapped,
   SystemExit → "skipped"/75.
8. [minor] Verification `cd … &&` into a worktree — ACCEPTED: repo-root absolute paths,
   one command per line.
9. [minor] tp#1765 coverage — ACCEPTED: `tests/test_connect_hang.py` added to Verification;
   `tests/test_down.py` not needed (no `down` internals used any more).
10. [minor] `reap -o` on every `up` — ACCEPTED: stamp file, at most once per 10 min per
    instance; MCP kills from the timer only.
11. [minor] Marker start time as epoch — ACCEPTED: v2 marker carries a 12-hex sha256 of the
    raw lstart string the ledger stores as `pid_start_time`; no epoch conversion.
