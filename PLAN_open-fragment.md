# PLAN: `browser.py open` with a URL that carries a #fragment (tp#1900)

> **Resume here.** Status: planned (Opus), not debated, nothing built. Next box: B1.
> Planned against `HEAD` 05fd068 (2026-11-18). `bin/browser.py` is LIVE (consumers
> exec it): every code box works in ONE worktree
> (`git -C /Users/albert/obsidian/42-Git/home/browser-login worktree add
> /Users/albert/obsidian/42-Git/home/browser-login/.worktrees.noindex/open-fragment -b
> open-fragment`) and B6 installs atomically. Never touch the live 9222/9223 browser
> in a test; B1/B4 use a disposable headless Chromium on a free port.

## Session

Ticket: tp#1900 (depends on tp#1724, resolved)
Resume: `c --resume 294aa102-b944-4da6-8df6-74fa8409ef3b`

## Problem (ticket, live 2026-11-08 22:26 CET, tp#1724 B8 step 7)

`browser.py open https://decide.dom42.space/pair#<code>` printed `✓ Opened` and a
`target=` line, but the tab never navigated: `tabs` showed LOADED `-` and origin
`about:…`, and `eval -T <id>` timed out after 60 s ("tab unresponsive"). The same
URL without its fragment opened fine. Two defects: (1) the fragment URL does not
load, (2) `open` reports success for a navigation that never happened.

## Findings (code read, HEAD 05fd068) — the ticket's mechanism is NOT what the code does

The ticket says `open` "appends its own `#owned-<pid>-<hash>` marker to the target
URL". It does not, and has not since tp#1792 (376efc2, 2026-11-06, two days before
the incident):

- `_open_new_raw` (bin/browser.py:6307) → `_open_create_target` (6053):
  `Target.createTarget {url: about:blank#owned-<marker>, background: true}`
  (`_owned_marker_url`, 12258; `_cdp_create_background_target`, 1640), THEN
  `_cdp_navigate_target` (6088) sends `Page.navigate {url: <the caller's URL,
  untouched>}` on the tab's own websocket. The marker lives only on the initial
  `about:blank` document; the navigated URL never contains it.
- `_cdp_navigate_target` treats ANY answered `Page.navigate` as success: it ignores
  `errorText` (by design — "a page error still counts") and ignores a missing
  `loaderId` (CDP's signal for a same-document navigation, i.e. nothing loaded).
- `_await_target_load` (6028) polls `/json/list` up to 15 s while the tab is on
  `about:blank` or a marker, then returns whatever it last saw — the caller
  (`_open_new_raw`, 6331) prints `✓ Opened: about:blank#owned-…` and exits 0 even
  when the tab is still on its marker. That is defect (2), exactly as observed
  ("origin about:…").

So the true root cause of (1) is unknown. Hypotheses B1 must decide between:

- **H1** Chromium treats `Page.navigate` from the marker document to a URL with a
  fragment specially (answers without `loaderId` / with `net::ERR_ABORTED`, never
  commits). Would reproduce on a disposable Chromium with a local server.
- **H2** The navigation is sent before the new target's frame can take it; the
  fragment is incidental (timing). Would reproduce intermittently, not per-URL.
- **H3** Site/network specific: the decide hub (LAN-only after tp#1724) left the
  navigation provisional (no commit) — macOS Local Network privacy (cf. tp#703) or
  the hub's `/pair` handling of the hash. Would NOT reproduce with a local server.
- **H4** The URL was altered before `browser.py` saw it (caller quoting, `#` in the
  shell). Ruled in/out by the journal's redacted argv for that run, if still kept.

### Every reader of the owner marker today (none of them needs it in the navigated URL)

| Reader | Line | Use |
| --- | --- | --- |
| `_is_blank` | 6017 | a marker tab is never "blank" (never reused) |
| `_await_target_load` | 6028 | keeps waiting while the tab is on its marker |
| `_open_create_target` / `_marker_target` | 6053 / 12644 | lost create reply → find the late tab by its exact marker URL, close it |
| `_match_page` (`eval -u`, default `eval`) | 6156 | a marker tab is never an eval match |
| `_create_owned_target` / `_owned_background_page` | 12719 / 12654 | ledger two-phase: pending marker → bind tid; lost reply recovery |
| `_reap_owner` phase-1 resolution | 12909 | ledger entry without tid → resolve by marker URL |
| `_is_blank_page_url` / blank trim | 12948 | a marker is never a trimmable blank page |
| `_tabstate_observe_reapable` | 12996 | marker pages age in tabs.json (`first_seen`) |
| `_orphan_markers` (`reap -A`, the 2 h LaunchAgent) | 13030 | a marker page no ledger names: v2 + dead owner → close; legacy → close after 10 min |
| `_owned_ledger_tids` (`close`/idle reap exemption) | 20617 | ledger marker entries resolved by URL |

`eval -T` does NOT read the marker (`_eval_target_raw`, 6450: by target id only);
its 60 s timeout in the incident is the stuck tab itself. `tabs` ownership for
`open` tabs is `tabs.json` `via="open"` + target id (`_tabstate_record_open`,
20496), also marker-free. An `open -N` tab is a caller handoff: never ledgered,
never reaped by ledger (README §owned tabs).

## Options for carrying the owner marker (weighed)

| # | Option | Lost-create-reply recovery (tp#1792) | Orphan reaping (tp#1759) | Fragment safety | Verdict |
| --- | --- | --- | --- | --- | --- |
| O1 | **Keep today's split**: create on `about:blank#owned-<marker>`, `Page.navigate` to the untouched URL; marker only on the initial document | yes (by URL) | yes | the URL is never touched; the bug is in the navigate/verify step | **chosen** |
| O2 | Create on plain `about:blank`; ownership by target id only (tabs.json) | no: a late tab is a plain blank, indistinguishable from another client's fresh `open -N` handoff | only via the blank trim | yes | rejected: regresses tp#1792 |
| O3 | Create directly on the caller's URL (pre-tp#1792) | no: a late tab is an unowned content tab no rule closes | no | yes | rejected: reintroduces the leak tp#1792 fixed |
| O4 | Marker in `window.name` / `sessionStorage` via `Runtime.evaluate` after create | no (needs the tid first, same as O2) | would need a per-tab eval in every reap pass | yes | rejected: page-visible to the site, cleared/varies on cross-site navigation, costly |
| O5 | O1, but navigate over a flattened browser-session attach (`Target.attachToTarget` + `Page.enable`) and wait for `Page.frameNavigated` of the main frame | yes | yes | yes | fallback inside O1 if B1 proves H1/H2 (event-based commit instead of fire-and-forget) |

Decision: **O1**. The marker already never reaches the navigated URL; the plan adds a
test that pins that invariant (B3) so a later change cannot start appending to the
URL, and fixes the navigate/verify step. Whether `Page.navigate` stays on the page
websocket or moves to O5's attached session is B1's output, not a guess here.

## Design

1. **Root-cause fix (B2)** per B1's finding, inside `_open_create_target` /
   `_cdp_navigate_target` only:
   - H1: if Chromium will not cross-document-navigate the marker document to a
     fragment URL, navigate in two steps that keep the marker semantics: first
     `Page.navigate` to the URL WITHOUT its fragment is NOT acceptable (a hash
     SPA reads `location.hash` on load); instead use O5 (attach + `Page.enable`,
     `Page.navigate`, wait for the main frame's `frameNavigated` with a non-marker
     URL) or `Page.navigate` with `transitionType: "typed"` — whichever B1 measured
     to commit with the fragment intact.
   - H2: wait for the target to be listed WITH a committed marker URL (today the
     wait is only for a websocket URL) before `Page.navigate`, or O5.
   - H3/H4: no navigation change; B2 shrinks to the verification below plus a
     README note, and the site-specific cause is a follow-up ticket.
2. **Navigation verification (B2, always)**: after `Page.navigate`, `open` waits
   up to `OPEN_LOAD_BUDGET_S` (new constant, 15 s — today's `_await_target_load`
   budget; override `-w/--wait SECONDS`, `-w` is free on `open`) for the tab's
   `/json/list` URL to leave `about:blank` / its marker. Outcomes:
   - committed on the target origin (scheme+host+port of the requested URL): `✓`
     as today, exit 0;
   - committed on another http(s) origin (a redirect, e.g. SSO login): `✓` plus
     one `⚠ open: redirected to <origin>` line on stderr, exit 0 (guided login's
     `open -N` of a login URL relies on redirects succeeding);
   - still on `about:blank` / its marker at the deadline: close the tab (as a
     failed navigate does today), `❌ open: the new tab did not navigate to
     <origin> within <N>s (tab closed)`, no `target=` line, exit 1;
   - `Page.navigate` answered `errorText` or the tab is on `chrome-error://`:
     **unchanged — still exit 0** (documented tp#1792 behaviour; see Questions).
   Every ❌/⚠ line is origin-only (`_tab_hint`): a fragment can be a pairing code
   or an OAuth token. The `✓ Opened:` line keeps printing the URL Chrome reports
   (existing behaviour, README "`open` already prints every navigated URL").
   `_open_create_target`'s return gains the "did not navigate" case; `_await_target_load`
   is `open`'s only caller and is folded into it (no other caller: grep 6331).
3. **Journal**: one `open_navigate` event per open with `loader` (bool),
   `error` (CDP `errorText`, plain), `committed` (`target` / `redirect` / `none`),
   origin only — so the next live incident is diagnosable from the journal.
4. **Callers**: `_guided_open_owned` (18909) already treats exit ≠ 0 or no
   `target=` as failure — no change. mydotfiles `SKILL.md` shows
   `tid=$(browser.py open … | sed -n 's/^target=//p')` — unchanged contract
   (no `target=` on failure). `login_viewer.py` only references `open -N` ids.

## Boxes

- [ ] B1 [opus] Root cause, no browser.py change (scratch script in the worktree's
  `tests/` is fine, deleted or turned into B4 afterwards). On a disposable headless
  Chromium (the `test_ws5_client_s2_cdp.py` launch pattern: free port, temp
  profile, temp `CLAUDE_BROWSER_CACHE_DIR`) plus a local `http.server` serving
  `/pair` that writes `location.hash` into the title: run `browser.py`'s
  `_open_create_target` + `_await_target_load` for `/pair` and `/pair#code-123`,
  record the raw `Page.navigate` reply (`loaderId`, `errorText`), the listed URL
  over time, and whether `Runtime.evaluate` answers. One run each, no loops. If it
  reproduces → H1 or H2 (tell which by also sending `Page.navigate` after the
  marker is listed as committed). If it does not → ask the overseer for one
  attended run of the same script against `https://decide.dom42.space/pair#bogus`
  on the disposable instance (H3), and check the journal for the 2026-11-08 22:26
  run's argv (H4). Output: a `## Root cause` section handed back to the overseer
  (plan edits are the overseer's), naming the chosen B2 variant.
- [ ] B2 [opus] (after B1) `bin/browser.py` in the worktree: the B1 navigation fix
  (Design 1) + navigation verification and `-w/--wait` (Design 2) + the
  `open_navigate` journal event (Design 3); `open`'s help/description names the
  exit-1 case. Touches `_open_create_target`, `_cdp_navigate_target`,
  `_await_target_load`, `_open_new_raw`, `cmd_open`, `_add_open_eval_parsers`,
  the `open` dispatch (21761). Nothing else reads the marker differently.
- [ ] B3 [sonnet/tests] `tests/fake_cdp.py` + `tests/test_connect_hang.py`
  (no real browser): fake `_navigate` gains `navigate_noop` (answers like the
  incident per B1 — ok, URL never changes) and `navigate_redirect_to` (commits
  another origin). Tests, one run each: (a) URL with fragment → exit 0, the fake's
  `Page.navigate` param is byte-identical to the requested URL (fragment intact),
  the `createTarget` param is a marker URL and the marker substring appears in no
  `Page.navigate` param; (b) the same without fragment; (c) `navigate_noop` with
  `OPEN_LOAD_BUDGET_S` monkeypatched to 0.3 → exit 1, one ❌ line that is
  origin-only (no `code-123` in stderr/stdout), no `target=`, tab closed;
  (d) redirect → exit 0 + one ⚠ line; (e) `-w` parses and reaches `cmd_open`.
- [ ] B4 [sonnet/tests] `tests/test_open_fragment_chromium.py` (new,
  `@pytest.mark.launches_chrome`, skipped when Playwright's Chromium is missing;
  disposable Chromium + local `http.server` as in B1, never the shared browser):
  `cmd_open` on `/pair` and on `/pair#code-123` → both exit 0; `eval -T <id>`
  (`_eval_target_raw`) returns `location.hash` `""` and `"#code-123"`
  respectively; the browser is stopped in a `finally`. Deterministic: the server
  answers instantly, one open per case, no repeats.
- [ ] B5 [sonnet/docs] README `open` rows (around line 76): exit 1 when the tab
  did not navigate within `-w` (default 15 s), the ⚠ redirect line, fragments are
  passed through untouched; one line in the owned-tabs section that the marker is
  only ever the initial `about:blank` of the tab.
- [ ] B6 [sonnet/verify] Verify + install + land: `ruff format`, `ruff check`,
  `mypy`, `uv run pylint` on the touched files; targeted tests
  (`tests/test_connect_hang.py`, `tests/test_owned_tabs_tp845.py`,
  `tests/test_tab_reaper.py`, `tests/test_guided_login.py`, the B4 file); full
  suite only via `pytest-slot -- uv run pytest`; `bin/browser.py -h` and
  `bin/browser.py open -h` exit 0. Install `bin/browser.py` atomically (check the
  live file still equals the worktree base, `cp` to a temp name in `bin/`, `mv`),
  then `ai.py push -W <worktree>` naming every changed file.
- [ ] B7 [opus] **[Albert]** acceptance on the live browser (ticket's
  `acceptance: needed yes`): `browser.py open 'https://decide.dom42.space/pair#<a
  bogus code>'` → `✓` + `target=`; `browser.py eval -T <id> 'location.hash'`
  returns the fragment; `browser.py close -i <id>`. Then one URL that cannot load
  in time (e.g. a blackholed LAN address with `-w 3`) → `❌`, exit 1, no tab left.

## Verification

```bash
cd /Users/albert/obsidian/42-Git/home/browser-login/.worktrees.noindex/open-fragment && uv run pytest -q tests/test_connect_hang.py tests/test_owned_tabs_tp845.py tests/test_tab_reaper.py tests/test_guided_login.py tests/test_open_fragment_chromium.py
cd /Users/albert/obsidian/42-Git/home/browser-login/.worktrees.noindex/open-fragment && uv run ruff check bin/browser.py tests/fake_cdp.py tests/test_connect_hang.py tests/test_open_fragment_chromium.py
cd /Users/albert/obsidian/42-Git/home/browser-login/.worktrees.noindex/open-fragment && bin/browser.py open -h
```

Definition of done:

- B3 (a)-(e) and B4 pass; the existing tp#1792 tests in `test_connect_hang.py` and
  `test_owned_tabs_tp845.py` pass unchanged (lost reply, late tab, navigate failure).
- No ❌/⚠ line of `open` contains a path, query or fragment.
- Live acceptance B7 done with Albert.

## Risks

- A legitimately slow first commit (> 15 s, e.g. a cold SSO hop) now fails `open`
  where it used to "succeed" on a blank tab. Mitigation: `-w`; guided login's
  `_self_run(... timeout=60.0)` already allows passing `-w 45` if B7 shows need.
- Closing a tab that commits right after the deadline: the close is by target id,
  so a commit in between still closes our own tab — never another client's.
- If B1 cannot reproduce anywhere (H3 not confirmable without Albert), B2 still
  lands the verification, which turns the silent failure into a ❌ — the ticket's
  second demand — and the root cause becomes a follow-up ticket.

## Questions for Albert

- Should a Chrome error page (`errorText` / `chrome-error://`, e.g. DNS failure)
  also make `open` exit 1? Recommendation: not in this ticket — it is documented
  tp#1792 behaviour and some callers may inspect the error page; a separate ticket
  if wanted.
- Should `open`'s `✓ Opened:` line stop printing the full URL (a fragment can be a
  pairing code / token)? Recommendation: yes, origin-only, as a separate small
  ticket (it changes output other tools may scrape).
