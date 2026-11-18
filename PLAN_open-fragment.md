# PLAN: `browser.py open` with a URL that carries a #fragment (tp#1900)

> **Resume here.** Status: planned (Opus), debated (Opus adversary, 2026-11-19, Codex
> seat unavailable; see "Debate outcome"), nothing built. Next box: B1.
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
  shell). NOT checkable from the journal: `open` argv is logged origin-only
  (`_journal_origin`, bin/browser.py:2245/2294); dropped as a B1 step.

### Journal evidence (`~/.cache/claude-browser/journal.jsonl` lines 7193-7204)

- 22:25:51 failing `open https://decide.dom42.space -N` (origin-only argv):
  `held_ms` 16257 = ~1 s create+navigate + the full 15 s `_await_target_load`. So
  `Page.navigate` answered quickly and the tab never committed.
- 22:26:27 `eval -T 7BFB…` hits the 60 s watchdog (the stuck tab).
- 22:27:49 and 22:28:01 two further `open` runs: `held_ms` 1127 / 979 — the
  "same URL without fragment works" control ran ~2 min later, on a hub that had
  meanwhile been reached (warm). The journal cannot tell which run carried a
  fragment. Fragment vs. first-contact timing (H3: cold LAN hub, macOS Local Network
  privacy, tp#703) is therefore NOT separated by the incident; H3 is at least as
  likely as H1. Expected B1 outcome: **not reproduced locally** — then B2 is the
  verification fix only and the root cause is a follow-up ticket.

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

## Root cause (B1, 2026-11-19)

**Not reproduced locally → B2 is verification-only (Design 2 and 3); the cold-LAN /
first-contact stall (H3) goes to a follow-up ticket.**

- Setup: `tests/repro_open_fragment.py` (5040df3) drives browser.py's own
  `_open_create_target` + `_await_target_load` on Playwright Chromium 148 (`--headless=new`,
  temp profile, temp `CLAUDE_BROWSER_CACHE_DIR`, free port) against a local `http.server`
  whose `/pair` writes `location.hash` into the title. Each order (`/pair` first,
  `/pair#code-123` first) got a fresh browser and server; each ended with an H2 probe
  (navigate only after `/json/list` showed the marker committed). Two runs. Evidence:
  `~/.claude/scratch/294aa102/tp1900-b1-evidence.json`.
- Result: every answered `Page.navigate` had a `loaderId`, no `errorText`, and committed in
  ~0.5–3.6 s; `location.hash` was `#code-123` for the fragment URL, `""` for `/pair`. No case
  took the incident's path (navigate answered, tab left on its marker, `✓`).
- H1 (Chromium will not leave the marker for a fragment URL): **refuted**. H2 (timing):
  **not supported**. H3 (site/network): **leading, unconfirmed** — decide's `web/public/sw.js`
  answers navigations network-first with no timeout, so a profile holding the service worker
  sent to a cold or unreachable LAN hub stays uncommitted on its marker until TCP gives up;
  a plain stalled connect does the same. H4: dropped (argv logged origin-only).
- `/pair#<bogus>` is side-effect free (`PairView.svelte` posts `/api/pair` only on submit),
  but `/pair` calls `history.replaceState(null, '', '/pair')` on mount, so `eval -T …
  location.hash` reads `""` after load: B7 checks the fragment another way or uses `/#x`.
- For B2: under load the listed URL briefly reads `""` right after a commit (3 of 5
  committed cases) — the poll treats `""` as undecided, never as "still on marker".
  `Target.createTarget` over its 5 s budget and the page websocket over its 1 s open timeout
  already exit ❌; they are not the incident's silent `✓`.

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
   for the tab's `/json/list` URL to leave its marker (and `about:blank`, unless the
   requested URL is itself `about:blank`). `OPEN_LOAD_BUDGET_S` (new constant, 15 s —
   today's `_await_target_load` budget; override `-w/--wait SECONDS`, `-w` is free on
   `open`) is the TOTAL deadline over `Page.navigate` (today's separate
   `OPEN_NAVIGATE_BUDGET_S` 10 s, 6050, is capped by what remains of it) and the commit
   poll, so `open -w N` never runs much longer than N s plus the create budget; `-w`
   is clamped to 50 s so it stays under guided login's `_self_run(timeout=60.0)`
   (18909) with margin. Outcomes:
   - committed on the target origin (scheme+host+port of the requested URL): `✓`
     as today, exit 0;
   - committed on another http(s) origin (a redirect, e.g. SSO login): `✓` plus
     one `⚠ open: redirected to <origin>` line on stderr, exit 0 (guided login's
     `open -N` of a login URL relies on redirects succeeding);
   - requested `about:blank`: committed = the tab left its marker → `✓`, exit 0;
   - committed on any non-marker URL that is not http(s) (`data:`, `file:`,
     `chrome://…`, `about:srcdoc`): `✓`, exit 0 (no origin comparison);
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

- [x] B1 [opus] Root cause, no browser.py change (scratch script in the worktree's
  `tests/` is fine, deleted or turned into B4 afterwards). On a disposable headless
  Chromium (the `test_ws5_client_s2_cdp.py` launch pattern: free port, temp
  profile, temp `CLAUDE_BROWSER_CACHE_DIR`) plus a local `http.server` serving
  `/pair` that writes `location.hash` into the title: run `browser.py`'s
  `_open_create_target` + `_await_target_load` for `/pair` and `/pair#code-123`,
  record the raw `Page.navigate` reply (`loaderId`, `errorText`), the listed URL
  over time, and whether `Runtime.evaluate` answers. One run per case, no loops,
  in both orders on fresh tabs (`/pair` then `/pair#x`, and `/pair#x` then
  `/pair`) so fragment and first-contact timing are told apart. If it reproduces →
  H1 or H2 (tell which by also sending `Page.navigate` after the marker is listed
  as committed). If it does not (the expected outcome, see "Journal evidence") →
  ask the overseer for one attended run of the same script against a side-effect-free
  decide URL with a fragment on the disposable instance (H3; `/pair#bogus` only
  if B1 first confirmed from the hub's code that loading `/pair` with a hash sends
  no pairing request). Output: a `## Root cause` section handed back to the
  overseer (plan edits are the overseer's), naming the chosen B2 variant, or
  "not reproduced → verification-only B2 + follow-up ticket".
- [ ] B2 [opus] (after B1) `bin/browser.py` in the worktree: the B1 navigation fix
  (Design 1) + navigation verification and `-w/--wait` (Design 2) + the
  `open_navigate` journal event (Design 3); `open`'s help/description names the
  exit-1 case. Touches `_open_create_target`, `_cdp_navigate_target`,
  `_await_target_load`, `_open_new_raw`, `cmd_open`, `_add_open_eval_parsers`,
  the `open` dispatch (21761). Nothing else reads the marker differently.
- [ ] B3 [sonnet/tests] `tests/fake_cdp.py` + `tests/test_connect_hang.py`
  (no real browser): fake `_navigate` (fake_cdp.py:241) gains `navigate_noop`
  (returns `{"frameId": <tid>}` with NO `loaderId` and NO `errorText`, leaves
  `target.url` on the marker — the incident's shape per the journal) and
  `navigate_redirect_to` (commits another origin). Tests, one run each: (a) URL with fragment → exit 0, the fake's
  `Page.navigate` param is byte-identical to the requested URL (fragment intact),
  the `createTarget` param is a marker URL and the marker substring appears in no
  `Page.navigate` param; (b) the same without fragment; (c) `navigate_noop` with
  `OPEN_LOAD_BUDGET_S` monkeypatched to 0.3 → exit 1, one ❌ line that is
  origin-only (no `code-123` in stderr/stdout), no `target=`, tab closed;
  (d) redirect → exit 0 + one ⚠ line; (e) `-w` parses and reaches `cmd_open`,
  and `-w 90` is clamped to 50; (f) `open about:blank` → exit 0 once the tab left
  its marker; (g) a commit to `data:text/html,x` → exit 0. (c) must fail on HEAD
  (today it exits 0): the builder shows that once before B2's code is in.
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
- [ ] B6 [opus] Verify + install the LIVE `bin/browser.py` + land: `ruff format`, `ruff check`,
  `mypy`, `uv run pylint` on the touched files; targeted tests
  (`tests/test_connect_hang.py`, `tests/test_owned_tabs_tp845.py`,
  `tests/test_tab_reaper.py`, `tests/test_guided_login.py`, the B4 file); full
  suite only via `pytest-slot -- uv run pytest`; `bin/browser.py -h` and
  `bin/browser.py open -h` exit 0. Install `bin/browser.py` atomically (check the
  live file still equals the worktree base, `cp` to a temp name in `bin/`, `mv`),
  then `ai.py push -W <worktree>` naming every changed file.
- [ ] B7 [opus] **[Albert]** acceptance on the live browser (ticket's
  `acceptance: needed yes`): `browser.py open 'https://decide.dom42.space/#x'` (a
  fragment on a side-effect-free route; `/pair#<bogus>` only if B1 confirmed it
  sends no pairing request) → `✓` + `target=`; `browser.py eval -T <id> 'location.hash'`
  returns the fragment; `browser.py close -i <id>`. Then one URL that cannot load
  in time (e.g. a blackholed LAN address with `-w 3`) → `❌`, exit 1, no tab left.

## Verification

```bash
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests/test_connect_hang.py tests/test_owned_tabs_tp845.py tests/test_tab_reaper.py tests/test_guided_login.py tests/test_open_fragment_chromium.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run ruff check bin/browser.py tests/fake_cdp.py tests/test_connect_hang.py tests/test_open_fragment_chromium.py
cd /Users/albert/obsidian/42-Git/home/browser-login && grep -c OPEN_LOAD_BUDGET_S bin/browser.py
cd /Users/albert/obsidian/42-Git/home/browser-login && bin/browser.py open -h
```

The block runs against the repo root on `main` (the landed, installed code), never
the worktree, which is gone or stale after `ai.py push -W`; the `grep -c` proves
the live `bin/browser.py` carries the change (it exits 1 on HEAD 05fd068). The
block is not strict-eligible on purpose: the change is only proven by the targeted
tests and the installed script's own `-h`, which run in the reviewer session.

Definition of done:

- B3 (a)-(g) and B4 pass; the existing tp#1792 tests in `test_connect_hang.py` and
  `test_owned_tabs_tp845.py` pass unchanged (lost reply, late tab, navigate failure).
- Only defect (2) is guaranteed a test that fails on HEAD (B3 c). Defect (1) is
  closed as fixed only if B1 reproduced it and B4 was shown failing on HEAD before
  B2; otherwise it is recorded as "not reproduced locally" with a follow-up ticket
  for the cold-LAN / first-contact hang (B4 and B7 then prove fragments pass
  through, not that the incident's cause is gone).
- No ❌/⚠ line of `open` contains a path, query or fragment.
- Live acceptance B7 done with Albert.

## Risks

- A legitimately slow first commit (> 15 s, e.g. a cold SSO hop) now fails `open`
  where it used to "succeed" on a blank tab. Mitigation: `-w`; guided login's
  `_self_run(... timeout=60.0)` allows passing `-w 45` if B7 shows need (`-w` is
  the total deadline and clamped to 50 s, so it stays under that 60 s kill).
- Closing a tab that commits right after the deadline: the close is by target id,
  so a commit in between still closes our own tab — never another client's.
- If B1 cannot reproduce anywhere (H3 not confirmable without Albert), B2 still
  lands the verification, which turns the silent failure into a ❌ — the ticket's
  second demand — and the root cause becomes a follow-up ticket.

## Scope calls (settled by the overseer, 2026-11-19)

- Chrome error pages (`errorText` / `chrome-error://`, e.g. DNS failure) keep
  exiting 0 — documented tp#1792 behaviour; OUT of this ticket.
- `open`'s `✓ Opened:` line printing only the origin (a fragment can be a pairing
  code / token) — a separate small ticket; OUT of this ticket.

## Debate outcome (Opus adversary)

Critic: fresh Opus subagent, 2026-11-19, 1 round (Codex round 0 refused:
`debate_seat_unknown`, the seat probe timed out). Verdict: sound-with-fixes.

1. [major] H4 journal-argv check impossible (argv is origin-only); journal timing
   points to first-contact/H3 — accepted: H4 dropped as a step, "Journal evidence"
   added to Findings, B1 runs both orders, "not reproduced" stated as the expected
   outcome.
2. [major] B6 `[sonnet/verify]`: no such class, and it swaps the LIVE script —
   accepted: B6 retagged `[opus]`.
3. [major] Verification block `cd`s into the worktree that is gone/stale after
   landing — accepted: block runs at the repo root on main, plus a `grep -c
   OPEN_LOAD_BUDGET_S` proof of install.
4. [major] "still on about:blank → exit 1" breaks `open about:blank`; non-http(s)
   commits undefined — accepted: Design 2 outcomes for both, B3 (f)/(g).
5. [major] No test fails on HEAD for defect (1) — accepted: Definition of done says
   only defect (2) is guaranteed a HEAD-failing test (B3 c, shown failing first);
   defect (1) closes as fixed only if B1 reproduces it.
6. [minor] B3 `[sonnet/tests]` underspecified (`navigate_noop` "per B1") —
   accepted: reply shape fixed now (`{"frameId"}`, no `loaderId`/`errorText`, URL
   stays on the marker).
7. [minor] Navigate budget + poll + `-w` can exceed guided login's 60 s kill —
   accepted: `-w` is the total deadline, clamped to 50 s; B3 (e) checks the clamp.
8. [minor] B7 on `/pair#bogus` may fire a pairing attempt on the live hub —
   accepted: B7 uses `https://decide.dom42.space/#x` unless B1 shows `/pair` is
   side-effect free.

Requirement challenges (relayed to Albert):

- R1 (moderate): the ticket's framing ("fragment collision") may chase an effect
  that does not exist — the only no-fragment control ran 2 min later on a warm hub.
  Alternative: retitle tp#1900 to "open reports success for a tab that never
  committed" and file the cold-LAN / first-contact hang separately if B1 does not
  reproduce. The plan keeps the ticket's framing until Albert decides.
