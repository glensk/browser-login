# PLAN: headless, unattended Notion login in the shared Chromium (tp#1633)

> **Resume here.** Status: planned + reconciled after one Opus critique round, nothing
> built. Next box: B1. Work in a worktree
> (`git -C /Users/albert/obsidian/42-Git/home/browser-login worktree add
> /Users/albert/obsidian/42-Git/home/browser-login/.worktrees.noindex/notion-headless -b
> notion-headless`) — `bin/browser.py` and `agent-login.py` are LIVE (consumers exec
> them). Install atomically at the end (B9). B10 is the live canary and is run by the
> build agent itself, not handed to Albert.

## Session

Ticket: tp#1633
Session: dbf9d84c-78a1-4c3c-89ad-9c924903487b
Decision (Albert, 2026-11-03): agents may renew the Notion session in the HEADLESS
shared Chromium (CDP 9222) anytime — also while Albert is away / the Mac is idle or
locked — with no Safari window and no focus loss. The Safari login stays for "log
Albert in" (attended only).

## Decisions

- D1 (Albert, 2026-11-03): headless Notion login allowed, also unattended; notion only.
- D2 (overseer, 2026-11-03): `notion_probe_verified: true` is set in
  `~/.config/agent-login/safari-logins.json` ONLY after the canary's
  `browser.py logged-in notion -R <file>` shows `server: invalid` AND `proof: server`
  for the logged-out session (B10 step 4). The overseer edits that private file.
- D3 (overseer): the code-mail cooldown is 15 min.
- D4 (overseer): `-L` stays refused inside LaunchAgents (`AGENT_LOGIN_SCHEDULED`), notion
  included — "anytime" means any agent session, not a scheduled job.

## Goal

`agent-login.py -L notion` renews Notion without a Safari window:

1. the shared Chromium is already logged in → done (exit 0);
2. Safari holds a session → `browser.py import-safari notion` (headless, no window);
3. **new:** headless e-mail-code login in the shared Chromium (`browser.py login
   notion -M`): e-mail → "Continue" → 6-digit code from `notify@mail.notion.so` read by
   himalaya → "Continue with login code" — NOT gated by `interactive_gate`, notion only;
4. only if 3 cannot run / stops before sending anything, and the interactive gate is
   open: the existing Safari login + import.

Plus: a real sentinel proof for notion's logged-in check, so agents.md stops saying
"weak proof (no sentinel yet)".

## Findings (read before building)

- **Account e-mail.** Resolves from the private override file
  `~/.config/agent-login/safari-logins.json`, key `notion.expected_email` (set today);
  browser.py reads it via `_notion_expected_email()` / `_safari_overrides("notion")`,
  agent-login via `_safari_plan`. The headless path uses the SAME value for the e-mail
  field and as the `To:` the code mail must be addressed to. Missing → stop
  `identity_unconfigured` (rc 2), nothing sent.
- **Mailbox.** Same file, `notion.mailbox = "epfl"` → `himalaya -a epfl` (EPFL Exchange,
  IMAP XOAUTH2). Tokens come from `sdsc/email/epfl_oauth.py token` (a 0600 file store,
  `~/.config/sdsc-email/tokens.json`): **no Keychain, no Touch ID** — works on an idle or
  locked (logged-in, FileVault-unlocked) Mac. Trap: when the EPFL refresh token is dead,
  `epfl_oauth.py` `_auto_reauth` OPENS A BROWSER (focus loss) unless
  `SDSC_EMAIL_NO_AUTO_AUTH=1`. Static read (2026-11-03): both himalaya token commands
  (`token` → line 665, `refresh-token` → line 689) reach `_auto_reauth`, whose first
  line is `if headless(): raise EpflAuthError` (`NO_AUTO_AUTH_ENV =
  "SDSC_EMAIL_NO_AUTO_AUTH"`, line 258) — and himalaya passes its own environment to
  `*.cmd` children. B1 still proves it with a test (see B1); if it does not hold, B1b
  applies. The headless path runs himalaya with that variable → a dead grant is
  `mailbox_unreadable` (rc 2, nothing triggered: the baseline is read first).
- **Reusable pieces** (all in `agent_login_safari.py`, stdlib-only, browser.py already
  imports this module lazily at ~line 15347): `RECIPES["notion"]` (step `mail_code`,
  senders, `code_re \b\d{6}\b`, subjects "login code"/"Anmeldecode", trigger
  "Continue", submit "Continue with login code"), `MailReader`, `mail_baseline`,
  `find_code` (new vs keyed baseline, DKIM pass for the sender domain, addressed to the
  expected e-mail, exactly one distinct code), `DETECTOR_JS`/`detector_js`
  (captcha incl. `challenges.cloudflare.com` frames and `#challenge-form`, sms, push,
  key, sentinel), `ALBERT_STOPS`, `MAIL_WAIT_S`, `MAIL_POLL_S`. `EMAIL_FILL_JS` /
  `CODE_FILL_JS` are `__PARAMS__` text-substituted IIFEs (lines ~1122-1153, used at
  ~1387/1401) — NOT usable with `page.evaluate(js, arg)`; B1 adds function-form
  variants. The Safari `Machine` itself is NOT reused (it speaks safari.py argv); the
  headless runner is a small sibling in browser.py driving a Playwright page.
- **Routing.** `browser.py login notion` resolves through `_resolve_site("notion",
  for_login=True)` (~17439): the static registry (name `notion`, ~17375) matches before
  the broker lookup, so the fill-only broker item never intercepts it (static read;
  B7 has a test, B10 runs it live).
- **Current browser.py notion login** (`cmd_notion_login`, ~15968) is guided-only:
  warm probe → `_guided_login_allowed` → NEEDS_ALBERT_RC (4). The logged-in check
  (`cmd_notion_logged_in` / `_notion_check`) is tri-state: server
  `/api/v3/loadUserContent` + sidebar `.notion-sidebar, .notion-sidebar-switcher`;
  proof `server` / `dom` / `dom-unverified`. `notion_probe_verified` is NOT set yet:
  only a 401 counts as "invalid"; an unverified opaque redirect is `indeterminate`
  (~15819, 15855-15859), and the stdout line cannot tell those apart (~16045-16048) —
  only the `-R` result record's `server` / `proof` fields can.
- **Why agents.md says "weak proof".** The broker lists a `notion` item that is
  `fill_only: true` with no `logged_in_selector` → `has_sentinel` False → the row's
  `sentinel` column (built ~645 in `_broker_fields`) is False → `needs_sentinel(row)`
  True (~1460, ~1067). The real proof is browser.py's own built-in check, which the
  row logic never consults.
- **`browser.py logout notion` does NOT work today:** `cmd_broker_logout` hits
  `_is_fill_only` → `_fill_only_exit` (exit 2, nothing touched). The cookie delete that
  exists is `_builtin_clear(port, "notion")` (ALL in-scope cookies via
  `safari_cookies.replaced_on_import`, shared jar only). Neither touches Safari:
  `broker/safari_cookies.py` only READS `Cookies.binarycookies`.
- **Timeouts.** `_result_timeout` (~10353-10363) quarantines on a `LoginDeadline`
  expiry only for phase `unknown` + a broker site — a deadline after the code submit
  would today leave notion UNquarantined (B2 fixes that). `login_timeout_s()` budget is
  480 s (runner adds `RUNNER_MARGIN_S` 90 s, `agent_login_jobs.py` ~469/510).
- **Interaction lease.** Every clicking flow takes registration (gate) first, then
  `_interaction_lease("login …")`, in an `_owned_background_page` closed in a
  `finally`; `_bring_to_front` is only for the headed-lease holder. Unattended `login`
  runs under `LoginDeadline`; agent-login passes `timeout_s=browser_timeout("login")`.

## Design

### Headless mail-code login (`browser.py login notion -M`)

New opt-in flag on `login`: `-M/--mail-code` ("notion only, else exit 2: the
unattended e-mail-code login in a background tab"). Without `-M` `login notion` keeps
today's behaviour (warm probe → guided gate → 4), so a stray `browser.py login notion`
never sends a code mail. Flow, in a fresh owned background tab (no `_bring_to_front`,
headless only — a headed browser without a live lease is reverted by the preflight as
today):

1. Warm probe outside the lease (`_notion_check` with expected):
   - `valid` + identity `match` → 0;
   - `valid` + identity `unknown` (or `unconfigured`) → rc 2 `indeterminate`, nothing
     sent (objection 10);
   - `valid` + `mismatch` → rc 2 `wrong_account` (the mail-code login would add a
     second account; the Safari import path owns that case);
   - `indeterminate` → rc 2 `indeterminate`;
   - only `invalid` (definite logged-out) goes on.
2. Preconditions, all before anything is sent: not quarantined
   (`_als.quarantined("notion")` → rc 2 `quarantined`); the per-site flock
   `<state>/notion-mail-code.lock` (non-blocking → `BUSY_RC` 75), held to the end;
   under it, the cooldown file `<state>/notion-mail-code.json` (own file, NOT
   `site-state.json`, which `prune()` can rewrite — objection 8) shows no trigger within
   `NOTION_MAIL_CODE_COOLDOWN_S` = 900 s (else rc 2 `cooldown`); expected e-mail set;
   himalaya on PATH (`himalaya_missing`).
3. Registration, then `_interaction_lease("login notion")` held for the whole flow.
4. Mail baseline (`mail_baseline`) BEFORE the trigger; unreadable → rc 2
   `mailbox_unreadable`, nothing sent.
5. `goto https://www.notion.so/login` (lands on `app.notion.com/login`); every page read
   re-checks the page host ∈ {`www.notion.so`, `app.notion.com`} (else rc 2
   `tab_moved`) and runs the detector. Any `ALBERT_STOPS` flag (CAPTCHA / Cloudflare
   challenge / sms / push / key) → stop NEEDS_ALBERT_RC 4 with fixed code
   `needs_albert_captcha` etc., **never a retry, never a reload**. A page that shows
   neither the e-mail field, the code field nor the sentinel for `IDLE_POLLS` reads
   (a silent headless block: blank page, "unusual activity", endless spinner) → rc 2
   `recipe_stuck` — a fixed code, bounded by `IDLE_POLLS × POLL_S`, never a loop.
6. Fill the e-mail (function-form `EMAIL_FILL_FN`, value passed as the
   `page.evaluate` argument — never argv, never a JS string). Require exactly ONE
   visible button with the exact label "Continue" (else `recipe_stuck`, nothing sent).
   **Then write the cooldown stamp (`{"at": <epoch>}`, atomic 0600) — BEFORE the
   click; a failed write aborts rc 2 `state_unwritable`, nothing sent (objection 2).**
   Then click.
7. Wait for the code: `find_code` polls (`MAIL_POLL_S`, `MAIL_WAIT_S` = 180 s, must agree
   on two consecutive polls, as `Machine._wait_code`). No code / several codes → rc 2
   `email_code`, no quarantine (nothing secret was submitted), cooldown stays. The
   code field must appear (`_OTP_FIELD`); if not within the wait → `recipe_stuck`.
8. Before the submit: `_result_set(phase_hint="mail-code-submitted", site="notion")`
   (objection 1) — from here a `LoginDeadline` expiry quarantines (B2). Fill + submit
   the code ONCE (function-form `CODE_FILL_FN`: exactly one visible button "Continue
   with login code" in the field's form; the code passes as the evaluate argument, the
   local is cleared in a `finally`, never printed / logged / put in the result file).
   From here `credential=True`: any later failure quarantines notion
   (`_als.quarantine("notion", phase, code)`) and the result record carries
   `quarantined: true`.
9. Archive the used mail (`MailReader.archive`, best effort; result `mail_archived`).
10. Proof: `_notion_wait_for_login` (60 s, passive) then `_notion_check(port, expected)`
    must say `valid` + identity `match` → rc 0, `_record_login_event("notion",
    "mail-code")`, result `route: mail-code`. Anything else (incl. an SSO redirect off
    the notion hosts) → quarantine + rc 2.

Once-only: steps 6 (trigger) and 8 (submit) each run at most once per process; there is
no loop back from a later step.

**Worst-case time budget (vs `login_timeout_s()` = 480 s):** warm probe ≤ 40 s (30 s
sidebar poll + 10 s server fetch) · flock/registration/lease ≤ 10 s · baseline 3
folders × (list + reads) ≤ 30 s (himalaya `timeout=30` per call is the per-call
ceiling; B3 caps total baseline reads at 45 s) · goto + detector reads ≤ 30 s ·
fill/trigger ≤ 5 s · code wait 180 s + last poll ≤ 30 s · fill/submit ≤ 5 s · archive
≤ 30 s · post-login sidebar wait 60 s + check 40 s = **≈ 460 s worst case** — under 480 s
but tight. B3 makes it safe: the post-submit sidebar wait shrinks to 45 s, archive gets
a 15 s cap, and the code wait is `min(MAIL_WAIT_S, deadline_left − 120 s)` so the
proof always has 120 s left. A deadline hit after step 8 still quarantines (step 8).

himalaya env: `SDSC_EMAIL_NO_AUTO_AUTH=1` for every MailReader call of this path
(MailReader gets an optional `env` field; default unchanged for the Safari path).

### `-L notion` pipeline (agent-login.py)

`safari_login_action` for notion only:

- `scheduled()` refusal stays (D4).
- The `interactive_gate()` call moves from the top to right before `_drive_safari`
  (notion only; other recipes keep the gate on top, unchanged).
- Lock order (objection 12): `safari_login_lock` is held for the free check and the
  Safari import only, then RELEASED before the `-M` subprocess (which serialises
  itself on the per-site notion flock); it is REACQUIRED only for a Safari fallback
  (after re-running the free-check gate: another run may have logged in meanwhile).
- Safari jar unreadable (today exit 3 at ~3826-3829, objection 4): for notion it counts
  as "no Safari session" → go to the headless route; the why is recorded in the
  result detail (`safari_jar: <why>`). Other recipes unchanged.
- Order: free check gate → Safari import (unchanged rules) → if the import did not stop
  the pipeline (same `IMPORT_STOP_RCS` / code rules) or Safari holds no / an unreadable
  session: run `browser.py login notion -M -R <result>` under `site_session("notion")`.
  - rc 0 → record_check ok, route `mail-code`, `✅ notion: logged in headlessly (e-mail
    code)`.
  - stop codes that must NOT fall through to Safari: any result with `credential` /
    `quarantined`, `needs_albert_*`, `cooldown`, `quarantined`, `wrong_account`,
    `indeterminate`, `email_code`, 75, timeouts → `_safari_fail(…, route="mail-code")`
    and exit.
  - stop codes that may fall through (nothing was sent: `mailbox_unreadable`,
    `identity_unconfigured`, `himalaya_missing`, `state_unwritable`, `recipe_stuck`
    with no trigger) → Safari login only when `interactive_gate()` is open; else exit 3
    with the gate's code (as today).
- `_safari_fail` gains a `route` parameter (default `safari-login`, objection 7); when
  the `-R` result already says `quarantined: true`, it does NOT call `als.quarantine`
  again (just reports it with the `-Q` hint).
- `-L notion -n` (dry run) also prints: whether the headless route is ready (expected
  e-mail set, himalaya present, mailbox baseline readable — read-only, no trigger), the
  cooldown state, and a value-free short HMAC of Safari's notion session fingerprint
  (`safari fp: <8 hex>`, keyed with a per-host constant salt so two runs compare;
  never the value) — used by B10 (objection 5).

### Real sentinel proof

- browser.py: `_notion_check_page` adds `sentinel: bool` (sidebar seen) to its dict;
  proof becomes `server+sentinel` when server `valid` AND the sidebar is up.
  `cmd_notion_logged_in` writes `sentinel` and that proof to the result record. Verdict
  rules unchanged (no new false negatives).
- agent-login.py (objection 9): where rows are built (`_broker_fields` ~645 /
  `overview`), a built-in-proof site (`notion`) whose latest check (`checks.json`) has
  proof `server+sentinel` gets `sentinel: "built-in"` (truthy, not `False`);
  `needs_sentinel(row)` stays row-only and unchanged (`is False` test), so the
  "weak proof" suffix disappears. The matrix shows `built-in`. Slack/OpenAI out of
  scope.

### Logout for the canary

`browser.py logout notion`: for `SAFARI_BUILTIN` sites check BEFORE the broker lookup
(the fill-only item would refuse) and delete ONLY the session cookies
(`NOTION_AUTH_COOKIES` = `token_v2`, `notion_user_id`, on the notion hosts) — device /
browser-id cookies (e.g. `notion_browser_id`, `device_id`) stay, so the next login is
not a "new device" (risk below). Runs under registration + `_interaction_lease("logout
notion")`; prints the count and the names deleted (names only); never touches Safari,
never calls the broker's `logout` op. Exit 2 when the jar is missing.

## Boxes

- [x] B1 `agent_login_safari.py`: `MailReader` gains an optional `env` mapping passed
  to `subprocess.run` (default None = inherit, Safari path unchanged); export
  `NOTION_MAIL_ENV = {"SDSC_EMAIL_NO_AUTO_AUTH": "1"}`; export function-form
  `EMAIL_FILL_FN` / `CODE_FILL_FN` (`(P) => {…}`, same bodies, for
  `page.evaluate(js, params)`) — the Safari `EMAIL_FILL_JS` / `CODE_FILL_JS` stay
  byte-identical (objection 6); module docstring gets a "Headless Notion" paragraph
  (the mail-code step may also run in the shared Chromium, `login notion -M`, ungated,
  notion only; same once-only + quarantine rules). Test: run
  `epfl_oauth.py token` logic with `SDSC_EMAIL_NO_AUTO_AUTH=1` against a temp
  `SDSC_EMAIL_STATE_DIR` with a dead store and `webbrowser.open` patched to fail →
  `EpflAuthError`, no browser call (imports `sdsc/email/epfl_oauth.py` by path, skipped
  when absent).
- [ ] B1b (only if the B1 epfl test shows `SDSC_EMAIL_NO_AUTO_AUTH` is NOT honoured on
  the himalaya `*.cmd` path): stop and hand back — the fix lives in the `sdsc/email`
  repo (`epfl_oauth.py` honours the variable in `token` and `refresh-token`), a separate
  ticket; B2 must not ship without it.
- [ ] B2 `bin/browser.py`: `login -M/--mail-code` flag (notion only, else exit 2) and
  `_notion_mail_code_login(port)` implementing Design steps 1–10 (owned background tab,
  registration → lease, detector stops, own cooldown file + flock with stamp BEFORE the
  click, once-only trigger + submit, quarantine after `credential`, archive, proof,
  result record fields `route`, `phase`, `code`, `mail_archived`, `quarantined`; no
  code value anywhere in output/result/journal). `_result_timeout` (~10353): when the
  result carries `phase_hint == "mail-code-submitted"` and `site == "notion"`, it calls
  `_als.quarantine("notion", "submit", "timeout")` and sets `quarantined: true`
  (objection 1).
- [ ] B3 `bin/browser.py`: the time budget of the Design section — baseline read cap
  45 s, archive cap 15 s, post-submit sidebar wait 45 s, code wait
  `min(MAIL_WAIT_S, deadline_left − 120)`; assert in a unit test that the sum of caps ≤
  `login_timeout_s()` (480 s) and that agent-login's `browser_timeout("login")` covers
  it (`agent_login_jobs.py`).
- [ ] B4 `bin/browser.py`: real sentinel — `sentinel` field + `server+sentinel` proof in
  `_notion_check_page` / `cmd_notion_logged_in` result record.
- [ ] B5 `bin/browser.py`: `logout SITE` for `SAFARI_BUILTIN` sites → delete only the
  site's session cookies (notion: `NOTION_AUTH_COOKIES`) under registration + lease,
  before the fill-only/broker path; help text says "shared browser only, session
  cookies only, Safari untouched".
- [ ] B6 `agent-login.py`: `-L notion` pipeline (gate moved before the Safari drive,
  lock released before `-M` and reacquired only for the Safari fallback, jar-unreadable
  → headless route, fall-through rules, `_safari_fail(route=…)` without double
  quarantine, record_check route `mail-code`, dry-run lines incl. `safari fp`); rows get
  `sentinel: "built-in"` for notion with a `server+sentinel` check.
- [ ] B7 tests (unit, no network, no real Chrome — `CLAUDE_BROWSER_TEST_NO_LAUNCH=1`):
  new `tests/test_notion_mail_code.py` with a fake page (pattern of
  `tests/fake_cdp.py` / `chromium_page.py`) and a fake himalaya runner
  (pattern of `test_ws1b_safari.py` mail tests):
  happy path (baseline → stamp → trigger once → one new DKIM-signed code to the
  expected address → submit once → sentinel → rc 0, mail archived);
  stamp written before the click (call order recorded) and an unwritable stamp →
  rc 2 `state_unwritable`, zero clicks;
  CAPTCHA / Cloudflare frame on the login page → rc 4 `needs_albert_captcha`, zero
  clicks, zero mail reads after baseline;
  silent block (blank page / no known element) → rc 2 `recipe_stuck` after
  `IDLE_POLLS` reads, no reload;
  no code within the wait → rc 2 `email_code`, no quarantine, cooldown stamped;
  second `-M` inside the cooldown → rc 2 `cooldown`, page never opened; a `prune()`
  of site-state leaves the cooldown file alone;
  two codes → `email_code`; an old (baseline) code ignored; wrong recipient / failed
  DKIM / foreign sender ignored;
  code submitted but no sidebar → quarantine written, `quarantined: true`, rc 2;
  deadline expiry after the submit (`_result_timeout` with the phase hint) →
  quarantine written; expiry before the submit → no quarantine;
  quarantined before start → rc 2, nothing opened;
  dead mailbox (himalaya fails) → `mailbox_unreadable`, no trigger; himalaya called
  with `SDSC_EMAIL_NO_AUTO_AUTH=1`;
  warm probe `wrong_account` / `indeterminate` / `valid`+identity `unknown` → rc 2,
  no trigger;
  the code never appears in stdout/stderr/result file (capsys + file scan);
  `login notion` without `-M` still returns 4 when not guided; `-M` on another site →
  2; `_resolve_site("notion", for_login=True)` returns the static notion Site even
  when the broker lists a fill-only `notion` item;
  budget test of B3.
  In `tests/test_ws1b_agent_login.py` / `test_agent_login.py`: `-L notion` order
  (logged in → import → headless → Safari), idle/locked gate does NOT block the
  headless route but DOES block the Safari fallback (exit 3), Safari jar unreadable →
  headless route (why recorded), `safari_login_lock` not held while `-M` runs, no
  fall-through after a credential/needs_albert/cooldown/email_code stop, no double
  quarantine when the result says `quarantined: true`, `_safari_fail` route
  `mail-code`, `scheduled()` still refuses, other recipes still gated on top; rows get
  `sentinel: "built-in"` and the agents.md notion line has no "weak proof"; `-n`
  prints the `safari fp` HMAC and never a cookie value. `logout notion` test: clears
  only `token_v2`/`notion_user_id`, keeps other notion cookies, never reads/writes
  Safari (safari_cookies patched to raise).
- [ ] B8 docs: README notion row (~586: no longer "Assisted" only — headless e-mail
  code via `-L notion`, unattended allowed; sentinel + server proof), the -L section
  (~1078–1170, 1562, 1586, 1593: order import → headless code → attended Safari);
  `docs/AGENTS_REFERENCE.md` §"Agents renew Albert's own sessions through his Safari"
  gets the notion exception; `agent-login.py` agents.md generator text (~939:
  "through Albert's Safari or the magic link" → add "Notion: headless e-mail code,
  also while Albert is away; exit 3 only for the Safari fallback") and the usage line
  ~47; regenerate with `agent-login.py -A` and check the notion line. Live skill (NOT
  editable by the builder — list for the overseer): `~/.claude/skills/browser-login/SKILL.md`
  line 139 (troubleshooting row `logged-in SITE exit 2 unexpectedly` → add "notion:
  `agent-login.py -L notion` (headless e-mail code, anytime)") and line 169 ("First
  login per site is manual (ask Albert once …)" → "… except Notion: agents renew it
  headlessly with `agent-login.py -L notion`").
- [ ] B9 verify + install: `ruff format`, `ruff check`, `mypy`, `uv run pylint` on every
  touched file; targeted pytest (new file + the touched test files) in the foreground;
  `bin/browser.py -h` and `login -h` exit 0; `browser.py doctor` against a DISPOSABLE
  instance (`CLAUDE_BROWSER_CACHE_DIR=<tmp> browser.py --cdp-port <free> up`, then
  `down`). Install into the live checkout atomically (cp to temp name + mv, after
  checking the live files are unchanged since the worktree base); commit with the
  grant the brief carries.
- [ ] B10 LIVE CANARY (build agent runs it, after B9, on the live 9222 browser — the
  one deliberate exception to "never login casually", approved by tp#1633). Result
  files go to a fresh `mktemp -d` dir (0700).
  1. `browser.py logged-in notion -R <dir>/before.json` → 0 (if not 0, stop and report).
  2. Safari baseline (read-only): `osascript -e 'tell application "Safari" to count
     windows'` → N0; `agent-login.py -L notion -n` → note its `safari fp: <hex>` line.
     Note the journal position: `browser.py journal -n 1` (or the journal file's line
     count, `wc -l` on the path `browser.py status` prints).
  3. `browser.py logout notion` → prints 1–2 cookies deleted (`token_v2`,
     `notion_user_id` only).
  4. `browser.py logged-in notion -R <dir>/out.json` → exit 2; assert in the file
     `"code": "logged_out"`, `"server": "invalid"`, `"proof": "server"` (a 401, not an
     opaque redirect — objection 3). Only then may the overseer set
     `notion_probe_verified: true` (D2). If `server` is `indeterminate`: stop, report,
     restore with `agent-login.py -L notion` (Safari import).
  5. Headless route forced: `browser.py login notion -M -R <dir>/login.json` → 0, result
     `route: mail-code`. (The `-L` pipeline would take the Safari import first while
     Safari holds a session.)
  6. Import route: `browser.py logout notion`, then `agent-login.py -L notion` → 0.
  7. After 5 and after 6: Safari window count == N0; `-L notion -n` `safari fp`
     unchanged; `browser.py status` shows mode headless; the journal lines since step 2
     contain no `bring_to_front` that is not `skipped` (`grep -c '"bring_to_front"'` on
     the new lines, each with `"skipped"`) and no `switch headed`.
  8. `browser.py eval-fresh -t 60
     'https://app.notion.com/p/renku/SDSC-Authentication-Service-Build-Team-3950df2efafc8065bb56cf328894afa9'
     'document.querySelectorAll("[contenteditable=true]").length'` → a number > 0.
  9. `browser.py logged-in notion -R <dir>/after.json` → 0, `"proof": "server+sentinel"`;
     `agent-login.py -A`; `grep -c "weak proof" ~/.local/state/agent-login/agents.md`
     on the notion line → 0.
  **Stop rules:** any exit 4 (CAPTCHA / Cloudflare / new-device challenge) or
  `recipe_stuck` in step 5 → no retry; report the code; restore via step 6 (Safari
  import) so notion is not left logged out. `email_code` → no retry inside the 15-min
  cooldown; restore via step 6, report. A quarantine → report, never `-Q` it yourself.

## Verification

```
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run --project /Users/albert/obsidian/42-Git/home/browser-login ruff format --check /Users/albert/obsidian/42-Git/home/browser-login/bin/browser.py /Users/albert/obsidian/42-Git/home/browser-login/agent-login.py /Users/albert/obsidian/42-Git/home/browser-login/agent_login_safari.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_notion_mail_code.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run --project /Users/albert/obsidian/42-Git/home/browser-login ruff check /Users/albert/obsidian/42-Git/home/browser-login/bin/browser.py /Users/albert/obsidian/42-Git/home/browser-login/agent-login.py /Users/albert/obsidian/42-Git/home/browser-login/agent_login_safari.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_notion_mail_code.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run --project /Users/albert/obsidian/42-Git/home/browser-login mypy /Users/albert/obsidian/42-Git/home/browser-login/bin/browser.py /Users/albert/obsidian/42-Git/home/browser-login/agent_login_safari.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run --project /Users/albert/obsidian/42-Git/home/browser-login pylint /Users/albert/obsidian/42-Git/home/browser-login/bin/browser.py /Users/albert/obsidian/42-Git/home/browser-login/agent_login_safari.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run --project /Users/albert/obsidian/42-Git/home/browser-login pytest -q /Users/albert/obsidian/42-Git/home/browser-login/tests/test_notion_mail_code.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws1b_agent_login.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws1b_safari.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_agent_login.py
cd /Users/albert/obsidian/42-Git/home/browser-login && /Users/albert/obsidian/42-Git/home/browser-login/bin/browser.py login -h
cd /Users/albert/obsidian/42-Git/home/browser-login && python3 -c "raise SystemExit(any('weak proof' in l for l in __import__('pathlib').Path.home().joinpath('.local/state/agent-login/agents.md').read_text().splitlines() if 'Notion (' in l))"
```

Every line starts with `cd <repo> &&` because `tp verify`'s grammar requires it; the
tools themselves get absolute paths and `--project` (objection 11). The last line is a
read-only check of agents.md: exit 0 when no Notion line says "weak proof" (today it
exits 1; after B6 + `agent-login.py -A` it must exit 0). Full suite: skipped unless a touched file's
neighbours fail (say so in the report). Live: B10 steps 3–9 as stated; the code value
never in any output; Safari window count and `safari fp` identical before/after;
browser mode headless throughout.

## Risks

- **The mail_code step has never succeeded live (UNVERIFIED):** the button labels
  "Continue" / "Continue with login code", whether `_OTP_FIELD` matches Notion's code
  input, and that the EPFL address gets a code (not an SSO redirect to EPFL's IdP —
  an SSO redirect lands off the notion hosts → `tab_moved` / `recipe_stuck`, before the
  trigger when it happens on the e-mail page). B10 step 5 is the first live run; a stop
  there is a finding, not a retry.
- **Silent headless block by Notion** (bot detection without a visible challenge:
  blank page, spinner, "unusual activity"): ends `recipe_stuck` after `IDLE_POLLS`
  reads — a fixed code, bounded, never a loop; cooldown blocks repeats.
- **New-device challenge:** deleting all notion cookies would make the next login look
  like a new device (extra verification). The logout deletes only `token_v2` /
  `notion_user_id`; device cookies stay.
- **Notion bot detection in headless Chromium** (Cloudflare / visible CAPTCHA):
  detector stops with exit 4 `needs_albert_captcha`, never loops; the cooldown blocks
  repeats. Fallback is the attended Safari route — no UA tricks.
- **`SDSC_EMAIL_NO_AUTO_AUTH` on the himalaya `*.cmd` path** is honoured by static read
  only; B1's test proves it, B1b stops the build if not.
- **Routing `_resolve_site("notion", for_login=True)`** → static Site: static read; B7
  test + B10 step 5.
- **Time budget** ≈ 460 s worst case vs 480 s: B3 caps make the proof always fit; a
  deadline after the submit quarantines (B2).
- **Code mail delay on EPFL Exchange** (>180 s): `email_code`, cooldown; agent retries
  after 15 min. A late code mail is harmless (excluded by the next run's baseline).
- **Dead EPFL OAuth grant**: `mailbox_unreadable` before any trigger (no browser pop-up);
  Albert must run `epfl_oauth.py auth` — named in the message.
- **Label drift / German UI**: exact single match or nothing; if B10 shows a German UI,
  add the German labels as a recipe alternative (small follow-up, not guessed now).
- **Another CDP client clicking**: excluded by the interaction lease for the whole
  flow; the owned tab is closed in a `finally`.
- **Concurrent `-L notion`**: per-site notion flock → 75; `safari_login_lock` only around
  import and Safari fallback.
- **Live-file edits**: worktree + atomic install only (B9).

## Debate outcome (Opus adversary)

Critic: fresh Opus subagent, 2026-11-03, 1 round.

1. [major] A deadline after the code submit left notion unquarantined (`_result_timeout` only quarantines phase unknown + broker site) — accepted: step 8 sets `phase_hint="mail-code-submitted"` + site; B2 makes `_result_timeout` quarantine notion on it; B7 tests both sides.
2. [major] Cooldown stamp written after the trigger click — accepted: stamp written BEFORE the click; a failed write aborts `state_unwritable` with nothing sent; tested.
3. [major] The canary could not tell a 401 from a redirect — accepted: B10 step 4 uses `logged-in notion -R <file>` and asserts `server: invalid`, `proof: server`; D2 gates `notion_probe_verified` on it.
4. [major] An unreadable Safari jar exited 3 before the headless route — accepted: for notion it counts as "no Safari session", the why is recorded; tested.
5. [major] B10 claims were uncheckable (fingerprint not printed, no bring_to_front command) — accepted: `-L notion -n` prints a value-free `safari fp` HMAC; B10 step 7 names the journal check.
6. [minor] `EMAIL_FILL_JS` / `CODE_FILL_JS` are text-substituted IIFEs — accepted: B1 exports function-form `EMAIL_FILL_FN` / `CODE_FILL_FN`; Safari constants untouched.
7. [minor] `_safari_fail` hard-codes route and quarantines from `out.credential` — accepted: `route` parameter; no second quarantine when the `-R` result says `quarantined: true`.
8. [minor] `mail_code_at` in site-state.json could be wiped by `prune()` — accepted: own `<state>/notion-mail-code.json` under the per-site flock; tested against `prune()`.
9. [minor] `needs_sentinel(row)` only takes the row — accepted: rows get `sentinel: "built-in"` where they are built; `needs_sentinel` unchanged.
10. [minor] Warm probe `valid` + identity unknown was undefined — accepted: rc 2 `indeterminate`, nothing sent; tested.
11. [minor] Verification used `cd … &&` chains — accepted: `uv run --project <abs>` lines with absolute paths, a pylint line and a read-only agents.md `weak proof` count.
12. [minor] The headless run held `safari_login_lock` up to ~8 min — accepted: the lock is released before `-M` and reacquired only for the Safari fallback; the per-site notion flock serialises; tested.
