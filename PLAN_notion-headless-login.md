# PLAN: headless, unattended Notion login in the shared Chromium (tp#1633)

> **Resume here.** Status: planned, nothing built. Next box: B1. Work in a worktree
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
  locked (logged-in, FileVault-unlocked) Mac. One trap: when the EPFL refresh token is
  dead, `epfl_oauth.py` `_auto_reauth` OPENS A BROWSER (focus loss) unless
  `SDSC_EMAIL_NO_AUTO_AUTH=1`. The headless path MUST run himalaya with
  `SDSC_EMAIL_NO_AUTO_AUTH=1` in the child env → a dead grant is `mailbox_unreadable`
  (rc 2, nothing triggered because the baseline is read first). Gmail/other accounts
  are not involved.
- **Reusable pieces** (all in `agent_login_safari.py`, stdlib-only, browser.py already
  imports this module lazily at ~line 15347): `RECIPES["notion"]` (step `mail_code`,
  senders, `code_re \b\d{6}\b`, subjects "login code"/"Anmeldecode", trigger
  "Continue", submit "Continue with login code"), `MailReader`, `mail_baseline`,
  `find_code` (new vs keyed baseline, DKIM pass for the sender domain, addressed to the
  expected e-mail, exactly one distinct code), `DETECTOR_JS`/`detector_js`
  (captcha incl. `challenges.cloudflare.com` frames and `#challenge-form`, sms, push,
  key, sentinel), `EMAIL_FILL_JS`, `CODE_FILL_JS`, `ALBERT_STOPS`, `MAIL_WAIT_S`.
  The Safari `Machine` itself is NOT reused (it speaks safari.py argv); the headless
  runner is a small sibling in browser.py driving a Playwright page.
- **Current browser.py notion login** (`cmd_notion_login`, ~15968) is guided-only:
  warm probe → `_guided_login_allowed` → NEEDS_ALBERT_RC (4). The logged-in check
  (`cmd_notion_logged_in` / `_notion_check`) is tri-state: server
  `/api/v3/loadUserContent` + sidebar `.notion-sidebar, .notion-sidebar-switcher`;
  proof `server` / `dom` / `dom-unverified`. `notion_probe_verified` is NOT set yet
  (only a 401 counts as "invalid").
- **Why agents.md says "weak proof".** The broker lists a `notion` item that is
  `fill_only: true` with no `logged_in_selector` → `has_sentinel` False →
  `needs_sentinel(row)` True (`agent-login.py` ~1067). The real proof is browser.py's
  own built-in check, which the row logic never consults.
- **`browser.py logout notion` does NOT work today:** `cmd_broker_logout` hits
  `_is_fill_only` → `_fill_only_exit` (exit 2, nothing touched). The cookie delete that
  exists is `_builtin_clear(port, "notion")` (in-scope cookies via
  `safari_cookies.replaced_on_import`, shared jar only). Neither touches Safari:
  `broker/safari_cookies.py` only READS `Cookies.binarycookies`.
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

1. Warm probe outside the lease (`_notion_check` with expected). `valid`+match → 0.
   `wrong_account` → stop rc 2 `wrong_account` (the mail-code login would add a second
   account; the Safari import path owns that case). `indeterminate` → stop rc 2
   `indeterminate`. Only `invalid` (definite logged-out) goes on.
2. Preconditions, all before anything is sent: not quarantined
   (`_als.quarantined("notion")` → rc 2 `quarantined`); cooldown not active (below);
   expected e-mail set; himalaya on PATH; the per-site flock
   `<state>/notion-mail-code.lock` (non-blocking → `BUSY_RC` 75).
3. Registration, then `_interaction_lease("login notion")` held for the whole flow.
4. Mail baseline (`mail_baseline`) BEFORE the trigger; unreadable → rc 2
   `mailbox_unreadable`, nothing sent.
5. `goto https://www.notion.so/login` (lands on `app.notion.com/login`); every step
   re-checks the page host ∈ {`www.notion.so`, `app.notion.com`} and runs the detector.
   Any `ALBERT_STOPS` flag (CAPTCHA / Cloudflare challenge / sms / push / key) → stop
   NEEDS_ALBERT_RC 4 with fixed code `needs_albert_captcha` etc., **never a retry,
   never a reload loop**. A page that shows neither the e-mail field nor the sentinel
   for `IDLE_POLLS` reads → rc 2 `recipe_stuck`.
6. Fill the e-mail (`EMAIL_FILL_JS`, value passed as a `page.evaluate` argument — never
   argv). Click "Continue" only when exactly ONE visible button has that exact label
   (else `recipe_stuck`, nothing sent). From here the run is "triggered": write the
   cooldown stamp.
7. Wait for the code: `find_code` polls (`MAIL_POLL_S`, `MAIL_WAIT_S` = 180 s, must agree
   on two consecutive polls, as `Machine._wait_code`). No code / several codes → rc 2
   `email_code`, no quarantine (nothing secret was submitted), cooldown stays.
8. Fill + submit the code ONCE (`CODE_FILL_JS`: exactly one visible button "Continue
   with login code" in the field's form; the code passes as an evaluate argument, the
   local is cleared in a `finally`, never printed / logged / put in the result file).
   From here `credential=True`: any later failure quarantines notion
   (`_als.quarantine("notion", phase, code)`), which agent-login prints with the `-Q`
   release hint.
9. Archive the used mail (`MailReader.archive`, best effort; result `mail_archived`).
10. Proof: `_notion_wait_for_login` (60 s, passive) then `_notion_check(port, expected)`
    must say `valid` + identity `match` → rc 0, `_record_login_event("notion",
    "mail-code")`, result `route: mail-code`. Anything else → quarantine + rc 2.

Once-only: steps 6 (trigger) and 8 (submit) each run at most once per process; there is
no loop back from a later step. **Cooldown:** a triggered run (step 6 reached) stamps
`site-state.json` (via `agent_login_state.update`) with `mail_code_at`; a new `-M`
within `NOTION_MAIL_CODE_COOLDOWN_S` (15 min) stops rc 2 `cooldown` before anything is
sent — so repeated agent runs can never spam Notion or the mailbox. Total budget: fits
inside `login_timeout_s()`; if the default is below ~4 min, `-M` raises its own
`LoginDeadline` floor (B3 checks the numbers).

himalaya env: `SDSC_EMAIL_NO_AUTO_AUTH=1` for every MailReader call of this path
(MailReader gets an optional `env` field; default unchanged for the Safari path).

### `-L notion` pipeline (agent-login.py)

`safari_login_action` for notion only:

- `scheduled()` refusal stays (hard rule: `-L` is agent-invoked, never a LaunchAgent).
- The `interactive_gate()` call moves from the top to right before `_drive_safari`
  (notion only; other recipes keep the gate on top, unchanged).
- Under the existing `safari_login_lock` (it also serialises concurrent `-L notion`):
  free check gate → Safari import (unchanged) → if the import did not stop the pipeline
  (same `IMPORT_STOP_RCS` / code rules) or Safari holds no session: run
  `browser.py login notion -M -R <result>` under `site_session("notion")`.
  - rc 0 → record_check ok, route `mail-code`, `✅ notion: logged in headlessly (e-mail
    code)`.
  - stop codes that must NOT fall through to Safari: any `credential=True` result,
    `needs_albert_*`, `cooldown`, `quarantined`, `wrong_account`, `indeterminate`, 75,
    timeouts → `_safari_fail`-style record (route `mail-code`) and exit.
  - stop codes that may fall through (nothing was sent: `mailbox_unreadable`,
    `identity_unconfigured`, `himalaya_missing`, `recipe_stuck` before the trigger) →
    Safari login only when `interactive_gate()` is open; else exit 3 with the gate's
    code (as today).
- `-L notion -n` (dry run) also prints whether the headless route is ready (expected
  e-mail set, himalaya present, mailbox readable baseline — read-only, no trigger).

### Real sentinel proof

- browser.py: `_notion_check_page` adds `sentinel: bool` (sidebar seen) to its dict;
  proof becomes `server+sentinel` when server `valid` AND the sidebar is up.
  `cmd_notion_logged_in` writes `sentinel` and that proof to the result record. Verdict
  rules unchanged (no new false negatives).
- agent-login.py: `needs_sentinel(row)` is False for a built-in-proof site (`notion`)
  whose latest check (`checks.json`) has proof `server+sentinel` (or `server` with
  `sentinel: true`); the row's `sentinel` column shows `built-in`. Slack/OpenAI are
  out of scope (unchanged).

### Logout for the canary

`browser.py logout notion`: for `SAFARI_BUILTIN` sites check BEFORE the broker lookup
(the fill-only item would refuse) and run `_builtin_clear(port, site)` under
registration + `_interaction_lease("logout notion")`; prints the count; never touches
Safari, never calls the broker's `logout` op. Exit 2 when the jar is missing.

## Boxes

- [ ] B1 `agent_login_safari.py`: `MailReader` gains an optional `env` mapping passed
  to `subprocess.run` (default None = inherit, Safari path unchanged); export a
  `NOTION_MAIL_ENV = {"SDSC_EMAIL_NO_AUTO_AUTH": "1"}`; module docstring gets a
  "Headless Notion" paragraph: the mail-code step may also run in the shared Chromium
  (browser.py `login notion -M`), ungated, notion only; same once-only + quarantine
  rules.
- [ ] B2 `bin/browser.py`: `login -M/--mail-code` flag (notion only, else exit 2) and
  `_notion_mail_code_login(port)` implementing Design steps 1–10 (owned background tab,
  registration → lease, detector stops, once-only trigger + submit, cooldown stamp,
  quarantine after `credential`, archive, proof, result record fields `route`, `phase`,
  `code`, `mail_archived`; no code value anywhere in output/result/journal).
- [ ] B3 `bin/browser.py`: budget — confirm `login_timeout_s()` ≥ baseline + page
  steps + `MAIL_WAIT_S` + proof; if not, the `-M` path sets its own deadline floor and
  agent-login's `browser_timeout("login")` for it matches (`agent_login_jobs.py`).
- [ ] B4 `bin/browser.py`: real sentinel — `sentinel` field + `server+sentinel` proof in
  `_notion_check_page` / `cmd_notion_logged_in` result record.
- [ ] B5 `bin/browser.py`: `logout SITE` for `SAFARI_BUILTIN` sites → `_builtin_clear`
  under registration + lease, before the fill-only/broker path; help text says
  "shared browser only, Safari untouched".
- [ ] B6 `agent-login.py`: `-L notion` pipeline (gate moved before the Safari drive,
  headless route, fall-through rules, record_check route `mail-code`, dry run lines);
  `needs_sentinel` built-in-proof rule for notion.
- [ ] B7 tests (unit, no network, no real Chrome — `CLAUDE_BROWSER_TEST_NO_LAUNCH=1`):
  new `tests/test_notion_mail_code.py` with a fake page (pattern of
  `tests/fake_cdp.py` / `chromium_page.py`) and a fake himalaya runner
  (pattern of `test_ws1b_safari.py` mail tests):
  happy path (baseline → trigger once → one new DKIM-signed code to the expected
  address → submit once → sentinel → rc 0, mail archived);
  CAPTCHA / Cloudflare frame on the login page → rc 4 `needs_albert_captcha`, zero
  clicks, zero mail reads after baseline;
  no code within the wait → rc 2 `email_code`, no quarantine, cooldown stamped;
  second `-M` inside the cooldown → rc 2 `cooldown`, page never opened;
  two codes → `email_code`; an old (baseline) code ignored; wrong recipient / failed
  DKIM / foreign sender ignored;
  code submitted but no sidebar → quarantine written, rc 2;
  quarantined before start → rc 2, nothing opened;
  dead mailbox (himalaya fails) → `mailbox_unreadable`, no trigger; himalaya called
  with `SDSC_EMAIL_NO_AUTO_AUTH=1`;
  `wrong_account` / `indeterminate` warm probe → no trigger;
  the code never appears in stdout/stderr/result file (capsys + file scan);
  `login notion` without `-M` still returns 4 when not guided; `-M` on another site → 2.
  In `tests/test_ws1b_agent_login.py` / `test_agent_login.py`: `-L notion` order
  (logged in → import → headless → Safari), idle/locked gate does NOT block the
  headless route but DOES block the Safari fallback (exit 3), no fall-through after a
  credential/needs_albert/cooldown stop, `scheduled()` still refuses, other recipes
  still gated on top; `needs_sentinel` False for notion with a `server+sentinel` check;
  agents.md line for notion has no "weak proof". `logout notion` test: clears only
  in-scope cookies, never reads/writes Safari (safari_cookies patched to raise).
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
  one deliberate exception to "never login casually", approved by tp#1633):
  1. `browser.py logged-in notion` → 0 (baseline; if not 0, stop and report).
  2. Record Safari's state: `osascript -e 'tell application "Safari" to count windows'`
     (read-only) and the notion Safari cookie fingerprint via `agent-login.py -L notion
     -n` ("holds session").
  3. `browser.py logout notion` → prints N > 0 cookies deleted; `browser.py logged-in
     notion` → 2, code `logged_out` (this also verifies the L0 probe: a 401 → invalid).
  4. Force the headless route: run `browser.py login notion -M` directly (the `-L`
     pipeline would take the Safari import first while Safari holds a session), then
     separately `agent-login.py -L notion` once more after a second `logout notion`
     to prove the import route also opens no window. Each must exit 0.
  5. After each: Safari window count unchanged, Safari notion fingerprint unchanged,
     `browser.py status` mode headless, no `bring_to_front` in the journal.
  6. `browser.py eval-fresh -t 60
     'https://app.notion.com/p/renku/SDSC-Authentication-Service-Build-Team-3950df2efafc8065bb56cf328894afa9'
     'document.querySelectorAll("[contenteditable=true]").length'` → a number > 0.
  7. `agent-login.py -A`; the notion line in `~/.local/state/agent-login/agents.md`
     shows ✅ without "weak proof".
  If a CAPTCHA/Cloudflare stop (exit 4) appears: do not retry; report the code and
  leave notion logged out only if the import route (step 4, `-L notion`) also fails —
  otherwise restore via `-L notion` (Safari import).

## Verification

```
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run ruff format --check bin/browser.py agent-login.py agent_login_safari.py tests/test_notion_mail_code.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run ruff check bin/browser.py agent-login.py agent_login_safari.py tests/test_notion_mail_code.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run mypy bin/browser.py agent_login_safari.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests/test_notion_mail_code.py tests/test_ws1b_agent_login.py tests/test_ws1b_safari.py tests/test_agent_login.py
cd /Users/albert/obsidian/42-Git/home/browser-login && bin/browser.py login -h
```

- Unit: all B7 tests green; full suite skipped unless the touched files' neighbours
  fail (say so in the report).
- Lint: ruff format/check, mypy, pylint clean on `bin/browser.py`, `agent-login.py`,
  `agent_login_safari.py`, the test files.
- Live: B10 steps 3–7 all as stated; the code value never in any output; Safari window
  count and Safari notion cookie fingerprint identical before/after; browser mode
  headless throughout.

## Risks

- **Notion bot detection in headless Chromium** (Cloudflare / "unusual activity"):
  detector stops with exit 4 `needs_albert_captcha`, never loops; the cooldown blocks
  repeats. Mitigation if it happens live: fall back is the attended Safari route — the
  plan does not try UA tricks.
- **Code mail delay on EPFL Exchange** (>180 s): `email_code`, cooldown; agent retries
  after 15 min. A late code mail is harmless (excluded by the next run's baseline).
- **Dead EPFL OAuth grant**: `mailbox_unreadable` before any trigger (no browser pop-up
  thanks to `SDSC_EMAIL_NO_AUTO_AUTH=1`); Albert must run `epfl_oauth.py auth` — named
  in the message.
- **Label drift** ("Continue", "Continue with login code", German UI): exact single
  match or nothing; a drift stops `recipe_stuck` before or after the trigger. If the
  shared browser's Notion UI is German, B10 shows it — then add the German labels as a
  recipe alternative (small follow-up, not guessed now).
- **Another CDP client clicking**: excluded by the interaction lease for the whole
  flow; the owned tab is closed in a `finally`.
- **Concurrent `-L notion`**: `safari_login_lock` + the per-site flock → 75.
- **Live-file edits**: worktree + atomic install only (B9).

### Questions for Albert

- Set `notion_probe_verified: true` in `~/.config/agent-login/safari-logins.json` once
  B10 step 3 shows a logged-out session answering 401 → "invalid"? Recommendation: yes
  (overseer edits the private file after the canary).
- Cooldown between headless code mails: 15 min OK? Recommendation: yes.
- Should `-L` stay refused inside LaunchAgents (`AGENT_LOGIN_SCHEDULED`) for notion
  too? Recommendation: yes — "anytime" means any agent session, not a scheduled job
  (hard rule: `-L` is agent-invoked only).
