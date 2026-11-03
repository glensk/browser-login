# PLAN: Notion Safari login recipe — match the new login page (tp#1643)

> **Resume here.** Status: planned, debated (Opus adversary, 2026-11-04) and
> reconciled, nothing built. Next box: B1.
> Overseer session: 5aa659e4-da4b-437b-8cb7-af851b04c9f2. Work in a worktree
> (`git -C /Users/albert/obsidian/42-Git/home/browser-login worktree add
> /Users/albert/obsidian/42-Git/home/browser-login/.worktrees.noindex/notion-safari-fix -b
> notion-safari-fix`) — `agent_login_safari.py` and `agent-login.py` are LIVE (consumers
> exec them). Install atomically in B3. B4 is the parent's B13, run with Albert present.

Parent: PLAN_notion-safari-login.md (B1-B12 done; this plan unblocks its B13)

## Session

Ticket: tp#1643
Session: 5aa659e4-da4b-437b-8cb7-af851b04c9f2 (overseer)
Trigger (Albert, 2026-11-03 ~23:50): a real logout test. Safari was logged out of
Notion, then `./agent-login.py -L notion -s` exited 2 with "the Safari login recipe
found no next step on the page" (`recipe_stuck`, broker/phases.py:127). No code mail
went out (cooldown file mtime unchanged), nothing quarantined. Right after it, the
headless route (`./agent-login.py -L notion`, no `-s`) logged the shared Chromium in
by e-mail code (last-check 2026-11-03 23:49, "logged in headlessly (e-mail code)").

## Goal

`./agent-login.py -L notion -s` logs a genuinely logged-out Safari in to Notion by
e-mail code on the current login page (`app.notion.com/login`), then opens the
workspace home — the parent's B13 passes live. No behaviour change to the headless
route (it shares `recipe.start_url`, browser.py ~17065, and now opens the login page
it already landed on directly).

## Findings (root cause)

Read from the code, plus two READ-ONLY JS reads of Albert's open Safari tab
(`safari.py -e <probe.js> -u app.notion.com/login -F`: counts and labels only, no
click, no fill, no navigation).

1. **Root cause (high confidence): the recipe's step host is `www.notion.so`, the
   login page now lives on `app.notion.com`.** `RECIPES["notion"]`
   (agent_login_safari.py ~394-423) has ONE `mail_code` step with
   `host="www.notion.so"`; `start_url="https://www.notion.so/login"` redirects to
   `https://app.notion.com/login` (the open tab's `location.host` is
   `app.notion.com`, path `/login`; browser.py already says so at ~372-378:
   `NOTION_LOGIN_URL = "https://app.notion.com/login"`). `Machine.tab_host`
   accepts `app.notion.com` (it is in `recipe.hosts`), but `Machine._next_step`
   (~1462-1469) skips every step with `step.host != host` → no step ever matches →
   `IDLE_POLLS` (4) reads → `_end(2, "recipe_stuck")` (~1450-1452) before the e-mail
   fill — hence no code mail and no quarantine (`out.credential` false). Even with
   the host check passed, every action would have failed: `_mail_code` pins
   `--expect-host step.host` (`www.notion.so`) on the e-mail fill, the trigger click
   and the code fill, and safari.py's click script refuses on an origin mismatch
   (`reason: "origin"`).
2. **Why the headless route works:** `_nmc_page` (browser.py ~16891) accepts any host
   in `NOTION_MAIL_CODE_HOSTS = ("www.notion.so", "app.notion.com")` and waits for
   the detector's generic `user` flag (`_nmc_wait_page(need="user")`); it never reads
   `step.host` or `step.when`. It uses the same `step.email_field`
   (`input[type="email"]`), `step.trigger` ("Continue"), `_OTP_FIELD` and
   `step.submit` + `CODE_SUBMIT_VARIANTS` — all proven live tonight. So the field
   selectors and labels are fine; only the Safari-only host binding is stale.
3. **The new page's DOM (read-only probe, 2026-11-03):** one form; ONE visible
   `input[type="email"]` (`autocomplete="username"`, no name) → `step.when` and
   `_USER_FIELD` match; ONE visible element labelled "Continue" under safari.py's
   click selector (a `div[role="button"]`) → `--click Continue --row Continue` finds
   exactly one; other buttons: Google, ChatGPT, Apple, Microsoft, Passkey, SSO,
   "Language: English (US)"; an `input[type="password"]`
   (`autocomplete="current-password"`) inside an `aria-hidden="true"` container (a
   password-manager helper) → the detector's `password` flag reads true; harmless
   (no Notion step uses `unless`, `password` is not an Albert stop). No OTP field,
   no sidebar. The code page was NOT probed (that needs a sent code).
4. **Second divergence (hardening, same flow):** after the code arrives, the Safari
   `_mail_code` sets `out.credential = True` and evaluates `CODE_FILL_JS` without
   first seeing the code field; the headless `_nmc_code` waits until the detector's
   `code` flag is set (≤ `IDLE_POLLS` unknown reads). A code page that renders late
   in Safari would end in `email_code` WITH `credential` → quarantine, although
   nothing was typed. B1 adds the same wait and sets `credential` only once the field
   was seen.
5. **Why the tests missed it:** `tests/test_ws1b_safari.py` drives the Machine with a
   synthetic `NOTION_LIKE` recipe on `www.example.org`; `test_notion_safari_target.py`
   fakes `_drive_safari`; nothing runs the REAL `RECIPES["notion"]` against the host
   the start page lands on. B2 closes that gap.
6. **The stop said nothing useful:** `recipe_stuck` does not tell "no step for this
   host" from "step conditions unmet" from "page unreadable". B1 adds a value-free
   reason (host only) to the record and the ❌ line.
7. **Safari and the shared Chromium share ONE Notion session after an import**
   (`import-safari` copies Safari's `token_v2`). Notion's logout
   (`https://www.notion.so/logout`, or the in-app "Log out") revokes that token
   server-side, so logging Safari out also logs the shared Chromium out when its
   session came from Safari. Tonight Chromium then logged in on its OWN token (the
   headless e-mail code), so from now on the two sessions are independent until the
   next import. Documented in B3.

## Design

- `RECIPES["notion"]`: the `mail_code` step's `host` → `"app.notion.com"`; comment
  "L2 (2026-11-03): the login page is app.notion.com/login (www.notion.so/login
  redirects there); one visible input[type=email], one div[role=button] 'Continue'".
  `start_url` → `https://app.notion.com/login` (= browser.py `NOTION_LOGIN_URL`
  ~378): no redirect dependence, and no redirect reads on `www.notion.so` eating the
  shared `idle` budget (`IDLE_POLLS` 4 × `POLL_S` 3 s, ~1447-1452) — a slow or
  client-side redirect would otherwise end in a false `no_step_for_host`. The
  headless route uses the same `start_url` (browser.py ~17065) and already treats
  that URL as the login page (~16595). `hosts`
  stay `("www.notion.so", "notion.so", "app.notion.com")`; `sentinel_host` stays
  `app.notion.com`. Decided: ONE step on one
  host, no second `mail_code` step for `www.notion.so` (two credential steps could
  send two code mails); a future host move again ends in a clean `recipe_stuck` with
  the B1 reason, nothing sent.
- `Machine._mail_code`, after `_wait_code` returned a code and BEFORE
  `out.credential = True`: poll (≤ `IDLE_POLLS` reads, `POLL_S` apart) `tab_host()`
  FIRST, then `read_page(step.host)`, until `page["code"]`. A `tab_host` stop
  (`safari_tab_moved`, …) → that stop; a tab host ≠ `step.host` → keep polling, and
  at the end `stuck_host` = that real tab host; an Albert stop on the page → that
  stop; never seen → `_end(2, "recipe_stuck")` with `out.stuck = "code_field"` and
  `credential` still false (no quarantine; the code mail went out, the cooldown
  stamp already blocks a repeat), and `out.mail_archived = reader.archive(code)` so
  the unused code does not sit in INBOX (value-free status only). Then
  `credential = True` and `CODE_FILL_JS` as today (`CODE_FILL_JS` / `EMAIL_FILL_JS`
  bodies untouched — their sha256 pins in `test_notion_mail_code.py` stay).
  (Interleaving the field check into `_wait_code`'s polls, as headless does, is
  optional — not required; the extra ≤ 12 s is inside the code's validity.)
- **Post-submit wait (new, critique objection 1):** today, after `_mail_code`
  returns None, `_loop` sleeps one `POLL_S` and the next read of a page that still
  shows the code field + "inbox" text (detector ~804 `email_code`) ends the run
  `email_code` WITH `credential` → quarantine (~1446-1449), although Notion may
  finish the login a second later. Fix: `Machine.submitted: bool` set when the
  mail-code fill answered ok; while `submitted` and the sentinel is not yet seen, a
  page with `code` / `email_code` (or `None`) counts as waiting, bounded by
  `POST_SUBMIT_S = 30` s (clock-based, `POLL_S` apart); sentinel → ok; Albert stop
  → that stop; timeout → `_end(2, "recipe_stuck")`, `stuck = "after_submit"`
  (credential stays true: the code WAS typed → quarantine, as intended). This mirrors
  the headless `_nmc_proof` sidebar wait (browser.py ~17252).
- `Outcome.stuck: str = ""` — fixed vocabulary: `no_step_for_host`,
  `step_conditions_unmet`, `page_unreadable`, `code_field`, `after_submit`. `_loop` sets it at each
  `recipe_stuck` end (no step whose `host` equals the tab host → `no_step_for_host`;
  a step on that host whose `when`/`unless` never fit → `step_conditions_unmet`;
  `read_page` None → `page_unreadable`). `Outcome.stuck_host` = the tab host (a host
  from `recipe.hosts`, never a URL, path or query). agent-login.py `_safari_fail`:
  `detail = detail or out.stuck` and the ❌ line appends
  `(<stuck> on <stuck_host>)` when set. No other caller changes.

## Boxes

- [x] B1 `agent_login_safari.py` + `agent-login.py` (worktree): the Design's
  changes — notion step `host="app.notion.com"` + `start_url=
  "https://app.notion.com/login"` + its L2 comment; the code-field wait (tab_host
  first, archive on `code_field`) before `credential` / `CODE_FILL_JS` in
  `Machine._mail_code`; the post-submit wait (`submitted`, `POST_SUBMIT_S`,
  `after_submit`) in `_loop`; `Outcome.stuck` / `stuck_host` set in `_loop` and
  `_mail_code`, read by `_safari_fail` (record detail + ❌ line). **Check first:** (a) every existing `Machine` test that ends in
  `recipe_stuck` or fills a code (`test_ws1b_safari.py` ~187, ~205, `MailSafari`
  ~699-790, `test_notion_safari_target.py`) — the new code-field read is one extra
  `--eval` of the detector: update the fakes' scripts so the code page reports
  `code: true`, never weaken an assertion; (b) no test pins
  `RECIPES["notion"].steps[0].host == "www.notion.so"`
  (`grep -rn 'www.notion.so' tests/` showed only cookie domains and one URL in
  `test_notion_mail_code.py:1554`, which is a probe URL, not the step).
- [x] B2 tests, new `tests/test_notion_safari_recipe.py` (no network, no real Safari;
  headless Chromium only through `tests/chromium_page.py`, skipped when Playwright's
  Chromium is missing). A hand-written fixture of the new login page as a string
  constant — the probe's structure only (form, `input[type=email]
  autocomplete=username`, the `aria-hidden` password helper, a `div[role=button]`
  "Continue", the six provider `div[role=button]`s, the page text from the brief), no
  ids, tokens or URLs from Albert's tab — plus a minimal code page (an
  `input[autocomplete=one-time-code]` and a `div[role=button]` "Continue"; its shape is
  UNVERIFIED, mirrors what the headless fill matched). Cases:
  (1) `detector_js(RECIPES["notion"], sentinel)` evaluated on the login fixture
  (routed as `https://app.notion.com/login`) → `user` true, `steps[0].when` true,
  `unless` false, `sentinel` false, no Albert stop; on the code fixture → `code` true;
  (2) `EMAIL_FILL_JS` with `step.email_field` fills the fixture's field (`ok: true`);
  `CODE_FILL_JS` on the code fixture → `ok: true, clicked: true`;
  (3) the real `RECIPES["notion"]` through `Machine.run` with the `FakeSafari` style
  runner whose `--tabs` reports `https://app.notion.com/login` (then the code page,
  then `https://app.notion.com/` with the sentinel): call order e-mail fill →
  `before_trigger` → `--click Continue` → code fill; EVERY `--expect-host` is
  `app.notion.com`; exit 0, `mail_archived` set;
  (4) regression guard: `RECIPES["notion"].steps[0].host ==
  browser.NOTION_APP_HOST` (browser.py loaded via `chromium_page.load_script`), and
  every `RECIPES` step host is in its recipe's `hosts`;
  (5) tab on a host with no step (`www.notion.so`, fake page with the e-mail field) →
  `recipe_stuck`, `stuck == "no_step_for_host"`, `stuck_host == "www.notion.so"`, zero
  fills/clicks, `credential` false;
  (6) code mail found but the code field never shows → `recipe_stuck`,
  `stuck == "code_field"`, `credential` false, no `CODE_FILL_JS` eval, no
  quarantine through `_safari_fail` (fake `als.quarantine` not called), the ❌ line
  names `code_field on app.notion.com`, `reader.archive` called once;
  (7) the code value never appears in stdout/stderr/argv (capsys + recorded calls);
  (8) after the code fill the fake keeps the code page (code field + "Check your
  inbox") for 3 reads, then the sentinel page → exit 0, NOT `email_code`, no
  quarantine; and the same with the code page held past `POST_SUBMIT_S` (fake clock)
  → `recipe_stuck`, `stuck == "after_submit"`, `credential` true;
  (9) the login window disappears during the code-field wait (`--tabs` without it) →
  `safari_tab_moved`, not `code_field`, `credential` false;
  (10) `RECIPES["notion"].start_url == browser.NOTION_LOGIN_URL`.
- [ ] B3 docs + verify + install. README: the notion row (~594) and §"Agents renew…"
  (~1117) gain one sentence — "Safari and the shared Chromium share one Notion session
  after an import: a Notion logout in Safari (`notion.so/logout` or the in-app Log out)
  revokes it server-side and logs the shared Chromium out too, unless Chromium has
  since logged in on its own (headless e-mail code)"; the `recipe_stuck` stop now
  names its reason. Keep "the Safari code fill is not proven live yet" until B4
  passed (B4 removes it in README ~594 / ~1117 / ~1608 / ~1675 and agent-login.py
  ~27 / ~1095 / ~5118, then regenerates agents.md with `agent-login.py -A`; that
  edit of a live file goes through the SAME worktree → verify → atomic install path
  below, never in place). **Pre-install verification:** run the Verification block's
  commands with the worktree root
  (`/Users/albert/obsidian/42-Git/home/browser-login/.worktrees.noindex/notion-safari-fix`)
  in place of the live root, fix to green (the block as written checks the LIVE
  files and is the post-install `tp verify`).
  **Install (one path, cp/mv into live, commit from live):** `<base>` = the live
  `HEAD` recorded when the worktree is created (`git -C <live> rev-parse HEAD`, noted
  in the build report). (1) Check the live files are unchanged since `<base>`
  (`git -C <live> diff --quiet <base> -- agent_login_safari.py agent-login.py
  README.md`, and `git -C <live> status --porcelain -- <same files>` empty); stop if
  not. (2) Backups OUTSIDE the repo: `mkdir -p ~/.local/state/agent-login/bak-1643`
  (0700), `cp -p <live file> ~/.local/state/agent-login/bak-1643/<name>` for both .py
  files. (3) Per file in this order `agent_login_safari.py` → `agent-login.py`:
  `cp -p <worktree file> <live dir>/.<name>.new` (`-p` keeps mode; then `chmod +x`
  on `.agent-login.py.new` explicitly), `mv <live dir>/.<name>.new <live file>`
  (same-directory rename = atomic; a consumer exec'ing mid-swap sees either the old
  pair or new-module + old-script — the new module only ADDS fields with defaults,
  so old agent-login.py keeps working with it, which is why the module goes first).
  README.md and `tests/test_notion_safari_recipe.py` are copied the same way (not
  live-executed, plain cp is fine). (4) Post-install: live `./agent-login.py -h` exit
  0, live `pytest -q tests/test_notion_safari_recipe.py` green (the real smoke —
  `./agent-login.py -L notion -s -n` is only an import smoke: `-n` never runs the
  Machine, agent-login.py ~5135), then the live Verification block. (5) Commit from
  the live checkout with the brief's grant: `ai.py push -m "…" agent_login_safari.py
  agent-login.py README.md tests/test_notion_safari_recipe.py` (explicit paths only —
  another session may be committing other files there), then remove the worktree
  and delete the branch (`git -C <live> worktree remove …`, `git -C <live> branch -D
  notion-safari-fix`).
- [ ] B4 LIVE CANARY (= parent B13; Albert present at the Mac; he asked for a real
  logout test on 2026-11-03, which overrides the parent's "never forced by a logout"
  rule for this run only). Preconditions: the cooldown is free (`stat -f %m
  ~/.local/state/agent-login/notion-mail-code.json` ≥ 15 min ago — tonight's headless
  code mail was 23:49, so not before 00:05), nothing quarantined (`agent-login.py -L
  notion -n`). Result files in a fresh `mktemp -d` (0700).
  1. **Albert logs out by hand** in Safari: Notion's sidebar account menu → "Log out"
     (this browser only). NEVER "Log out of all devices" (Settings → Account), which
     revokes every session incl. the Pixel and the shared Chromium. The agent does
     not open `/logout` itself: a GET of `https://www.notion.so/logout` is unverified
     (cross-host since the session now lives on `app.notion.com`; it may log out
     every account in the account switcher, or not clear the app.notion.com session
     at all). Before the logout, Albert says which Notion accounts Safari's account
     switcher holds; if more than one, he picks the per-account logout if offered,
     else accepts that all Safari Notion accounts log out (the other one(s) re-login
     by hand afterwards). Albert confirms Safari shows the login page. Expect the
     shared Chromium to stay logged in (its token is its own since 2026-11-03 23:49,
     provided no `import-safari` ran since — check `last-check` before) — note
     `browser.py logged-in notion` before and after. Step 2 is the gate that the
     logout really took effect.
  2. `browser.py import-safari notion -P -R <dir>/prove.json` → exit 2 `logged_out`
     (or `no_safari_session`).
  3. `./agent-login.py -L notion -s` → a new Safari window opens directly on
     `app.notion.com/login`, e-mail filled, "Continue" once, the code filled once, the
     window closes; then "shared Chromium already logged in, nothing imported" (or an
     import when it is logged out); the workspace home opens in a new tab; exit 0. The
     cooldown stamp is fresh; `mail_archived: ok` in the check detail.
  4. `browser.py import-safari notion -P` → `match`; `browser.py logged-in notion` →
     0 (if 2: `./agent-login.py -L notion` re-imports from Safari, then 0).
  **Stop rules:** exit 4 → Albert finishes in that window by hand, no retry;
  `recipe_stuck` → read the new `stuck` reason, no retry inside the cooldown, report
  (a finding, not a bug hunt in place); `email_code` → report; a quarantine → report,
  never `-Q` it. On pass: drop the "not proven live yet" wording (B3's list), commit,
  and the overseer ticks the parent's B13 with this evidence.

## Verification

```
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff format --check /Users/albert/obsidian/42-Git/home/browser-login/agent_login_safari.py /Users/albert/obsidian/42-Git/home/browser-login/agent-login.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_notion_safari_recipe.py
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff check /Users/albert/obsidian/42-Git/home/browser-login/agent_login_safari.py /Users/albert/obsidian/42-Git/home/browser-login/agent-login.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_notion_safari_recipe.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run --project /Users/albert/obsidian/42-Git/home/browser-login mypy /Users/albert/obsidian/42-Git/home/browser-login/agent_login_safari.py /Users/albert/obsidian/42-Git/home/browser-login/agent-login.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_notion_safari_recipe.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run --project /Users/albert/obsidian/42-Git/home/browser-login pylint /Users/albert/obsidian/42-Git/home/browser-login/agent_login_safari.py /Users/albert/obsidian/42-Git/home/browser-login/agent-login.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_notion_safari_recipe.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run --project /Users/albert/obsidian/42-Git/home/browser-login pytest -q /Users/albert/obsidian/42-Git/home/browser-login/tests/test_notion_safari_recipe.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws1b_safari.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_notion_safari_target.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_notion_mail_code.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_notion_l_pipeline.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws1b_agent_login.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_agent_login.py
cd /Users/albert/obsidian/42-Git/home/browser-login && ./agent-login.py -h
```

Each line is `cd <repo> && <argv>` (`tp verify` grammar); no live login. The block
checks the LIVE files (post-install `tp verify`); B3 runs the same commands against
the worktree root before the install. The old `grep -c "app.notion.com"` line was
dropped (it already passed at HEAD: `hosts` / `sentinel_host` contain the string);
B2 cases (4) and (10) pin the step host and start URL instead. Not strict-eligible
(uv env, pytest, mypy, pylint, a live `-h`), as the parent plan's note says. Read-only
smoke (not in the block, B3): `./agent-login.py -L notion -s -n`. Full suite: skipped
unless a touched file's neighbours fail (say so in the report).

## Rollback

- Before B3's install: discard the worktree branch; nothing live changed.
- After the install, before the commit: per file, reverse order (`agent-login.py`
  first, then `agent_login_safari.py`): `cp -p
  ~/.local/state/agent-login/bak-1643/<name> <live dir>/.<name>.new`, `mv <live
  dir>/.<name>.new <live file>`; README / test via `git -C <live> checkout --
  README.md` and removing the new test; live `./agent-login.py -h` exit 0. After the
  commit: `git revert` of that commit through `ai.py push`. The recipe fix alone is
  two lines (`host`, `start_url`). Remove `~/.local/state/agent-login/bak-1643/` only
  after B4 step 3 passed (or after Albert decides to defer B4 and the B3 smoke
  passed).
- No state migration: the cooldown / quarantine files are untouched by the code change.

## Risks

- **The code page in Safari is unprobed** (it needs a sent code): its host and field
  are inferred from the headless success (`_OTP_FIELD`, same hosts). If it moves host,
  B1's `code_field` / host-pinned fill stops cleanly without a quarantine; B4 reports it.
- **One code mail per B4 attempt:** the 15-min cooldown blocks a quick retry; a stuck
  run costs one mail and a 15-min wait.
- **The post-submit page in Safari is unprobed:** the `after_submit` wait (30 s)
  covers a slow verification; a code page that stays longer quarantines (code typed).
- **Logout side effects:** Albert's in-app "Log out" revokes Safari's session only
  (moderate confidence; it may cover every account in Safari's switcher, never other
  devices — "Log out of all devices" is a separate Settings action); the shared
  Chromium currently holds its own token (headless login 23:49), so it should stay
  logged in. If it had been imported from Safari since, it is logged out too and B4
  step 4 re-imports.
- **Live-file edits:** worktree + ordered atomic install with `.bak` rollback (B3).

## Open points

- None blocking. The code page's DOM in Safari is confirmed only by B4.

## Debate outcome (Opus adversary)

Critic: fresh Opus subagent, 2026-11-04, 1 round (Codex round 0 refused:
`debate_seat_unknown`, no fresh five-hour reading on either seat). Verdict:
sound-with-fixes. All objections accepted, so no round 2 was needed.

1. [major] After the code submit, `_loop` ends `email_code` with `credential` → a
   quarantine on the first read that still shows the code page (detector ~804,
   `_loop` ~1446-1449). Accepted: Design "Post-submit wait" (`submitted`,
   `POST_SUBMIT_S` 30 s, `after_submit`), B1 item, B2 case (8).
2. [major] The Verification block checks the live files, so before the install it
   tests the old code, and `grep -c app.notion.com` already passed at HEAD.
   Accepted: B3 runs the commands against the worktree root before the install; the
   grep line is dropped, and B2 cases (4) and (10) pin the step host and start URL.
3. [major] The B3 install and commit path was undefined (`<base>`, which checkout
   commits, the merge-back conflict). Accepted: one path. `<base>` is the live HEAD
   recorded at worktree creation, plus a diff/status check; files are copied into
   live by cp -p + mv; the commit runs from live with explicit paths; then the
   worktree and branch are removed.
4. [major] B4's GET of `www.notion.so/logout` has unverified scope (the account
   switcher, cross-host). Accepted: Albert logs out by hand through the in-app
   "Log out", never "Log out of all devices", and the agent never opens `/logout`.
   The accounts in the switcher are noted first, and step 2 is the gate.
5. [minor] The code-field wait skipped `tab_host()`, so a closed or moved window
   was misreported. Accepted: `tab_host` is polled first, and B2 case (9) covers it.
6. [minor] `start_url` should move to `app.notion.com/login`. Accepted: Design,
   the Goal wording (headless shares `start_url`, no behaviour change), B2 case (10).
7. [minor] An unused code mail stays in INBOX on a `code_field` stop. Accepted:
   `reader.archive(code)` on that stop, asserted in B2 case (6).
8. [minor] The `.bak` files sat inside the repo, which has no `*.bak` ignore.
   Accepted: backups go to `~/.local/state/agent-login/bak-1643/`, and Rollback is
   updated.
9. [minor] The post-B4 wording edit changed live agent-login.py in place.
   Accepted: it goes through the same worktree → verify → atomic install path.
10. [minor] The `-n` smoke never runs the Machine. Accepted: it is labelled an
    import smoke, and a live `pytest tests/test_notion_safari_recipe.py` runs right
    after the swap.

Overseer checks (brief): every safari.py origin check (`read_page`, e-mail fill,
trigger click, code fill) uses `self._on(step.host)` or the tab host
(agent_login_safari.py ~1360, ~1387, ~1545, ~1554, ~1571). One `host` change
therefore moves them all, and B2 case (3) asserts every `--expect-host`. The
sentinel host is already `app.notion.com`. The cooldown is stamped in
`before_trigger`, right before the click, so a late code page costs one mail plus
15 min and never a quarantine.
