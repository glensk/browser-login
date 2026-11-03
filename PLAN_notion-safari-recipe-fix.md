# PLAN: Notion Safari login recipe — match the new login page (tp#1643)

> **Resume here.** Status: planned, nothing built. Next box: B1.
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
workspace home — the parent's B13 passes live. No change to the headless route.

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
  `start_url` stays `https://www.notion.so/login` (the redirect is proven in both
  routes; the headless route reads the same field — unchanged behaviour). `hosts`
  stay `("www.notion.so", "notion.so", "app.notion.com")`. Decided: ONE step on one
  host, no second `mail_code` step for `www.notion.so` (two credential steps could
  send two code mails); a future host move again ends in a clean `recipe_stuck` with
  the B1 reason, nothing sent.
- `Machine._mail_code`, after `_wait_code` returned a code and BEFORE
  `out.credential = True`: poll `read_page(step.host)` (≤ `IDLE_POLLS` reads,
  `POLL_S` apart) until `page["code"]`; an Albert stop on the page → that stop; never
  seen → `_end(2, "recipe_stuck")` with `out.stuck = "code_field"` and `credential`
  still false (no quarantine; the code mail went out, the cooldown stamp already
  blocks a repeat). Then `credential = True` and `CODE_FILL_JS` as today
  (`CODE_FILL_JS` / `EMAIL_FILL_JS` bodies untouched — their sha256 pins in
  `test_notion_mail_code.py` stay).
- `Outcome.stuck: str = ""` — fixed vocabulary: `no_step_for_host`,
  `step_conditions_unmet`, `page_unreadable`, `code_field`. `_loop` sets it at each
  `recipe_stuck` end (no step whose `host` equals the tab host → `no_step_for_host`;
  a step on that host whose `when`/`unless` never fit → `step_conditions_unmet`;
  `read_page` None → `page_unreadable`). `Outcome.stuck_host` = the tab host (a host
  from `recipe.hosts`, never a URL, path or query). agent-login.py `_safari_fail`:
  `detail = detail or out.stuck` and the ❌ line appends
  `(<stuck> on <stuck_host>)` when set. No other caller changes.

## Boxes

- [ ] B1 `agent_login_safari.py` + `agent-login.py` (worktree): the Design's three
  changes — notion step `host="app.notion.com"` + its L2 comment; the code-field wait
  before `credential` / `CODE_FILL_JS` in `Machine._mail_code`; `Outcome.stuck` /
  `stuck_host` set in `_loop` and `_mail_code`, read by `_safari_fail` (record detail
  - ❌ line). **Check first:** (a) every existing `Machine` test that ends in
  `recipe_stuck` or fills a code (`test_ws1b_safari.py` ~187, ~205, `MailSafari`
  ~699-790, `test_notion_safari_target.py`) — the new code-field read is one extra
  `--eval` of the detector: update the fakes' scripts so the code page reports
  `code: true`, never weaken an assertion; (b) no test pins
  `RECIPES["notion"].steps[0].host == "www.notion.so"`
  (`grep -rn 'www.notion.so' tests/` showed only cookie domains and one URL in
  `test_notion_mail_code.py:1554`, which is a probe URL, not the step).
- [ ] B2 tests, new `tests/test_notion_safari_recipe.py` (no network, no real Safari;
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
  names `code_field on app.notion.com`;
  (7) the code value never appears in stdout/stderr/argv (capsys + recorded calls).
- [ ] B3 docs + verify + install. README: the notion row (~594) and §"Agents renew…"
  (~1117) gain one sentence — "Safari and the shared Chromium share one Notion session
  after an import: a Notion logout in Safari (`notion.so/logout` or the in-app Log out)
  revokes it server-side and logs the shared Chromium out too, unless Chromium has
  since logged in on its own (headless e-mail code)"; the `recipe_stuck` stop now
  names its reason. Keep "the Safari code fill is not proven live yet" until B4
  passed (B4 removes it in README ~594 / ~1117 / ~1608 / ~1675 and agent-login.py
  ~27 / ~1095 / ~5118, then regenerates agents.md with `agent-login.py -A`). Run the
  Verification block in the worktree, fix to green. Install: check both live files are
  unchanged since the worktree base (`git -C <live> diff --quiet <base> --
  agent_login_safari.py agent-login.py`; stop if not), then per file in this order
  `agent_login_safari.py` → `agent-login.py`: `cp <live> <live>.bak`, `cp <worktree
  file> <live dir>/.<name>.new`, `mv <live dir>/.<name>.new <live>` (+x kept on
  `agent-login.py`); live `./agent-login.py -h` exit 0 and `./agent-login.py -L notion
  -s -n` (read-only) after the swap. Commit with the brief's grant.
- [ ] B4 LIVE CANARY (= parent B13; Albert present at the Mac; he asked for a real
  logout test on 2026-11-03, which overrides the parent's "never forced by a logout"
  rule for this run only). Preconditions: the cooldown is free (`stat -f %m
  ~/.local/state/agent-login/notion-mail-code.json` ≥ 15 min ago — tonight's headless
  code mail was 23:49, so not before 00:05), nothing quarantined (`agent-login.py -L
  notion -n`). Result files in a fresh `mktemp -d` (0700).
  1. Albert (or the agent on his explicit go) opens `https://www.notion.so/logout` in
     Safari; Albert confirms Safari shows the login page. Expect the shared Chromium
     to stay logged in (its token is its own since 23:49) — note `browser.py logged-in
     notion` before and after.
  2. `browser.py import-safari notion -P -R <dir>/prove.json` → exit 2 `logged_out`
     (or `no_safari_session`).
  3. `./agent-login.py -L notion -s` → a new Safari window opens on
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
cd /Users/albert/obsidian/42-Git/home/browser-login && grep -c "app.notion.com" /Users/albert/obsidian/42-Git/home/browser-login/agent_login_safari.py
```

Each line is `cd <repo> && <argv>` (`tp verify` grammar); no live login. Read-only
smoke (not in the block, B3): `./agent-login.py -L notion -s -n`. Full suite: skipped
unless a touched file's neighbours fail (say so in the report).

## Rollback

- Before B3's install: discard the worktree branch; nothing live changed.
- After the install: `mv agent-login.py.bak agent-login.py`, then
  `mv agent_login_safari.py.bak agent_login_safari.py` (reverse order); live
  `./agent-login.py -h` exit 0. The recipe fix alone is one line (`host`) to revert.
  Remove the `.bak` files only after B4 step 3 passed (or after Albert decides to defer
  B4 and the B3 smoke passed).
- No state migration: the cooldown / quarantine files are untouched by the code change.

## Risks

- **The code page in Safari is unprobed** (it needs a sent code): its host and field
  are inferred from the headless success (`_OTP_FIELD`, same hosts). If it moves host,
  B1's `code_field` / host-pinned fill stops cleanly without a quarantine; B4 reports it.
- **One code mail per B4 attempt:** the 15-min cooldown blocks a quick retry; a stuck
  run costs one mail and a 15-min wait.
- **Logout side effects:** `notion.so/logout` revokes Safari's session only; the shared
  Chromium currently holds its own token (headless login 23:49), so it should stay
  logged in. If it had been imported from Safari since, it is logged out too and B4
  step 4 re-imports.
- **Live-file edits:** worktree + ordered atomic install with `.bak` rollback (B3).

## Open points

- None blocking. The code page's DOM in Safari is confirmed only by B4.
