## Session

Resume: `c --resume 3871ad21-0f16-4b68-828e-f9eb1f7a6847`

# WS1b — durability per login flow: agents log in through Albert's Safari

## Context

Part of `plans-done/PLAN_agent-login-repair_DONE.md` (box WS1b). Goal: every site in `./agent-login.py` stays
✅ for agents with no human to-do. Only four things stay with Albert: a CAPTCHA, a locked
vault, a hardware-key or push approval, and an SMS code.

Albert, 2026-10-11: the assisted and guided logins are done by AGENTS in his Safari. That
covers galaxus-de, notion, openai, slack and the Safari sites (anibis, kleinanzeigen, tutti,
galaxus). The agent fills the login from his unlocked Vaultwarden tab (`safari.py`), then
imports the session into the shared Chromium. It is never a `-g` to-do for Albert.

**Debate:** Codex (gpt-5.6-sol), 3 rounds, converged by the judge.

- 19 objections: 18 accepted, 1 rejected (the non-strict Verification block, kept with the
  reason below).
- In round 3, O6 was split into O6.1–O6.3, all accepted.
- Ledgers, replies and the outcome are in the session scratchpad, `ws1b/`.

Evidence gathered for this plan (read-only, 2026-10-12; cookie names and expiry only, never
values):

- **Safari already holds sessions** for:
  - Notion (`token_v2` until 2027-10-08);
  - Google (`SID`, `__Secure-1PSID`, `LSID` until 2027-11-14);
  - claude.ai (`sessionKey` until 2026-11-07);
  - Ricardo (`appSession`, `auth0` until 2026-11-01).
- **Safari holds none** for slack (`b`, `utm` only), chatgpt/openai (`cf_clearance`,
  `oai-did` only), galaxus.de and galaxus.eu (nothing).
- **The broker listing names each item** (`name`: "Galaxus.de", "tutti.ch", …) and gives
  `login_url`, `check_url` and `logged_in_selector`.
- **Portainer** (`https://portainer.dom42.space/`, nginx) still serves `index.html` with
  `Cache-Control: max-age=31536000` and no ETag. `/index.html` answers 301 with the same
  header.
- **The browser venv runs on uv's own CPython 3.14**, so a brew upgrade cannot break it.
  `agent-login.py` is stdlib only. Brew-sensitive: `vault-touchid` (pins python3, node and
  bw.js by sha256 in `~/.local/libexec/vault-touchid.stamp`) and the python user sites. Today
  both are current (3.15 holds all of 3.14's packages; the stamp matches).
- **The 10-min snapshot job cannot read Safari's cookie file** (no Full Disk Access). An
  agent's terminal can.

**The Verification block is not strict-eligible, and that is intended.** It runs ruff, mypy,
pylint, pytest and pre-commit, which execute repository code. Every Safari step is a manual
acceptance step for the main session. That covers live Safari logins, recipe labels, the
Notion endpoint spike, LaunchAgents, the disposable-instance run, and the NPM and mydotfiles
changes. Tests mock `safari.py` and himalaya; no test drives the real Safari.

## Closure matrix (every row: agent-only recovery, proof, allowed human blocker)

| row                         | recovery (agent)                                                                 | proof                                    | account proof                     | blocker allowed               |
| :-------------------------- | :------------------------------------------------------------------------------- | :--------------------------------------- | :-------------------------------- | :---------------------------- |
| broker sites (ready/extra)  | `browser.py login SITE` (broker), daily `-c`                                     | strict sentinel / server proof           | WS5 identity where multi-account  | none (vault Touch ID for setup) |
| npm-* (refreshable)         | + 6-hourly `-R` refresh pass (D7)                                                | sentinel + JWT expiry                    | –                                 | none                          |
| myfritz                     | on demand: `browser.py login myfritz` when needed (D6)                            | sentinel                                 | –                                 | none                          |
| anibis, tutti, kleinanzeigen | `-L SITE`: import Safari's session, else log Safari in (D1–D2)                   | broker sentinel after import             | –                                 | CAPTCHA, vault locked         |
| galaxus, galaxus-de         | `-L SITE` (import only by explicit run; broker never submits)                     | `[data-testid="customer-account-button"]` | –                                 | CAPTCHA, vault locked         |
| ricardo                     | `-L ricardo` logs Safari in; agents use Safari itself (no import)                 | Safari-side sentinel                     | –                                 | CAPTCHA, vault locked         |
| notion                      | `-L notion`: import Safari's session, else Google SSO, else the mail code         | tri-state server probe (D8)              | expected e-mail, in-page (O5)     | push (Google), SMS            |
| slack                       | `-L slack`: Google SSO, else the mail code                                        | team + token                             | team domain == SLACK_WORKSPACE_URL | push (Google), SMS           |
| openai                      | `-L openai`: Google SSO                                                          | admin members page                       | expected workspace, in-page       | push (Google), SMS            |
| anthropic, anthropic-private | `-L SITE` → the automated magic link `browser.py login anthropic -e EMAIL` (no Safari) | billing / account e-mail          | CLAUDE_ACCOUNTS e-mail            | a mailbox himalaya cannot read (L8) |
| switch / eduid              | broker SSO click (exists); blocked only by setup → L7 (sentinel, `-V`, `-p`)      | sentinel (after L7)                      | –                                 | Touch ID for the vault write  |
| multi-account groups (WS5)  | WS5 S4 (separate plan)                                                           | identity proof                           | WS5                               | Touch ID for vault fields     |

## Design

### D1 — `agent-login.py -L/--safari-login SITE`: one explicit agent run

**Explicit only. Why:**

- it drives Albert's real Safari: a new window, and his one Vaultwarden tab moves to a
  search;
- `safari.py` copies secrets through his clipboard (cleared twice);
- an SSO step may send a push to his phone.

A scheduled job doing that while he works is desktop interference nobody started. The agent
that needs the site IS the human-equivalent trigger, acting for Albert in a session he
started.

Enforced in three ways:

- every agent-login LaunchAgent sets `AGENT_LOGIN_SCHEDULED=1`, and `-L` refuses with it
  (exit 2);
- `-c`, `-S` and `-R` never call it;
- `-L` cannot be combined with `-c/-S/-R/-I/-U`.

Pipeline (one site, one run, no retries):

1. **Free check** in the site's instance. ✅ → record, exit 0. Busy → 75. Only a DEFINITIVE
   logged-out verdict (exit 2, code `logged_out`) continues. `indeterminate`, identity-unknown
   and quarantined (exit 2 with the release command) stop.
2. **Safari already holds a session** (cookie file; names, expiry, in-memory digest only)
   → the explicit import (`browser.py import-safari SITE -R`) and its proof. ✅ → done. This
   alone covers Notion today.
3. **Login in Safari** (D2) needs safari.py features `open, tabs, eval, handle, new_window`
   plus each step's own feature (`safari.py -V -j`; no `-V` = the v0 set, which has no
   `handle` → stop `safari_py_outdated`, exit 3, before any Safari action). It opens the start
   page in a NEW Safari window (`-o URL -W`) and runs the step machine.
4. **Cookie flush:** poll Safari's cookie file (≤ 90 s, every 2 s) until the session cookies'
   value-inclusive digest differs from the one taken before step 3. On timeout the import
   still runs; its proof decides.
5. **Import + proof** (`import-safari SITE -R -a`): event `safari-agent` only after an
   authenticating step and a passing proof. The verdict is recorded with route
   `safari-login`.

**Quarantine:** a run that may have sent a credential, SSO choice or code (`credential`) and
does not end ✅ writes the EXISTING client quarantine (`als.quarantine`). `-L` refuses a
quarantined site until the audited `-Q SITE`. Proven pre-credential stops are retryable.

**One Safari login at a time:** flock `<state>/safari-login.lock`, 120 s wait, then exit 75.

**Exit codes:**

| code | meaning                                                                   |
| :--- | :------------------------------------------------------------------------ |
| 0    | logged in                                                                 |
| 2    | not logged in / stuck / refused                                           |
| 3    | environment: safari.py missing or outdated, Safari unavailable, cookie file unreadable |
| 4    | needs Albert (D3)                                                         |
| 75   | busy                                                                      |

**`-n/--dry-run`:** steps 1–2 report only (no import), plus `safari.py -V`.

**claude.ai** (`anthropic`, `anthropic-private`): `-L` routes to the existing automated
magic-link login in the site's instance (`browser.py login anthropic -e EMAIL`;
`_claude_auto_login`: sender allow-list, baseline, embedded-e-mail check). No Safari.

### D2 — recipes and the step machine (`agent_login_safari.py`)

**Recipe:** `Recipe(site, hosts, sentinel_host, steps, start_url, sentinel, broker,
import_after, identity)`. For a broker site, the start page, the sentinel and the vault item
come from the broker listing.

**Override file:** `~/.config/agent-login/safari-logins.json` (0600, this user, regular
file, outside the public repo). It holds `{site: {item?, account?, expected_email?,
expected_workspace?, mailbox?}}`; an unknown key → refused.

**Step kinds** (each needs its own safari.py feature):

| kind        | safari.py call                                                      | feature        |
| :---------- | :------------------------------------------------------------------ | :------------- |
| `user`      | `-L ITEM -H WID -X -S LABEL` (username only)                         | `user_only` (M1) |
| `login`     | `-L ITEM -H WID -S LABEL [-N]`                                       | `login`        |
| `otp`       | `-O ITEM -H WID -S LABEL`                                            | `otp`          |
| `click`     | `-c LABEL -R LABEL -H WID`                                           | `click`        |
| `account`   | `-c ACCOUNT -R ACCOUNT -H WID` (the Google chooser; account from the override file) | `account_pick` (M2) |
| `mail_code` | himalaya read (D2b) + `-e FILE -H WID` (a 0600 JS file, deleted in `finally`) | `eval`  |

**The loop** (≤ 40 polls, 3 s apart):

- **Read the tab:** `-t -j` → the login window must hold exactly ONE tab on a recipe host.
  Otherwise stop `safari_tab_moved` (insertion, closing, a foreign host); `about:blank` =
  still loading.
- **Read the page:** the detector (D3) through `-e FILE -H WID`, validated against a closed
  schema of booleans.
- **Done:** the sentinel is visible on `sentinel_host` → done.
- **Albert's stop** → exit 4.
- **Run a step:** the first unrun step for this host whose `when` is visible and `unless` is
  not runs, ONCE.
- **Stuck:** nothing to do for 4 polls → `recipe_stuck`.
- **Always** `-C -H WID` (closes only that one-tab window) in `finally`.

**What leaves safari.py:** only `ok`, the exit code, `window_id`, tab URLs (reduced to a
validated https host), and `result` (the detector JSON). Its error text is classified by
fixed patterns into codes and then dropped. `text`, `candidates` and `row` are never read.

**Recipes** (labels UNVERIFIED until L2; a wrong label only stops the run):

| site           | hosts                                     | steps                                             |
| :------------- | :---------------------------------------- | :------------------------------------------------ |
| galaxus-de     | www.galaxus.de, id.galaxus.eu             | user "Weiter" → login -N "Anmelden"                 |
| galaxus        | www.galaxus.ch, id.digitecgalaxus.ch      | same                                                |
| anibis / tutti / kleinanzeigen | www + auth/login host     | one-page login, else user → login -N               |
| ricardo        | www.ricardo.ch, login.ricardo.ch          | same; `import_after=False`                          |
| openai         | chatgpt.com, auth.openai.com, accounts.google.com | click "Continue with Google" → account (opt.) → click "Continue" (opt.) |
| slack          | swiss-data-science.slack.com, app.slack.com, slack.com, accounts.google.com | Google as above → mail_code (fallback) |
| notion         | www.notion.so, app.notion.com, accounts.google.com | Google as above → mail_code (fallback) |

**D2b — mail codes** (Notion / Slack fallback):

- **Mailbox:** himalaya, account from the override file (`mailbox`). L8/M6 are blocking:
  WS1b does not close while the Notion/Slack mailbox is unreadable.
- **Baseline before the trigger:** process-local HMAC digests (random per-run key, memory
  only) of every code in login-subject mails from the allowed senders. An old mail moved to
  Archive under a new id stays excluded. An unreadable baseline → no code is ever taken.
- **After the trigger:** only new mails from an allowed sender (exact address/domain),
  addressed to the expected e-mail, whose subject matches the recipe's login-subject
  predicate. Exactly ONE distinct code across them (duplicates of one code are fine; two
  different codes → `email_code`).
- **Typing:** the code goes in through a 0600 JS file (native setter + events, exact-one
  submit button), never argv or output. It is a credential step.

### D3 — hard stops (detected, never clicked)

The detector returns these booleans: `captcha`, `sms`, `push`, `hardware_key`,
`email_code`, `password`, `user`, `code`, `sentinel`, and per step `when`/`unless`.

- **`captcha`:** a visible challenge: the reCAPTCHA `bframe`, an `anchor` iframe larger
  than 2×2 that is not `size=invisible` (the myfritz learning), hCaptcha, Turnstile, Arkose,
  Cloudflare's `#challenge-form`.
- **`push` and `hardware_key`:** only on a page without password, user or code fields (a page
  that merely offers "use a passkey" is not a stop).
- **`sms`:** needs a visible code field.
- **The texts** are fixed EN/DE/FR regexes evaluated in the page; only booleans leave it.
- **Vault locked:** safari.py exit 3 with the lock-screen or missing-vault-tab class.

**Albert's stops** are `needs_albert_captcha|sms|push|hardware_key|vault_locked`: exit 4,
phase `safari-source`. agents.md shows "needs Albert (…)". `email_code` is the agent's (D2b).

### D4 — imports of the new sites

- **`SAFARI_SITES["galaxus-de"]`:**

  | setting           | value                    |
  | :---------------- | :----------------------- |
  | domains           | `galaxus.de`, `galaxus.eu` |
  | session cookie    | `.at`                    |
  | drop_bot_cookies  | yes                      |
  | import_unattended | no                       |

  It stays `agent_no_submit` and joins TARGETS as a `safari` row.
- **`SAFARI_BUILTIN`** (built-in sites, consent = this table, Albert 2026-10-11): notion
  (`token_v2`), slack (`d`), openai (`__Secure-next-auth.session-token*`). Their own
  `login`/`logged-in` routing is unchanged; only the explicit `import-safari` knows them.
  Session cookie names are fnmatch patterns.
- **A built-in import is ONE transaction under ONE interaction lease:**
  1. replace the in-scope cookies;
  2. run the built-in proof plus the identity check (O5): Notion's expected e-mail in-page
     through `loadUserContent`, OpenAI's expected workspace in-page on `/admin`, Slack's team
     domain;
  3. on anything but a proven match, FAIL TO LOGGED-OUT in a `finally`: delete every in-scope
     cookie (and Slack's `localConfig_v2` on app.slack.com).

  A missing expected value → `identity_unconfigured`, nothing imported.
- **Events:** a plain import records `safari-import`, not a login. `-a` → `safari-agent`.

### D5 — what agents and Albert see

- **agents.md header:** "for sites on Albert's session run `agent-login.py -L <site>`
  (through Albert's Safari: a new window, his clipboard; one run, no retries) — never ask
  Albert; only CAPTCHA / SMS / push / security key / locked vault are his".
- **❌ lines:** they say `-L SITE`, or "needs Albert (…)" for his stops.
- **`_setup_problem`:** a Safari row with a recipe and no Safari session is not a setup ❌
  while its Chromium check is ✅. It gets a flag instead.
- **`safari_fix`, the mail, `NO_SUBMIT_NOTE` and the TARGETS notes:** `-L` instead of `-g`.

### D6 — on demand (myfritz)

`ON_DEMAND_SITES = {"myfritz"}` (Albert: 10 h Keycloak session, "on demand").

- **Overview:** the row shows ⏯ on demand plus the last check.
- **`-c`:** neither checks nor logs it in and records nothing. It removes its
  `last-check.json` row (infra/status).
- **agents.md:** "⏯ myfritz: on demand — `browser.py logged-in myfritz`; if it fails,
  `browser.py login myfritz`".
- **A vault field** for this is deferred: it needs a broker release and touches WS3's config
  canon.

### D7 — refresh pass `-R/--refresh-pass` + `com.albert.agent-login-refresh`

- **The pass:** network wait (≤ 60 s) → `ensure_browser_up` → `reap-owned` → for every
  default-instance row with `session_refresh`: one free probe, then the existing
  `refresh_step` (`login -F` below 12 h).
- **Never:** it never logs in, never submits, never quarantines, and records nothing in
  checks.json.
- **Skipped:** busy, off-LAN and role-instance rows.
- **Its own LaunchAgent** (6 h, not RunAtLoad, `AGENT_LOGIN_SCHEDULED=1`), not part of `-S`:
  `-S` must stay fast and is loaded today.
- **Install:** `-I`/`-U`/`-P` handle all three agents as ONE transaction. Old plists are
  backed up and the loaded state recorded; any failure → unload, restore and reload what was
  loaded. So the refresh pass stays off while the daily job is off.

### D8 — Notion: tri-state, 2-run mail rule, telemetry, login events

**The probe:** in the probe tab on app.notion.com, a `fetch` with an AbortController (10 s).
It returns an enum only:

| server answer                                  | enum            |
| :--------------------------------------------- | :-------------- |
| 200 + the expected shape                       | `valid`         |
| 401 or an opaque redirect                      | `invalid`       |
| anything else                                  | `indeterminate` |

**The verdict:**

| server        | page                 | verdict                   |
| :------------ | :------------------- | :------------------------ |
| valid         | any                  | valid                     |
| invalid       | /login or no sidebar | invalid                   |
| invalid       | sidebar              | indeterminate             |
| indeterminate | sidebar              | valid, `proof: dom`       |
| indeterminate | /login               | invalid                   |
| indeterminate | else                 | indeterminate             |

- **The endpoint:** L0 checks it live before the server verdict can turn a row ❌. A wrong
  endpoint only yields `indeterminate`.
- **Exit codes:** 0 valid; 2 + code `logged_out` (invalid) or `indeterminate`. `server`,
  `proof` and `cookie_days_left` go to the result record.
- **Expiry telemetry:** `context.cookies(app.notion.com)` → the days to expiry of `token_v2`
  and `notion_user_id`. Values are dropped at once. The overview warns below 30 days.
- **agent-login:**
  - assisted rows read the result record; `indeterminate` = could not tell (unknown);
  - checks.json `invalid_streak` counts RUNS: +1 at most once per run id and ≥ 1 h after the
    previous counted invalid; ok resets it, unknown keeps it;
  - `-c` re-probes a first-invalid assisted row once at the end of the run, which decides
    only this run's verdict;
  - `-m` mails an assisted site only at streak ≥ 2.
- **`_record_login_event`:**
  - a guided login that ends ok records `guided`, at the transaction layer, and only if no
    event of the site was logged since it began;
  - `guided` joins `ASSISTED_MODES`;
  - imports record as in D4.

### D9 — toolchain after a brew upgrade (`agent_login_toolchain.py`; the remedy is M3)

- **(a) The vault-touchid stamp:**
  - the header must be `# vault-touchid build stamp v1`, else ❓;
  - runtime rows are recognised by path shape (Cellar python@*/bin/python3.*, Cellar
    node/*/bin/node, @bitwarden/cli/build/bw.js);
  - the helper is stale when a pinned file is missing or its sha256 differs, or when
    `/opt/homebrew/bin/{python3,node}` now resolves elsewhere;
  - → `❌ … fix: ~/obsidian/42-Git/home/mydotfiles/tools/vault-touchid/build.sh`.
- **(b) The user site** of the running python3 against the newest lower minor's:
  - names come from METADATA, canonicalised (PEP 503);
  - the missing ones are pinned `name==version` in ONE `uv pip install --python … --target …`
    line;
  - `direct_url.json` or several versions of one name → "reinstall by hand", never pinned.
- **Shown:** in the overview and in `-c` (failed list). Never in agents.md. agent-login
  never runs a build or an install itself.

### D10 — Portainer's long-cached `index.html`: still relevant, server fix, no client code

- **Why it is still relevant:** the cache bypass protects only the broker profile and the
  proof tabs. An agent's own tab reads the shared HTTP cache. After a Portainer upgrade that
  tab would load the stale shell and render blank while the probe says ✅.
- **The fix is on the server:** NPM proxy host `portainer.dom42.space` → Advanced:

  ```nginx
  location = / { proxy_pass $forward_scheme://$server:$port; proxy_hide_header Cache-Control; add_header Cache-Control "no-cache" always; }
  ```

  plus the same for `= /index.html`. Rollback = remove the block.
- **Proof:** `curl -sI` of `/` and `/index.html` shows exactly one Cache-Control line,
  containing `no-cache` and not `max-age`. It must FAIL before the change (recorded) and pass
  after.
- **Ownership:** a tp item for the main session (subagents do not file). WS1b ships no client
  code for it.

## mydotfiles specs (not built here)

- **M0 — `safari.py -V/--capabilities -j`** → `{"v": 1, "features": [...]}`. Features:
  `status, open, tabs, eval, click, login, otp` + the new ones below.
- **M1 — `-L ITEM -X/--user-only`:** copy and fill only the username, then `-S`. It excludes
  `-N`/`-P`. Feature `user_only`.
- **M2 — `-c` also matches** `[role=link]`, `[role=option]` and `[data-identifier]` (the
  Google chooser; the label may equal `data-identifier`). Same exactly-one rule. Feature
  `account_pick`.
- **M4 — handles:**
  - `-o URL -W/--new-window` opens a new window and returns `window_id`;
  - `-H/--handle WID` addresses -e/-c/-L/-O/-C to that window's ONLY tab, exit 2 when it is
    gone or holds ≠ 1 tab;
  - `-C/--close -H WID` closes it under the same check;
  - `-t -j` includes `window_id` (it already does);
  - features `handle`, `new_window`, `close`;
  - adversarial tests: tab inserted into the window, window closed, a same-host tab
    elsewhere.
- **M3 — brew-maintenance post-upgrade hook:** after `python@*`, `node` or `bitwarden-cli`:
  `tools/vault-touchid/build.sh` (stamp-checked), then a user-site re-sync pinned
  `name==version` from METADATA (`direct_url.json` and ambiguous versions excluded and
  reported). On failure, an ntfy alert + a ❌ line. The same check sits in mac_bootstrap's
  `build:vault-touchid`.
- **M6 — a read-only himalaya account for the mailbox Notion/Slack send codes to**, if L8
  shows none. Blocking for WS1b's closure.

## Steps

- [x] S1 `broker/safari_cookies.py`: galaxus-de, `SAFARI_BUILTIN`, `rule`, fnmatch session
      cookies, value-inclusive `session_fingerprint`; tests.
- [x] S2 `bin/browser.py`: `import-safari` for built-ins as one lease transaction with
      identity + fail-to-logged-out; `-a`; `safari-import` events; Notion tri-state probe
      (`server`, `proof`, `cookie_days_left`, expected e-mail); Slack team check; guided
      event; tests.
- [x] S3 `broker/phases.py`: the new codes; tests.
- [x] S4 `agent_login_safari.py`: recipes, override file, detector, step machine, mail codes
      (D2b); tests with a fake safari.py and a fake himalaya (adversarial: leak, tab moved,
      foreign sender, wrong recipient, moved old mail, two codes).
- [x] S5 `agent-login.py`: `-L`, `-n`, `-R`; galaxus-de row; on-demand; texts; tri-state +
      streak + end-of-run re-probe; quarantine + `-Q`; claude.ai route; toolchain lines; tests.
- [x] S6 `agent_login_state.py`: `invalid_streak` (runs, 1 h), `server`, `cookie_days_left`,
      `drop_legacy`; tests.
- [x] S7 `agent_login_jobs.py`: refresh LaunchAgent, `AGENT_LOGIN_SCHEDULED`, transactional
      `-I`; tests.
- [x] S8 `agent_login_toolchain.py`; tests.
- [x] S9 README + AGENTS.md + the master plan's WS1b box.
- [x] S10 lint + full suite + `lint-gate.py -c -M -b HEAD <files>`.

## Build notes (2026-10-12, worktree; not committed, not released)

Deviations from the design text above, each deliberate:

- **Only Notion's `-c` check is tri-state** (`TRISTATE_SITES`, `assisted_verdict`).
  The other assisted sites keep their boolean `logged-in`. The re-probe and the 2-run
  mail rule apply to every assisted row.
- **Slack's team check and OpenAI's workspace check run only in the built-in import**,
  where they decide commit or clear. The daily probes are unchanged. Notion's free check
  compares the e-mail only once `expected_email` is configured (then `wrong_account` → ❌).
- **The Google chooser and consent steps are `optional`:** a safari.py refusal
  (exit 2, nothing copied) skips them instead of stopping the run.
- **`-L` stops at once when Safari's own session imports with `identity_unconfigured`
  or `wrong_account`**: a Safari login cannot change either.
- **claude.ai uses `browser.py login anthropic` with `ANTHROPIC_LOGIN_EMAIL` set** (the
  automated magic link). It does not use `-e`, which is the assisted path only. Without a
  readable mailbox it ends with browser.py's exit 4.
- **Toolchain findings join `-c`'s failed list** (exit code and the `-m` mail), not
  `last-check.json`.
- **Test isolation (conftest):** `AGENT_LOGIN_SAFARI_OVERRIDES` (override file path) and
  `AGENT_LOGIN_TOOLCHAIN=off`.
- **Every recipe label and the Safari-side sentinels for openai and slack are guesses**
  until L2. Notion's server endpoint and response shape are guesses until L0. A wrong
  value only stops a run or reads `indeterminate`.

## Security review round 1 (overseer, 2026-10-12): applied

- **B1 — `-L` goes on only from a definite logged-out.** That is `rc == 2` and
  code `logged_out` (`CONTINUE_CODES`; Notion also `wrong_account`). Every other
  answer stops with its code named: `internal`, `unknown`, empty, a timeout, a
  kill, `indeterminate` or a gated code. `cmd_slack_logged_in` and
  `cmd_openai_logged_in` are tri-state now (`_slack_state`, `_chatgpt_state`):
  - `logged_out` only when the sign-in URL or page is reached;
  - `indeterminate` on a navigation error, a timeout, a Cloudflare challenge
    or an unexpected landing page.
- **S1/S4 — long safari.py options only.** Every machine call uses
  `--open/--new-window/--wait`, `--tabs`, `--eval`, `--click/--row`,
  `--login/--otp/--submit/--user-only/--no-user`, `--close`, `--capabilities`
  and `--json`. Every `--eval`, `--click`, `--login` and `--otp` passes
  `--handle WID --expect-host HOST`. The required features are `handle`,
  `new_window`, `close`, `expect_host` and `sigterm_clear`, plus `user_only` /
  `account_pick` per recipe. A safari.py without `--capabilities` has NO
  features.
- **S2 — agents.md promises `-L` only when the features are there.**
  `agent_route` (agents.md, `_summary_reason`, ❌ texts, `safari_fix`,
  `_setup_problem`) promises `-L` only when `missing_features(site)` is empty.
  claude.ai's magic link needs no safari.py. Otherwise the old wording stays
  (`-g` / `-t` / "Albert logs in in Safari"). `-L SITE -n` prints the capability
  check.
- **S3 — the runner terminates, then kills.** The runner is Popen in its own
  process group: SIGTERM, a 5 s grace, then SIGKILL (`Reply.killed`). After a
  killed `login` / `user` / `otp` step the clipboard is cleared
  (`clear_clipboard`, pbcopy of nothing). Budgets: 180 s for `--login` /
  `--otp` (safari.py's worst case is about 125 s), 75 s otherwise.
- **S5 — the interactive gate** (`interactive_gate`, exit 3, named reason). It
  refuses when:
  - `AGENT_LOGIN_SCHEDULED` is set;
  - the console is not unlocked or Albert is not on it (`ioreg -n Root`
    `IOConsoleUsers`);
  - `HIDIdleTime` > 15 min.

  An unreadable state is also refused. README: "a Safari login never runs on
  an unattended Mac".
- **S6 — proof in a throwaway context.** The proof runs in a THROWAWAY
  Playwright context (`browser.new_context()` = `Target.createBrowserContext`,
  closed in `finally`, disposed on detach). The shared jar changes only on
  `match`, then the shared browser's own check runs again. A failure is
  undone and `undo: done|failed` recorded; `-L` shows a failed undo. No
  pending-import marker was needed: the isolated proof is feasible for all
  three sites (live check L1).
- **S7 — the import starts with the site's own check.** It must say a
  definite logged-out (Notion: or another account). A working session (exit
  0) or an undecidable one (exit 2) is never touched.
- **S8 — Slack.** The commit clears `localConfig_v2` first. The proof is
  `/api/auth.test` with the token from the page's own storage + the `d`
  cookie, comparing team id AND user id (`expected_team_id`,
  `expected_user_id`).
- **S9 — OpenAI.** The session's access token (`/api/auth/session`, it stays
  in the page) asks `/backend-api/accounts/check/v4-2023-04-27`.
  `expected_workspace_id` must be among the account ids. No `innerText`.
- **S10 — Notion.** The user record whose id is the `notion_user_id` cookie
  (or the ONLY record) — its e-mail is compared in the page.
- **S11 — Notion before L0.** Until `notion_probe_verified: true` only a 401 is
  `invalid`. A visible sidebar against a server "invalid" stays ✅ with a
  warning (`proof: dom-unverified`). The import's proof always needs the
  server's `valid`.
- **S12 — `Step` has a `trigger` and a `submit`.** The Notion recipe is the
  mail code:
  1. the expected e-mail is filled (`EMAIL_FILL_JS`);
  2. the trigger "Continue" is clicked;
  3. the mail is awaited;
  4. the code is filled and the submit "Continue with login code" clicked in
     ONE eval (`CODE_FILL_JS` gets the submit label).

  The order is tested.
- **S13 — signed, stable mail codes.** A mail code counts only when the
  topmost `Authentication-Results` says `dkim=pass` for the sender's domain
  (or a parent of it). The body comes from
  `himalaya message read --preview --header Authentication-Results`. The code
  must be one distinct code in two consecutive polls.
- **N1 — toolchain.** A user-site gap is ❌ only within 14 days of the minor
  change, ⚠️ afterwards; `AGENT_LOGIN_USERSITE_IGNORE` lists names never
  reported. The vault-touchid check hashes EVERY pinned file of the stamp.
- **N2:** `-R` skips while `com.albert.agent-login-check` is not loaded
  (`daily_loaded`).
- **N3:** the install marks a label before writing; a write error rolls back;
  rollback file errors are reported, the rest still rolled back.
- **N4:** the import after a login is `-a` only when steps ran.
- **N5:** an import that answered 75 / 124 / 125 / killed / `indeterminate`
  stops; no Safari login follows.
- **N6:** `-n` is read-only: no free check, no import, no record;
  `--capabilities` + gate + Safari session. `-L` is exclusive with
  `-c/-S/-R/-I/-U/-t/-g/-p/-Q/-D/-E`.
- **N7:** `_record_assisted` keeps `wrong_account`.
- **N8:** `busy` → 75. An open without a window id → `safari_window_unknown`,
  named ("may be left open"). A failed open that named its window closes it.
  "Quarantined" is printed only when the quarantine was written.
- **N9:** the Google account / consent steps have `unless: password`.
  `push` / `hardware_key` need a challenge route (`/challenge|mfa|2fa|verif|…/`)
  AND no form field, not just the text.
- **N10:** `MAIL_FOLDERS` += `[Gmail]/All Mail`. Missing folders are skipped
  only at the baseline; a baseline folder that stops answering = unreadable.
- **N11:** a quarantined row's ❌ names `./agent-login.py -Q SITE`.
- **Tests:** conftest pins `AGENT_LOGIN_SAFARI_FEATURES=none`; the
  feature-dependent wording is tested both ways.
- **A convention change for S6.** The throwaway context's page is the ONE
  sanctioned `new_page` in browser.py. `tests/test_owned_tabs_tp845.py` now
  allowlists `_builtin_prove_isolated` instead of forbidding every `new_page`.
  `browserContextId` stays forbidden in the source: Playwright creates the
  context. `_stub_checks` there also stubs the new tri-state checks.

- **safari.py review, item 1:** every `--expect-host` is the RECIPE's step host.
  The mail-code fill no longer derives it from the tab.
- **safari.py review, item 2:** a safari.py exit by a signal (≥ 128 through a
  shell, or a negative Popen code) counts as "may have been done"
  (`interrupted`). It sets `credential` for login, user and otp steps, clears
  the clipboard and is never an optional skip. Code `safari_signal`.

**Updated mydotfiles spec (replaces M0–M4 above; final letters per the
safari.py review):** `-V/--capabilities`, `-M/--new-window`, `-H/--handle`,
`-C/--close`, `-X/--user-only`, `-E/--expect-host HOST`. agent-login uses the long
names only. `--expect-host` is a hostname, re-checked right before every fill and
click; safari.py additionally pins the tab's full origin as it was when selected.
On SIGTERM safari.py clears the clipboard (feature `sigterm_clear`).

## Re-review round (SF1–SF3, gate, NITs; overseer, 2026-10-12): applied

- **SF1:** AGENTS.md states the ONE `new_context()` exception precisely,
  including the residual. For as long as the proof runs, the proof tab shows up
  to other Playwright clients of the shared browser. Its jar, storage and service
  workers stay separate. The window is as short as the prover: Notion one server fetch
  (≤ 10 s), OpenAI two fetches (≤ 10 s), Slack its boot poll (≤ 20 s) plus
  `auth.test` (≤ 10 s), each plus the page load — about 45 s at most.
  - Notion's proof is now ONE server fetch with no sidebar wait.
  - The owned-tab ledger line names the exception.
- **SF2:** agents.md promises `-L` only where `agent_route` routes:
  - **The header (`_route_header`):** lists only the routed sites, then
    "exit 3 = the Mac is locked or idle: retry later, do not ask Albert", then
    "ask Albert to run `-g`" for the rest.
  - **The target notes:** neutral, with `route_hint(site, row)` appended.
  - **The `check_only_gate` text and the ❌ / ✅ lines:** built from
    `route_hint`.
  - **A recipe site with a live, unexpired Safari session** (`safari is True`)
    is routed even without the new safari.py features: `-L` then imports
    Albert's existing session ("an agent imports Albert's existing Safari
    session").
- **SF3:**
  - **ChatGPT** (`_chatgpt_state`): read from `/api/auth/session`. `{}` =
    invalid, a `user` = valid, anything else (a challenge or a fetch error) =
    indeterminate. The landing URL no longer decides.
  - **Slack** (`_slack_state`): polls for `localConfig_v2` every 1 s, for up
    to 20 s. Both the proof (`_slack_identity`) and the post-copy check
    (`_slack_logged_in`) use it.
  - Both are **to verify live in L1/L2**.
- **The gate:** refuses when `CGSSessionScreenIsLocked` or `IOConsoleLocked`
  (on the root or the session) is true. A present but non-boolean value is
  `console_unknown`. Documented: the gate proves SOMEONE is at the unlocked Mac,
  not that Albert started the run.
- **TERM grace:** `TERM_GRACE_S = 8.0` (safari.py's signal path takes about
  6 s).
- **NITs:**
  - `TRISTATE_SITES` = notion, slack, openai.
  - Notion's `mine` comes from `context.cookies()` (`_notion_user_id`).
  - OpenAI takes an optional `expected_email`, compared with
    `session.user.email`.
  - The AST test maps each `new_page` / `new_context` call to its innermost
    enclosing def (async and module level included), counting each call once.
  - `AGENT_LOGIN_SAFARI_FEATURES` is honored only under `PYTEST_CURRENT_TEST`.
  - `-L notion` is worded as working with an existing Safari session.
  - "Scheduled" = any non-empty `AGENT_LOGIN_SCHEDULED`.

## Live acceptance (main session; not in the Verification block)

- [x] L0 (2026-10-12) Notion: `logged-in notion` → proof `server`, server `valid`, identity `match` (expected e-mail set). `notion_probe_verified` left false on purpose (the logged-out redirect is untested; unverified = a redirect is "cannot tell", never ❌). Slack ids from `auth.test` with Albert's own token (slack-api). OpenAI workspace id: no independent source yet → OpenAI import stays unconfigured (fails closed). Override file written (0600). Original: Notion spike (owned tab, read-only): the status + key shapes of `loadUserContent`.
      The expected e-mail is confirmed from an independent source (workspace members in
      Albert's Safari, or the invitation mail), then written to the override file. The
      OpenAI workspace id (`expected_workspace_id`) is confirmed in the Business admin
      console the same way, and Slack's team and user ids (`expected_team_id`,
      `expected_user_id`) from the workspace's admin pages. Once a 401 is seen logged
      out and 200 logged in, set `"notion": {"notion_probe_verified": true}`.
- [x] L1 (2026-10-13: cold import ✅ account proven; wrong expected e-mail → mismatch in the throwaway context, nothing imported — the jar holds only the anonymous cookies of Notion's own logged-out check, no session cookie) Disposable instance (`CLAUDE_BROWSER_CACHE_DIR=<tmp> browser.py --cdp-port <free>
      up`): cold `import-safari notion` ✅. A wrong expected e-mail → `wrong_account` and the
      cookies are gone. Then `down`.
- [x] L2 (DONE 2026-10-13: fixes c… — visible one-page form, Auth0 captcha = needs_albert_captcha, tutti "Einloggen", galaxus(-de) one-page "Weiter", safari.py ignores aria-hidden decoys; re-run `-L tutti` → "needs Albert: a CAPTCHA in Safari" before any credential step. Read-only: galaxus-de verified; galaxus/anibis/kleinanzeigen/ricardo IdPs redirect while logged in, labels unverified. Albert allowed logging out tutti: `-L tutti` → "no next step". Live findings on auth.tutti.ch (Auth0): user button "Einloggen" not "Weiter"; two "Einloggen" buttons, the first aria-hidden (decoy); a hidden helper password input makes ONE_PAGE_FORM match the identifier page; an auth0_v2 captcha blocks the submit → Albert's stop. Builder fixing the recipe + captcha detection + read-only check of the other Safari IdPs. Earlier wording: waits for a Safari site's session to lapse: notion/slack/openai/galaxus are ✅ today, and `-L` starts only from a definite logged-out) Per recipe, in Albert's Safari (after M0/M1/M2/M4): confirm the hosts and labels
      (`safari.py -r`), fix the table, one `-L SITE` where a session is due.
- [x] L3 (2026-10-13 ✅: Notion cookies cleared in the shared jar → definite logged-out; `-L notion -n` = import first, `-L notion` imported Albert's Safari session, logged-in ✅; earlier dry run ✅ 2026-10-12: features complete, gate closes when the Mac is idle, Safari session present → import first) `-L notion -n`, then `-L notion` (import path).
- [x] L4 Final acceptance: `./agent-login.py -I`, then one observed refresh pass. (2026-10-13: two launchd runs via `launchctl kickstart` (= the scheduled job's context): the first found launchd's PATH lacked /usr/sbin (lsof → role browsers never stopped, exit 1), fixed + reinstalled; the second: every site ✅ or ⏸ off-LAN, role browsers stopped; open: openai 'could not tell' (builder), komga needs the home LAN to promote. `-I` ✅ — check daily 09:15, snapshot 10 min, refresh 6 h; a manual `-R` refreshed cscs/npm-nixos/npm-raspi with no login. Open: the first SCHEDULED 09:15 run, read from its log.)
- [x] L5 (tp#935, done 2026-10-12) Portainer NPM change + the header proof (fails before, passes after).
- [x] L6 (M0–M4 released 2026-10-12; M6 not needed: himalaya `epfl` reads the Notion mails) mydotfiles M0–M4, M6 (builders in mydotfiles, their own plan).
- [x] L7 (2026-10-13) edu-ID: sentinel `a[href="/account/security"]` (the account tabs; the
      `/oidc/logout` links sit in closed dropdowns, invisible → no proof), check/login URL
      `https://eduid.ch/account/organisations/`, fill `https://login.eduid.ch`, cookie hosts
      `eduid.ch,login.eduid.ch`; `-p eduid` ✅, then `-t switch` ✅ (SSO click on the edu-ID
      session; switch is a built-in site, no promotion). Lesson: `broker-add.py -L` alone
      RE-DERIVES every login field from the item's URIs (documented) — always dry-run (`-n`)
      and pass `-s -o -c -u -k` explicitly. Original steps:
      1. `browser.py logged-in eduid -x '<CSS>'` (two-sided);
      2. `agent-login.py -V -i <manifest>`;
      3. `broker-add.py -L` (Touch ID);
      4. `-p eduid`, then `-p switch`.
- [x] L8 (2026-10-12: Notion codes go to albert.glensk@epfl.ch → himalaya `epfl`) Mailbox: which himalaya account reads the Notion/Slack code mails. None → M6, then a
      self-sent test mail is listed and read. Blocking.

## Deferred

- `agent_on_demand` as a vault field (broker release + WS3 canon).
- Credential-change detection beyond `-f` (WS4).

## Verification

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run ruff format --check bin/ broker/ tests/ agent-login.py agent_login_jobs.py agent_login_state.py agent_login_safari.py agent_login_toolchain.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run ruff check bin/ broker/ tests/ agent-login.py agent_login_jobs.py agent_login_state.py agent_login_safari.py agent_login_toolchain.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run mypy bin/browser.py agent-login.py agent_login_state.py agent_login_jobs.py agent_login_safari.py agent_login_toolchain.py broker/safari_cookies.py broker/phases.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pylint bin/browser.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pylint agent-login.py agent_login_state.py agent_login_jobs.py agent_login_safari.py agent_login_toolchain.py broker/safari_cookies.py broker/phases.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pre-commit run --all-files
cd /Users/albert/obsidian/42-Git/home/browser-login && bin/browser.py -h
cd /Users/albert/obsidian/42-Git/home/browser-login && ./agent-login.py -h
```
