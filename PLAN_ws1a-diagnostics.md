## Session

Resume: `c --resume 3871ad21-0f16-4b68-828e-f9eb1f7a6847`

# WS1a — login diagnostics, scheduler safety, attempt groups

## Context

Part of `PLAN_agent-login-repair.md` (section WS1a, the hard gate before any secret-submitting
site retry). Albert: "we need every time to see from the ./agent-login.py script what broke
exactly ... where the error was; as granular as possible"; the daily check must never burn the
broker limiter again; a ✅ must be a proven, fresh ✅. Plan debated with Codex (gpt-5.6-sol),
2026-10-09; the ledger is in the session scratchpad (`ws1a/ledger_r*.md`).

What is wrong today (read from the code, 2026-10-09):

- **Reasons are lost.** The broker returns `{"error", "detail", "diag"}`; `browser.py` prints the
  diag to stderr; `agent_login_jobs.run_browser(capture=True)` drops stderr; `record_check`
  stores only `"NOT logged in (browser.py login exit 2, check exit 2)"`. A locked site then reads
  "rate limited" forever and the first failure's reason is gone.
- **The daily `-c` walks sites into the hard block.** A post-submit failure starts a 30-min
  cooldown; the next daily run makes attempt 2, the next attempt 3 → hard block (how calibre,
  galaxus, galaxus-de, npm-nixos, npm-raspi, myfritz-alzenau got locked). `ensure_logged_in`
  (agent-login.py:883) even retries once after a 124 — the broker may already have typed the
  password in that run.
- **The positive proof is weak.** `recipes.logged_in` and `browser.py _broker_probe` accept
  "off every fill origin, no visible password field" — which also passes on an Access-Denied
  page (zendesk). A visible selector is not bound to an origin or an HTTP status.
- **No freshness.** A ✅ from three weeks ago still reads ✅; removed items (zendesk) stay
  listed; a new broker item is scheduled for logins the moment it appears.
- **One account, two site ids** (galaxus / galaxus-de) is invisible to the limiter.

**The Verification block is not strict-eligible, and that is intended.** It runs pytest,
mypy and pylint, which execute repository code. Live steps (install.sh, selfcheck, the
scheduled acceptance, canaries) are manual release steps under the master plan's attempt policy.

## Design

### D1 — Phase codes, versioned (`PHASE_V = 1`)

One closed vocabulary in `broker/phases.py` (pure; imported by the daemon, `bin/browser.py` and
`agent-login.py`): phase → fixed text, code → fixed text, `phase_for_error(code, phase)`,
`post_submit(phase, submitted)`, `redact(text)`.

| phase               | where it stops                                                                   |
| :------------------ | :------------------------------------------------------------------------------- |
| `precheck`          | site lookup, broker unreachable, client gates (quarantine / pending / state)     |
| `limiter`           | broker limiter refused (`locked`, `cooldown`, `interval`, `cap`, `busy`, `quarantined`, `unreadable`) |
| `vault`             | unknown / refused item, `needs_sentinel`, Bitwarden unreadable                   |
| `recipe`            | the recipe gave up BEFORE the password reached the page                          |
| `submit`            | failure after the password was entered (wrong password, OTP, still on login)     |
| `profile-proof`     | PRE-auth: the broker profile's proof could not decide (no reservation made)      |
| `broker-proof`      | POST-auth: the recipe returned, the proof (status + origin + sentinel) failed    |
| `bundle-export`     | proof passed, export failed or empty (0 cookies and 0 storage keys)              |
| `cookie-inject`     | client could not inject cookies                                                  |
| `storage-inject`    | client could not write / read back storage keys                                  |
| `client-proof`      | session in place, the client's proof fails                                       |
| `consumer-followup` | logged in, the site's follow-up failed (cscs token)                              |
| `safari-source`     | Safari holds no usable session for a Safari-flow site                            |
| `unknown`           | cannot tell whether a password was entered (deadline during the request, kill)   |
| `ok`                | logged in                                                                        |

Quarantine authority is the persisted submit state (`submitted` in the reply / the limiter's
mark), never the phase alone; the phase decides only for replies without `submitted`.
A reply WITHOUT a phase (an older broker) maps `rate_limited` → limiter, `vault_error` /
`unknown_site` / `refused` → vault, everything else → `unknown` (never assumed pre-submit).

### D2 — Broker → client → agent-login, end to end

- **Broker** (`daemon.py _do_login`): every error reply carries `phase`, `phase_v`, `submitted`;
  limiter refusals carry `limit` `{key, state, retry_s, consecutive, reset}` (`reset` = exact
  command). Success: `phase: "ok"`, `fresh_auth: bool`. `RecipeError` gains `phase` and
  `auth_proven`; `ExportFailed` (code `export_failed`/`empty_bundle`, phase `bundle-export`,
  `auth_proven=True`); proof failure → `phase="broker-proof"`.
- **Side channel** (`bin/browser.py`): `login SITE -R/--result-file PATH`, `logged-in SITE -R
  PATH`. A process-global recorder is set at every exit of `_broker_login`, `_safari_login`,
  `_broker_check_entry` (and the eduid-sso route): `{v, site, cmd, ok, rc, phase, code,
  submitted, route, detail, screenshot, stop_origin, limit}`; written atomically (0600) in a
  `finally` of `cmd_login`/`cmd_logged_in`, and by `LoginDeadline._fire` before `_hard_exit`
  (phase from the breadcrumb: `broker:precheck` → precheck, `broker:request` → unknown,
  `broker:cookies` → cookie-inject, `broker:storage` → storage-inject, `broker:verify` →
  client-proof, `broker:after` → consumer-followup; code `timeout`).
- **Runner** (`agent_login_jobs.run_browser(..., result=True)`): `-R <0700 tempdir>/r.json`,
  read back into `BrowserRun.result`; missing/corrupt → derived from the exit code; a runner
  kill → phase `unknown`, code `killed`.
- **Record**: v2 records in a NEW file `checks.json` (fcntl.flock on `checks.json.lock`,
  atomic replace, merge per site): `{v: 2, state: ok|failed|unknown, at, phase, code,
  submitted, route, detail (redacted ≤200), screenshot (only
  /var/db/login-broker-run/last-failure-<site>.png), stop_origin (origin only), last_success}`.
  `last-check.json` becomes a write-only legacy projection (`ok`/`how`/`at`) for old readers;
  the new code never reads it except once to seed nothing but history.
- **Legacy projection = the infra/status contract** (overseer, 2026-10-09): `last-check.json`
  keeps `ok` (bool), `how` (str), `at` ("YYYY-MM-DD HH:MM" local) per site; infra/status
  reads it passively (ok=false → red, newest `at` > 36 h → red). An `unknown` check
  (offline, busy, broker down) projects `ok=false` and does NOT bump `at`.
- **No daily mail** (overseer, 2026-10-09): the LaunchAgent runs `-c` (no `-m`); logged-out
  sites become an infra/status item. `-m` stays for manual use.
- **Overview** (Albert's terminal): per ❌ row `phase · fixed reason [— redacted detail] [📷
  path]`. **agents.md**: only fixed vocabulary + validated identifiers (site ids, phase/code
  texts, the EXPECTED claude.ai account constant) — never `how`, detail, broker reason,
  screenshot, origin or any page-read value.

### D3 — Status freshness and inventory

- ✅ needs the LATEST v2 state `ok` AND its time within `MAX_STATUS_AGE_S` (36 h,
  `$AGENT_LOGIN_MAX_STATUS_AGE_S`); an older `ok` → `stale` (❓); `last_success` is history.
- A `-c` run that cannot check (offline, shared browser down, broker unreachable, busy) records
  `state: unknown` (code `offline` / `browser_down` / `broker_unavailable` / `busy`) for every
  row it could not check. agents.md lists stale/unknown under "❓ verify first
  (`browser.py logged-in SITE`)".
- Inventory = TARGETS ∪ fresh broker list ∪ `site-state.json` ∪ the last valid `sites.json`
  snapshot. Broker down → those rows stay, broker columns `unknown`. **Pruning** (checks.json,
  site-state.json, legacy file) only after a FRESH live `sites` answer (`-S`, `-r`), never from
  the cached snapshot; it removes sites in neither TARGETS nor that answer (zendesk).

### D4 — Scheduler safety

- **site-state.json** (`agent_login_state.py`, flock + atomic): `{site: {stage: pending|usable,
  quarantine: {phase, code, at} | null, audit: [...]}}`. EVERY broker site starts `pending` (no
  promotion from old records). `agent-login.py -p/--promote SITE` and `-Q/--release SITE`
  write an audit entry (time, argv, parent command, `$CLAUDE_SESSION_ID` when set) here and to
  the browser.py journal. `-t` never promotes.
- **Scheduled mode, fail-closed**: `-c` passes `-s/--scheduled` to EVERY `browser.py login`.
  With `-s`, `_broker_login` refuses the broker route unless site-state.json is readable, valid
  and says `usable` and not quarantined (missing / corrupt / unreadable → refuse, code
  `pending` or `state_unreadable`), and sends `"scheduled": true` to the broker.
- **Promotion is mechanical** (`-p SITE` refuses otherwise): a FRESH live broker listing shows
  the item not refused with `sentinel: true`; its latest checks.json record is `ok`, fresh,
  and from the strict proof (`proof_v >= 1`, written only by the new browser.py); it is not
  quarantined. `-p`/`-Q` are audited; the main session is the releaser (same uid as every
  agent, so no technical actor boundary exists — the master plan's rule + the audit).
- **Broker-side, authoritative**: a scheduled reservation is denied when ANY key has an
  unresolved post-submit failure (`consecutive > 0`), code `quarantined` (reset: an approved
  manual login with fresh auth, or `sudo install/install.sh -r KEY`). This covers deadline
  exits, SIGKILLs and client disconnects the client never sees.
- **Client quarantine** (non-scheduled callers too): written by `_broker_login` on every
  post-submit result, by `LoginDeadline._fire` when the step was `broker:request`, and by
  agent-login after a runner kill of a login. Enforced in `_broker_login` before the request.
  Released only by `-Q`.
- **`-c` per row**: free `logged-in` probe first (✅ → done). Not logged in → no login when the
  site is assisted, pending, quarantined, needs-sentinel, or the snapshot's `limit.state` is
  locked/cooldown/quarantined — one line each with the exact next command. Otherwise ONE
  `browser.py login -s`. **No retry** unless the result file proves phase `precheck`.

### D5 — Mandatory authenticated proof

- Proof (tri-state) = (a) the `page.goto()` Response status — absent/0 → indeterminate, 4xx →
  invalid, 5xx → indeterminate (broker and client alike; `_with_prepared_background_page`
  passes the Response to the probe), (b) final origin == the check URL's origin or one of the
  new optional `agent_proof_origins`, (c) the visible DOM sentinel `agent_logged_in_selector`.
  Never valid without a status. CSCS needs a DOM sentinel AND keeps its token check.
- No sentinel → `needs_sentinel`: the broker answers it (phase `vault`) before reserving or
  fetching anything — such a site can never burn an attempt; the client probe says "cannot
  verify" (exit 2, code `needs_sentinel`); agent-login status `needs-sentinel` (❌).
- **Two-sided candidate check (free)**: `browser.py logged-in SITE -x/--try-sentinel CSS` —
  PRESENT in the shared browser (status + origin + visible) AND ABSENT on the same check URL in
  a fresh throwaway profile inside the broker (new secret-free op `sentinel_absent {site,
  sentinel}`: temporary user-data dir, deleted after, no secret, no limiter). ✓ only when both
  hold; it names the failing side. A candidate present in both states (logo, nav) is rejected.
- **Candidate login (bootstrap for logged-out sites)**: `browser.py login SITE -x CSS` (never
  with `-s`; the broker refuses it for a scheduled request) sends `candidate_sentinel`; used
  only when the item has none. Pre-auth the profile proof must load the check page with the
  candidate ABSENT (still logged in / indeterminate → `candidate_unverifiable`, phase
  `profile-proof`, nothing reserved); then ONE normal reserved attempt, and the post-auth proof
  must show the candidate PRESENT. Success replies `candidate_verified: true`; the main session
  then writes it with `broker-add.py -L`. It is that site's one approved attempt under the
  master plan's policy; a failure quarantines it like any post-submit failure.

Sites without a sentinel today (snapshot 2026-10-09 22:42): anibis, cscs, docker, docker-hub,
eduid, galaxus, galaxus-de, infomaniak, kleinanzeigen, myfritz-alzenau, myfritz-prilly,
ricardo, runai-admin, runai-test3, tutti, zoho-desk. No code or recipe names an authenticated
element for any of them, so none can be derived; all are `needs-sentinel` until a verified
selector is written (release step R3).

### D6 — Attempt groups (master plan O6, final design)

- **Field** `agent_attempt_group` (opaque slug `^[a-z0-9][a-z0-9._-]{0,63}$`). Malformed →
  item refused; containing the item's username or its local part (≥ 3 chars) → refused.
- **Keys**: raw `SITE` keys unchanged; `group:<id>` added. Every reservation first records the
  site's binding `groups` (ordered union of every group ever bound); login keys = site + current
  group + every previously bound group, so a group change never escapes an old group's block.
- **API** (`broker/limiter.py`; old `check`/`begin_attempt`/`record_attempt`/`reserve` kept):
  `peek(keys)` / `peek_site(site)` (reporting only), `reserve_site(site, *, group, scheduled)`
  (binds the group, then every key: block, cooldown, live inflight → `busy`, scheduled + streak
  → `quarantined`, interval, caps; then `[now, "pending", id]` + inflight `{id, ts, state:
  reserved, instance, pid, pid_start}`), `mark_entered(grant)`, `mark_submitted(grant)`,
  `finish(grant, ok|not_submitted|unknown)`.
- **Crash recovery**: a mark is abandoned only when its instance differs AND (its pid is gone OR
  the pid's start time differs). No age-based recovery: a live owner's mark stays `busy`.
  Abandoned `entered`/`submitted` → `unknown`; `reserved` → `not_submitted`. Old-format marks
  (no pid) keep the old rule.
- **Locking/ownership**: every read-modify-write holds the thread lock + `flock(LOCK_EX)` on
  `<state>.lock`, opened `O_NOFOLLOW`, `fstat` regular file with `st_nlink == 1` (else fail
  closed). The daemon creates its lock file at start. Root's reset chowns the replaced state
  (and a lock file it created) to the home's owner BEFORE releasing the flock.
- **Daemon — admission order (binding, from the converged WS2-cscs debate C8).** Today
  `_do_login` calls `limiter.check` BEFORE the runner (daemon.py:671), so a still-valid
  profile cannot even be re-exported during a cooldown — verified in the code. New: item
  metadata (`_items()`, groups) is read first; limiter admission (`reserve_attempt`) runs
  inside `get_secret`, under the per-site lock, only when the runner first needs the secret;
  `vault.secret(site)` only after a granted reservation. A validated profile reuse proceeds
  during cooldown or hard block and leaves `limiter.json` byte-identical (reply
  `fresh_auth: false`). `fresh_login` items reserve FIRST, then clear cookies; a denied
  reservation leaves the profile's cookies and storage unchanged.
- **Attempt controller + submit marker (binding).** Recipes receive an `AttemptController`
  (`attempt=` keyword; `mark_submitted()`, `entered()`). `mark_submitted()` is persisted
  immediately before the `click()`/Enter that submits a secret — inside the submit helpers
  (`_submit_password`, `click_keycloak_submit`, Smartsheet sign-in, the OTP submit), after the
  submit element was found; no element found stays a pre-submit error with no marker. A
  marker write failure aborts before the click. Additionally `_fill_password` persists
  `entered` before the first password character reaches the DOM: crash recovery treats an
  abandoned `entered` or `submitted` mark as `unknown` (a page could auto-submit on input);
  a clean failure after `entered` follows the outcome mapping below.
- **Outcome mapping (binding, reconciled with O10).** Never `entered` (silent SSO, reuse,
  failure before typing) → `not_submitted`, streak unchanged. Marker + valid proof → `ok`
  (fresh_auth), even when the export then fails (`bundle-export`). Marker + anything else
  (invalid or indeterminate proof, recipe error, timeout, crash recovery) → `unknown`
  (cooldown; scheduled quarantine). `entered` without a marker → `unknown` too (typing can
  auto-submit), EXCEPT a recipe error raised with `unsent=True`, which a recipe sets only after
  verifying at that moment that the password field still holds the typed value on a fill
  origin (no login button, the submit button's origin check failed) → `not_submitted`. Only
  `ok` clears a streak.
- **Tri-state proof (binding).** `recipes.check_proof(page, item) -> "valid" | "invalid" |
  "indeterminate"` (indeterminate: navigation timeout/error, HTTP 5xx, malformed answer); a
  per-site proof registry (`proof_for(site)`, default generic) lets a recipe plug its own
  (WS2-cscs adds the server-validated CSCS proof — NOT part of WS1a). Pre-auth (reuse check)
  indeterminate → `profile-proof` error before any reservation or `vault.secret`; pre-auth
  invalid → login. Post-auth indeterminate → `broker-proof` error, limiter outcome by the
  marker.
- **Resets**: `daemon.py -r KEY [-G]`: KEY = site | `group:<id>` (own parser) | secret keys
  (unchanged). A key with a live in-flight mark → refused (exit 3). `-r SITE` warns per bound
  group that still blocks; `-r SITE -G` resets the site + every bound group and clears the
  bindings ("no group bound yet" when none). `install.sh -r group:<id>`, `-G/--with-group`.
- `sites` op adds `attempt_group`, `sentinel`, `limit` (peek). selfcheck h) also checks
  `limiter.json` (+ lock files).

### D7 — Acceptance matrix

`agent-login.py -x/--matrix [-j]`: one row per inventory item: site, flow/route, consumer,
privilege, check URL, sentinel (yes/none), proof origins, bundle scope (cookie hosts + storage
origins), attempt group, refresh policy (daily `-c` / Safari session / Albert `-g` / none while
pending), stage, quarantine, limit state, last phase, state. Consumer/privilege from a small
static `MATRIX_META` table (unknown = `?`). Broker down → broker columns `unknown`.

## Steps

- [x] S1 `broker/phases.py` + tests.
- [x] S2 `broker/limiter.py`: flock/O_NOFOLLOW, `peek`, `reserve_attempt` (bindings, scheduled
      quarantine), `mark_submitted`, `finish`, pid+start-time recovery, reset refusal + chown in
      lock; frozen legacy copy `tests/legacy/limiter_pre_ws1a.py` + compat tests.
- [x] S3 `broker/vault.py`: `agent_attempt_group`, `agent_proof_origins`, `has_proof`,
      `public()` additions; tests.
- [x] S4 `broker/recipes.py`: tri-state `check_proof` (status + origin + sentinel) +
      `proof_for` registry; `AttemptController` (`entered` in `_fill_password`,
      `mark_submitted` in the submit helpers); `RecipeError.phase`/`auth_proven`,
      `ExportFailed`; tests.
- [x] S5 `broker/daemon.py`: `_do_login` on the attempt API, phases + `limit` in replies,
      op `sentinel_absent`, `candidate_sentinel` logins,
      `scheduled`, empty-bundle check, `needs_sentinel`, `sites` additions, `-r` parser +
      `-G` + busy refusal; tests.
- [x] S6 `install/install.sh` (`-r group:<id>`, `-G`), `broker/selfcheck.py` h).
- [x] S7 `agent_login_state.py`: checks.json v2 + legacy projection, site-state.json
      (pending/usable, quarantine, audit), pruning; tests.
- [x] S8 `bin/browser.py`: result recorder + `-R`, `login -s`, `logged-in -x`, quarantine gate
      and writers, deadline write, proof in `_broker_probe`; tests.
- [x] S9 `agent_login_jobs.py` + `agent-login.py`: result runs, verdict/freshness, overview,
      agents.md allowlist, `-c` gates + unknown records + no retry, `-p`, `-Q`, `-x`; tests.
- [x] S10 README + AGENTS.md; lint + full test suite green.

## Tests (hermetic; no Chrome, no broker)

Limiter: pre- vs post-submit; group cooldown across members; crash recovery per transition;
pid reuse; live owner older than an hour stays busy; concurrent reservations in one group
(threads and two instances); profile reuse never clears a streak; fresh auth + export failure
clears it; scheduled denied on streak > 0; frozen legacy limiter reading new state (no crash,
blocked stays blocked, double count only adds denial); reset refused during a live attempt,
allowed after; chown inside the lock; symlinked lock refused; malformed group; group with the
username; blocked-before-binding; group change keeps the old block; `-G` clears. Daemon: phase
per failure point; `needs_sentinel` before any secret fetch; `limit.reset`; `-r group:x`,
`-r SITE` warning, `-r SITE -G`; (WS2-cscs C8) cooldown + validated profile → bundle, limiter
file byte-identical, `vault.secret` never called; cooldown + stale profile (also a
`fresh_login` item) → `rate_limited`, `vault.secret` never called, profile cookies unchanged;
crash right after `mark_submitted` → `unknown`; crash after `entered` → `unknown`; submit
helper with no element → pre-submit error, no marker; silent SSO + export failure →
`bundle-export`, streak unchanged; check endpoint 503 on reuse → `profile-proof`,
`vault.secret` never called; marker + 503 post-auth → `unknown`; auto-submit on input
(entered, no marker, value gone) → `unknown`; no button + value still in the field →
`not_submitted`; pre-auth 503 → `profile-proof`, no quarantine; candidate login: present
before → `candidate_unverifiable`, nothing reserved; absent before + present after →
`candidate_verified`; scheduled + candidate → refused. Recipes: 403 + selector →
invalid; wrong origin + selector → invalid; 5xx/timeout → indeterminate; marker-write failure
aborts before the click. browser.py: result file per exit; deadline write + quarantine; `-s` refusals per
state failure; `-x` two-sided (present+absent ✓, present in both ✗); probe status missing/0 →
indeterminate, 403 → invalid, 503 → indeterminate. agent-login: `-p` refusals (stale list, no
sentinel, stale/weak/failed record, quarantined); v2 record + legacy projection; stale/unknown verdicts;
offline/browser-down/broker-down/busy records; pruning only on fresh lists; first-run-offline
inventory; `-c` never calls `login` for pending/quarantined/locked/cooldown/needs-sentinel/
assisted; no retry after a non-precheck 124; hostile strings in every free-text field never
reach agents.md.

Implemented 2026-10-09 in the WS1a worktree; hermetic suite + lint green. New test files:
`tests/test_ws1a_broker.py`, `tests/test_ws1a_client.py`; frozen legacy limiter
`tests/legacy/limiter_pre_ws1a.py`.

## Review round 1 (overseer, 2026-10-10) — applied

- [x] B1 candidate: refused with any unresolved failure (pre-check + at reservation);
      outcome `candidate` (interval/caps only, never clears a streak/cooldown); absent on a
      fresh logged-OUT throwaway profile, checked before reserving or clearing cookies.
- [x] B2 `-r SITE` keeps the site's group bindings; `-r SITE -G` still finds the group.
- [x] B3 the post-reset warning is a pure read (`Limiter.blocking`); every write as root is
      chowned (no symlink follow) before the lock is released.
- [x] B4 `ps -o lstart` runs with LC_ALL=C, TZ=UTC.
- [x] B5 `profile-proof`, `candidate_unverifiable` (+ offline, browser_down, …) in phases.py.
- [x] Broker should-fix: plain-CSS `selector_ok` (also for `agent_logged_in_selector`);
      `sentinel_absent` one at a time, not during a login of the site, refused items refused;
      a failed `finish` keeps the bundle and its own mark is recovered with the outcome;
      strict `check_proof` with no status → indeterminate; `_reset_keys` fails cleanly on a
      symlinked lock; login audit lines carry scheduled/candidate/phase/fresh_auth.
- [x] C1 the free `logged-in` check runs before the gates; a logged-in quarantined site exits 0.
- [x] C2 no sentinel = the OLD proof for manual `login`/`logged-in` (CSCS: its token rule);
      the row is flagged `needs sentinel (old proof)` (✅ stays ✅ for agents, "weak proof"),
      never scheduled (`needs_sentinel` gate + broker refusal of scheduled requests), never
      promoted (`proof_v` 0).
- [x] C3 `-c` records the rows it skips: needs-sentinel → the old proof's result with
      how="needs sentinel (old proof)"; broker unreadable → unknown/broker_unavailable.
- [x] Client should-fix: strict site-state writes; prune keeps quarantine/audit entries;
      `login -x` only for plain broker sites (+cscs); `-Q` names the broker item; exit 0
      forces ok and each broker step resets phase/code/detail; `-p` accepts the free check's
      strict ✅; `-Q`/`-p` validate the site id.
- [x] Proof origins: every check records `final_origin`/`origin_ok`; `agent-login.py -x`
      lists the sites whose last check ended on another origin.

## Review round 2 (overseer, 2026-10-10) — applied

- [x] N1 `login -x`: a broker reply without `candidate_verified: true` (an older broker)
      is `candidate_unverifiable`, exit 2, nothing injected, no broker-add hint.
- [x] N2 the logged-out half of a candidate's proof reuses the runner's Playwright
      (`sentinel_absent(..., pw=)`, run in `__call__` before the site context opens); a
      nested `sync_playwright()` raised inside the outer event loop. Real-runner e2e test
      `tests/test_ws1a_e2e.py` (disposable headless Chromium, local fixture site).
- [x] (a) the dead status `needs-sentinel` is gone; `needs_sentinel(row)` is the one rule.
- [x] (b) an older broker's `login_failed` maps to `recipe` only for details it raised
      before typing; everything else stays `unknown`.
- [x] (c) the weak-proof warning: once per site and process, only on a terminal.
- [x] `agent-login.py -V`: live items whose selectors the new broker refuses (pre-install).

## Learnings

- `ensure_logged_in` used to retry a 124 blindly: a deadline inside `broker:request` may
  already have typed the password. Only a record proving phase `precheck` may retry.
- The limiter's old crash rule (another instance = crashed) let a root `daemon.py -r` turn a
  LIVE daemon's in-flight attempt into a failure; liveness is now pid + start time.
- Today the broker consulted the limiter before the profile check (daemon.py:671), so a
  still-valid profile could not be re-exported during a cooldown — fixed by admission
  inside `get_secret`.
- 16 broker items have no sentinel; they keep the old proof (flagged, not ❌) until R3.

## Release (main session; manual, under the attempt policy)

- R1 hermetic checks → commit → `ai.py push` → `origin/main` contains it (browser.py with
  `logged-in -x` and `login -s` is then live from the root checkout; the daily job stays
  unloaded).
- R2 `sudo install/install.sh` + selfcheck (no broker state migration: `limiter.json` gains
  group keys, bindings and 3-element attempts only as they are used).
- R3 sentinel discovery per sentinel-less site: logged in somewhere → the free two-sided
  `browser.py logged-in SITE -x 'CSS'`; logged out everywhere → one approved candidate login
  `browser.py login SITE -x 'CSS'`. Then `broker-add.py … -L 'CSS'`.
- R4 `./agent-login.py -x` review; promote reviewed sites with `-p`.
- R5 scheduled acceptance: `sudo cat /var/db/login-broker/limiter.json` + `checks.json` before,
  one `./agent-login.py -c` with pending / quarantined / locked / cooldown / assisted rows
  present, the same after; the diff shows no counter change for those rows.
- R6 one canary on a promoted green sentinel site.
- Rollback: previous broker release under `/usr/local/libexec/login-broker/releases` +
  `git revert` of the client, with the daily job unloaded and no secret-submitting login until
  WS1a is restored. The old daemon reads the new limiter.json (only `attempts[i][0]`; group keys
  ignored → group enforcement is lost while rolled back; a leftover new-format mark counts once
  more as `unknown` — more denial, never less). Old agent-login reads/writes only
  `last-check.json`; `checks.json` and `site-state.json` are untouched by it.

## Verification

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run ruff format --check bin/ broker/ agent-login.py agent_login_jobs.py agent_login_state.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run ruff check bin/ broker/ agent-login.py agent_login_jobs.py agent_login_state.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run mypy bin/browser.py agent-login.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pylint bin/browser.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests
cd /Users/albert/obsidian/42-Git/home/browser-login && bin/browser.py -h
```
