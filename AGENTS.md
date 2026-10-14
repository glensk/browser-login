# AGENTS.md

Conventions for AI coding agents (and humans) working in this repo.

## What this is

A single shared, logged-in Chromium (`bin/browser.py`) that CLI tools and AI agents
drive over the Chrome DevTools Protocol (CDP), plus a generic multi-site auto-login
framework. It is a **provider**: other repos depend on it, not the reverse. See
`README.md` for the full story.

## Environment

- Python via **`uv`** (preferred over Homebrew/system installs): `uv sync` for a
  project-local venv. But note `bin/browser.py` **self-bootstraps** its own isolated
  venv at `~/.cache/claude-browser/venv` on first run, so usually you just run it.
- One-time browser binary: `uv run playwright install chromium`.
- Secrets live in the macOS keychain / 1Password and are read at runtime — **never**
  in `.env` or the source. `.env` is gitignored; `.env.example` documents env vars.

## Build / test / lint

- Python: `ruff format bin/ && ruff check bin/ && mypy bin/browser.py && uv run pylint bin/browser.py`
  (`uv sync` first — pylint has to run inside the project venv so the deferred
  playwright/pyotp/requests imports resolve).
- Shell: `shellcheck` (no shell scripts currently)
- Pre-commit: `pre-commit run --all-files` (gitleaks secret scan)
- Smoke test: `bin/browser.py -h` must exit 0; `browser.py up && browser.py status`.
- Full health check: `browser.py doctor` (bounded probe on a disposable tab;
  asserts the desktop is left untouched; certifies mode=headless, the desired
  mode and the headed lease). Run it after changes to launch, lifecycle, or
  coordination code — against a DISPOSABLE instance
  (`CLAUDE_BROWSER_CACHE_DIR=<tmp> browser.py --cdp-port <free port> up`, then
  `down`), never the live 9222/9223 browser.

## Conventions

- Every subcommand supports `-h/--help`; every CLI flag has a short and long form.
- **Consumers own tabs by target id** (tp#786): `open -N URL` → `eval -T <id>` →
  `close -i <id>` (in a `finally`). Never navigate "the oldest tab on this URL"
  or pick a tab by URL substring in new code — a redirect or a user's own tab on
  the same URL defeats URL matching; the target id cannot be impersonated. The
  in-repo checks and logins obey it too (tp#845): they run in
  `_owned_background_page` / `_background_page_run`; `_match_page` (evaluate
  only, never navigate) is reserved for `eval --url`.
- **Owned-tab ledger** (tp#845): three ownership kinds — maintenance-owned
  (`tx.owned`), in-process ephemeral (`_owned_background_page`: recorded in
  `<cache>/owned/<pid>-<rand>.json`, its flock on the sidecar `.lock` held for
  the ledger's life) and `open -N` handoffs (the caller's; NEVER ledgered).
  Two-phase marker: the entry (random marker) is written before
  `Target.createTarget {url: about:blank#owned-<marker>, background}` — no
  `browserContextId`, no `new_context()` (ONE exception, outside the ledger:
  the WS1b import proof's throwaway context, see "Agents renew Albert's own
  sessions" below); the target id is bound right after the reply; the tab is
  navigated only after that. Liveness is tri-state
  (`_owner_state`: live = flock held or pid+start time match; dead = flock free
  and pid gone/reused; unknown = unreadable → never reaped). Reaping only via
  `reap-owned`, the guided-login transaction (start, `_guided_a`'s finally) and
  the maintenance watchdog — never `_preflight`, never `status`.
- This repo declares **no** `EXTERNAL_DEPS` registry (extdeps package) — it is a
  provider, not a consumer. Its own external tools (`op`, `himalaya`, `security`, Playwright) are
  **optional** and degrade gracefully (assisted fallback); they are documented in
  `README.md` (Requirements), not enforced with fail-loud checks.
- The CDP endpoint is always `http://127.0.0.1:<port>` — never `localhost` (Chrome's
  debug port is IPv4-only; `localhost`→`::1` stalls on macOS).
- A site's `logged_in` check must read a DOM sentinel on a stable post-login surface,
  not "the URL isn't `/login`".
- Tab URLs and titles in any captured output (`status`, error lines) go through
  `_tab_hint`/`_tab_title` — origins only, fail closed; raw URLs are opt-in
  (`status --full-urls`) and never the default.
- **Headless by default — the invariant** (tp#836): the shared browser is
  headless unless a live guided-login MAINTENANCE RECORD of mode A exists
  (`<cache>/maintenance.json`; Phase 2's "headed lease" is that record with
  `mode: "A"`), written only by a guided login Albert starts
  (`agent-login.py -g SITE` → `browser.py assisted-login SITE`, or
  `agent_login_jobs.guided_window` for the claude.ai/SWITCH window flows). `up`
  always launches headless (`up -H` is a no-op; there is no `up --headed`, and
  `CLAUDE_BROWSER_HEADLESS` is ignored); `switch headed` exits 2 unless the
  caller carries the owner nonce (`$CLAUDE_BROWSER_MAINTENANCE`) of a live
  mode-A record; every connecting command reverts a headed browser without one
  first (`_preflight` in `main`, before any gate; output to stderr only; best
  effort — a failed revert warns and the command proceeds;
  `doctor`/`close`/`close-hung` never revert). Never add a way around it.
  The lease-less revert (preflight, `up`, a human `switch headless`) is a
  short maintenance transaction (`_revert_tx`: record with `purpose:
  "revert"`, mode B → pause registered exec clients → `cmd_switch` as the
  owner → record cleared → resume); a second revert waits for or stands down
  from the first (BUSY is a skip for the preflight, never its exit code).
  Only callers that already coordinate clients (`_ensure_headless` as the
  record's owner, the watchdog with `revert=True`) take `cmd_switch`'s plain
  path.
- **Guided login = one maintenance transaction** (`_maintenance`, Phase 3):
  ONE record file is the single source of truth (`owner_nonce`, pid + start
  time, `site`, `mode` B|A, `state`, `owned_targets`, `paused`,
  `watchdog_pid`, 10 s heartbeat; liveness = owner pid alive with its start
  time and heartbeat < 120 s). While it lives, a NEW registration without the
  owner token exits **75** (`BUSY_RC`, EX_TEMPFAIL: `busy: guided login for
  SITE in progress (until ~HH:MM)`), and so do `down`/`switch` unless
  `-F/--force-maintenance` — never add an exemption; the transaction's own
  children inherit the token. 75 is NOT "logged out": callers (agent-login
  `-c`/`ensure_logged_in`) skip and re-check later — never `login`, never a
  failure mail. Human entry only: `assisted-login` refuses without `/dev/tty`
  (exit 2) — never add a non-interactive way in. **Pause protocol**:
  `register-exec` installs every signal handler first, then registers with
  `kind: exec`, then spawns its child in its own process group and records
  `child_pid`/`child_pgid`/`child_start_time`; SIGUSR1 = pause (only while a
  record lives: SIGSTOP the group, drop the shared gate, `paused: true`),
  SIGUSR2 = resume (retake the gate, SIGCONT). A paused wrapper resumes itself
  only when the record FILE is gone or names another owner (a dead owner is
  the watchdog's to recover first — it needs the gate exclusively for its
  revert), or after 60 s of a not-live record. The transaction signals ONLY
  pids from a live registry entry whose pid AND start time it re-validated —
  never a bare number; a dead wrapper's validated child group is an orphan and
  is stopped (resume path, watchdog, `clients`). A registration without `kind`
  that is not browser.py's own (a pre-protocol wrapper) refuses the start,
  naming its pids. Cleanup order on every exit: owned targets → headless →
  lease → record → resume. The detached `maintenance-watchdog` does the same
  when the owner dies. Everything is journaled. Owned targets come from
  `open -N` and the relay's target supervisor (popups whose `openerId` is
  owned) — never a tab picked by URL, and `logged-in` checks always run in a
  fresh background tab (`_logged_in_page_check`), not only while a record
  lives (tp#845).
- **Tests never leave a real Chrome**: `tests/conftest.py` sets
  `CLAUDE_BROWSER_TEST_NO_LAUNCH=1`, so `_launch_browser` exits in the test
  process and every `browser.py` subprocess it starts; a test that must launch
  a disposable headless browser carries `@pytest.mark.launches_chrome` and
  stops it again. A fake CDP endpoint reports `HeadlessChrome` (a headed fake
  makes the preflight "revert" it by launching a real browser).
- **`bin/login_viewer.py` stays an allowlist relay**: only `ALLOWED_METHODS`
  leave it, `Target.*` only for owned ids, `Runtime.evaluate`/`addBinding`/
  `addScriptToEvaluateOnNewDocument` only with the relay's own hook strings;
  the viewer sends typed messages, never raw CDP. Event handlers that send CDP
  commands run as tasks, never inline in the CDP reader (they would wait for
  answers only the reader can deliver).
- **Never interfere with the user's desktop**: no app activation, no window
  raising. `_bring_to_front` is a journaled no-op outside the lease holder's
  headed browser; never call `page.bring_to_front()` directly. A login step
  that needs Albert goes through `_guided_login_allowed` and returns
  `NEEDS_ALBERT_RC` (4, "needs Albert: agent-login.py -g SITE") — no TTY or
  env heuristics, no window flow outside the lease, no `op`/Touch-ID fallback
  in unattended paths. Interactive flows hold the interaction lease;
  long-lived CDP clients register via `register-exec`; `switch` fails closed
  on unregistered clients. Full contract: README "Why you never see the
  window" and "Consumer contract".
- **Proxy = per-host PAC only**: the launch passes one inline
  `--proxy-pac-url=data:…` built from `bin/pac_hosts.json` (or
  `$CLAUDE_BROWSER_PAC_HOSTS`): listed hosts via their SOCKS proxy with a
  `; DIRECT` fallback, everything else DIRECT. Never a global `--proxy-server`,
  never `$ALL_PROXY`; no host → no proxy flag at all. A `file://` PAC URL is
  ignored by Chrome for Testing 153 — keep the `data:` URL. README "Campus-only
  hosts (proxy PAC)".
- **No `--remote-allow-origins`**: CDP WebSocket clients send NO `Origin`
  header (Chrome then answers 403); new `websockets` clients pass
  `origin=None` explicitly.
- **A Playwright attach is bounded and can be blocked by ONE tab** (tp#693):
  `connect_over_cdp` waits for every page target, so `_connect` passes
  `timeout=CONNECT_TIMEOUT_S` and turns a timeout into `BrowserAttachTimeout`
  naming the wedged tab. Anything that must work while a tab is wedged
  (`_cdp_browser_close`, `_probe_targets`, `close-hung`, doctor's probe-tab
  cleanup) uses the raw CDP helper `_cdp_ws_call` (one websocket, one command,
  one monotonic deadline) — never Playwright. The raw helpers are
  registration-free (shutdown calls them while holding the gate exclusively);
  the COMMANDS built on them register a client and, for `close-hung` and
  `close`, take the interaction lease. Nothing closes a real tab without
  `close-hung`'s three-probe + confirmation contract — with ONE exception
  (tp#786): `close -i TID…` closes target ids the caller was handed by
  `open -N`, which is proof of ownership, not a heuristic. Its URL mode
  (`close URL…`, exact match sans query/fragment, http(s) only) is manual
  cleanup of leftover tabs only; no tool uses it. Both modes re-read
  `/json/list` under the lease right before each `Target.closeTarget`, never
  close the last page (a blank keep-alive first, tp#317), and run over raw CDP
  under one deadline. `open -N` and `eval -T` are raw CDP too (no Playwright
  attach).
- **Every unattended `login`/`logged-in` runs under a `LoginDeadline`**
  (tp#843): armed at the top of `cmd_login`/`cmd_logged_in` unless the process
  owns a live maintenance record (`_maint_owner()` — guided logins are never
  bounded); one watcher thread, nested step deadlines (`_deadline_push`) and
  `step_to` breadcrumbs (journal `login_step`). Background pages create and
  close their owned target over raw CDP by id (never `page.close()`);
  `_close_owned_targets` has one budget and confirms by re-listing. A fired
  deadline exits 124 (tabs closed) / 125 (unconfirmed) via `_hard_exit`.
  Runner calls (`agent_login_jobs.run_browser`/`_browser`) always pass an
  explicit `timeout_s` — `None` only for the two guided calls; the AST test in
  `tests/test_agent_login.py` enforces it.
- **Login phases and limiter safety (WS1a, `plans-done/PLAN_ws1a-diagnostics_DONE.md`)**: every
  broker/client exit records a phase from `broker/phases.py` (never free page
  text into `agents.md`). The broker limiter is admitted only inside
  `get_secret`; recipes call `attempt.entered()` before typing the password and
  `attempt.mark_submitted()` right before the submitting click/Enter (inside the
  submit helpers) — a new recipe must do the same, or every failure counts as
  pre-submit. A proof is `recipes.check_proof` (valid / invalid /
  indeterminate: status + origin + sentinel); site-specific proofs plug into
  `recipes.PROOFS`. Never add an automatic retry after phase `submit`/`unknown`;
  `agent-login.py -c` stays scheduled (`browser.py login -s`).
- **A token's shape proves nothing; the server decides (WS2-cscs)**: a
  `recipes.PROOFS` entry is a SERVER proof — CSCS asks `/api/users/me/` from
  the portal page with the stored `waldur/auth/token` (the app's own scheme,
  no cookies, no redirects, bounded; the token never leaves the page) — and is
  strict without a DOM sentinel (`has_server_proof`, advertised as
  `strict_proof`). A site's required storage that cannot be exported validated
  is `bundle_export`, never a silent empty bundle; the client re-checks a CSCS
  token against the API before touching cookies and undoes (compare-and-swap,
  under the lease) an injection the site rejects. Order of the deadlines:
  broker run (`daemon.RUN_DEADLINE_S`, from request receipt, Chromium killed
  past it) < `BROKER_TIMEOUT_S` < `LOGIN_TIMEOUT_S` < the runner and consumers.
- **Sentinel proofs poll, blank is undecided (WS2-npm)**: a proof polls
  `page_state.await_sentinel` (every match, any visible) — never
  `wait_for_selector(state="visible")`, which sees the first match only; a
  blank, unrendered page is `indeterminate`, never "still on the login page".
  Every broker launch clears the profile's HTTP cache (`clear_http_cache`) and
  the client's proof/storage tabs bypass it (`_broker_bypass_cache`): a stale
  cached SPA `index.html` after an app upgrade imports chunks the server no
  longer has and renders blank (NPM 2026-10-10). Storage-token sites renew
  their token on a profile reuse via `recipes.SESSION_REFRESHERS` (vault field
  `agent_session_refresh`, defaults by site id); `login` with `refresh_only`
  re-exports without ever reaching the secret. The client keeps such a session
  fresh: a passing check reads the token's expiry (never the token), and with
  < 12 h left `browser.py login` asks for a `refresh_only` re-export
  (`login -F/--refresh-only` never logs in; `agent-login.py -c` runs it for
  every refreshable ✅, pending sites included). A refresh never quarantines.
- **A submit is never a guess (WS2-calibre)**: `_submit_password` /
  `_submit_identifier` read the form's submit buttons first
  (`login_form.read_submit_buttons`) and raise `SubmitUnidentified` (pre-submit,
  no marker) when they cannot — never fall back to Enter, which fires whatever
  the default button is (CWA's `forgot` reset a password, 2026-10-08). The OTP
  step submits through `_submit_password` too; Keycloak's generic fallback
  button (visible, non-secondary, guarded with `allowed`) and Smartsheet's
  sign-in are a known primary or nothing; destructive labels (delete, log out
  …) are secondary. Fill-origin checks compare parsed origins, never
  substrings (`_on_cscs_auth`).
  `generic_login` runs every submit under `recipes.SubmitTripwire` (a CONTEXT
  route on the fill origins; it screens form navigations until the login
  went out and every request carrying a shielded field, matches a secondary
  button by its (name, value) pair per step — never a name a login button
  shares — and aborts one naming a secondary action:
  `secondary_action_blocked`, client-quarantined; the
  attempt is `not_submitted` only when the context saw nothing else that could
  carry the password since it was armed, before typing — by request
  identity — and no service worker of a fill origin ran; the OTP step runs
  under it too, and a self-submitting OTP page is marked, never re-pressed)
  and ticks a SESSION "remember me" (never a trusted
  device / browser / choice) before typing. A new recipe that submits a form
  uses the same helpers. A Cloudflare Access page (`origins.access_gated`:
  `*.cloudflareaccess.com` or `/cdn-cgi/access/`) is `precheck` ·
  `access_gated` on both sides, before any reservation — agent-login shows it
  as "unreachable off-LAN", never ❌; a login page answering 401/403 is
  `precheck` · `login_blocked` (the broker loads it before reserving), a
  bot challenge there (`recipes.raise_if_blocked`) `needs_human`.
  `agent_max_session_days` (with `agent_fresh_login`): the client renews a
  session that old since its last proven fresh login
  (`SESSION_AGE_DIR/<site>.json` under a per-site flock, `fresh_auth_at`
  written only after a verified injection; none on record → counted from the
  first check, never "due"; one claimed attempt per 20 h), gated like any
  login; a failed renewal of a working session is exit 0 with
  `renewal: failed`.
  `agent_login_mode=username-only` (Mullvad's account number): the item's
  username is the credential and travels as `Secret.password` (`username`
  empty, `mode` set), so every masking path treats it as the secret;
  `generic_login` hands it to `_credential_login` (the form's ONLY text-like
  field, `OTHER_FIELDS_JS` = 0, else nothing typed) with the same tripwire /
  fail-closed submit / marker. The tripwire marks the attempt submitted
  before ANY request carrying the whole secret leaves (`secret_fields`, a
  page that submits by itself); a marker it cannot write stops the request.
  Diagnostics mask every string (longest secret first, URL without userinfo)
  and withhold a text the page side had to cut. Never screenshot such a login
  (`screenshot_withheld`), never expose such an item through the secret ops,
  never put the mode's name in the `sites` view (`username_only` flag).
- **API recipes log in without a form (authentik, `broker/authentik.py`)**: a
  site whose login form defeats the form recipe (authentik: shadow-root stages
  plus an off-screen password-manager helper form the generic recipe typed
  into) logs in through the site's own documented API, the one its UI uses.
  The rules:
  - **Where it runs:** every request in a FRESH CDP isolated world of the
    login page, which must be on the item's fill origin (checked in Python and
    in the page).
  - **What it may call:** ONE fixed path (authentik's flow executor,
    `/api/v3/flows/executor/<slug>/`), same-origin only (`mode:
    'same-origin'`, the final URL must be that path). A POST never follows a
    redirect: a 307/308 would re-send its body; on a redirect the step GETs
    the fixed path itself.
  - **The secret:** origins are checked, then `attempt.entered()` and
    `mark_submitted()` run, right before the ONE POST that carries the secret.
    That secret is never sent again: a stage asking for it again is a failure.
    Once it went out, a passed deadline or an unanswered request ends the
    recipe WITHOUT a verdict (the broker's logged-in check decides), never a
    "did not finish" failure.
  - **What comes back:** only a value-free summary (stage name, error field
    names and codes, device classes) — never page text, never a secret.

  `SubmitTripwire` and `read_submit_buttons` do not apply: there is no form, so
  no default button to guess, no secondary form action to screen, and every
  request is the recipe's own to a fixed path.
- **Onboarding guard (WS3, `plans-done/PLAN_ws3-onboarding_DONE.md`)**: a new or changed broker
  item is reviewed BEFORE the vault write (`agent-login.py -V -i MANIFEST`,
  `broker/onboarding.py`: the broker's own `site_item_from_json` +
  `identity_rules` over the whole collection, displacement of established items
  included; levels refused / unusable / risk / hint, fixed codes, sanitised
  ids). Never duplicate a broker refusal rule in the review — call the broker's
  function (the storage-key rule lives in the leaf `broker/storage_rules.py`
  for both). `-p SITE` is the ONE promotion transaction: one budgeted
  `browser.py login` at most (`als.claim_trial` under the site-state flock,
  refunded only on a proven pre-submit record, `-E` re-arms), never a retry;
  a promotion holds for ONE `onboarding.config_digest` of the VAULT-authored
  config (`config_canon`, versioned `CONFIG_V`: never hash a view-format
  detail or a code-derived flag, or a broker release flips every promotion;
  `changed` / `config_unknown` stop `login -s`; an older version re-adopts
  only after a fresh strict ✅). `-t` of a not-usable broker site takes the
  same budget. Removal is `-D SITE` twice (listed: demote + logout incl.
  storage, skipped when a sibling account shares the scope in the same
  instance unless `-F`; gone: the daemon's `forget` op under its site lock
  after a fresh, non-shrunken vault read, then every client trace). `forget`
  never lifts a limiter block or an identity lockout (`left`, for
  `install.sh -r`). Client state is same-uid policy, not a security
  boundary — the broker limiter is.
- **Credential rotation safety (tp#965, `PLAN_cred-broker-rotation.md`)**: the
  broker has NO password oracle — never add an op, report field or CLI that
  answers a secret's length, a hash or any comparison of it (`fingerprint`
  answers `removed`; comparisons are mydotfiles `credctl.py check -T`). An
  item in BOTH the login and the secrets collection is refused on both sides
  by its OWN `collectionIds` (`vault.collection_membership`, unreadable =
  refused too), never by its fields or name; the onboarding review calls that
  function.
- **The `agent_script` gate (tp#991, `PLAN_cred-one-collection.md`)**: the
  bootstrap's `secret_gate` (`collections` default | `report` |
  `agent_script`, `install.sh -W`) decides what `secret-run` may read; under
  `agent_script` ONLY items with `agent_script=true` (fail closed: absent,
  false or malformed = refused), from the one login collection plus the
  legacy secrets collection until `install.sh -D`. Refusals carry the closed
  `gate_code` set (`vault.GATE_CODES`) — consumers (credctl) map codes, never
  reason texts; never add a code without updating the plan's compare
  interface. The gate never becomes an oracle: no op compares a value.
  Flipping the live gate is a main-session live step (tp#889 R7g), never a
  builder's. `held` (a `rotation_lease` or `agent_hold`) is a skip, never a
  failure: checked before any vault read, never counted by the limiter (a
  hold found on the fresh secret read withdraws the reservation), never a
  quarantine or a failure mail; clients map it to exit 75 / `⏸ held`.
- **Agents renew Albert's own sessions through his Safari (WS1b,
  `plans-done/PLAN_ws1b-durability_DONE.md`)**:
  - **Who runs it:** `agent-login.py -L SITE` is agent-invoked ONLY. Every
    LaunchAgent sets `AGENT_LOGIN_SCHEDULED=1` and `-L` refuses with it. Never
    call it from `-c`, `-S` or `-R`.
  - **The interactive gate** (`alsafari.interactive_gate`, exit 3): it also
    refuses on a locked console, when Albert is not on the console, and when
    nobody touched the Mac for 15 min. Locked = `CGSSessionScreenIsLocked` or
    `IOConsoleLocked` true; either present but not a boolean, or anything
    unreadable = refused. It proves SOMEONE is at the Mac, not that Albert
    started the run (the explicit agent invocation is that part).
  - **When `-L` goes on:** only from a DEFINITE logged-out of the free check
    (code `logged_out`; Notion also `wrong_account`). Never from `internal`,
    `unknown`, `indeterminate` or a gated code.
  - **Safari is driven only through `safari.py`, by LONG option names**
    (`--new-window`, `--handle`, `--expect-host`, `--user-only`, `--close`,
    `--capabilities`; never the short letters). Every fill, click and eval names
    the window AND the RECIPE's host (`--expect-host`, never a host read off the
    tab; safari.py also pins the tab's full origin). A safari.py exit by a
    signal (≥ 128, or negative) counts as "may have been done", like a kill.
    A safari.py whose `--capabilities` lack
    `handle`, `new_window`, `close`, `expect_host` or `sigterm_clear` drives
    nothing (`safari_py_outdated`). agents.md promises `-L` only when every
    feature the site's recipe needs is there (`agent_route`).
  - **The runner:** SIGTERM, a grace period, then SIGKILL. After a killed
    credential step `-L` clears the clipboard.
  - **What leaves safari.py:** only the closed fields `agent_login_safari`
    parses. Its page text, candidates and error messages are never stored or
    printed.
  - **Albert's stops:** only `needs_albert_captcha|sms|push|hardware_key|vault_locked`.
    Every other stop is the agent's.
  - **Credentials:** a credential step runs once. A failure after one
    quarantines (`-Q` releases it).
  - **A built-in import** (`SAFARI_BUILTIN`: notion, slack, openai) is one
    interaction-lease transaction:
    1. the site's own check must say a definite logged-out;
    2. Safari's cookies are proven in a THROWAWAY browser context, server-side
       (Slack `auth.test` team + user id, OpenAI account ids, Notion's user
       record);
    3. only on `match` does the shared jar change.

    A failed post-copy check is undone, and a failed undo is recorded
    (`undo: failed`).
  - **The ONE `new_context()` / `new_page` exception to the owned-tab ledger:**
    `_builtin_prove_isolated` (allowlisted in `tests/test_owned_tabs_tp845.py`).
    - The context is Playwright's (`Target.createBrowserContext`; no
      `browserContextId` in this source). It is closed in a `finally` right
      after the prover answers, and disposed when the process detaches.
    - The proof window is as short as the prover: Notion one server fetch (≤ 10
      s, no sidebar wait), OpenAI two fetches (≤ 10 s) after a self-clearing Cloudflare challenge (≤ 15 s), Slack its boot poll (≤ 20
      s) + `auth.test` (≤ 10 s), each plus the page load.
    - Residual: for up to ~45 s, another Playwright client attached to the
      shared browser (an agent's MCP, `browser.py eval`) can LIST the proof
      tab. Its cookie jar, storage and service workers stay separate from the
      default context, so it holds no foreign session where agents work.
  - **Mail codes** count only from DKIM-signed mail (the topmost
    Authentication-Results) and only when two polls in a row agree.
  - **Expected accounts** live in the 0600 override file
    `~/.config/agent-login/safari-logins.json`, never in this repo.
  - **Tests** set `AGENT_LOGIN_SAFARI_OVERRIDES`, `AGENT_LOGIN_TOOLCHAIN=off` and
    `AGENT_LOGIN_SAFARI_FEATURES=none` (conftest), and fake safari.py, himalaya
    and ioreg.
- **`security` (keychain) calls go through `_security_run` only**: new session, no
  timeout, never `kill`/`terminate` — killing a client mid-dialog crashed
  `securityd` (tp#504). Writes are delete-then-add pinned to the default keychain,
  never `add-generic-password -U`. Reads wait for a locked keychain.
- The shared browser is LIVE infrastructure with the user's real sessions:
  never `down`/`switch`/`login` it casually, and never edit `bin/browser.py`
  in place from a subagent while consumers may exec it — use a worktree.
- **Headless = plain Chrome UA**: `--headless=new` says `HeadlessChrome`, which
  Cloudflare challenges (claude.ai, chatgpt.com); headless launches pass
  `--user-agent` from `_headless_user_agent`, so `_browser_mode` also reads the
  root process's `--headless` flag. Keep both in sync.
- **Instances**: `CLAUDE_BROWSER_INSTANCE=private` runs a second shared browser
  (own profile `~/.cache/claude-browser-private`, CDP 9223, own coordination
  files) — for Albert's private claude.ai account, since one profile holds one
  claude.ai session. Known instances: `INSTANCE_PORTS` in `bin/browser.py`.
  WS5 role instances `admin` (CDP 9224) and `alt` (9225) hold the accounts of a
  site that must not share a cookie jar with its default account (a broker
  item's `instance`; README "Accounts that share a site"). **Invariant**: one
  cookie scope in one instance holds at most one account (`identity_rules`
  refuses a second), and a multi-account item passes `logged-in` only with the
  server identity proof (below): `login`/`logged-in` of such an item re-run themselves in
  its instance when `CLAUDE_BROWSER_INSTANCE` is unset, and refuse
  (`wrong_instance`) when a run is pinned to another one (an explicit instance,
  ANY `--cdp-port`, or a port that is not the instance's); `logout` and
  `assisted-login` refuse the same way. A `logged-in` that finds a foreign
  account's session in an item's instance (`wrong_account`) clears it at once —
  the item's cookies (its cookie hosts and subdomains, its `cookie_names`; with
  path scopes — `agent_cookie_scopes`, `identity.CookieScope` — only inside
  the scope paths and on their ancestor paths, never a sibling realm's) and,
  when its recipe reads its token from localStorage (ABS, Navidrome), its
  declared storage keys on its check / fill origins plus the recipe's token
  key on the check origin only — and, for a recipe that names the page's own
  account claim (Run:ai `logged-in-user-email`), that key on the recipe's
  origin (`identity.foreign_storage_keys`; registered,
  then the lease; a fresh owned tab with the service-worker bypass applied,
  served a nonce-marked blank document by its own route, so the app never
  runs there — keys are removed only after the isolated world sees that nonce
  and no controlling worker, else nothing and "could NOT be cleared"; never
  `Storage.clearDataForOrigin`), never anything else and never the broker's
  profile; the next login then starts logged out. Another open tab of the
  same app may write its token back later: "cleared" holds at read-back time
  (fail-safe — such a session is still never proven as the item's account: the
  next proof mismatches, or the broker's guard gives no verdict). A multi-account item
  passes `logged-in` only with the server identity proof (the reviewed recipe in
  an isolated world of the probe tab + the broker's one-use challenge); only a
  digest ever crosses CDP or the socket. `agent-login.py -c` starts a role
  instance only when one of its rows needs it and stops it again unless a
  registered client (e.g. the opt-in `playwright-admin` MCP) uses it.
- **Keychain list = names only**: `agent_login_keychain.py` reads attributes and
  access lists (`dump-keychain -a`, never `-d`), and masks any service/account
  name that looks like a secret value (`safe_name`) — some items store the
  secret AS their name. Never print raw keychain attribute dumps.
- **What agents can use** = `agent-login.py -A` (the file
  `~/.local/state/agent-login/agents.md`, refreshed by `-S` every 10 min and by
  every `agent-login.py` run; a SessionStart hook in mydotfiles' Claude
  settings prints it into each session).
- **No secrets, ever** — this is a public repo. Configuration is env vars + keychain
  *labels* only. gitleaks must stay clean.

## Where things live

- The tool: `bin/browser.py` (single file).
- Cross-repo overview of who consumes it: `~/obsidian/42-Git/README_AUTOLOGIN.md`.
- Private/local notes: `CLAUDE.local.md` (gitignored); `CLAUDE.md` is a gitignored
  shim that imports this file.
