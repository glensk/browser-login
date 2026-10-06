# PLAN — login broker: agents use Albert's site logins without ever seeing the credentials

## Session

Resume: `c --resume c3d7e4e6-c54d-42eb-8b30-c40a70341a4f`

## Context

tp#733. Albert (2026-10-01): "log in yourself" interrupts unattended runs. He wants to decide
which of his logins agents may use, have a trusted component log in for them, and never let the
agent see the credentials. CSCS agent login comes back the same way.

## Goal

An agent running as uid 501 (`albert`) — Claude Code, Codex, scripts — gets a **logged-in
session** for a site Albert has whitelisted, **without Albert being present** and **without the
agent being able to read the password or the TOTP secret**.

`browser.py login ricardo` → the shared Chromium is logged into ricardo.ch seconds later.

## Decisions (Albert, 2026-10-01)

| #  | Decision                                                                                       |
| :- | :--------------------------------------------------------------------------------------------- |
| D1 | **Handoff = a session bundle** (cookies + the site's named origin storage, see 2.2) injected into the shared Chromium. The agent holds a session, never the password/TOTP. |
| D2 | **Always automatic.** No per-login approval. Oversight = audit log.                            |
| D3 | **Credentials come from Bitwarden (self-hosted Vaultwarden), pulled by the broker itself** with its own account. No 1Password anywhere. |
| D4 | **Lives in this repo** (browser-login); deployed root-owned.                                   |
| D5 | **CSCS agent login comes back** via the broker. Reverses `plans-done/PLAN_cscs-cred-daemon_SUPERSEDED.md` A8 ("human-only, no session injection") and tp#97 credplane 4.3 ("token stays inside the minter"). |

### D3: Vaultwarden has no Secrets-Manager machine accounts

`bw status` → `https://vaultwarden.dom42.space`; server has `SIGNUPS_ALLOWED=false`,
`INVITATIONS_ALLOWED=true`, `SMTP_HOST=smtp.gmail.com`. Equivalent that works:

- A **dedicated Vaultwarden user** for the broker (e.g. `albert.glensk+loginbroker@gmail.com`).
- An **organization collection `agent-logins`**; the broker user is a *confirmed* member with
  read-only access to that collection only.
- **Whitelisting a site = moving its login item into `agent-logins`** (moving transfers it to
  the org; Albert stays owner, single copy, no drift). Removing it stops NEW sessions (see
  "Revocation").
- Each item must carry a custom field **`agent_fill_origins`**: exact HTTPS origins where the
  broker may type secrets (e.g. `https://auth.cscs.ch`). The item's ordinary autofill URIs are
  NOT trusted for this. Items without the field are refused. Optional fields: `agent_site`
  (short id; default = name slug), `agent_cookie_hosts` (cookie host allowlist override).
- Bootstrap: the broker user's API key (`client_id`/`client_secret`) + master password, in a file
  only the broker uid can read.

## Architecture

```
 agent (uid 501)                          _loginbroker (role account)
 ───────────────                          ───────────────────────────
 browser.py login ricardo
   │ logged-in? → yes: done (no broker call)
   │ {"op":"login","site":"ricardo"}
   ├──────────── unix socket ────────────▶ login-broker (LaunchDaemon, root-owned code)
   │             /var/db/login-broker-run/   ├─ peer uid check (LOCAL_PEERCRED == 501)
   │                                         ├─ per-site mutex (coalesces concurrent calls)
   │                                         ├─ limiter (fsync'd state, root-only reset)
   │                                         ├─ own profile still logged in? → re-export
   │                                         ├─ bw (own appdata) → agent-logins/<site>
   │                                         ├─ own headless Chromium, profile per site,
   │                                         │    sandbox ON, CDP over pipe, mock keychain
   │                                         ├─ recipe: exact-origin check before each fill
   │                                         ├─ verify logged-in sentinel
   │ ◀── session bundle (allowlisted ───────┘ └─ audit log (no secrets)
   │      cookies + named storage keys)
   ▼ interaction lease → delete site's allowlisted cookies → inject (CDP) → logged-in check
 shared Chromium (127.0.0.1:9222)
```

### Why the agent cannot get the credentials

| Path the agent could try                         | Blocked by                                                                 |
| :----------------------------------------------- | :------------------------------------------------------------------------- |
| Read bootstrap / bw data / broker profiles       | `/var/db/login-broker` owned `_loginbroker` 0700 (selfcheck asserts)       |
| Read broker memory / attach a debugger           | different uid; no `task_for_pid` across users without root                 |
| Attach to the broker's Chromium                  | pipe transport only; selfcheck fails on `--remote-debugging-port` or `--no-sandbox` in live argv |
| Edit broker code or a recipe                     | code, venv, `bw`, Node and Playwright browsers root-owned under `/usr/local/libexec/login-broker`; updates need Albert's sudo |
| Make the broker type a secret on its own page    | request carries a site id only; fill origins come from `agent_fill_origins` (Albert's vault), exact host + HTTPS, re-checked right before every fill and submit; foreign form actions rejected |
| Old uid-501 copies (keychain, 1Password fallback, transcripts) | 3.3 deletes the code paths and keychain items; 3.4 rotates the CSCS password and TOTP before enrolment |
| Request cookies of another domain / an IdP       | per-site cookie host+name allowlist; IdP hosts (accounts.google.com, Keycloak `auth.*`, SwissID …) excluded by default |

### Accepted residuals (stated, not solved)

- **The session is power** (D1). While valid, the agent can do on that site anything that does
  not re-ask for the password.
- **Revocation.** Removing an item from `agent-logins` only stops NEW sessions. A session
  already injected lives on until the site expires it. Real revocation = `browser.py logout
  SITE` (server-side logout from the shared browser + delete its cookies) or log out /
  rotate at the provider.
- **Bot defences.** Some sites refuse a headless broker. Phase 0.1 measures this per site; a
  failing site is dropped, not built for. A runtime captcha returns `needs_human: <reason>` +
  one ntfy push, never a retry loop.
- **Albert's admin account.** An agent running as albert could keylog a later sudo/login
  password (same residual as tp#97's threat model).
- **Recipe changes need sudo** (a recipe decides where secrets are typed). The generic recipe
  covers ordinary username/password(/TOTP) forms, so whitelisting a *site* is a Bitwarden
  action, not a sudo one.

## Relation to tp#97 (credential plane)

credplane 4.3's separate-uid CSCS minter is this broker's CSCS recipe; D1/D5 deliberately give
the agent the portal session. Record as Albert's decision of 2026-10-01 in
`tp/plans/PLAN_credential-plane.md` (4.3/4.4) and in tp#97.

## Steps

### Phase 0 — prove the platform (go/no-go before anything else)

> **Status 2026-10-01:** code for 0.2–0.4, Phase 2 and the 3.2 CSCS recipe is built and
> hermetically tested (`broker/`, `install/install.sh`, client in `bin/browser.py`; 2 real-browser
> E2E tests against a local login page). Nothing is installed yet. Deviations from the text below:
> socket dir `/var/db/login-broker-run`; install.sh runs as root only system binaries plus pinned,
> sha256-checked downloads (uv 0.12.18, bw 2026.9.0 native arm64), installs only a clean tree whose
> HEAD is on origin/main (`git archive`), logs commit + diffstat; limiter = 30 min cooldown (was 12 h) after a
> post-submit failure, hard block (root reset) after 3 in a row.
> **2026-10-02 (positive proof, two-step):** success needs a visible sentinel OR, on the item's
> check URL (`agent_check_url`, else `DEFAULT_CHECK_URLS` in `broker/recipes.py`: kleinanzeigen,
> anibis, ricardo, tutti, cscs), a final page off every fill origin with no visible password
> field — checked by the broker after every login and by the client in a background tab; items
> with neither are refused. Without `agent_login_url` the flow starts at the check URL (Auth0
> `state`). The generic recipe handles identifier-first (Auth0) two-step forms; ricardo still
> faces Cloudflare Turnstile. Default cookie scope = the check page's site domain
> (`kleinanzeigen.de`) + fill-origin hosts, IdP hosts still dropped. Toppreise logs in inline on
> www.toppreise.ch — it needs `agent_logged_in_selector`. geizhals: one-page overlay
> `https://geizhals.de/?loginbox=login` (maybe reCAPTCHA), no check page known yet. Session-only
> cookies (no expiry) are lost when the broker profile closes, so such sites log in fresh each time.
> `login-cscs-assisted` (TTY-only) keeps the old keychain/1Password path until 3.3.
> Vaultwarden: Albert creates a NEW organization for the broker (not "Family").
>
> **Status 2026-10-02 00:20 (live):** broker INSTALLED (`/usr/local/libexec/login-broker`, role
> account `_loginbroker` uid 450, socket `/var/db/login-broker-run/broker.sock`), enrolled
> (Vaultwarden org "Agents", collection `agent-login`, broker user
> `albert.glensk+loginbroker@gmail.com`), Bitwarden readable (`./agent-login.py` 🟢). Items in
> the collection: Kleinanzeigen, anibis, Ricardo. Fixes shipped tonight: role UID 450-499,
> `bw config server` → Vaultwarden, launchd unload wait, fixed-text bw error reasons.
> **Open bug:** `login kleinanzeigen` reported success but the shared browser was not logged in
> (account page → `login.kleinanzeigen.de/u/login/identifier`). Kleinanzeigen, anibis, Ricardo are
> all Auth0 identifier-first (two-step). **Fixed and committed 2026-10-02** (positive proof,
> two-step, cookie scope — see above). NEXT: Albert runs `sudo install/install.sh`, then
> `./agent-login.py -t kleinanzeigen` / `-t anibis` and verify on the account page (open
> `https://www.kleinanzeigen.de/m-meine-anzeigen.html` in the shared browser — must NOT land on
> `login.kleinanzeigen.de`). Shared Chromium runs headless.
> **2026-10-02 12:30:** fix installed; `-t kleinanzeigen` now FAILS honestly (no false success),
> cause unknown → added a secret-free failure report (`diag`: URL w/o query, title, visible
> inputs, messages/buttons with username+password masked, iframe hosts, bot check) + screenshot
> `/var/db/login-broker-run/last-failure-<site>.png` (password fields blanked first); cooldown 30 min;
> `sudo install/install.sh -r SITE` clears a site's limiter.
> **2026-10-02 13:40:** report showed Kleinanzeigen's password page saying "Das ist ein Pflichtfeld"
> (password empty at submit; in a manual repro the value stays → likely a hydration race). Fix:
> wait 1.5 s on the password page, fill, verify `input_value()`, retry key by key, fail before
> submit if it still drops. Then Kleinanzeigen showed **"IP-Bereich vorübergehend gesperrt"** for
> the EPFL range (128.179.x) — triggered by 3 broker attempts + dummy test submits. Block pages
> are now detected (`BLOCKED_TEXT_RE` → needs_human). RULE: never submit dummy credentials to a
> production login; one real attempt per site, then read the report. Retry Kleinanzeigen only
> after the block lifts (hours), ideally from another network.
> **2026-10-02 14:00:** anibis (and by platform tutti, Ricardo — all SMG) shows Cloudflare
> Turnstile on the login; headless it does NOT auto-clear (turns into "Vérifiez que vous êtes
> humain"). Decision: no captcha bypass. These sites are "manual": Albert logs in once in the shared
> Chromium (`./agent-login.py -m anibis` shows the window, waits for the positive check, hides it
> again); agents use that session until it expires. Broker remains for Kleinanzeigen and CSCS.
> **2026-10-02 15:30 — PRIMARY ROUTE = Safari sessions (Albert's go).** Albert logs in in Safari
> (Bitwarden autofill passes Cloudflare); `browser.py import-safari SITE` copies only that site's
> cookies (minus Cloudflare/Akamai bot cookies) from Safari's `Cookies.binarycookies` into the
> shared Chromium, gated on the site being in the Bitwarden `agent-login` collection. Verified:
> anibis + tutti logged in. Ricardo: Cloudflare challenges the automated browser on EVERY page →
> agents drive Albert's Safari directly (saved search "portasplit ≤ CHF 850" set that way).
> Kleinanzeigen: Safari holds an Auth0 refresh_token — import only manually, after a careful test
> (rotation could log Safari out). Daily check `agent-login.py -c -m` (LaunchAgent
> `com.albert.agent-login-check`, 09:15) re-imports anibis/tutti and mails only on failure.
> Rejected after a test: headed Chrome on Xvfb from home still gets Turnstile's interactive box.

- [ ] 0.1 **Bot-defence spike, per candidate site** (ricardo, kleinanzeigen, geizhals, toppreise,
      cscs): headless Chrome for Testing as `_loginbroker` with no WindowServer, real login with
      Albert's test credentials typed by Albert, then inject the bundle into the headed shared
      Chromium and check the session survives the User-Agent/IP switch (`cf_clearance` and similar
      bot cookies bound to UA). Record go/no-go per site here; drop no-go sites before Phase 1.
      *Pre-spike 2026-10-01 (uid 501, no credentials, page load only):* default Playwright
      headless shell → ricardo + toppreise blocked (Cloudflare "Nur einen Moment…", 403).
      `channel="chromium"` (new headless) + normal Chrome User-Agent +
      `--disable-blink-features=AutomationControlled` → ricardo, toppreise, kleinanzeigen
      (login form), geizhals, cscs (`auth.cscs.ch` login form) all load. ⇒ the broker uses
      that launch profile; the real-login go/no-go as `_loginbroker` is still open.
- [ ] 0.2 `install/install.sh` (sudo, idempotent, `-U` uninstalls, shellcheck-clean): role account
      `_loginbroker` with home `/var/db/login-broker` (0700); `/usr/local/libexec/login-broker`
      (root 0755: code, uv venv, pinned `bw` + Node, Playwright browsers via
      `PLAYWRIGHT_BROWSERS_PATH`); `/var/db/login-broker-run` (root:`_loginbroker` 0775; /var/run is wiped at boot); log
      `/var/log/login-broker.log`; LaunchDaemon `com.albert.login-broker` (`UserName=_loginbroker`).
      Rollout: install into a versioned dir, selfcheck, then swap the `current` symlink; rollback
      = previous symlink.
- [ ] 0.3 Daemon skeleton: socket, `LOCAL_PEERCRED` check, JSON protocol (`ping`, `sites`,
      `login`, `logout`), per-site mutex, audit log. Chromium launched with `--use-mock-keychain`
      and a persistent per-site profile; acceptance: after a broker restart the per-site session
      is still valid (no "new device" login).
- [ ] 0.4 `broker/selfcheck.py -b`: read-only boundary check run as uid 501: live broker Chromium
      argv has no `--remote-debugging-port`/`--no-sandbox`; `/var/db/login-broker` unreadable;
      libexec not writable by 501; socket refuses a request whose peer uid is not 501
      (unit-level); exit non-zero on any violation.

### Phase 1 — Vaultwarden

- [ ] 1.1 Albert (Bitwarden UI, one time): organization + collection `agent-logins`; invite the
      broker user; accept the invite (mail via SMTP); **confirm the member** (Admin Console →
      Members → Confirm); give it read-only on `agent-logins` only; create its API key.
- [ ] 1.2 `sudo login-broker enroll-bootstrap`: getpass in Albert's terminal → bootstrap file
      0600 (never argv/env/clipboard).
- [ ] 1.3 Broker `bw` with own `BITWARDENCLI_APPDATA_DIR`: `login --apikey`, unlock per request
      (session key in memory only), list the collection, `get totp`, lock.
- [ ] 1.4 `sites` op: site ids + fill origins + cookie hosts, never secrets. Items without
      `agent_fill_origins` are listed as refused.

### Phase 2 — login + handoff

- [x] 2.1 Generic recipe: open the first `agent_fill_origins` origin's login page, find
      username/password fields, exact-origin check before each fill and submit, TOTP step if the
      item has one, verify the logged-in sentinel. Before logging in, check whether the broker's
      own profile is still logged in → re-export instead of logging in again.
- [x] 2.2 Session bundle: cookies filtered by per-site host+name allowlist (IdP hosts excluded by
      default) + named localStorage/sessionStorage keys per origin. Never the whole jar.
- [x] 2.3 Client in `browser.py`: name resolution = static `Site` registry → broker `sites` list →
      exit 2 "not whitelisted / broker down" (no assisted fallback for broker-only sites). Flow:
      `logged-in SITE` first (no broker call when already logged in) → interaction lease → delete
      the site's allowlisted cookies → `Storage.setCookies` + `DOMStorage.setDOMStorageItem` →
      `logged-in` check. New: `browser.py broker-sites`, `browser.py logout SITE`.
- [x] 2.4 Limiter: per site minimum interval, hourly and daily cap; state fsync'd under
      `/var/db/login-broker`; root-only reset; an unknown outcome (crash, timeout mid-submit) is
      never retried automatically. `needs_human` path: one ntfy push per site per day.

### Phase 3 — sites

- [ ] 3.1 Generic-recipe sites that passed 0.1 (expected: kleinanzeigen, geizhals, toppreise,
      ricardo if not captcha-gated); per-site sentinel + cookie allowlist.
- [ ] 3.2 CSCS recipe from `cmd_cscs_login` / `_submit_keycloak_login` / `_fill_keycloak_otp` with
      exact host equality (replaces the substring checks at bin/browser.py:4458/4545/4614/4650).
      Bundle = portal.cscs.ch cookies + the Waldur token from portal localStorage (what
      `_scan_token` bin/browser.py:3619-3646 reads); Keycloak `auth.cscs.ch` cookies are NOT
      handed over. Acceptance: `browser.py token` succeeds unattended after `browser.py login cscs`.
- [ ] 3.3 Remove uid-501 credential paths: delete `_op_creds` and the keychain read in
      `_cscs_creds`, `cscs-store-creds`/`store-creds` print a pointer to Bitwarden; delete any
      remaining keychain items; test asserts no credential-reading path remains for broker sites.
- [x] 3.4 Albert: rotate the CSCS password and re-enrol TOTP at CSCS, then put the item (with
      `agent_fill_origins`) into `agent-logins`. Same for any site whose password ever sat in a
      uid-501 store.
      **Done 2026-10-02:** password changed, new authenticator "Mac m1" (seed in the Vaultwarden
      item), item in `agent-login` (username `aglensk`, `agent_fill_origins` =
      https://auth.cscs.ch). The old authenticator "work" cannot be deleted (CSCS console 500;
      Service Desk ticket), so the CSCS login page offers TWO authenticators → new item field
      `agent_otp_label` (= `Mac m1`) makes the broker pick the right one; without it the broker
      stops with needs_human instead of guessing. Recorded in credplane R0.3 and tp#97.
      Old-OTP deletion tracked in t.py (SDSC Zoho #275, linked to CSCS SD-71369, waiting until
      12.10.26) — 2026-10-02: "work" deleted by CSCS (SD-71369), #275 closed. First broker test 2026-10-02 19:40: CSCS answered "Invalid username or
      password" (username aglensk entered correctly) → either the Vaultwarden item's password is
      not CSCS's current one, or the field lost the value (CSCS recipe now uses the same
      verified `_fill_password` as the generic one). Next: Albert confirms the item's password
      logs in by hand; reinstall; ONE retry.
      **2026-10-03:** retry → broker login SUCCEEDED (its own check on the portal passed), but
      the shared browser still bounced to Keycloak: the portal's Waldur token lives in
      localStorage and was not exported (no `agent_storage_keys`). Fix: for cscs the broker adds
      the portal localStorage key(s) whose value is a 40-hex Waldur token (key found by value
      shape; `_with_portal_token_keys`). Needs reinstall, then `./agent-login.py -t cscs`.
      **2026-10-04 ROOT CAUSE:** `agent-login.py -f cscs` → `len=0` — the broker received an
      EMPTY password from Bitwarden (also explains Kleinanzeigen's "Das ist ein Pflichtfeld" on
      2026-10-02). Cause: the broker account's permission on `agent-login` is "Can view, except
      passwords" (Bitwarden then hands items over without the password). Fix: Albert sets "Can
      view"; the broker now refuses an empty password with that hint (no login attempt).
      After the permission fix (`-f cscs` → len=28, matches Albert's copy) the broker LOGS IN, but
      the portal (Waldur 8.x) re-runs OIDC against auth.cscs.ch and the shared browser has no
      Keycloak session (IdP cookies excluded by design) → bounce. Albert wants CSCS SSO for
      agents (portal + support.cscs.ch/Jira) → explicit opt-in on the item:
      `agent_cookie_hosts = cscs.ch, auth.cscs.ch` (filter allows an IdP host only when named).
      2026-10-04 21:20: anibis + tutti now Cloudflare-challenge the shared Chromium even with the
      Safari session (403/"Just a moment" since 10-03, likely after heavy probing) — re-check;
      if it persists they become Safari-direct like Ricardo. agent-login.py overview now shows
      each site's last REAL check (state ~/.local/state/agent-login/last-check.json).
      **2026-10-06 ROOT CAUSE 2:** the broker's CSCS check was "URL is on portal.cscs.ch 1.5 s
      after load" — the HomePort SPA renders there first and only then sends a token-less
      session to Keycloak, so the broker's STALE profile passed: it skipped the login
      (`via: profile`), exported only `sessionid`, 0 storage keys → the shared browser bounced
      to Keycloak. Fix (code, needs `sudo install/install.sh`): `cscs_portal_ready` = still on
      the portal AND a 40-hex token in localStorage (browser.py `_scan_token`'s rule; Waldur 8
      still keeps it there — the keychain login cached one 2026-10-04); `_TOKEN_KEYS_JS` matches
      the token anywhere in the value. Then `./agent-login.py -t cscs`. If it still bounces,
      Albert sets `agent_cookie_hosts = cscs.ch, auth.cscs.ch` on the item (today: unset →
      `cscs.ch` only, auth.cscs.ch cookies filtered as IdP).
      agent-login.py overview is now ONE list (✅ works for agents / ❌ + reason) and includes the
      built-in assisted sites anthropic, openai, slack, switch (`-g SITE` = your login in the
      shown window; `-t`/`-c` only check them, never start an email-code/SSO flow).
      **2026-10-06 (later):** CSCS ✅ after the reinstall (1 cookie + 1 storage key, token
      verified). Headless shared Chromium announced `HeadlessChrome/151` → Cloudflare "Just a
      moment" on claude.ai/chatgpt.com: headless launches now pass a plain Chrome UA
      (`_headless_user_agent`, version from Info.plist; mode detection also reads the root
      process's `--headless`). Anthropic = two lines (work/private) decided by the claude.ai
      account email (`/api/account`); one profile holds one claude.ai session. Speed: the
      broker caches its site list `SITES_TTL_S`=600 (`"fresh": true` bypasses; NEEDS REINSTALL),
      agent-login reads a snapshot (`-S`, LaunchAgent com.albert.agent-login-snapshot every 10
      min; `-r` asks live) → overview 41 s → 0.1 s. Agents: `-S` also writes
      ~/.local/state/agent-login/agents.md, which a SessionStart hook (mydotfiles
      settings.json) prints into every Claude Code session; `-A` shows it.
      **2026-10-06 (evening):** reinstall done; SWITCH (-g) and Ricardo (-t) ✅. Private
      claude.ai = browser.py instance `private` (CDP 9223, own profile), `-g anthropic-private`
      waits for the account email. Overview column `agent_fill_origins` (True = the item is in
      the agent-login collection WITH the field; the assisted sites need no Bitwarden item).
      geizhals: Albert has no Vaultwarden item. Security review → tp#785 (login-keychain items
      readable by agents via the security CLI; CSCS copies of 3.3 still present).
      **2026-10-06 (late):** CSCS keychain copies DELETED (`cscs-forget-creds`; 3.3's keychain
      part done). Private claude.ai ✅; its instance is started per use and stopped again (the
      session persists in the profile). geizhals dropped (no account). Overview gains a
      login-keychain list (`agent_login_keychain.py`, names only; 🔓 = an agent can print it
      without a prompt; `-K` rescans; `-S` rescans hourly). 8 items carry a SECRET as their
      service name → masked in the list, logged under tp#97.

### Phase 4 — close out

- [x] 4.1 Hermetic tests (`tests/test_login_broker.py`): origin checker (incl.
      `https://evil.example/?auth.cscs.ch`), cookie/storage filter, peer-cred check, limiter
      persistence, mutex coalescing, name resolution, re-run idempotence.
- [ ] 4.2 README / AGENTS.md / `browser-login` skill; credplane plan + tp#97 note (D5); memory.

## Verification

Hermetic tests cover the origin checker, bundle filter, limiter, mutex and name resolution;
`selfcheck.py -b` checks the live security boundary (argv, file modes, socket peer uid), which is
why the block is not strict-eligible.

```
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run --no-sync pytest tests/test_login_broker.py
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff check broker bin
cd /Users/albert/obsidian/42-Git/home/browser-login && shellcheck install/install.sh
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run --no-sync python broker/selfcheck.py -b
```

## Debate outcome (Opus adversary)

Critic: fresh Opus subagent, 2026-10-01, 1 round (Codex seats rate-limited). All accepted.

1. [blocker] Cookies alone cannot restore the CSCS Waldur token (localStorage) — accepted: D1 becomes a session bundle (cookies + named storage keys); 3.2 hands over the portal token.
2. [blocker] ricardo etc. are not in the Site registry, no assisted fallback — accepted: 2.3 resolution order registry → broker list → exit 2.
3. [blocker] Headless proven only on a test page — accepted: 0.1 per-site bot-defence go/no-go spike first, incl. UA switch after injection.
4. [major] Registrable-domain filter leaks IdP/SSO cookies — accepted: per-site host+name allowlist, IdP excluded; Keycloak cookies not handed over.
5. [major] uid-501 keychain/1Password copies remain, no rotation — accepted: 3.3 removes paths, 3.4 rotation before enrolment.
6. [major] Org member confirm step missing — accepted: 1.1 confirm + SMTP evidence + move-not-clone.
7. [major] Role account keychain/home for Chromium and bw — accepted: home `/var/db/login-broker`, `--use-mock-keychain`, pinned bw+Node, restart-keeps-session acceptance.
8. [major] No concurrency/idempotence — accepted: broker per-site mutex, client lease + cookie clear + logged-in-first.
9. [major] Agent-triggerable lockout, weak limiter — accepted: logged-in-first, re-export, daily cap, fsync'd state, root reset, no unknown-outcome retry.
10. [minor] Verification does not test security claims — accepted: `selfcheck.py -b`, `uv run --no-sync`.
11. [minor] Loose item URIs as fill origins — accepted: mandatory `agent_fill_origins` field.
12. [minor] Revocation overstated — accepted: residual stated, `logout SITE` added.
