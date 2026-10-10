## Session

Resume: `c --resume 3871ad21-0f16-4b68-828e-f9eb1f7a6847`

# Agent-login repair — every broker site ✅, and it stays ✅

## Context

Goal (Albert, 2026-10-09): agents can use **every** login in `./agent-login.py`. ❌ sites get
fixed at the root, durably. The overview always shows *exactly* where a login broke. The
scheduled check never locks a site again. New broker items cannot fall into the same holes. The
agent-login list reaches subagents, Codex and OpenCode.

Orchestration: this session oversees. Every workstream runs as a subagent: investigate, find
the root cause, run a codex-debate (fallback: opus-plan-critique), then implement in a git
worktree. This session reviews every diff, commits, pushes, deploys and re-verifies. Subagents
never commit. Plan debated with Codex 2026-10-09 (gpt-5.6-sol); the ledger lives in the
session scratchpad.

Albert's go (2026-10-09): resetting broker limiters, and `SECRET_RUN_GUARD_OFF=1` for broker
state work, are allowed for this repair. Zendesk is no longer used (SDSC moved to Zoho Desk):
remove the site, don't fix it.

**The Verification block is not strict-eligible, and that is intended.** It runs pytest,
mypy and pylint, which execute repository code. Live steps are NOT in the block: broker
installs, shared-browser checks, guided logins and limiter-consuming canaries. They are
manual acceptance steps under the attempt policy below.

### State at start (2026-10-09 21:30)

- Re-tested: github ✅, cloudflare ✅ (both ❌s were stale).
- Hard-locked by the limiter (3 post-submit failures in a row): calibre, galaxus, galaxus-de,
  npm-nixos, npm-raspi, myfritz-alzenau. **All 6 were reset 2026-10-09 21:35** (`sudo
  install/install.sh -r SITE`). The original failure reasons are unknown (masked by "rate
  limited").
- WS-Z found that most failing sites were batch-added on 2026-10-07/08 without a validated
  check (`1ec8c711`, `37758d65`), so they may never have worked.
- cscs: broker login `ok`, but the exported bundle carries 1 cookie and 0 storage keys, and the
  portal redirects to Keycloak. `cscs-api.py` / Waldur depend on it.
- Notion: needs Albert's guided login; why does its session expire?
- `com.albert.agent-login-check` (09:15, `-c -m`) is **unloaded** until the final acceptance.

## Rules for every subagent

- **Attempt policy.** A site gets at most ONE secret-submitting production login per
  diagnostic cycle, and only after the main session approves it. No automatic retry after
  phase `submitted`/`unknown`. Logged-in probes (no submit) are free and must not count as
  attempts. A site that fails after submit is **quarantined** until the main session releases
  it. A limiter reset does not reset a vendor-side lock.
- **Before WS1a is deployed, site work is read-only.** Allowed: screenshots
  `/var/db/login-broker-run/last-failure-*.png`, journal, broker log, recipes, site config,
  logged-in probes.
- **Integration queue.** One implementing worktree at a time per file set. It starts from the
  last accepted commit on `main`. The main session commits from it and fast-forwards `main`.
  Live `bin/browser.py` changes land only when `browser.py clients` shows no registered exec
  client and no maintenance record is live.
- **Release procedure (main session).** Hermetic checks (Verification block) → commit → `ai.py
  push`, then confirm `origin/main` contains the commit (`install.sh` refuses otherwise) → `sudo
  install/install.sh` + broker selfcheck → one bounded canary → rollback point is the previous
  release under `/usr/local/libexec/login-broker/releases`.
- **Debate.** Once the root cause is found: `codex-debate` mode=diagnose (no Codex seat →
  `opus-plan-critique`). Every root cause gets a sanitized fixture plus a regression test.
- **Never** page text in `agents.md` (prompt-injection surface). Show phase codes and fixed
  text only.

## Steps

- [x] WS0 — agent-login list for every agent kind (verified live 2026-10-09; mydotfiles
      commit "feat(agents): give subagents, Codex and OpenCode the agent-login list"):
      subagents through the SubagentStart hook `agent-login-subagent-context.py`
      (additionalContext); Codex through a trusted `[[hooks.SessionStart]]` in the shared
      `config.toml`, with a trust row per seat; OpenCode through `instructions` in
      `opencode.json`.
- [x] WS-Z — Zendesk: not needed (Albert, 2026-10-09). Remove it instead of fixing it.
- [x] Zendesk removal: Albert deleted the Vaultwarden item (2026-10-09). Verified: gone from
      the broker snapshot, the overview and agents.md. A stale `last-check.json` entry is left;
      WS1a pruning removes it.
- [ ] WS1a — diagnostics and scheduler safety. Hard gate: merged + deployed before any
      secret-submitting site retry. Plan → codex-debate → implement → review → release:
  - [ ] acceptance matrix generator (`agent-login.py -j` based): one row per item, static
        TARGETS + broker extras: consumer, privilege, check URL, authenticated sentinel,
        bundle scope, attempt group, refresh policy, last phase, state. With the broker down,
        extras show as `unknown`, never disappear.
  - [ ] versioned phase codes end to end: `precheck`, `limiter`, `vault`, `recipe`, `submit`,
        `broker-proof`, `bundle-export`, `cookie-inject`, `storage-inject`, `client-proof`,
        `consumer-followup`. Structured JSON from the broker through browser.py (a side
        channel, not the stderr that `agent_login_jobs.run_browser` discards) into
        `record_check`, written atomically under a lock, details redacted and length-capped.
        The overview shows phase + short reason + the screenshot path.
  - [ ] status freshness: last-attempt vs last-success timestamps; a maximum status age, after
        which a site reads `stale`; an offline run records `unknown`, never success; removed
        items are pruned
  - [ ] scheduler safety: `-c` never submits for locked / cooldown / quarantined / pending /
        assisted sites, and reports them as such (e.g. "locked — needs `sudo install.sh -r
        SITE`"). New or unplanned broker items start as `pending` and are excluded from
        scheduled logins until promoted. No inner retry after submit (agent-login.py:883).
  - [ ] mandatory authenticated DOM sentinel in the broker proof (`_broker_probe`,
        bin/browser.py:10616). "Off the fill origin, no password field" alone no longer
        passes. Every existing site is migrated to an explicit sentinel; a site without one
        cannot be `usable`.
  - [ ] attempt groups (debate O6, final design):
    - **Static group.** The group is an explicit opaque vault field `agent_attempt_group`
      (a validated slug), known before navigation. It is set on every known shared realm,
      and each WS2 investigation confirms or corrects it. Galaxus is an example: are
      id.digitecgalaxus.ch and id.galaxus.eu one account? No dynamic derivation at
      attempt time. WS3 may *suggest* a group, never enforce one.
    - **Keys.** Raw `SITE` keys stay unchanged (rollback-compatible, no migration). Only
      `group:<id>` keys are added.
    - **Outcome-aware API.** `reserve_attempt(keys) -> id`, `mark_submitted(id)`,
      `finish(id, outcome)`, each applied atomically to every key. Crash recovery turns
      an abandoned `submitted` into `unknown`, and an abandoned pre-submit into
      `not_submitted`. This replaces the use of `Limiter.reserve`, which records "ok"
      immediately.
    - **Both keys enforce everything:** minimum interval, `cooldown_until` (the multi-key
      deny path, limiter.py:227), hourly/daily caps and the hard block.
    - **Streak reset.** The streak clears only on a proven *fresh* password authentication
      (sentinel after submit), even when export fails later. A reused broker profile never
      clears it.
    - **Cross-process locking.** Every read-modify-write takes an exclusive `fcntl.flock` on
      a sidecar lock shared by the daemon and the reset process.
    - **Resets.** daemon.py gets a login-key parser that accepts `group:<id>` (separate
      from the `secret:`/`totp:` validator, daemon.py:865). `install.sh -r group:<id>`
      resets a group; `-r SITE` reports a group that still blocks; `-r SITE -G` resets
      both together. The site→group binding is persisted at reservation time.
    - **Tests:** pre- vs post-submit failure; group cooldown across members; crash recovery
      at every transition; concurrent reservations in one group; profile reuse not
      clearing a streak; auth success + export failure; old code reading new state; reset
      racing a live write; a malformed group field; group ids never revealing usernames.
- [ ] WS2 — per-site root-cause fixes, serial, each from the previous accepted + deployed
      base. Acceptance per site: logged-in probe ✅ in the shared Chromium, plus its consumer
      where one exists:
  - [ ] cscs: token discovery proven, exported storage keys > 0, injection read back before
        the SPA redirect, stable portal probe, `cscs-api.py` (Waldur) call succeeds.
    - [x] Root cause found (read-only, Codex diagnose debate converged in 3 rounds):
          `cscs_portal_ready` (recipes.py:791) passes on ANY 40-hex localStorage value, even
          an expired Waldur token (about 1 h lifetime). The broker therefore reuses a dead
          profile and skips the login. Discovery on `/` then loses the race against the
          portal's new `boot-redirect.js`, and `_with_portal_token_keys` (daemon.py:234)
          silently returns 0 keys. The audit still says `ok`.
          Second issue: a fresh login (188 s) exceeds the client's `BROKER_TIMEOUT_S` 180 s.
          `cscs-api.py:773` also kills the login after 180 s.
    - [ ] Fix (after WS1a deploys):
      - the check asks the server: `/api/users/me/` 200 + identity, returning
            valid/invalid/indeterminate;
      - export allowlist `waldur/auth/token` (+ expires_at, method), read on `/profile/`;
      - `BundleExportError` instead of the silent fallback;
      - client-side bundle check before touching cookies;
      - inject + read-back on `/profile/`;
      - `cmd_token` validates its token;
      - timeout ordering, incl. the sdsc `cscs-api.py` subprocess timeout;
      - hermetic portal fixture tests (stale/valid/503/export-fail).

      One live submit is needed.
  - [x] npm-nixos — ✅ 2026-10-10: release 388456e, broker 388456eb4ade. Profile reuse with no secret during the cooldown; limiter hash unchanged.
    - [x] Root cause (read-only, Codex diagnose debate converged in round 1): the vault
          password is stale (len 19 `36d8`). The live one is SOPS `NPM_ADMIN_PASSWORD`
          (len 28 `e426`), verified against the NPM hash on nixos. All 3 `POST /api/tokens`
          answered 400 with the 96-byte "Invalid email or password" body. The July rotation
          never updated the agent-login items. `npm-password` (agent secret) is stale too.
    - [x] Vault updated by Albert 2026-10-10: both NPM login items and `npm-password` show
          len 28 `e426`. The duplicate `npm-admin-password` (no consumer) was deleted.
          Albert's own login on both NPM instances works with this value.
    - [x] Canary root cause (WS2-npm builder, Codex converged in round 3): the broker
          profile's HTTP cache held the pre-upgrade NPM `index.html` (no Cache-Control). Its
          hashed assets were gone after the 2026-10-09 container recreate, and NPM serves HTML
          for them, so the SPA rendered blank. It was not a reload.
          Fix built: clear the cache at every broker launch; script-MIME diagnostics; polled
          sentinel; blank page = indeterminate; NPM JWT refresher; `refresh_only`; bundle
          completeness + rollback. Server side: tp#898. Deferred to WS1b: a 6-hourly
          `login --refresh-only` keeps the 1-day token alive.
          Review round 1 (2026-10-10) pulled that refresh forward: the client renews when
          < 12 h are left, and `agent-login.py -c` runs `login -F` (pending sites included).
          A live opt-in test shows NPM 2.16 does not renew its own token in a short tab.
          Tick "refresh before export" after the release and a live check.
    - [ ] Code (after WS1a):
      - poll `sentinel_shown()` instead of `wait_for_selector`, since the first
            `a[href='/nginx/proxy']` is a hidden navbar item;
      - refresh the NPM JWT before export when less than 12 h remain (`GET /api/tokens`);
      - bundle completeness check;
      - sentinel `a.card-link[href='/nginx/proxy']` on both NPM items.
  - [x] npm-raspi — ✅ 2026-10-10 (one approved login after the release). Same failure, same fix. The password is unconfirmed (Home Assistant
        protection mode blocks docker), so one approved submit after the vault update is
        the test. Separate realm, so no shared attempt group. Off-LAN it must report
        `unreachable` (precheck), never submit.
  - [ ] calibre (Calibre-Web Automated v4.0.8, container `calibre-web` on nixos)
    - [x] Root cause (read-only; Opus critique, since every Codex seat was above its cap):
          the vault had the factory default `admin123`. On 2026-10-08 the broker's
          pre-tp#835 Enter-submit pressed CWA's `forgot` button twice, which reset the admin
          password twice and mailed it (Gmail msgs 52409/52410; 52410 is live). The third
          attempt failed, which caused the hard lock. Latent: the sentinel `#logout` sits in
          a closed dropdown (theme caliBlur), and anonymous browsing renders `/` without a
          login.
    - [ ] Albert: log in with the password from mail 52410, set a new one in `/me`, paste it
          into the `calibre` item, drop the `192.168.178.72` URI, purge both mails (tp#97).
          Decision: agents use `admin` or a dedicated non-admin user (recommended).
    - [ ] Fields (`broker-add.py -b`): `agent_logged_in_selector=#top_admin` (non-admin:
          `#top_tasks`), `agent_check_url=https://calibre.dom42.space/me`,
          `agent_cookie_names=session,remember_token`, `agent_fresh_login=true`.
    - [ ] Code (after WS1a), generic:
      - `_submit_password`/`_submit_identifier` fail closed: no Enter fallback when the
            buttons can't be read;
      - a POST tripwire for secondary buttons (`forgot=`), reported as
            `secondary-action-blocked`;
      - `submitted` is set only after the click;
      - "remember me" is checked before submit;
      - a Cloudflare Access redirect reads `access-gated`, never a submit;
      - re-login at 28 days or more of session age;
      - the promotion gate requires the sentinel visible after a real login.
    - [ ] Security defects in CWA itself: tp#886 (needs Albert's decision).
  - [ ] galaxus
    - [x] Root cause (read-only, Codex diagnose converged in round 1): phase `submit`. The
          identity server accepts the e-mail, then shows "Deine Anmeldedaten sind nicht
          korrekt" for the password. Galaxus' frontend shows that text for `InvalidCredentials`
          AND for `Unknown`, and Galaxus answers a failed reCAPTCHA/bot check with it on
          purpose. Most likely bot rejection of the headless broker (Akamai Bot Manager +
          reCAPTCHA, about 70 %); a stale password is the alternative. Albert is unsure which
          vault item filled his 2026-09-19 Safari login, so we take the branch that works
          either way: **no more broker submits**. galaxus.ch and galaxus.de are SEPARATE
          accounts (separate groups).
    - [ ] Build (after the npm release, same files):
      - `SAFARI_SITES["galaxus"]`: import Albert's Safari session; per-site flag that drops
            Chromium's own bot cookies.
      - `BOT_COOKIE_DENY` += `bm_*`.
      - `MANUAL_START` += galaxus, galaxus-de, using the headed window flow.
      - Allowlisted reason codes from `submit-password` (`idp_invalid_credentials` /
            `idp_unknown` / `captcha_required`).
      - Vault: sentinel `[data-testid="customer-account-button"]`, check `/de/orders`; Albert
            sets the groups `digitecgalaxus-ch` / `galaxus-eu` by hand.
      - Both stay `pending` forever, so the scheduled check probes and never submits.
  - [ ] galaxus-de: same analysis. No Safari cookies and no TOTP, so it gets an assisted
        login (Albert once, in the window) plus monitoring.
  - [ ] myfritz-alzenau
  - [ ] notion: instrument why the session expires (vendor policy or lost profile state). No
        subagent runs a guided login. Albert does exactly one `-g notion`, observed over the
        interval. "Monitored + alert to Albert" is an acceptable durable outcome.
- [ ] WS1b — durability per flow, after WS2's root causes: broker re-export before expiry,
      credential-change handling, Safari-cookie expiry, monitoring of assisted sessions with
      an alert to Albert. Plan → codex-debate → implement.
- [ ] WS4 — no more unsynced rotations (Albert, 2026-10-10: layers 1 and 2). Plan →
      codex-debate → implementation:
  - Layer 1: Vaultwarden is the single master copy. SOPS and Keychain copies are derived
    by a sync tool, and duplicates are merged (`npm-password` → `npm-admin-password`).
  - Layer 2: one rotation command (server → Vaultwarden with Touch ID → every copy →
    fingerprint verify), and a hook blocks agents from rotating any other way.
  - Plan file: `mydotfiles/PLAN_credential-single-source.md` (tp#889, Opus critique, 12
    objections accepted). Albert accepted Q1–Q6 on 2026-10-10. S1 is building; S2
    (broker) waits for the WS1a merge.
- [ ] calibre account (Albert, 2026-10-10):
  - [x] Non-admin CWA user `agent` created (role 258, no e-mail). Password (len 32 `47b0`)
        in Keychain `CALIBRE_AGENT_PASSWORD`. Verified: `#top_tasks` visible after login,
        `/me` 200. Backups `app.db.bak-20261010-000354-pre-agent-user`.
  - [x] tp#886 part 1: Guest role 430 → 290 (browse + download). Docs committed.
  - [x] tp#886 part 2 (closed 2026-10-10): start-up patch
        `homelab/calibre-web/custom-cont-init.d/50-disable-forgot.sh` (commit 6f29da9). It
        fails closed by holding the app down if upstream code drifts. Verified live: reset
        refused, hashes unchanged, login via the button and via Enter both work. Upstream
        comment posted on CWA #1585.
  - [x] Albert set the `calibre` item (2026-10-10). Broker snapshot verified: user `agent`,
        password len 32 `47b0`, check `/me`, sentinel `#top_tasks`, cookie names
        `session,remember_token`, `fresh_login` true, LAN URI removed.
- [ ] WS1a release order (re-review 2026-10-10: B1–B5, C1–C3, N1/N2 fixed; tp#893):
  1. [x] Client committed and pushed 2026-10-10 (`5e55b33`). Sentinel-less sites keep the old proof.
  2. [x] 2026-10-10: a check-only `-c` over all 54 sites, with every site pending. The
     limiter.json hash was identical before and after (`8f39f83c…`), so the daily check no
     longer burns the limiter. 33 ✅. The 8 origin mismatches are all logged-out sites
     redirected to their IdP, which is expected; no logged-in site mismatched. `-V`: all 48
     selectors pass. Original text of this step:
     Run the free `browser.py logged-in` for every sentinel site, then `agent-login.py -x`.
     Every site whose page ends on another origin gets `agent_proof_origins`
     (broker-add has no column for it yet → extend or edit by hand) BEFORE step 3.
     Otherwise the stricter origin rule would quarantine working sites (risk R-a).
  3. Selector check: done 2026-10-10, 0 of 48 current selectors fail the plain-CSS rule
     (R-b). Re-run the new read-only helper right before the install.
  4. [x] Broker installed 2026-10-10 (release `fd9f8a063d90`), selfcheck all ✅.
     Canary npm-nixos (1 submit): the server accepted it (`POST /api/tokens 200`,
     `/api/users/me 200`), but the post-submit proof judged during NPM's page reload and
     recorded "still on login page" [phase submit] → cooldown + quarantine. This is a proof
     timing bug for SPAs that reload after login. Fix with the WS2-npm builder (poll the
     sentinel, wait for reload, indeterminate on a blank page, profile reuse for storage
     tokens, JWT refresh). Re-test after that release, then the candidate logins.
- [x] Sentinel batch 1 (broker-add, Albert's Touch ID, 2026-10-10): anibis, docker,
      docker-hub (check URL → app.docker.com), infomaniak, ricardo, tutti, zoho-desk, both
      NPMs (`a.card-link[href='/nginx/proxy']`), calibre (`#top_tasks`, check `/me`).
      The 7 logged-in sites pass with their sentinel.
      kleinanzeigen was skipped by broker-add (name lookup?), to redo.
      Still need a candidate login after WS1a: galaxus, galaxus-de, myfritz-alzenau,
      myfritz-prilly, runai-admin, runai-test3, cscs (`#quick-issue-toggle`), eduid.
      switch needs a code constant.
- [x] Cloudflare item split (Albert's go, 2026-10-10): the new agent secret
      `CLOUDFLARE_API_KEY` / `cloudflare-api-key` holds only the API key (len 52 `ab22`;
      created via secret-run → Keychain → broker-add -x -N with Touch ID; the staging copy
      is deleted). The `Cloudflare` login item was taken out of agent-secrets and lost
      agent_secret_id/agent_secret_fields/api_key, done in Albert's Safari via AppleScript.
      Verified: `secret-run -l` lists only cloudflare-api-key, and the Cloudflare broker
      login still works. Phase 2 of the leaked DNS token's rotation is running (tp#97).
- [ ] WS3 — onboarding guard (plan → codex-debate → implement): static validation of a new
      item (sentinel present, fill origins, cookie scope, attempt group), a budgeted
      promotion test (`pending` → `usable`), and a removal path (`broker-add.py` remove or
      documented) that also prunes agent-login state
- [ ] Final acceptance: a check-only inventory (logged-in probes only), then per-site canaries
      under the attempt policy. Re-enable the 09:15 job (`./agent-login.py -I`) only after
      locked / cooldown / pending / assisted / quarantined sites provably cannot trigger a
      login. Observe one real scheduled run: limiter counters must not move for green or
      quarantined sites.

## Learnings (carried to every subagent)

- The broker limiter hard-blocks a site after 3 post-submit failures in a row. Only root resets
  it (`sudo install/install.sh -r SITE`). Once locked, every attempt reports only "rate
  limited", which hides the original reason.
- `agent-login.py -t SITE` prints the broker's detailed failure: stop URL, page text, password
  fingerprint, and the screenshot at `/var/db/login-broker-run/last-failure-SITE.png`. The
  overview and `last-check.json` keep only the exit code (fixed by WS1a).
- `secret-run -A -N 500` prints the broker audit log: result per login, no reasons.
- The broker runs the INSTALLED code (`/usr/local/libexec/login-broker/current`, `git archive`
  of a commit on `origin/main`). `bin/browser.py` is live for every consumer immediately.
- The positive proof "ended off the fill origin, no password field" also passes on an "Access
  Denied" page (zendesk). Only a DOM sentinel proves a login.
- An audit `ok` does not prove a usable session. A check on a value's *shape* (a token-like
  string in storage) passes on expired tokens. Only a server-validated proof counts (CSCS:
  `/api/users/me/` 200). Look for the same pattern in every other site's check.
- Today the limiter is consulted before profile reuse, so a cooldown also blocks a reuse that
  needs no password. WS1a moves admission into `get_secret` (CSCS debate rule).
- Broker run times must stay inside the client timeouts. Required order: broker deadline <
  browser.py socket < `LOGIN_TIMEOUT_S` < runner / consumer subprocess timeouts.
- **Stale credentials are a top suspect.** Rotations updated Keychain/SOPS but not the
  `agent-logins` items. Compare fingerprints (`agent-login.py -f SITE`: length + 4 hex)
  against the authoritative copy, and prove it in-host where possible (hash compare,
  nothing printed). WS1b/WS3 need a drift check plus a rotation path that updates every
  copy.
- A server's error-body size or text can tell "unknown user" from "wrong password" without
  another submit (NPM: 60 vs 96 bytes).
- A sentinel whose FIRST match is hidden makes `wait_for_selector(visible)` time out, and
  then the one-shot scan decides. Use a selector whose first match is the visible element,
  and poll.
- Storage-token sites need a refresh-before-export rule, or the daily check costs a
  password submit each day (NPM JWT lasts 1 day).
- **A wrong submit can change server state.** A "stale" credential may have been destroyed
  by the broker itself (CWA `forgot` reset). Audit pre-fix attempts on forms with secondary
  buttons.
- Evidence sources:
  - the app's own mails in Gmail (`himalaya message read -p` does not mark them read);
  - the app's activity database;
  - NPM per-host logs `/data/logs/proxy-host-<id>_access.log*` (status codes, and the UA,
        which dates the broker release);
  - the full broker audit `/var/db/login-broker/audit.log`.
- **Sentinels:**
  - must be proven VISIBLE after a real login, not only absent before one;
  - apps with anonymous browsing need a check URL that requires login (`/me`);
  - apps that tie sessions to IP+UA survive bundle injection only via remember-me;
  - apps whose session row isn't extended by use need `agent_fresh_login` to refresh.
- A post-submit proof must wait out SPA reloads: NPM stores the JWT and calls
  `location.reload()`, and a proof taken mid-reload reads "still on the login page" or a
  blank page. Check the server's access log before believing a submit failed.
- Debate outcome files: every subagent must write its own path. The shared
  `$TMPDIR/ccc-codex-debate/<session>.outcome.json` was overwritten between two debates.
- Subagents never see SessionStart output, only a SubagentStart hook's `additionalContext`. A
  Codex hook without a trust row is skipped silently in `codex exec`, and each seat needs its
  own row.

## Verification

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run ruff format --check bin/ broker/ agent-login.py agent_login_jobs.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run ruff check bin/ broker/ agent-login.py agent_login_jobs.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run mypy bin/browser.py agent-login.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pylint bin/browser.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests
cd /Users/albert/obsidian/42-Git/home/browser-login && bin/browser.py -h
```
