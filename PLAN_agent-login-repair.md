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
- **Tests never contain credential-shaped literals** (a quoted fake password assigned to a password field): the repo's git-secrets
  hook blocks the commit. Generate fake values at runtime (`secrets.token_hex`), or build
  action words from parts. This blocked 3 releases on 2026-10-11.
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
  - [x] cscs: token discovery proven, exported storage keys > 0, injection read back before
        the SPA redirect, stable portal probe, `cscs-api.py` (Waldur) call succeeds.
    - [x] Root cause found (read-only, Codex diagnose debate converged in 3 rounds):
          `cscs_portal_ready` (recipes.py:791) passes on ANY 40-hex localStorage value, even
          an expired Waldur token (about 1 h lifetime). The broker therefore reuses a dead
          profile and skips the login. Discovery on `/` then loses the race against the
          portal's new `boot-redirect.js`, and `_with_portal_token_keys` (daemon.py:234)
          silently returns 0 keys. The audit still says `ok`.
          Second issue: a fresh login (188 s) exceeds the client's `BROKER_TIMEOUT_S` 180 s.
          `cscs-api.py:773` also kills the login after 180 s.
    - [x] ✅ 2026-10-11: release f942dd0, broker f942dd0004dd. One login: 3 storage keys, token validated (aglensk); `cscs-api.py -lp` live data (22 projects); promoted (`-p cscs`). The server proof counts as strict, so no DOM sentinel is needed (this overrides the WS1a rule). Timeouts: broker 255 s < client 285 s < LOGIN_TIMEOUT 480 s < runner 570 s; cscs-api / user-management / smartsheet raised to 540 / 600 / 540 s. The cscs item's cookie hosts exclude auth.cscs.ch, so no Keycloak session reaches the shared browser.
    - [x] Fix delivered:
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
  - [ ] calibre (Calibre-Web Automated v4.0.8, container `calibre-web` on nixos). Generic fix released 2026-10-11 (175ccd2, broker 175ccd25130a): fail-closed submits, a (name,value) secondary-action tripwire that only screens credential carriers / form navigations, remember-me, Access gate, `agent_max_session_days`. Canary logins running.
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
          Done 2026-10-10 by the main session, with Albert's go:
          - admin password reset in the container (nixrun stdin);
          - stored in Albert's personal vault item `Calibre-Web (admin)` via Safari, and
            verified equal;
          - Keychain copy deleted;
          - the reset mails deleted from both Gmail accounts (main: himalaya Bin + expunge;
            kindle: IMAP inside calibre-web).
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
  - [x] galaxus ✅ 2026-10-11: vault batch (sentinel + /de/orders) written with Touch ID; `-t galaxus` imported 19 Safari cookies, positive check ✅. Code released 2026-10-11 (f0f4b16, broker f0f4b16a2490): never-submit guard (field + built-in sites/domains), Safari import manual-only and refused without a Safari session, galaxus.ch via Safari, galaxus-de assisted. Secrets baseline unchanged (28/28). Open: the vault batch (sentinel + /de/orders) needs Albert at the Mac for Touch ID, then `agent-login.py -t galaxus` (import) and Albert's `-g galaxus-de`.
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
  - [x] galaxus-de ✅ 2026-10-11 (Albert's guided login; check-only by design, never promoted). Same analysis. No Safari cookies and no TOTP, so it gets an assisted
        login (Albert once, in the window) plus monitoring.
  - [x] myfritz ✅ 2026-10-11 (captcha fix d629f6c, broker d629f6c41caa; one login through the invisible reCAPTCHA). On demand per Albert (10 h session), not promoted. Formerly myfritz-alzenau / myfritz-prilly
    - [x] Root cause (read-only, Codex diagnose converged in round 1): phase `submit`, a
          false `needs_human`. sso.myfritz.net (Keycloak) shows an INVISIBLE, self-submitting
          reCAPTCHA page between password and OTP. `challenge_reason` flags any visible
          recaptcha iframe within 500 ms. prilly once won the race (2026-10-09).
          alzenau (volker99934@proton.me) also hits "Dein E-Mail-Konto existiert nicht mehr".
          The two items are DIFFERENT accounts on one Keycloak scope, so they overwrite each
          other. prilly's logout = Keycloak's 10 h max session.
    - [ ] Code (after CSCS):
      - classify challenges (invisible anchor ≠ challenge; checkbox/popup = challenge;
            a grace period that resets on navigation; never click);
      - snapshot the challenge page at detection time;
      - no `fresh_login` for myfritz (it would drop CLOUD_SSO_DEVICE).
    - [x] Merge done 2026-10-11 ~15:20 by session status-35 via Albert's Safari: the Alzenau 7520 is now on albert.glensk@gmail.com (both boxes on /devices). `myfritz-alzenau` was removed from the agent-login collection (main session, Safari); broker list verified. Pending: Touch ID batch renames the prilly item to site `myfritz` + sentinel `#dropdownMenuButtonHeader`; captcha fix.
    - [ ] (old) Albert decided 2026-10-11: MERGE the Alzenau box into the gmail MyFRITZ account,
          then remove `myfritz-alzenau` and keep one `myfritz` site. Waits on the box
          re-registration (FRITZ!Box UI → Internet → MyFRITZ!-Konto) plus the confirmation
          mail in Gmail, which the main session can click.
    - [x] Albert decided 2026-10-11: MyFRITZ is on-demand (10 h Keycloak session). The
          scheduled check shows it as "on demand", not ❌; agents log in when they need it.
- [ ] Canary round 1 (2026-10-11, new submit code), one approved login each:
  - [x] calibre, stirling, smartsheet: ✅ and promoted.
  - [x] navidrome-albert: ✅ after the storage-check fix (`fix(browser): storage write proven at
        document start`). The app rotates its JWT on every call, and the old exact-value
        read-back could never pass.
  - [x] uptimerobot: agent secret `uptimerobot-api-key` already = the read-only key (fingerprint-verified); browser item taken out of agent-login (Safari). No password (SSO + API keys). Albert 2026-10-11: read-only API key as
        an agent secret (needs Touch ID), and drop the browser item.
  - [x] mullvad ✅ promoted 2026-10-11 (d88dc81, broker d88dc81291ac): `agent_login_mode=username-only` on the item; secret `mullvad-account` tagged too (secret-run refuses it, Albert's choice). Account-number login with no password. Albert 2026-10-11: teach the broker
        (`agent_login_mode=username-only`), builder running.
  - [x] portainer-ds218 ✅ promoted 2026-10-11 (fix 535e692, broker 535e692552ed). Root cause = OUR bug. The strict proof's `goto(check_url)` was a hash-only
        (same-document) navigation, so Playwright returns None → status 0 → indeterminate. The
        login itself worked. Jellyfin is hit the same way. Fix: `load_document` via about:blank
        + a proof reason channel (builder running). 1 `unknown` on the limiter (no reset); release
        the quarantine after the install.
  - [ ] dsm-readonly, authentik-glensk: submit "still on login page". Both are in WS5
        groups (blocked by the S0 guard anyway); investigate with WS5.
- [ ] WS5 — account identity (tp#833, hit 2026-10-10). Plan `PLAN_ws5-account-identity.md` (tp#909,
      Codex converged in round 1). Albert's decisions 2026-10-11:
      - guard first (S0, "⚠ account unproven");
      - proposed defaults accepted (gitlab-sdsc→glensk, abs→albert, navidrome→albert,
        dsm→readonly, authentik→glensk, runai→test3; admins in the `admin` browser;
        gitlab-sdsc-test, docker-hub, custos-admin in `alt`);
      - admin browser ALSO reachable via MCP (Albert chose this over browser.py-only).
      - [x] S0 guard released 2026-10-11 (919da8f): 8 groups / 20 items read "⚠ account unproven"; logged-in/login exit 2 `identity_unproven`; -p/-c skip them.
      - [x] S1 broker identity released 2026-10-11 (bea6b32, broker release bea6b327b2ed):
            identity fields + recipes (gitlab, audiobookshelf live-confirmed; dsm/authentik refused
            until confirmed), one-use pid-bound challenges, IdentityGuard lockouts, per-instance
            conflicts; three security review rounds before release.
      - [x] S2+S3 released 2026-10-11 (859c785, broker 859c785bf996): client proof in an isolated
            CDP world, admin 9224 / alt 9225 instances with port+instance gate, aliases, a
            `wrong_account` check clears the foreign cookies in that instance (no lockout spiral),
            identity verdict in checks.json, grouped agents.md. Two review rounds (2 blockers,
            port exemption + `-W` removed). Known gap for S4: audiobookshelf keeps its session in
            localStorage, cookie clearing does not remove a foreign abs session.
      - [x] S4a/S4b released 2026-10-11: broker-add identity options (mydotfiles b1aece79, push
            pending: YubiKey signing refused), navidrome recipe + storage-token foreign clear
            (1d54bd3, broker 1d54bd358b31); playwright-admin MCP config + `cba` alias.
            runai-test3 vault password was stale → rotated (test fixture). Docker/docker-hub:
            Albert: neither → leave the broker (the Safari collection removal did not persist; redo).
      - [x] S4c built + reviewed (2 rounds), committed locally b5f21ec (mydotfiles 5c83fd9f):
            path-scoped `agent_cookie_scopes`, server-bound `runai` recipe (token endpoint +
            JSON admin probe, admin side unconfirmed). Push + install wait on the YubiKey.
            Live gates: A0 logged-in cookie inventory, runai-admin admin probe, refresh-token
            rotation (broker reuse → client check → broker reuse).
      - [x] S4 vault fields written 2026-10-12 (broker-add, Touch ID): gitlab-sdsc (vault usernames
            switched from e-mail to GitLab username), abs, navidrome, runai (+cookie scopes, sentinel
            `button[aria-label^='Expand "']`), custos-admin (alt). docker/docker-hub removed (Albert:
            neither). gitlab-sdsc-test dropped (Albert): GitLab user Testuser2 is blocked; demoted,
            vault `-D` pending Touch ID.
      - [x] Live: gitlab-sdsc-glensk — the check found tp#833's admin session in 9222, cleared it, and
            after the 1 h guard cooldown the login is server-proven; glensk + admin promoted (-p).
      - [x] runai-test3 + runai-admin ✅ 2026-10-12, both server-proven, side by side (default and
            admin browser). Fix: `agent_fresh_login` (broker-add -F) — a broker relaunch loses Keycloak's
            session-only KEYCLOAK_IDENTITY, confirmed with `login -G` (0e9ace1); admin probe confirmed
            live (200 JSON as admin, 403 text/plain error object as user; d669be8). Promoted (-p).
            gitlab-sdsc-test fully removed (Testuser2 blocked; Albert: drop). Overview: 36 ✅.
      - [x] Home LAN 2026-10-12: abs-albert + navidrome-albert (default) and abs-root + navidrome-root
            (admin browser) ✅, all server-proven and promoted.
      - [x] DSM readonly TOTP 2026-10-13: fresh Safari window got through the enforce-2fa wizard (OTP
            method; seed held in a 0600 file, saved to the vault item's Authenticator key, proven by a
            Safari login with safari.py -O, file deleted). Vault: dsm-readonly -p readonly, dsm-albert
            -p admin -I admin (Touch ID).
      - [ ] DSM identity recipe (builder running): live as readonly — SynoToken from the server
            (`SYNO.API.Auth method=token v6` → data.synotoken), `SYNO.Core.NormalUser get` + X-SYNO-TOKEN →
            data.username (without the token: 119 even while logged in), admin probe `SYNO.Core.User list`
            → 105 for non-admin (admin_false confirmed). admin_true unconfirmed (dsm-albert not probed;
            its 2FA method unknown). Then `-i dsm` (Touch ID), mirror in broker_add_fields.py, release
            readonly's quarantine, login + promote dsm-readonly.
      - [x] authentik login fixed 2026-10-12 (e578c67, broker e578c6757cbf): root cause = the broker typed
            into authentik's off-screen password-manager helper form (empty uid submitted); new recipe
            drives the flow-executor API (isolated world, one secret POST, no redirect follow, TOTP).
            Reviewed. Both vault items: authentik usernames, TOTP seeds present.
      - [x] Off-LAN gate (2026-10-13, fixed 3c… broker 6bcaded): classify by the redirect chain (origins.access_gated_via, recipes.NavTrail); abs-root/navidrome-root now ⏸. Also: launchd PATH lacked /usr/sbin (lsof) → role browsers never stopped by the scheduled run; fixed in agent_login_jobs.py, plists reinstalled: abs-root / navidrome-root (admin browser) show ❌
            "login page left the fill origins" instead of ⏸ access_gated — Cloudflare Access with one IdP
            (GitHub) redirects straight on to github.com, so the final page has no cloudflareaccess.com /
            /cdn-cgi/access/ marker. Fix: classify by the redirect chain on every path; then re-check both.
      - [x] eduid + SWITCH Cloud 2026-10-13 (WS1b L7); gitlab-ethz, npm-nixos, npm-raspi promoted; DSM both
            accounts live (recipe 87e3722 + ad51414).
      - [x] authentik live 2026-10-13: Safari login as glensk (helper form for the uid, light-DOM proxy
            input for password + TOTP), `users/me` 200 JSON, no `original` key, glensk is a SUPERUSER →
            both items `privilege admin` (told apart by username), recipe live (e2b0856, admin_false stays
            unconfirmed), mirror in broker_add_fields.py, `-i authentik` on both; authentik-glensk
            (default) and authentik-akadmin (admin browser) logged in and promoted.
      - [x] custos-admin ✅ 2026-10-12 in the alt browser: identity recipe `keycloak-admin` (silent
            OIDC PKCE in the isolated world, id_token pins, master-only probe `/admin/realms/master/users/count`;
            d808a8f), reviewed (S1 login_required-only, S2 probe, S3 proxy). Overview: 37 ✅.
      Original line: account identity (tp#833, hit 2026-10-10): 8 same-scope groups report ✅ for
      the wrong account; gitlab-sdsc-test passed while the browser was `albertadmin`.
      Plan → codex-debate → implement:
  - identity proof per item (in-page compare against the vault username, never printed);
  - same-scope group invalidation;
  - per-account browser instances, or merged accounts, where two accounts are needed.
  - [x] notion — no defect (read-only, Codex converged in round 1). The 2026-10-09 ❌ was
        SELF-INFLICTED: session 7d725bed deleted all 36 Notion cookies via raw CDP on
        2026-10-08 21:11 for a guided-login test (tp#836), and raw CDP writes no journal
        event. Albert's guided login of 2026-10-09 still holds. The cookies slide one year
        per visit (now to 2027-10-11), so the daily check itself keeps Notion alive. False
        ❌s on 10-09 came from a hidden background tab (fixed in 07cf209). WS1b items:
        server-side tri-state probe, tri-state through to the mail (2× invalid before
        "log in once"), expiry telemetry (warn < 30 days), `_record_login_event` for guided
        logins, logout tests only on throwaway instances.
- [ ] WS1b — durability per flow, after WS2's root causes. Albert 2026-10-11: assisted/guided logins (galaxus-de, notion, openai, slack, Safari sites) are done by AGENTS in Albert's Safari (`safari.py -L/-O` from the Vaultwarden tab) plus a Safari cookie import into the shared Chromium — never a `-g` to-do for Albert (only CAPTCHA / locked vault / hardware or push approval / SMS stay his). Build: a SAFARI_SITES entry for galaxus-de and an `agent-login.py` path that runs the Safari login + import itself. The guided-login confirm is now 'press Enter'. broker re-export before expiry,
      credential-change handling, Safari-cookie expiry, monitoring of assisted sessions with
      an alert to Albert. Plan → codex-debate → implement.
  - [x] Plan `PLAN_ws1b-durability.md`, Codex (gpt-5.6-sol) converged in round 3 (19
        objections, 18 accepted, the non-strict Verification block kept). Built 2026-10-12
        in a worktree, not committed:
        - `-L SITE` (agent-invoked Safari login + import, claude.ai via the magic link);
        - `agent_login_safari.py` (recipes, window-handle step machine, hard stops, mail
          codes);
        - built-in imports with an account proof that fail to logged-out;
        - myfritz on demand;
        - the `-R` refresh pass + its LaunchAgent (transactional `-I`);
        - Notion tri-state + the 2-run mail rule + expiry telemetry;
        - toolchain lines.
  - [ ] Release + live steps L0–L8 of the WS1b plan; mydotfiles M0–M4, M6 first.
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
      login still works.
- [x] Leaked Cloudflare DNS token rotated (2026-10-10, tp#97/tp#660):
  - Three new tokens (`npm-dns01-nixos`, `npm-dns01-raspi`, `network-apis-dns-read`)
    replaced it. The old `68b86542…` is deleted and now gets 401 code 1000.
  - Real renewals on nixos and the raspi; nixos nginx reloaded. The raspi add-on was
    restarted with Albert's go, and serves the cert until 2027-01-08; all 7 hosts answer.
  - Records committed in macbook2014-nixos, credplane and tp.
- [ ] WS3 — onboarding guard (tp#934; plan → codex-debate → implement): static validation of a new
      item (sentinel present, fill origins, cookie scope, attempt group), a budgeted
      promotion test (`pending` → `usable`), and a removal path (`broker-add.py` remove or
      documented) that also prunes agent-login state
  - [x] Plan `PLAN_ws3-onboarding.md`, Codex (gpt-5.6-sol) converged in round 2 (17
        objections, all accepted; two parts of O6 rejected with evidence). Built 2026-10-12
        in a worktree; 3 security review rounds (blocker: digest drift across broker
        releases → vault-authored `config_canon` + `config_v`); committed locally c6730b4,
        not yet released: `broker/onboarding.py` + `storage_rules.py` +
        vendored PSL, `-V -i`, the `-p` transaction + budget + `-E`, config digest,
        `-D` two phases + the broker's `forget` op, logout storage clear, README section.
  - [ ] Release: broker install (storage-key rule + `forget`), then `-V -r` (no `bad
        agent_storage_keys` → else roll back), docker / docker-hub removal, one `-p` canary.
  - [ ] mydotfiles: broker-add dry-run review section + `-D` (spec in the WS3 plan).
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
- An invisible, self-submitting reCAPTCHA is not a human challenge. The failure screenshot
  can show the page AFTER the culprit; read the broker profile's visit history instead.
- Same cookie scope + different accounts = silent overwrite, with every sibling still ✅.
  A logged-in proof must prove WHICH account (WS5).
- Before calling a ❌ an expiry, check the cookies' creation dates against the transcripts.
  Our own tests can wipe a live session, and raw-CDP cookie deletes leave no journal trace.
- An SPA in a hidden headless background tab never renders its logged-in marker. Probe
  tabs need their own window (07cf209).
- A Homebrew upgrade of `node`/`python3` breaks the Touch ID helper (vault-touchid pins
  their digests): `bw status (pinned CLI) failed` until `tools/vault-touchid/build.sh`
  runs (2026-10-11 brew → python 3.15 / node 26.11.1). The 3.15 user site also starts
  empty. WS1b: rebuild vault-touchid and re-sync user-site packages automatically after
  brew upgrades (brew-maintenance hook or mac_bootstrap), with an alert on failure.
  Touch ID also refuses (-25308) when nobody is at the unlocked Mac.
- Apps that rotate their token on every API call (Navidrome) break an exact-value
  read-back after load. Prove the write at document start; afterwards only require
  presence.
- Vault items that are not password logins (SSO-only, account-number-only) need an explicit
  mode, or the API route. The broker's "no password → permission" hint was wrong.
- Playwright `page.goto` returns None for a same-document (hash-only) navigation. Strict
  proofs must load the check page fresh (about:blank first), never as an SPA route change.
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
