# PLAN — login broker: agents use Albert's site logins without ever seeing the credentials

## Session

Resume: `c --resume c3d7e4e6-c54d-42eb-8b30-c40a70341a4f`

## Goal

An agent (Claude Code, Codex, scripts) running as uid 501 (`albert`) can get a **logged-in
session** for a site Albert has whitelisted, **without Albert being present and without the
agent ever being able to read the password or the 2FA (TOTP) secret**.

`browser.py login ricardo` → the shared Chromium is logged into ricardo.ch a few seconds
later. No terminal prompt, no Touch ID, no human.

## Decisions (Albert, 2026-10-01)

| #  | Decision                                                                                       |
| :- | :--------------------------------------------------------------------------------------------- |
| D1 | **Handoff = session cookies.** The broker logs in inside its own browser and returns only that site's cookies; the client injects them into the shared Chromium. The agent holds a session (bounded, revocable), never the password/TOTP. |
| D2 | **Always automatic.** No per-login approval. Oversight = audit log only.                       |
| D3 | **Credentials come from Bitwarden (self-hosted Vaultwarden), pulled by the broker itself** with its own account. No 1Password anywhere. |
| D4 | **Lives in this repo** (browser-login); deployed root-owned.                                   |
| D5 | **CSCS agent login comes back** through the broker (reverses the tp#97 credential-plane rule "`browser.py login cscs` stays human-only" — see "Relation to tp#97"). |

### D3 refinement: Vaultwarden has no Secrets-Manager "service account"

`bw status` → `https://vaultwarden.dom42.space`. Vaultwarden does not implement the Bitwarden
Secrets Manager API (no machine accounts). Equivalent that Vaultwarden does support:

- A **dedicated Vaultwarden user** for the broker (e.g. `albert.glensk+loginbroker@gmail.com`),
  invited by Albert (`SIGNUPS_ALLOWED=false`, `INVITATIONS_ALLOWED=true` on the server).
- An **organization collection `agent-logins`**; the broker user is a member with read-only
  access to that collection only.
- **Whitelisting a site = putting its login item into `agent-logins`.** Removing it revokes
  the agent's ability to obtain new sessions. Albert manages the allowlist in the normal
  Bitwarden UI — no Mac-side config, no sudo.
- The item supplies username, password, TOTP secret (Vaultwarden serves TOTP for free) and
  its **URIs = the exact origins the broker may type secrets into**. A custom field
  `agent_site` gives the short site id (`ricardo`, `cscs`); default = item name slug.
- Broker bootstrap: that user's API key (`client_id`/`client_secret`) + master password, in a
  file only the broker uid can read. One console action (remove from org / deauthorize
  sessions / change password) revokes it.

## Architecture

```
 agent (uid 501)                         _loginbroker (role account, uid ~ 2xx)
 ───────────────                         ─────────────────────────────────────
 browser.py login ricardo
   │  {"op":"login","site":"ricardo"}
   ├──────────── unix socket ───────────▶ login-broker daemon (LaunchDaemon, root-owned code)
   │             /var/run/login-broker/     ├─ peer uid check (LOCAL_PEERCRED == 501)
   │                                        ├─ rate limiter (persisted)
   │                                        ├─ bw CLI (own data dir) → Vaultwarden item
   │                                        │     agent-logins/<site>: user, pw, totp, URIs
   │                                        ├─ own headless Chromium, own profile per site,
   │                                        │     sandbox ON, CDP over pipe only
   │                                        ├─ recipe: exact-origin check before every fill
   │                                        ├─ verify logged_in sentinel
   │  ◀──── cookies for the item's domains ─┘ └─ audit log (no secrets)
   ▼
 CDP Storage.setCookies → shared Chromium (127.0.0.1:9222) → logged in
```

### Why the agent cannot get the credentials

| Path the agent could try                         | Blocked by                                                                 |
| :----------------------------------------------- | :------------------------------------------------------------------------- |
| Read the bootstrap / bw data / broker profiles   | `/var/db/login-broker` owned `_loginbroker` 0700                           |
| Attach a debugger / read broker memory           | different uid; macOS denies `task_for_pid` across users without root       |
| Attach to the broker's Chromium over CDP         | pipe transport only, no TCP debug port (test asserts on live argv)         |
| Edit the broker code or a site recipe            | code + venv + Playwright browsers root-owned under `/usr/local/libexec/login-broker`; updates need Albert's sudo |
| Ask the broker to type the password on a page the agent controls | site id only — origins come from the Vaultwarden item URIs, exact host match + HTTPS, re-checked right before every fill and submit; foreign form actions rejected |
| Read the agent's own Vaultwarden access          | Albert's `bw` is locked; the broker's account sees only `agent-logins`     |
| Request cookies for another domain               | cookie export filtered to the item's registrable domains                   |

### Accepted residuals (stated, not solved)

- **The session itself is power.** While cookies are valid the agent can do anything Albert
  can on that site that does not re-ask for the password (D1). Mitigation: allowlist only
  what an agent needs; audit log; cookies expire.
- **Albert's admin account.** An agent running as albert can wait for Albert to type his
  sudo/login password into something it controls (keylogger LaunchAgent). Same residual
  as tp#97's threat model.
- **Captcha / "new device" e-mail codes.** Some logins will occasionally need a human. The
  broker returns `needs_human: <reason>` and sends one ntfy push; it never loops.
- **Recipe updates need sudo** (a recipe decides where secrets are typed, so it must not be
  agent-writable). The generic recipe (username + password + optional TOTP on the item's
  exact origin) covers most sites, so adding a *site* is a Bitwarden action, not a sudo one.

## Relation to tp#97 (credential plane)

`tp/plans/PLAN_credential-plane.md` 4.3 specifies a separate-uid **CSCS minter** that keeps
the derived token inside its own boundary and serves named operations. This broker is the
same building block (separate uid, hardened Chromium, exact-origin fill, persistent limiter)
generalised to N sites, with **D1/D5 deliberately weaker**: the agent receives the session.
Record this in the credplane plan as Albert's decision of 2026-10-01; 4.3's minter becomes
"login broker + CSCS recipe"; 4.4's removal of shared-browser refresh is superseded for CSCS.

## Steps

### Phase 0 — prove the platform (no secrets)

- [ ] 0.1 `install/install.sh` (run once with sudo): create role account `_loginbroker`
      (`sysadminctl -addUser _loginbroker -roleAccount`), dirs `/usr/local/libexec/login-broker`
      (root 0755), `/var/db/login-broker` (`_loginbroker` 0700), `/var/run/login-broker`
      (root:`_loginbroker` 0755), log `/var/log/login-broker.log`; copy code, build a uv venv,
      install pinned Playwright Chromium into `PLAYWRIGHT_BROWSERS_PATH` under libexec;
      LaunchDaemon `com.albert.login-broker` with `UserName=_loginbroker`. Idempotent;
      `-U` uninstalls. Must be shellcheck-clean.
- [ ] 0.2 Daemon skeleton: socket, `LOCAL_PEERCRED` peer-uid check, JSON protocol
      (`ping`, `sites`, `login`, `logout`), audit log.
- [ ] 0.3 Prove headless Chromium runs as `_loginbroker` under launchd (no WindowServer):
      log into a public test page, export cookies, inject into the shared Chromium.
- [ ] 0.4 Boundary tests (run as uid 501): cannot read `/var/db/login-broker`, cannot
      attach to the broker Chromium, live argv has no `--remote-debugging-port` and no
      `--no-sandbox`, socket refuses a foreign uid (simulated via a second test user if
      available, else unit-level).

### Phase 1 — Vaultwarden

- [ ] 1.1 Albert (one time, in the Bitwarden UI): org + collection `agent-logins`, invite
      the broker user, accept the invite, generate its API key.
- [ ] 1.2 `sudo login-broker enroll-bootstrap`: reads the broker account's API key + master
      password from Albert's terminal (getpass) into `/var/db/login-broker/bootstrap`
      (0600). Agent never sees it (it is typed, not passed via argv/env/clipboard).
- [ ] 1.3 Broker-side `bw` (own `BITWARDENCLI_APPDATA_DIR`): login with API key, unlock per
      request (session key in memory only), `list items --collectionid`, `get totp`, lock.
- [ ] 1.4 `sites` op: lists site ids + allowed origins (never secrets).

### Phase 2 — login + handoff

- [ ] 2.1 Generic recipe: navigate to item's first URI, find username/password fields,
      exact-origin check before each fill and submit, TOTP step if the item has one,
      verify a logged-in sentinel, persistent per-site broker profile (fewer "new device"
      challenges).
- [ ] 2.2 Cookie export filtered to the item's registrable domains; return over the socket.
- [ ] 2.3 Client: `browser.py login SITE` asks the broker first (if socket present), injects
      cookies via CDP, re-checks `logged-in SITE`; falls back to today's assisted flow.
      `browser.py broker-sites` lists what is available.
- [ ] 2.4 Persistent rate limiter (per site: min interval, hourly cap, no retry on unknown
      outcome) + `needs_human` path with one ntfy push.

### Phase 3 — site recipes

- [ ] 3.1 Ricardo, Kleinanzeigen, geizhals, Toppreise (generic recipe; site-specific only
      where the generic one fails).
- [ ] 3.2 CSCS recipe from `daemon/cscs_login_flow.py` (SPNEGO → password → OTP) with exact
      host equality (fixes the substring checks noted in credplane 4.3), then
      `browser.py token` works again unattended.
- [ ] 3.3 Remove the uid-501 keychain credential path for every site moved to the broker
      (`store-creds`/`cscs-store-creds` print a pointer to Bitwarden instead).

### Phase 4 — close out

- [ ] 4.1 Tests: origin checker, cookie filter, peer-cred check, rate limiter, protocol
      (hermetic); attended end-to-end per site.
- [ ] 4.2 README / AGENTS.md / skill `browser-login` updated; credplane plan + tp#97 updated
      (D5); memory updated.

## Open questions

- Which sites go into `agent-logins` first (proposal: ricardo, kleinanzeigen, geizhals,
  toppreise, cscs).
