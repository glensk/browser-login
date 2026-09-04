# PLAN — take the CSCS password + TOTP seed out of agent reach

> Reconciled after a judged Claude↔Codex debate (round 1, `converged: true`, 14/14
> objections accepted). The original "root launchd daemon" plan survives only as Phase 2B:
> Codex's first objection — investigate supported automation credentials before building a
> personal-credential oracle — was confirmed by live probing and demotes the daemon to a
> fallback.

## Session

Resume: `c --resume 5c9dba96-a144-4335-bef3-45a9f7e792ff`
Ticket: tp#144 (priority high)

## Goal

No process running as uid 501 (`albert`) — Claude Code, its subagents, any script — can
read the CSCS password or TOTP seed. `cscs-api.py` keeps working unattended, with no
Touch ID. An agent obtaining a *bounded* API credential is acceptable; an agent obtaining
the *account* is not.

## Why (measured, 2026-09-04)

`browser.py` stores the CSCS username/password/TOTP seed in the login keychain with
`-T /usr/bin/security` — silent access for anything running as albert. Verified this
session: a keychain lookup of the seed with its secret-printing flag returns 40 bytes with
no prompt. Those two values are the whole CSCS account, `sshservice.cscs.ch` SSH-certificate
signing included — not merely portal access. `browser.py login-log cscs` shows the keychain
path has been in use since 2026-07-05, so **every agent session since then could have read
them**.

## Threat model

- **In scope**: arbitrary code running as uid 501 with a full shell and network.
- **Out of scope**: Albert typing his password at a real sudo prompt; CSCS-side compromise.
- **Accepted**: an agent may hold a *scoped, expiring, revocable* API credential.
- **Unfixable residual**: an agent running as albert can install a user LaunchAgent that
  keylogs or screen-records and capture a sudo password later. No design here closes that;
  it is the general "an agent with your uid is you" limit. Recorded, not solved.

## Verified environment facts (2026-09-04, this Mac)

| Fact                                    | Value                                          | Consequence                                        |
| :-------------------------------------- | :--------------------------------------------- | :------------------------------------------------- |
| `sudo -n true`                          | `a password is required`                       | root is a real boundary                            |
| `pam_tid` for sudo                      | absent (only `sudo_local.template`)            | no biometric path to root                          |
| SIP                                     | enabled                                        | but see the interpreter row                        |
| `id albert`                             | includes `80(admin)`                           | admin is not root here, but see `/Applications`    |
| `/usr/local`, `/opt`, `/Library/LaunchDaemons`, `/Library`, `/Library/Developer` | `root:wheel`, not writable | safe install targets                 |
| **`/Applications`**                     | **`drwxrwxr-x root:admin` — albert-writable**  | **`/usr/bin/python3` is NOT safe (see D3)**        |
| `/usr/bin/python3`                      | shim to `/Applications/Xcode.app/…/python3` 3.9 | outside SIP, reachable via an admin-writable dir   |
| `/var/root`                             | `drwxr-x--- root:wheel`                        | unreadable as albert                               |
| FileVault                               | **Off**                                        | enable before provisioning rotated secrets         |

## Live API discovery (2026-09-04, read-only probes against portal.cscs.ch)

| Probe                                          | Result                                                               |
| :--------------------------------------------- | :------------------------------------------------------------------- |
| `GET /api/personal-access-tokens/`             | **200** `[]` — PATs supported, none exist yet                        |
| `OPTIONS /api/personal-access-tokens/` (POST)  | accepts `name`, `scopes`, **`allowed_networks`**, **`expires_at`**   |
| `GET /api/personal-access-tokens/available_scopes/` | 20 scopes                                                       |
| `GET /api/service-accounts/`                   | 404 — not at this API root                                           |
| `GET /api/auth-tokens/`                        | 403                                                                  |

Scope coverage for what `cscs-api.py` actually does:

| Operation                        | Scope                                          | Covered |
| :------------------------------- | :--------------------------------------------- | :------ |
| `-l projects`                    | `PROJECT.LIST`                                 | yes     |
| `-lu` (all users)                | `CUSTOMER.LIST_USERS`, `SERVICE_PROVIDER.LIST_USERS` | yes |
| `--list-users PROJECT` (team)    | `SERVICE_PROVIDER.LIST_PROJECT_PERMISSIONS`    | yes     |
| `--user-projects EMAIL`          | the above combined                             | yes     |
| `-a/--add-user` (email invite)   | only `INVITATION.LIST` exists, no create scope | **open** — `PROJECT.CREATE_PERMISSION` may substitute |

**No available scope can mint service accounts, sign SSH certificates, or change the
account password.** That is what bounds the credential an agent may hold.

## Phases

### Phase 0 — PAT go/no-go spike — **RUN 2026-09-04, RESULT: BLOCKED**

Authorised by Albert and executed: `POST /api/personal-access-tokens/` with the nine read
scopes, `allowed_networks` = egress `/32`, `expires_at` = +24 h.

```
HTTP 400  {"non_field_errors":["You are not allowed to create personal access tokens."]}
```

The account can *list* PATs (`GET` → 200 `[]`) but not create them — the `200 []` was not
sufficient evidence, which is why the spike was worth running. No PAT was created and none
exists (`GET` still returns `[]`).

Service accounts were checked as the alternative and **rejected on merit, not availability**.
The real endpoints are `marketplace-project-service-accounts` / `-customer-` (not
`/api/service-accounts/`, which 404s) and their `OPTIONS` advertises `POST`. But a CSCS
service account is an HPC access credential — API key → JWT → **signed SSH certificate** —
scoped to one project. Minting one would create a *durable SSH-capable* credential sitting
where an agent can read it: strictly worse for this threat model than the 1-hour portal
token, and it would not grant the cross-project portal reads `cscs-api.py` needs. Not created.

**Consequence**: Phase 2A is blocked pending CSCS enabling PAT creation for `aglensk`.
The decision returns to Albert — request that from CSCS, build Phase 2B, or both in parallel.

### Phase 1 — Rotation (mandatory whatever Phase 0 decides; needs Albert) — **now due**

Albert chose to defer rotation until the spike proved out. The spike is done and blocked,
so this is the next thing owed regardless of which design lands.

The password and TOTP seed have been agent-readable since 2026-07-05 and must be treated as
compromised. Rotate both at CSCS **with all agents stopped**, from a terminal no agent is
attached to. Deletion is not remediation. Enable FileVault **before** provisioning any new
secret store.

### Phase 2A — PAT-backed `cscs-api.py` (preferred; no daemon at all)

- [ ] `cscs-api.py` accepts a PAT (env `CSCS_PAT` or its own 0600 cache) and prefers it over the 1-hour DRF token
- [ ] On PAT expiry: a clear, actionable error telling Albert to mint a new one — no silent fallback to a credentialled login
- [ ] Delete the keychain username/password/seed items; remove `cscs-store-creds` and the keychain path from `browser.py` for CSCS
- [ ] The shared-browser CSCS login becomes human-only (1Password + Touch ID), never agent-triggerable with stored secrets
- [ ] Document the mint/rotate procedure; calendar the PAT expiry

### Phase 2B — Root-boundary login daemon (only if Phase 0 fails)

Redesigned per the debate:

- **D1** credentials never touch the CDP browser on port 9222 — the agent can read the form field
- **D2** the daemon takes no parameters; every endpoint is a compile-time constant
- **D3** **not** `/usr/bin/python3`: it resolves through `/Applications` (albert-writable) into
  Xcode.app, so an agent could substitute the bundle and get **root code execution**. The
  runtime must be pinned wholly inside a root-only-writable chain (`/usr/local/libexec/…`,
  audited `/` to `/usr` to `/usr/local` to `/usr/local/libexec`, all `root:wheel`), invoked
  with `-I -B`, or the daemon written as a compiled binary
- **D4** runs as a dedicated non-login `_cscslogin` user, **not root** — root is the boundary,
  not the runtime; a TLS client and HTML parser running as root turns any flaw into full compromise
- **D5** creds in a `_cscslogin`-owned `0400` file inside a root-owned directory; not the
  System keychain (its unlock material sits on the same machine). Apple Silicon storage is
  hardware-encrypted regardless of FileVault; FileVault's real contribution is binding volume
  access to user credentials
- **D6** returns `OK <token>` over the socket after a `getpeereid()` peer-uid check — no token
  file (`root:staff 0640` would widen exposure and invent atomicity/staleness work), and no
  fabricated expiry (a 40-hex DRF token encodes none)
- **D7** socket activation needs `launch_activate_socket` (no Python stdlib wrapper) and
  `SockPathMode` as decimal `384`; **decision: avoid it** — a `KeepAlive` daemon binding its
  own socket is more auditable
- **D8** limiter: coalesce concurrent callers into one in-flight login, serve a still-valid
  cached token without authenticating, persist atomically, trip an operator-resettable lock on
  the first definite credential rejection, return a uniform failure with secret-free logs
- **D9 — SETTLED 2026-09-04: the browserless flow does NOT work; use a private headless
  browser owned by the service account.** The prototype (`daemon/cscs_login_flow.py`, since
  trimmed) drove the whole HTTP flow: Kerberos-SPNEGO auto-submit → username/password →
  OTP, **all three accepted** by Keycloak, reaching the portal's OIDC callback, which answers

  ```
  {"detail":"keycloak error: Invalid auth state."}
  ```

  The portal validates a `state` its SPA registers server-side. That registration is not a
  cookie (six candidate names tested, portal sets no cookies on a plain visit), is not among
  the 285 endpoints in the API root, and has no server-side initiation URL
  (`/api-auth/keycloak/{login,start,begin,authorize}/`, `/api-auth/login/keycloak/` all 404;
  `/api-auth/keycloak/complete/` is GET-only "O Auth View Complete"). Driving it would mean
  reverse-engineering an undocumented, changeable mechanism — the brittleness Codex's O7
  warned about. Its sanctioned fallback applies: a headless browser owned by `_cscslogin`,
  launched with **no `--remote-debugging-port`**, so no agent can attach and read the
  password field. **Cost, accepted knowingly**: Playwright + Chromium become third-party code
  in a privileged runtime, pinned and installed root-owned under `/usr/local/libexec/`.
  What survives from the prototype is what the daemon still needs — the stdlib TOTP generator
  (RFC 6238 vectors in `tests/test_cscs_totp.py`) and `verify_token()`, the post-condition
  that the daemon never returns a token it has not seen work
- **D10** install ceremony: agents stopped, separate trusted terminal, audited artifact staged
  root-owned first, install from there, then `sudo -K` and assert `sudo -n true` still fails —
  `sudo ./install.sh` from this agent-writable checkout is itself an escalation
- **D11** a distinct command for daemon-backed refresh; `cscs-api.py` parses `browser.py`'s exact
  warm/cold markers and `needs_login` exit code (`cscs-api.py:597`), so the meaning of
  `cscs-login` / `logged-in cscs` must not silently change

### Phase 3 — Verification (all must fail closed, run as albert, no sudo)

Read the creds file · keychain lookup of the CSCS items · overwrite the daemon program ·
edit the plist · `lldb -p <pid>` · parameterised `LOGIN` · burst requests · inherited
descriptors · peer credentials · dependency-path writability · malicious redirect/form
action · proxy and CA injection · oversized/partial/stalled requests · concurrency · crash
and core artifacts · unified-log visibility · stale socket · reboot · update/rollback ·
rotation · the real 401-retry path in `cscs-api.py`.

**Never grep for the real secret** — argv and shell history are themselves a disclosure path.
Use synthetic canaries in an isolated test install; verify production only by absence,
ownership and behaviour.

## Steps

- [x] 1. Debate the plan with Codex; reconcile (round 1, converged, 14/14 accepted)
- [x] 2. File tp#144 (high) and link this plan
- [x] 3. Read-only API discovery — PAT endpoint, POST schema, 20 available scopes
- [x] 4. Albert authorised the PAT mint; rotation deferred until the spike proved out
- [x] 5. Phase 0 spike run — **PAT creation refused by CSCS policy**; service accounts rejected on merit
- [x] 5a. Albert: PAT was never required — it was the shortcut; build Phase 2B on the current credentials
- [x] 6. D9 spike: browserless flow disproven with evidence; TOTP + token verifier landed with RFC 6238 tests
- [ ] 7. Daemon: headless browser under `_cscslogin`, socket server, limiter, install ceremony
- [ ] 8. `browser.py` integration + the distinct refresh command (D11)
- [ ] 9. Phase 3 verification matrix, then rotation + FileVault
- [ ] 6. Phase 1 rotation + FileVault
- [ ] 7. Phase 2A (or 2B if the spike fails)
- [ ] 8. Phase 3 verification matrix
- [ ] 9. README + repo_scope updates; `_DONE` rename + `plans-done/` archive
