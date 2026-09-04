# PLAN — root credential daemon for CSCS login

## Session

Resume: `c --resume 5c9dba96-a144-4335-bef3-45a9f7e792ff`

## Goal

Put the CSCS password and TOTP seed out of reach of any process running as uid 501
(`albert`) — Claude Code, its subagents, any script — while keeping `cscs-api.py`
fingerprint-free and unattended. An agent may still *obtain a portal session*; it must
never be able to *read the credentials*.

## Why now (measured exposure, 2026-09-04)

`browser.py` stores its keychain items with `-T /usr/bin/security`, i.e. silent access for
any process running as albert. Verified in this session: `security find-generic-password`
with the account/service of the TOTP seed and its secret-printing flag returns 40 bytes
with no prompt and no Touch ID.

Password + TOTP seed is not "portal access" — it is the whole CSCS account, including
`sshservice.cscs.ch` SSH-certificate signing. That is the asset worth isolating.

## Threat model

- **In scope**: arbitrary code running as uid 501 with a full shell and network access.
- **Out of scope**: Albert typing his account password at a real sudo prompt; physical
  theft of the machine (see the FileVault decision); compromise at CSCS.
- **Accepted by design**: the daemon is an *oracle*. An agent can always ask it to log in
  and will then hold a portal token. Albert has explicitly accepted this ("after it's
  logged in the agent can do whatever").
- **Unfixable residual**: an agent running as albert can install a user LaunchAgent that
  keylogs or screen-records, and could capture the sudo password the next time Albert
  types one. No daemon design closes this; it is the general "an agent with your uid is
  you" limit. Recorded, not solved.

## Verified environment facts (2026-09-04, this Mac)

| Fact                                   | Value                                    | Consequence                                     |
| :------------------------------------- | :--------------------------------------- | :---------------------------------------------- |
| `sudo -n true`                         | `sudo: a password is required`           | root is a real boundary                         |
| `pam_tid` in `/etc/pam.d/sudo*`        | absent (only `sudo_local.template`)      | no Touch-ID path to root either                 |
| SIP                                    | enabled                                  | system binaries not replaceable                 |
| `id albert`                            | includes `80(admin)`                     | admin alone is not root here                    |
| `/usr/local`, `/opt`                   | `drwxr-xr-x root:wheel`, not writable    | safe install targets                            |
| `/Library/LaunchDaemons`               | `drwxr-xr-x root:wheel`, not writable    | safe plist target                               |
| `/var/root`                            | `drwxr-x--- root:wheel`                  | unreadable as albert                            |
| `/opt/homebrew`                        | `drwxr-xr-x albert:admin`                | **must not be on the daemon's path** — root RCE |
| `/usr/bin/python3`                     | `3.9.6`, `root:wheel`, SIP-protected     | usable interpreter, stdlib only, 3.9 syntax     |
| FileVault                              | **Off**                                  | drives the storage decision (D4)                |

## Design decisions

### D1 — No browser anywhere in the credential path

Credentials must never be typed into the shared Chromium on CDP port 9222: the agent
controls that browser and can read the password field's value mid-login via CDP. The
daemon performs the Keycloak flow in its own process and hands back only the result.

### D2 — The daemon takes no parameters

No target URL, no realm, no output path. Every endpoint is a compile-time constant
(`auth.cscs.ch`, `portal.cscs.ch`). A parameterised daemon lets the agent point the login
at a server it controls and harvest the password. The request protocol is a bare verb.

### D3 — Root-only runtime, stdlib only

Interpreter `/usr/bin/python3` (SIP-protected). **Zero third-party imports**: cookie
handling via `urllib.request` + `http.cookiejar`, form parsing via `html.parser`, TOTP via
a ~15-line RFC 6238 `hmac`/`base64` implementation instead of `pyotp`. This removes both
the root-owned venv and its supply chain. Code lives in `/usr/local/libexec/cscs-logind/`
(`root:wheel`, dirs 0755, files 0644, entrypoint 0755). Nothing under `/opt/homebrew`,
`~/.local`, or the repo working tree may be reachable from the daemon.
Python 3.9 constraint: `from __future__ import annotations` (same lesson as cscs-api tp#109).

### D4 — Credential storage, given FileVault is OFF

A plaintext `/var/root/cscs.creds` (0600) is root-proof but is a *regression* at rest: the
current login keychain is encrypted with Albert's login password, whereas a plaintext file
falls to an external boot or a pulled SSD. Options, to be settled in the debate:

- **(a)** System keychain (`/Library/Keychains/System.keychain`) — root-only, encrypted
  blob, but its unlock key in `/var/db/SystemKey` is also root-only-at-rest, so the same
  physical-access exposure with more moving parts.
- **(b)** `/var/root/cscs.creds`, 0600 root:wheel, plus **turn FileVault on** — simplest,
  and FileVault is the honest fix for the physical-access dimension.
- **(c)** File encrypted with an `age` key that itself lives in `/var/root` — theatre; the
  key sits next to the ciphertext.

Leaning **(b) + FileVault on**, and saying so plainly rather than pretending (a) solves
physical access.

### D5 — Trigger: launchd on-demand socket, no sudo

`/Library/LaunchDaemons/ch.cscs.logind.plist` with a `Sockets` entry at
`/var/run/cscs-login.sock`, `SockPathOwner` 501 / `SockPathMode` 0600, `RunAtLoad false`.
Connecting wakes the daemon **as root**; the caller needs no sudo. Protocol: client sends
`LOGIN\n`, daemon replies `OK <expires-in-seconds>\n` or `FAIL <machine-readable-reason>\n`.

### D6 — Rate limit and lockout protection

A hostile or looping agent must not be able to hammer Keycloak into locking the account.
Cap: one real login attempt per 60 s, max 10 per hour, tracked in a root-only state file;
over the cap the daemon replies `FAIL rate-limited` without touching CSCS. Consecutive
Keycloak auth failures (as opposed to transient errors) trip a longer cooldown.

### D7 — Token hand-off without a symlink hazard

The daemon must **not** write into `~/.cache/cscs-api/` — that directory is agent-writable,
so a symlink planted there would have root clobber an arbitrary path. Instead the daemon
writes `/var/run/cscs-login/portal_token` (dir `root:wheel` 0755, file `root:staff` 0640);
`cscs-api.py` and `browser.py` read it and copy it into their own cache. The token itself is
not a secret we are hiding from the agent — portal access is granted by design.

### D8 — Retire the user-side credential copies

The daemon is pointless while the same secrets stay readable in the login keychain. The
landing sequence ends with `browser.py cscs-forget-creds` and a verification that a
keychain lookup for the CSCS items reports *item not found*. The remaining fallback is the
1Password item behind Touch ID (interactive, and Albert-approved per use) — acceptable,
because it is not silently readable.

### D9 — Home for the code

`browser-login` already owns CSCS credential storage and login (`cscs-store-creds`,
`cscs-login`, the keychain helpers), so the daemon lands here under `daemon/`, with
`browser.py cscs-login` gaining a "daemon first, then fall back" path. Alternative
considered: a separate repo — rejected as splitting one concern across two.

## Steps

- [ ] 1. Debate this plan with Codex (`codex-debate`, mode=plan); reconcile through the judged loop
- [ ] 2. File the tp ticket (priority high) and link this plan
- [ ] 3. Settle D4 (storage) and D3 (stdlib-only vs root venv) from the debate outcome
- [ ] 4. `daemon/cscs_logind.py` — stdlib-only Keycloak flow: username/password page → OTP page → portal OIDC callback → extract the 40-hex Waldur DRF token
- [ ] 5. `daemon/cscs_logind.py` — socket server, `LOGIN` verb, rate limit (D6), token write (D7), structured logging that never logs a secret
- [ ] 6. `daemon/ch.cscs.logind.plist` — launchd socket-activated daemon spec
- [ ] 7. `daemon/install.sh` — one-time `sudo` install: copy files root-owned, import creds from the existing keychain, write the store per D4, `launchctl bootstrap system`; plus `uninstall.sh`
- [ ] 8. `browser.py`: `_daemon_login()` tried before the keychain path in `cmd_cscs_login`; `login-log` records mode `daemon`
- [ ] 9. Tests: TOTP vector check (RFC 6238), form-parse fixtures, rate-limiter, protocol contract, and a negative test asserting the daemon rejects any argument
- [ ] 10. Adversarial verification as albert (see below) — every item must fail closed
- [ ] 11. `browser.py cscs-forget-creds`, confirm the keychain items are gone, confirm `cscs-api.py -l` still works unattended
- [ ] 12. Turn FileVault on (if D4 lands on (b)); README + repo_scope updates; `_DONE` rename + `plans-done/` archive

## Adversarial verification (step 10 — all must fail)

Run as `albert`, no sudo:

| Attack                                                        | Required result       |
| :------------------------------------------------------------ | :-------------------- |
| read `/var/root/cscs.creds`                                    | Permission denied     |
| keychain lookup of the CSCS username/password/seed items       | item not found        |
| overwrite `/usr/local/libexec/cscs-logind/cscs_logind.py`      | Permission denied     |
| edit `/Library/LaunchDaemons/ch.cscs.logind.plist`             | Permission denied     |
| `lldb -p <daemon pid>` / read its memory                       | denied (not root)     |
| send `LOGIN https://evil.example/` on the socket               | `FAIL bad-request`    |
| 50 rapid `LOGIN` requests                                      | `FAIL rate-limited`   |
| grep the daemon log for the password or the seed               | no match              |

## Open questions for the Codex debate

1. D4: System keychain vs `/var/root` file + FileVault — which is honestly better here?
2. D3: is a stdlib-only Keycloak client too brittle against theme/flow changes, and is a
   root-owned Playwright worth its supply-chain surface as the alternative?
3. Is socket activation with `SockPathMode` 0600 the right trigger, or is there a macOS
   idiom (XPC, `SMAppService`) with a better authorisation story for a non-GUI tool?
4. Any escalation path missed — launchd env inheritance, `PATH`/`PYTHONPATH` injection,
   `DYLD_*`, core dumps, `sudo` timestamp reuse, Time Machine copies of `/var/root`?
5. Does the daemon-as-oracle design leak anything beyond the portal token (e.g. can a
   caller distinguish "wrong password" from "rate-limited" in a way that helps an attacker)?
