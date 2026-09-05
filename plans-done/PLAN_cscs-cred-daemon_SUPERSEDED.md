> **SUPERSEDED 2026-09-05** by
> `42-Git/home/tp/plans/PLAN_credential-plane.md` (the plan for tp#97).
>
> Why: this plan built a bespoke `credlogind` socket daemon for ONE credential. The
> successor adopts a shipped credential proxy for the ~46 brokerable credentials in tp#97,
> keeps a hand-written minter only for CSCS, and removes the non-HTTP credentials instead
> of brokering them.
>
> **Kept here on purpose**: the O13 capability-closure matrix (three-valued
> GREEN/RED/UNKNOWN gate, 403-vs-405 semantics, greedy-glob closure, method-override
> surfaces, operation equivalence) is the documented fallback if Phase 0 of the successor
> returns NO-GO. Do not delete.

# PLAN — `credlogind`: keep login credentials out of agent reach

> Reconciled after two judged Claude↔Codex debates (round 1: 14/14 accepted, converged;
> round 2 on the build: 12/12 accepted, converged). Round 2 pivoted the architecture from
> "daemon returns a token" to **a broker that never hands the token out**, and cut
> biopolwifi from v1.

## Session

Resume: `c --resume 5c9dba96-a144-4335-bef3-45a9f7e792ff`
Ticket: tp#144 (priority high)

## Goal

No process running as uid 501 (`albert`) can read a stored login credential, and no agent
can obtain more authority at CSCS than the specific operations `cscs-api.py` needs.

## Why (measured, 2026-09-04)

`browser.py` stores the CSCS username/password/TOTP seed in the login keychain with
`-T /usr/bin/security`: silent access for anything running as albert, verified this session
(a keychain lookup with the secret-printing flag returns 40 bytes, no prompt). `login-log`
shows that path in use since 2026-07-05, so **every agent session since then could have read
them**. The pair is the whole CSCS account — portal *and* `sshservice.cscs.ch` certificate
signing.

## Threat model

- **In scope**: arbitrary code running as uid 501 with a full shell and network.
- **Out of scope**: Albert typing his password at a real sudo prompt; CSCS-side compromise.
- **Accepted**: an agent may invoke bounded, named operations against CSCS.
- **Unfixable residual**: an agent running as albert can install a user LaunchAgent that
  keylogs or screen-records and capture a sudo password later. Recorded, not solved.

## Settled by evidence (do not re-litigate without new measurements)

| Question | Finding | Date |
| :--- | :--- | :--- |
| Waldur PAT instead of a daemon? | **No** — `POST /api/personal-access-tokens/` → `400 "You are not allowed to create personal access tokens."` Account lacks the permission; request drafted for CSCS, who are historically unresponsive | 2026-09-04 |
| CSCS service account instead? | **No, on merit** — real endpoints are `marketplace-{project,customer}-service-accounts`; a service account is an HPC credential (API key → JWT → signed SSH cert), so minting one puts a durable SSH-capable secret where an agent can read it | 2026-09-04 |
| Browserless Keycloak flow? | **No** — SPNEGO → password → OTP all accepted, then the callback returns `{"detail":"keycloak error: Invalid auth state."}`. The portal validates a `state` its SPA registers server-side: not a cookie, not in the 285-endpoint API root, no initiation URL | 2026-09-04 |
| Is root a real boundary here? | **Yes** — `sudo -n` refused, no `pam_tid`, SIP on, `/usr/local`, `/opt`, `/Library/LaunchDaemons`, `/var/db`, `/var/run` all root-owned and not albert-writable | 2026-09-04 |
| Safe interpreter? | **Not `/usr/bin/python3`** — it resolves via `xcode-select` through `/Applications` (`drwxrwxr-x root:admin`, albert-writable) into Xcode.app → root code execution | 2026-09-04 |
| FileVault | **Off** — must be enabled before provisioning rotated secrets | 2026-09-04 |

## Architecture — a broker, not a token dispenser

`cscs-api.py` today fetches a Waldur DRF **session** token and calls the API with it. That
token is not scoped: `OPTIONS /api/marketplace-project-service-accounts/` advertises `POST`
for it, so it may be able to mint SSH-capable service accounts. Handing it to an agent grants
far more than the portal reads the tool needs.

So the daemon **keeps the token** and exposes named operations:

```
LIST_PROJECTS · LIST_USERS · LIST_PROJECT_TEAM <uuid> · LIST_INVITATIONS · INVITE_USER <project> <email> <role>
```

`INVITE_USER` is the sole mutation. Arguments are validated against the site's schema; no URL,
path or header ever crosses the socket. The token never leaves the daemon.

- **A1 — Site identity is a compile-time enum.** The verb carries a site *name* that must match
  an entry in the daemon's own registry; every URL, selector and credential key is a constant in
  root-owned code. Unknown names are rejected before any credential is read.
- **A2 — One service UID per site.** Per-site launchd worker, socket, credential store, state
  directory and browser profile. Shared root-owned code is read-only. No privileged dispatcher
  holds every secret.
- **A3 — Exact-origin checks before every secret entry.** Not substring tests: `browser.py`
  currently uses `"auth.cscs.ch" in page.url` (`bin/browser.py:3056`) and `"portal.cscs.ch" in
  url` (`:3129`), which `https://evil.example/?auth.cscs.ch` satisfies. The adapter parses the
  URL, requires HTTPS and exact host equality, revalidates immediately before every
  username/password/TOTP fill and submit, rejects foreign form actions, and blocks off-allowlist
  requests with a route interceptor.
- **A4 — Private headless Chromium, hardened and asserted.** Pinned Playwright + Chromium
  installed root-owned. Launch with `chromium_sandbox=True`; a test reads the live process argv
  and **fails** if `--no-sandbox` is present or a TCP debugging port appears (Playwright defaults
  to `--no-sandbox` and always speaks CDP over a pipe, so "no listener" is not "no CDP").
  Dedicated `HOME`/`TMPDIR`/profile/cache per worker, downloads and crash artifacts disabled,
  browser closed the moment the token is minted.
- **A5 — Filesystem split.** Code `/usr/local/libexec/credlogind/`; secrets
  `/var/db/credlogind/<site>/` in a **root-owned** directory as `root:<site-group>` `0440` (the
  worker reads, cannot rewrite — a service-user-owned `0400` file can be chmodded by that user);
  sockets `/var/run/`; a separate service-owned state directory for cache and limiter data.
- **A6 — One source of truth.** Automated login logic is **removed** from `browser.py`, not
  duplicated. The adapter lives only in the daemon package, installed from a reviewed versioned
  bundle whose digest is recorded independently of this writable checkout. No auto-update.
- **A7 — Limiter.** Hard minimum interval and hourly cap regardless of failure classification;
  state persisted across crash and reboot; only the one proven stale-auth retry; every unknown
  outcome means no automatic retry; operator reset requires root.
- **A8 — Contract.** `cscs-api.py` calls the broker directly. `browser.py login cscs` remains an
  explicitly human-only shared-browser flow. No silent redefinition of the existing markers, and
  no session injection into the shared browser in v1.
- **A9 — Eligibility.** A site qualifies only with a stored credential AND a proven consumer AND
  defined transfer semantics AND an accepted privilege ceiling. **CSCS only in v1.** biopolwifi is
  excluded: `biopol-wifi.py` already has a browserless `BiopolClient` with a 5-minute JWT, and
  `browser.py`'s biopol login extracts no token, so a private headless session transfers nothing.

## Build sequence (single ordered list — earlier versions contradicted themselves)

- [x] 1. Debate round 1 (14/14 accepted, converged)
- [x] 2. tp#144 filed (high), plan linked
- [x] 3. PAT spike — creation refused; service accounts rejected on merit
- [x] 4. D9 spike — browserless flow disproven with evidence
- [x] 5. Stdlib RFC 6238 TOTP + `verify_token()` landed with conformance tests
- [x] 6. Debate round 2 on the build (12/12 accepted, converged) — broker pivot
- [ ] 7. Measure the DRF token's authorisation ceiling; record it. Decides whether any
      token-hand-back mode may ever exist
- [ ] 8. `credlogind` package: CSCS adapter (A3/A4), broker operations, socket server with
      `getpeereid()`, limiter (A7), structured logging that cannot emit a secret
- [ ] 9. launchd plist, per-site UID/group creation, `/var/db` + `/var/run` layout (A2/A5)
- [ ] 10. Reviewed bundle + root-owned provisioning tool with the runtime-closure audit (A6)
- [ ] 11. `cscs-api.py` refactored onto the broker; automated login removed from `browser.py` (A6/A8)
- [ ] 12. Acceptance suite — every row below with fixture, command and required result
- [ ] 13. Build and test on **synthetic** credentials only
- [ ] 14. Enable FileVault, reboot
- [ ] 15. Rotate the CSCS password and TOTP seed from a trusted environment, agents stopped
- [ ] 16. Provision through the verified root-owned tool
- [ ] 17. Remove the keychain copies and every automated fallback; verify absence
- [ ] 18. Production verification, including the real 401 refresh path
- [ ] 19. README + repo_scope updates; `_DONE` rename + `plans-done/` archive

## Acceptance suite (step 12 — each needs fixture, command, required result)

| # | Check | Required result |
| :- | :--- | :--- |
| 1 | Read `/var/db/credlogind/cscs/*` as albert | Permission denied |
| 2 | Keychain lookup of the CSCS items after step 17 | item not found |
| 3 | Overwrite the installed adapter / plist as albert | Permission denied |
| 4 | `lldb -p <worker pid>` as albert | denied |
| 5 | Live Chromium argv | no `--no-sandbox`, no TCP debug port |
| 6 | Adapter navigated to `https://evil.example/?auth.cscs.ch` | refuses before any fill |
| 7 | `LIST_PROJECTS https://evil/` and unknown site name | `FAIL bad-request`, no credential read |
| 8 | Burst + sequential floods | hard cap trips; account never locked |
| 9 | Limiter state after kill -9 and after reboot | preserved |
| 10 | Per-site UID isolation | worker cannot read another site's store |
| 11 | Oversized / partial / stalled socket requests | bounded, closed, no hang |
| 12 | Crash artifacts and unified log | no secret-bearing content |
| 13 | Runtime closure audit (python, node driver, Chromium helpers, dylibs, config) | nothing uid-501-writable |
| 14 | `cscs-api.py` full 401 refresh path against the broker | works unattended |

Secrets are never passed on a command line (argv and shell history are a disclosure path);
tests use synthetic canaries, and production is verified only by absence, ownership and
behaviour.
