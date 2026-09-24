# browser-login

> One persistent, **logged-in** Chromium that your CLI tools and AI agents share —
> plus a small framework that logs you into sites **once** and keeps you logged in.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-%E2%89%A53.10-blue.svg)
![Platform](https://img.shields.io/badge/platform-macOS-lightgrey.svg)

`browser.py` launches a single Chromium with a dedicated profile and remote
debugging (Chrome DevTools Protocol, CDP) on a fixed port. You authenticate **once**;
the session persists in the profile across restarts. Anything that speaks CDP —
Playwright, an MCP server, this script's own subcommands — then attaches to that
same logged-in browser. No tool re-implements authentication.

It is the shared **login provider** that other repos depend on instead of each
shipping its own brittle auth flow.

---

## Why

- **Log in once, reuse everywhere.** A persistent profile means one SSO/2FA dance,
  then every consumer (an AI agent's browser tools, a billing scraper, a token
  refresher) rides the same session.
- **Two clients, one browser.** Playwright MCP (native browser tools for an agent)
  and `browser.py`'s shell subcommands both attach over CDP to the *same* Chromium.
- **Credentials never get re-typed or embedded.** Secrets live in the macOS
  keychain (or 1Password); this repo holds **none**. Magic-link tokens are handled
  in memory only.

## Requirements

| Tool                    | For                                              | Required? |
| :---------------------- | :----------------------------------------------- | :-------- |
| macOS                   | uses the `security` keychain binary; profile paths | yes (today) |
| Python ≥ 3.10 + `uv`    | runtime (`uv` auto-creates the venv on first run) | yes       |
| Playwright + Chromium   | the browser itself (`playwright install chromium`) | yes       |
| `himalaya`              | full-auto claude.ai magic-link login (reads the email) | optional |
| `op` (1Password CLI)    | CSCS credential fallback before the keychain is set up | optional |

`playwright`, `pyotp`, and `requests` are declared in `pyproject.toml`. You don't
have to install them yourself: on first run `browser.py` **self-bootstraps** an
isolated venv at `~/.cache/claude-browser/venv` via `uv` and re-execs into it.

## Install

```commands
git clone https://github.com/glensk/browser-login.git
cd browser-login

# put browser.py on your PATH (pick one):
export PATH="$PWD/bin:$PATH"        # add to ~/.zshrc to make it permanent
#   …or symlink:  ln -s "$PWD/bin/browser.py" ~/.local/bin/browser.py

# one-time: fetch the Chromium build Playwright drives
uv run playwright install chromium   # (first `browser.py up` will prompt if missing)
```

That's it — `browser.py` creates its own venv on first use.

## Quick start

```commands
browser.py up                 # launch the shared Chromium (idempotent, BACKGROUND, clean tab)
browser.py up --headless      # opt-in windowless mode (same profile — see the headless note!)
browser.py status             # CDP health, version, open tabs (origins only; -f full URLs) + the lifecycle record
browser.py switch headless    # transactional mode switch (stop + relaunch, logins persist)
browser.py clients            # who is attached over CDP (registered + unknown clients)
browser.py doctor             # full health check on a disposable tab (never touches real tabs)
browser.py open https://…     # navigate a tab (opens in the BACKGROUND — no focus steal)
browser.py open -r https://…  # --reuse: navigate an existing same-URL tab (no duplicate tabs;
                              #   matches sans query/fragment, oldest first = eval's pick)
browser.py eval 'document.title' [--url SUBSTR]   # run JS in the active/matched tab → JSON
                              #   --url with no matching tab exits 1 (it never falls back to
                              #   another tab; the error names the open tabs by origin only —
                              #   no path, query or fragment); zero tabs → a blank one is created
browser.py down [-f]          # quit the shared browser (graceful CDP close → validated escalation);
                              #   refuses while a registered client (MCP server) stays attached —
                              #   -f/--force stops anyway; a stale record with no browser is cleared
```

`up` launches in the background (via `open -g` on macOS) so Chrome for Testing
never pops over what you're doing, and on a cold start it **wipes stale
session-restore state** so it opens ONE clean tab instead of resurrecting every
tab from last time (your logins persist — they live in Cookies/Local Storage,
not the session files). `open` likewise reuses a blank tab or creates new tabs
via CDP `Target.createTarget` with `background: true`. Only the assisted login
flows intentionally raise the window because you must act in it.

Env toggles: `CLAUDE_BROWSER_KEEP_TABS=1` keeps last session's tabs (skip the
wipe); `CLAUDE_BROWSER_FOREGROUND=1` launches in the foreground (skip `open -g`);
`CLAUDE_BROWSER_HEADLESS=1` makes `up` default to headless.
Separately, the Claude Code wrapper only auto-starts the browser when
`CLAUDE_BROWSER_AUTOSTART=1` — by default it is lazy (started on first use).

## Why you never see the window

The whole design goal is that **driving the browser never interferes with your
desktop**: no focus steal, no window raising, no z-order change. How that is
achieved (and where the sharp edges are — all measured, see
`PLAN_background-browser.md` for the evidence):

- **Background launch.** `open -g -n` opens the window *behind* everything;
  new tabs are created with `Target.createTarget {background: true}`, which
  does not raise the window.
- **Occlusion freezes rendering.** When the window is fully occluded, macOS
  pauses rendering: `requestAnimationFrame` stops, and every Playwright click
  times out on its "element is stable" wait (needs 2 rAF frames). The
  `--disable-backgrounding-*` launch flags alone did NOT prevent this.
- **`bring_to_front` unfreezes rendering but is NOT free.** On Chrome for
  Testing 151 the tab-level CDP `Page.bringToFront` can raise the window to
  the top of the z-order and even make Chrome the frontmost app (focus
  steal) — it depends on macOS cooperative-activation state, so it
  sometimes looks harmless. Treat it as an **escalation of last resort**:
  probe rAF first, call `bring_to_front` only when rendering is actually
  frozen (this is exactly what `browser.py doctor` does).
- **Headless would solve all of this — but is a NO-GO for the admin sites.**
  `--headless=new` advertises `HeadlessChrome` in the User-Agent and
  Cloudflare hard-challenges it: claude.ai and chatgpt.com never load
  ("Just a moment…" forever). CSCS/Slack/Cloudpath logins, screenshots,
  downloads and evals all work headless. Hence headless stays **opt-in**
  (`up -H`, `switch headless`) for non-Cloudflare work only.
- **A hidden window is not an option either.** `open -g -j` is undone by
  Chrome at window creation, and both `Target.createTarget` and
  `Page.bringToFront` un-hide a manually hidden (Cmd+H) app.

`status` prints the **lifecycle record** (`~/.cache/claude-browser/
.browser-lifecycle.json`): state (`starting|running|stopping|switching`),
mode, validated pid. Signals are only ever sent to a pid that still matches
the record (start time + command line + executable) — never a bare number
from a pid file. Its tab lines show **origins only** and fail-closed titles
(a title that is just the URL, a blank, a non-string or a multiline one renders
as `(untitled)`), because `status` output lands in logs and LLM transcripts and
an in-flight OAuth or magic-link tab carries its code/token in the path and
query; `-f/--full-urls` is the human opt-in for raw URLs (`status -f | pbcopy`)
and is unsafe from an agent session. `doctor` certifies the whole stack: record vs live process,
attached clients, and a bounded rAF/click/screenshot probe on a disposable
`data:` tab, asserting the frontmost app and window z-order are unchanged
afterwards.

## Consumer contract (multi-client coordination)

Any number of CDP clients may READ concurrently, but the browser is shared
state — so two layers coordinate everyone (all under `~/.cache/claude-browser/`):

1. **Registration (who is attached).** Every `browser.py` command that
   connects registers itself in `clients/` (a shared flock on the registry
   gate, held for the connection's lifetime). Long-lived clients — e.g. the
   Playwright MCP server — wrap themselves in
   `browser.py register-exec -t NAME -- CMD…` so their registration lives
   exactly as long as the process. `switch`/`down` acquire the gate
   exclusively (bounded wait, refusal names the holders), and `switch`
   **fails closed** when an *unregistered* client is attached (or when it
   cannot verify — no `lsof`); `-f/--force` overrides. `down` only warns
   about unregistered clients; a registered one that does not drain makes it
   refuse, and `down -f/--force` stops after a 5 s grace without draining
   (the registered wrappers keep running, only their CDP connection drops —
   the MCP server reconnects after the next `up`). Neither `--force` overrides
   a fresh `starting`/`stopping`/`switching` record (a transition in flight).
   A lifecycle record with no browser behind it (no CDP, no root process) is
   cleared by a plain `down` without waiting for the gate.
2. **Interaction lease (who is driving).** Anything that types, clicks for a
   login, or otherwise owns the user-visible interaction takes the exclusive
   `interaction.lock` flock (owner nonce + pid start time, 10 s heartbeat,
   compare-before-release). The assisted/unattended `login` flows take it;
   read-only probes (`logged-in`, `eval`, `open`, `token`, `slack-session`)
   do not. A parent that already holds the lock and shells
   `browser.py login …` exports `CLAUDE_BROWSER_LEASE_HELD=1` so the child
   doesn't deadlock against it.

Rules for anything that drives this browser:

- **Never activate the app or raise the window.** Tab-level
  `bring_to_front` only as an escalation when rAF is frozen (see above) —
  never unconditionally, never AppleScript `activate`.
- **`force=True` clicks never on final mutating controls.** Force-fallback is
  acceptable for non-final controls only; the last click of a mutation must
  pass normal actionability.
- **Bound every screenshot and wait** (explicit timeouts) — an occluded
  window can freeze rendering and an unbounded wait hangs forever.
- **Hold the interaction lease** around interactive flows; register if you
  hold a long-lived CDP connection.

## Multi-site login

A **site** is one entry in the `SITES` registry inside `browser.py`. Generic
subcommands dispatch through it:

```commands
browser.py login SITE         # ensure logged in (automated or assisted)
browser.py logged-in SITE     # exit 0 if logged in, 2 if not (no login attempted)
browser.py login-log [SITE]   # how often a *real* login was needed (no SITE = all tools)
browser.py store-creds SITE   # save credentials in the macOS keychain (cscs-style)
browser.py forget-creds SITE  # delete them
```

Two sites also expose a **credential-print** command for their consumer (bearer creds
→ stdout only, never logged): `browser.py token` (CSCS Waldur DRF token, also cached
0600) and `browser.py slack-session` (Slack `{token,cookie,team_domain}` JSON; not
cached — xoxc rotates).

Every time a site performs a **real (cold) login** — not a warm "already logged in"
— one record is appended to `~/.cache/claude-browser/login-log/<site>.jsonl` (with a
`mode`: `assisted` = you had to act, vs `auto`/`keychain`/`sso`/… automated — `sso`
is an SSO button click that completed with no password). Read it with
`browser.py login-log` — **no arg = a live aggregate across every tool** (total real
logins, how many you had to sign in for, per-site breakdown, recent events); add a
SITE for just one. That's how you measure how often re-auth — and specifically a
manual sign-in — actually happens.

### Bundled sites

| Site                   | Login style                                                           |
| :--------------------- | :------------------------------------------------------------------- |
| `anthropic` (`claude`) | **Magic-link, fully automatic** when `ANTHROPIC_LOGIN_EMAIL` is set and `himalaya` reads that mailbox: triggers the email, extracts the `claude.ai/magic-link#<token>` URL, opens it — only if it passes the three login-CSRF guards below. Otherwise **assisted** (you finish the email login once). |
| `cscs`                 | **Keycloak, unattended.** `store-creds cscs` caches username/password/TOTP-seed in the macOS keychain (from 1Password, one last Touch ID); thereafter login runs with no fingerprint. TOTP codes are generated locally with `pyotp` only once the OTP field appears (never before the password submit), waiting for the next 30 s step when the current one has under 5 s left; the 1Password fallback likewise fetches its live code at fill time. A flow Keycloak aborts with `authentication_expired` (stale `session_code` on a login page left open for hours) is retried once from a fresh page with a newly generated code; a wrong password still fails on the first attempt. After login the token is cached (0600) and checked against `/api/me/`; a network error or an unexpected answer exits 1 with a one-line reason, never a traceback. |
| `openai` (`chatgpt`)   | **Assisted.** ChatGPT Business logs in via Google SSO + 2FA, which can't be replayed from a stored secret — you complete the SSO once in the shared window; the session persists. Logged-in sentinel: the 'Invite member' button on `chatgpt.com/admin/members`. |
| `slack`                | **Assisted.** app.slack.com logs in via email-code / SSO; you sign in once and the session persists. Logged-in sentinel: a team with an `xoxc-` token in `localConfig_v2`. `browser.py slack-session` then prints `{token,cookie,team_domain}` (xoxc + httpOnly `d` cookie via CDP) so `slack-api` can call `users.admin.setInactive` on the Pro plan — where the API token is scope-blocked. Bearer creds → stdout only, never cached. |
| `biopolwifi`           | **Keychain email+password, unattended.** SDSC Biopole WiFi units are managed via a Ruckus Cloudpath MDU portal (`cloudpath.edificom.cloud`, a plain Vue SPA). `store-creds biopolwifi` caches the portal email+password in the macOS keychain (the same items `sdsc/biopol-wifi/biopol-wifi.py` reads); login fills the form and confirms the `SDSC - Biopole` / `Properties` sentinel. No SSO, no TOTP, no token extracted. Aliases: `biopol`, `cloudpath`, `edificom`. |
| `switch`               | **SSO click, assisted fallback.** `login switch` opens `/auth/login` and clicks the single SWITCH edu-ID button — passwordless while the browser's edu-ID IdP session lives; otherwise you finish the edu-ID login once in the window. Logged-in sentinel: on `cloud.switch.ch` outside `/auth/` with NO `/auth/openid_connect_eduid_ch` sign-in form — the anonymous root renders that form with HTTP 200, so the URL alone proves nothing. `logged-in switch` probes a background tab it closes again (never focuses the window) and exits 2 when logged out OR when it cannot tell — the `infra/status` check `switch-portal-login` runs it every 30 min. No stored credential by design: edu-ID is Albert's primary federated identity. Aliases: `switch-cloud`, `cloud.switch.ch`, `scp`. |

**claude.ai magic-link guards (login CSRF).** Opening a magic link signs the
shared browser into *whatever account the link belongs to*, so auto-login opens
a link only when all three hold:

1. **Sender allow-list** — the mail's From is in `ANTHROPIC_LOGIN_MAIL_SENDERS`
   (default `mail.anthropic.com`; exact address or exact domain, no subdomain
   match). The subject is only recognition — anyone can write it. The domain is
   meaningful because `_dmarc.mail.anthropic.com` and `_dmarc.anthropic.com` are
   `p=reject`: a DMARC-honouring receiver drops a forged From. A rejected sender
   is named in the failure output.
2. **Pre-trigger baseline** — before submitting the form, the sha256 of every
   magic link already in INBOX/Archive is recorded; such a link is never opened
   (survives the INBOX→Archive server rule). If the baseline cannot be taken,
   auto-login is not attempted at all.
3. **Link names `ANTHROPIC_LOGIN_EMAIL`** — the `#<token>:<base64 email>`
   fragment must decode to that address (defense in depth: whether Anthropic's
   server binds the token to that email is unverified).

Any refusal falls back to assisted login; if auto-login never submitted the
form (bad allow-list, no baseline), the assisted path submits it. Residual
risk: a receiver that ignores DMARC combined with a forged fragment email that
the server does not bind; and a mail landing between the baseline snapshot and
the form submission (guards 1 and 3 still apply to it).

CSCS back-compat aliases (`token`, `cscs-login`, `cscs-store-creds`,
`cscs-forget-creds`) are kept because downstream tools depend on their exact stdout
markers and exit codes.

## How other tools consume it

Consumers never re-implement auth — they shell out and react to the exit code:

```python
subprocess.run(["browser.py", "up"], check=False)
rc = subprocess.run(["browser.py", "login", "anthropic"], check=False).returncode
```

Resolution is **PATH-first**: with `bin/` on `$PATH`, `browser.py` is callable from
anywhere. Tools that use the external-dependency convention resolve it as
`command="browser.py"` (PATH) → a conventional sibling clone → the `BROWSER_PY_BIN`
override. So a colleague who has it on `$PATH` needs zero config.

Current consumers: a CSCS portal client (token auto-refresh + re-login), an
Anthropic admin tool (claude.ai login for roster auto-export + invoice download),
and a ChatGPT Business roster scraper (chatgpt.com admin login).

## Adding a new site

Two shapes cover almost everything:

- **Credential-based, unattended** (like CSCS): a scriptable username/password (+TOTP)
  form. Store secrets via `store-creds`, fill at login, optionally extract a token.
- **Assisted / magic-link** (like claude.ai): can't be scripted from a stored secret —
  let the user complete it once, or automate end-to-end if a login email is readable.

Steps: write `cmd_<site>_login(port)` and `cmd_<site>_logged_in(port)` (check a DOM
sentinel on a stable post-login surface — never "the URL isn't `/login`"), optionally
`cmd_<site>_store_creds()`, then register a `Site(...)` in `_sites()`. Reuse the
keychain helpers (`_keychain_get/set/set_all`, `_totp_now`/`_fresh_totp`, `_op_creds`) and, for email flows,
the `himalaya` helpers. The CDP endpoint is always `http://127.0.0.1:<port>` (never
`localhost` — Chrome's debug port is IPv4-only and `localhost`→`::1` stalls on macOS).

## Security

- **No secrets in this repo.** Verified with `gitleaks`; a pre-commit hook
  (`.pre-commit-config.yaml`) scans every commit. Configuration is by env var and
  keychain label only.
- **Magic links / tokens are bearer credentials** — kept in memory, never printed,
  logged, or committed.
- **Keychain note:** caching a password + TOTP seed in the login keychain collapses
  2FA to 1FA *on this machine*. FileVault + the keychain protect it at rest, not from
  code running as you. This is an explicit, documented trade-off for unattended login.
  `store-creds` hands each secret to `security -i` on stdin, never on the command
  line (argv is visible to every same-user process via `ps`), and reads the item back
  to confirm the write. The read parses `security`'s labelled attribute dump
  (quoted text vs. `0x`-hex), so a non-ASCII or hex-looking password round-trips
  exactly. A value with a control character (newline, tab, …) or a
  command line over 4000 bytes is refused before anything is written — `security -i`
  would otherwise split it and store a fragment in the login keychain. A write
  that fails part-way never leaves a mixed old/new credential set: every item of
  the set is deleted again (best effort, not atomic), and `store-creds` reports
  either "nothing changed", "no stored set remains", or the items whose cleanup
  failed (then run `forget-creds SITE`).
- **Keychain writes are delete-then-add, never `-U`** (tp#504). Updating an existing
  item with `add-generic-password -U` re-sets its access list, which can open a
  SecurityAgent dialog; a fresh add does not. Both the delete and the add name the
  same target — the user's default keychain (`security default-keychain -d user`),
  resolved once per `store-creds`; if it cannot be resolved nothing is written. The
  read-back is unpinned, so a shadowing copy earlier in the search list shows up as a
  failed write. Not atomic: a concurrent login can see an item missing in between.
- **`security` is never killed and never timed out.** On 2026-09-24 a 15 s timeout
  killed a `security` client while its dialog was open and `securityd` aborted; every
  later keychain read hung. Every `security` call now runs in its own session (a
  terminal Ctrl-C does not reach it), with no deadline; a Ctrl-C in `browser.py`
  waits for the running call to finish, removes a partially written set, then exits.
  Consequence: a read against a LOCKED keychain waits until you unlock it, and
  `store-creds` prints "If macOS shows a keychain dialog, answer it." first.

## License

[Apache-2.0](LICENSE).
