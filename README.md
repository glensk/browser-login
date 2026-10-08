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
| `op` (1Password CLI)    | legacy: only the human-only `login-cscs-assisted` / `cscs-store-creds`; never an unattended login | no (not in use) |

`playwright`, `pyotp`, `requests` and `websockets` (raw-CDP tab probe) are declared in `pyproject.toml`. You don't
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
browser.py up                 # launch the shared Chromium, always HEADLESS (idempotent, clean tab;
                              #   -H is a no-op kept for compatibility)
browser.py status             # CDP health, version, open tabs (origins only; -f full URLs) + the lifecycle record
browser.py status -p          # + probe every tab over raw CDP: marks '⚠ unresponsive' / '? indeterminate'
browser.py close-hung [-y]    # close tabs that answer no CDP command (asks first; see Troubleshooting)
browser.py switch headless    # revert a headed browser (stop + relaunch, logins persist);
                              #   `switch headed` only inside a guided login (else exit 2)
browser.py clients            # who is attached over CDP (registered + unknown clients)
browser.py journal [-n N] [-e EVENT] [-j]  # who launched/switched/stopped it, logins, window raises
browser.py doctor             # full health check on a disposable tab (never touches real tabs)
browser.py open https://…     # navigate a tab (opens in the BACKGROUND — no focus steal)
browser.py open -r https://…  # --reuse: navigate an existing same-URL tab (no duplicate tabs;
                              #   matches sans query/fragment, oldest first = eval's pick)
browser.py open -N https://…  # --new: ALWAYS a new background tab (raw CDP, no Playwright
                              #   attach); prints `target=<id>` — the tab you own (tp#786)
browser.py eval -T <id> 'location.host'  # --target: eval in exactly that tab over raw CDP;
                              #   exit 1 if it is gone; JSON-serialisable results only
                              #   (returnByValue — undefined prints null)
browser.py close -i <id>…     # close the tab(s) you opened (lease, re-check, never the last tab)
browser.py close [-n] URL…    # manual cleanup of leftover tabs by exact URL (query/fragment and
                              #   trailing slash ignored; http(s) only); -n = dry run;
                              #   -w lease wait (30 s), -d overall deadline (20 s)
browser.py eval 'document.title' [--url SUBSTR]   # run JS in the active/matched tab → JSON
                              #   --url with no matching tab exits 1 (it never falls back to
                              #   another tab; the error names the open tabs by origin only —
                              #   no path, query or fragment); zero tabs → a blank one is created;
                              #   -t/--timeout SECONDS (default 60) is a hard deadline, attach
                              #   included: ❌ + exit 1 on expiry — JS already running in the
                              #   page is NOT stopped
browser.py down [-f]          # quit the shared browser (graceful CDP close → validated escalation);
                              #   refuses while a registered client (MCP server) stays attached —
                              #   -f/--force stops anyway; a stale record with no browser is cleared
```

`up` launches the binary directly (detached) and HEADLESS — there is no window
at all — and on a cold start it **wipes stale session-restore state** so it opens
ONE clean tab instead of resurrecting every tab from last time (your logins
persist — they live in Cookies/Local Storage, not the session files). `open`
likewise reuses a blank tab or creates new tabs via CDP `Target.createTarget`
with `background: true`. The only time a window exists is a guided login you
start yourself (`agent-login.py -g SITE`, see the next section).

Env toggles: `CLAUDE_BROWSER_KEEP_TABS=1` keeps last session's tabs (skip the
wipe); `CLAUDE_BROWSER_OPEN_LAUNCH=1` launches a HEADED (guided-login) browser via
`open -g -n` instead (breaks LAN access — see below; never used for headless);
`CLAUDE_BROWSER_FOREGROUND=1` forces the direct launch;
`CLAUDE_BROWSER_CONNECT_TIMEOUT_S` (default 30) bounds every Playwright attach
(see Troubleshooting). `CLAUDE_BROWSER_HEADLESS` is ignored (headless is the
only mode `up` knows; `CLAUDE_BROWSER_HEADLESS=0` does NOT give a window).
Separately, the Claude Code wrapper only auto-starts the browser when
`CLAUDE_BROWSER_AUTOSTART=1` — by default it is lazy (started on first use).

## Why you never see the window

The design goal is that **driving the browser never interferes with your
desktop**: no focus steal, no window, no z-order change, no native prompt
(PLAN_focus-free-browser.md, tp#836). It is enforced by one invariant:

> **The shared browser is HEADLESS unless a live headed lease exists** — held by
> a guided login you start yourself (`agent-login.py -g SITE`). With no window,
> nothing can take focus, be raised or pop a dialog.

- **Headless by default.** `up` always launches `--headless=new` (same profile,
  same logins). `<cache>/desired-mode.json` records `{"mode": "headless"}` (no
  file = headless; any other value is reported by `doctor` and ignored). There is
  no `up --headed` and no env toggle for one; `up -H` is accepted as a no-op.
- **Why the 2026-08-20 NO-GO no longer holds.** Headless used to announce
  `HeadlessChrome` in the User-Agent, and Cloudflare hard-challenged it
  (claude.ai and chatgpt.com never loaded). Since commit `34c78ea` (2026-10-06)
  the headless launch passes a plain desktop `--user-agent` (version from the
  app's Info.plist), which removes that tell everywhere (page, workers, request
  headers, `/json/version`). The Phase 1 cold matrix (disposable profile,
  Chrome for Testing 153.0.8010.12, 2026-10-08) loaded 12/12 sites with no
  challenge: claude.ai, chatgpt.com, platform.openai.com, Slack, Notion, CSCS,
  SWITCH, Smartsheet, Infomaniak, gitlab.datascience.ch, console.anthropic.com
  and a LAN `*.dom42.space` site. Residual tells (empty high-entropy UA-CH, an
  800×600 `screen`, no "Google Chrome" brand) are harmless today.
- **The headed lease.** `<cache>/headed-lease.json` = `{owner_nonce, pid,
  pid_start_time, site, started, heartbeat}`, written by the guided login,
  heartbeat every 10 s (a write error is retried, never fatal), removed
  compare-before-release. It is LIVE while the owner pid runs with the recorded
  start time (no pid reuse), whatever the heartbeat's age — a Mac asleep for a
  minute keeps it — unless the heartbeat is over 120 s old (a hung owner). When
  `ps` cannot read the start time of a live pid, the lease counts as live (a
  `ps` hiccup never reverts a guided window). The owner exports
  `CLAUDE_BROWSER_HEADED_LEASE=<nonce>`;
  only processes carrying that nonce (the guided login and its `browser.py`
  children) may `switch headed`, run an assisted login step or call
  `bring_to_front`. Anybody else gets `switch headed` → exit 2 (`headed mode only
  inside a guided login: agent-login.py -g <site>`). The guided login switches
  back to headless at the end — unless another guided login's lease is live by
  then — and a failed switch back is a loud ❌ plus one retry.
- **Preflight revert (best effort).** Every command that drives the browser
  (all but `status`, `journal`, `down`, `switch`, `clients`, the recovery tools
  `doctor`, `close-hung`, `close`, and the offline ones) first checks: headed
  and no live lease → `switch headless` (journaled as `revert_headed`) BEFORE it
  takes the client gate, with all its output on stderr (a consumer's stdout —
  `slack-session` JSON, `token`, `open -N` — stays clean). It waits at most 5 s
  for the gate, re-checks under it (a guided login that took the lease
  meanwhile is left alone: `revert_skipped`), and is skipped while another
  up/switch/down is in flight. A revert that fails (e.g. an unregistered client
  blocks the switch) is one ❌ line on stderr plus a `revert_failed` journal
  event — the command still runs, and the next command tries again. By hand:
  `browser.py switch headless` (`-f` past an unregistered client).
- **`login` never opens a human flow.** Where a login needs you (claude.ai
  without a readable magic link, chatgpt.com, Slack, Notion, the SWITCH edu-ID
  fallback) it exits **4** and prints `needs Albert: agent-login.py -g <site>` —
  same code as the broker's "needs a human". Inside a guided login (lease held
  by this process tree, browser headed) the old window flow runs. No TTY or env
  heuristics. An unattended `login cscs` never falls back to 1Password/Touch ID.
- **`bring_to_front` is a journaled no-op** (`skipped: no-lease|headless`)
  outside a guided login; `token` and `slack-session` no longer call it. `doctor`
  never escalates to it in headless — frozen rendering is a ❌ there.
- **No native UI.** Launch flag `--deny-permission-prompts` plus profile prefs
  written before every launch (`profile.default_content_setting_values`
  notifications/geolocation/camera/mic = block; `download.default_directory` =
  `<cache>/downloads`, no Save dialog). Prefs rather than CDP
  `Browser.setDownloadBehavior`: that one is reset when the CDP session that set
  it detaches (measured on CfT 153), and each Playwright attach sets its own.
  `--disable-notifications` is not used — with it a page script probing
  `Notification` threw on CfT 153, and the prefs already deny notifications.
  Chrome for Testing has no auto-updater (Playwright's cache manages it). The
  macOS keychain prompts that remain possible are listed under Security.
- **No `--remote-allow-origins`.** Without it Chrome answers 403 to every CDP
  WebSocket that sends an `Origin` header (even its own origin), so no web page
  can drive the browser. Playwright (Python and Node, incl. the Playwright MCP)
  and this repo's `websockets` clients (`_cdp_ws_call`, `login_viewer.py`) send
  none; a third-party CDP client that sends an Origin must stop doing so.
- **Background launch (headed, guided login only).** The binary is spawned
  directly (not `open -a`): LaunchServices would make the app its own
  responsible process, and macOS Local Network privacy then blocked every LAN
  address (`ERR_ADDRESS_UNREACHABLE` on 192.168.178.x and `*.dom42.space`, tp#703);
  spawned directly it inherits the launching terminal's grant. A headed window
  opens behind the frontmost app; macOS pauses rendering of an occluded window
  (rAF stops, every Playwright click times out on "stable"), which is why the
  `--disable-backgrounding-*` flags stay, and why `Page.bringToFront` (which on
  CfT 151 could raise the window and even steal focus) is the guided login's
  escalation only.

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

The record says what the browser is doing NOW; the **journal**
(`~/.cache/claude-browser/journal.jsonl`, per instance, mode 0600) says who did
what before. Every `up`/`switch`/`down`/`login` (a start and an end line with
mode, `from`→`to`, site and flow, exit code, duration), every window raise
(`bring_to_front`, with the command and the page's origin), every client
`register`/`unregister` and an `eval` `watchdog` exit appends one JSON line
carrying the pid, ppid and argv — lifecycle, login and raise events also the
parent chain (5 ancestors, one bounded `ps` before any lock is taken).
Redacted like `status`, fail closed: any URL is cut to its origin, an `eval`
expression to its length, a `register-exec` command to its name and argument
count. Appends are single `O_APPEND`
writes (< 4 KiB, whole lines under concurrency); past 10 MB the file rotates
to `.1`/`.2`; a journal failure warns once on stderr and never fails the
command. `browser.py journal` tails it (`-n/--lines N`, default 50, `0` = all;
`-e/--event up|switch|down|login|bring_to_front|register|unregister|revert_headed|headed_lease`;
`-j/--json` raw lines).

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
   compare-before-release). The assisted/unattended `login` flows take it,
   and so do `close-hung` and `close`; read-only probes (`logged-in`, `eval`
   incl. `-T`, `open` incl. `-N`, `token`, `slack-session`) do not. A parent that already holds the lock and shells
   `browser.py login …` exports `CLAUDE_BROWSER_LEASE_HELD=1` so the child
   doesn't deadlock against it.

Rules for anything that drives this browser:

- **Never activate the app or raise the window.** The browser is headless;
  `bring_to_front` is a no-op outside a guided login (see above). Never
  AppleScript `activate`, never `switch headed` (it refuses without the lease).
- **Send no `Origin` header** on a CDP WebSocket — the browser runs without
  `--remote-allow-origins` and answers 403.
- **`force=True` clicks never on final mutating controls.** Force-fallback is
  acceptable for non-final controls only; the last click of a mutation must
  pass normal actionability.
- **Bound every screenshot and wait** (explicit timeouts) — an occluded
  window can freeze rendering and an unbounded wait hangs forever.
- **Hold the interaction lease** around interactive flows; register if you
  hold a long-lived CDP connection.
- **Close what you open (tp#786).** A tool that needs a tab of its own opens
  it with `open -N URL`, reads the `target=<id>` line, evaluates with
  `eval -T <id>`, and closes it with `close -i <id>` in a `finally`. Leftover
  tabs are not harmless: every Playwright attach waits for every page target,
  so a few heavy tabs (Smartsheet's desktop app) slow down EVERY consumer of
  the browser. `close` registers, takes the interaction lease (bounded by
  `-w`, inside one `-d` deadline; on a lease timeout it exits 1 and closes
  nothing), re-reads the tab list right before each close (id mode: the tab
  must still exist; URL mode: its URL must still match), and opens a blank
  keep-alive first when the tab is the last one. Exit 0 when every requested
  tab is closed or already gone, when nothing matches, or when the browser is
  down — so a retry is always safe. **Unregistered clients** (anything that
  drives the browser without `browser.py`) take no lease, so the re-check is
  best-effort against them: they can still navigate a tab in the
  milliseconds between the re-list and the close.

## Multi-site login

A **site** is one entry in the `SITES` registry inside `browser.py`. Generic
subcommands dispatch through it:

```commands
browser.py login SITE         # ensure logged in; exit 4 + "needs Albert: agent-login.py -g SITE"
                              #   when only you can finish it (never opens a window itself)
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
| `cscs`                 | **Keycloak, unattended.** `store-creds cscs` caches username/password/TOTP-seed in the macOS keychain (from 1Password, one last Touch ID); thereafter login runs with no fingerprint. TOTP codes are generated locally with `pyotp` only once the OTP field appears (never before the password submit), waiting for the next 30 s step when the current one has under 5 s left; the 1Password fallback likewise fetches its live code at fill time. A flow Keycloak aborts with `authentication_expired` (stale `session_code` on a login page left open for hours) is retried once from a fresh page with a newly generated code; a wrong password still fails on the first attempt. After login the token is cached (0600) and checked against `/api/me/`; a network error or an unexpected answer exits 1 with a one-line reason, never a traceback. Through the login broker (`login cscs` whenever the broker lists `cscs`), the session bundle carries the portal's token for `portal.cscs.ch` localStorage: it is written by an init script BEFORE the portal app loads (a token-less portal sends the tab to Keycloak right after load, so a post-load write loses the race) and read back on the portal as proof. The broker path's logged-in check (before and after the injection) polls up to 8 s for that token while the tab is on the portal — being on `portal.cscs.ch` alone proves nothing. |
| `openai` (`chatgpt`)   | **Assisted.** ChatGPT Business logs in via Google SSO + 2FA, which can't be replayed from a stored secret — you complete the SSO once in the shared window; the session persists. Logged-in sentinel: the 'Invite member' button on `chatgpt.com/admin/members`. |
| `slack`                | **Assisted.** app.slack.com logs in via email-code / SSO; you sign in once and the session persists. Logged-in sentinel: a team with an `xoxc-` token in `localConfig_v2`. `browser.py slack-session` then prints `{token,cookie,team_domain}` (xoxc + httpOnly `d` cookie via CDP) so `slack-api` can call `users.admin.setInactive` on the Pro plan — where the API token is scope-blocked. Bearer creds → stdout only, never cached. |
| `notion` (`notion.so`) | **Assisted.** Notion logs in by e-mail code or SSO, which can't be replayed from a stored secret — you sign in once in the shared window (`./agent-login.py -g notion`); the session persists. Logged-in sentinel: the workspace sidebar (`.notion-sidebar` / `.notion-sidebar-switcher`) on `app.notion.com` outside `/login` — notion.so and its `/login` both redirect to that host, so the URL alone proves nothing. `logged-in notion` probes a background tab it closes again. Aliases: `app.notion.com`, `notion.com`. |
| `biopolwifi`           | **Keychain email+password, unattended.** SDSC Biopole WiFi units are managed via a Ruckus Cloudpath MDU portal (`cloudpath.edificom.cloud`, a plain Vue SPA). `store-creds biopolwifi` caches the portal email+password in the macOS keychain (the same items `sdsc/biopol-wifi/biopol-wifi.py` reads); login fills the form and confirms the `SDSC - Biopole` / `Properties` sentinel. No SSO, no TOTP, no token extracted. Aliases: `biopol`, `cloudpath`, `edificom`. |
| `switch`               | **Broker edu-ID session + SSO click, assisted fallback.** `login switch` clicks the single SWITCH edu-ID button on `/auth/login` — passwordless while the browser's edu-ID IdP session lives. When the login broker lists an `eduid` item, `login switch` first runs `login eduid` (the bundle carries the live `login.eduid.ch` session) and then clicks in a BACKGROUND tab, so it needs no window and works headless (login-log mode `broker-sso`); `agent-login.py -t switch` therefore logs in instead of only checking. Without a usable `eduid` item, or when that path does not end logged in, it falls back to the click in the shown window, and you finish the edu-ID login there once (headed only). Logged-in sentinel: on `cloud.switch.ch` outside `/auth/` with NO `/auth/openid_connect_eduid_ch` sign-in form — the anonymous root renders that form with HTTP 200, so the URL alone proves nothing. `logged-in switch` probes a background tab it closes again (never focuses the window) and exits 2 when logged out OR when it cannot tell — the `infra/status` check `switch-portal-login` runs it every 30 min. No stored credential by design: edu-ID is Albert's primary federated identity. Aliases: `switch-cloud`, `cloud.switch.ch`, `scp`. |

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

### Login broker items (`agent-logins` custom fields)

A site the login broker (`broker/`, design in `PLAN_login-broker.md`) may log
into is a Vaultwarden login item in the `agent-logins` collection. Its custom
fields configure it (parsed in `broker/vault.py`; a malformed field refuses the
item, `agent-login.py` shows the reason):

| Field                      | Meaning                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| :------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `agent_fill_origins`       | **Required.** Exact `https://host[:port]` origins (comma/newline separated) where the broker may type the secrets; re-checked before every fill and submit.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `agent_site`               | Short site id (default: the item name as a slug).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `agent_check_url`          | Page that needs the login; the positive check passes when it ends off every fill origin with no password field (built-in defaults for known sites).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `agent_logged_in_selector` | CSS sentinel visible only when logged in (needed when the check page stays on a fill origin).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `agent_login_url`          | Where the login starts (default: the check URL, which redirects to the login with its state).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `agent_cookie_hosts`       | Hosts (and their subdomains) whose cookies leave the broker in the bundle. An identity-provider host (`login.eduid.ch`, `auth.cscs.ch`, `idp.*`, …) is exported only when listed exactly.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `agent_cookie_names`       | Optional cookie-name allowlist within those hosts.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `agent_storage_keys`       | JSON `{origin: [keys]}`: localStorage keys handed over too.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `agent_otp_label`          | Which authenticator to answer when the account offers several (substring of its label).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `agent_fresh_login`        | `true` (also `1`/`yes`/`on`; default `false`): every login first deletes the broker profile's cookies for the cookie hosts and fill origins (host, subdomains, parent domains), skips the "profile still logged in" shortcut and runs the full login (e-mail, password, TOTP). Needed when the bundle must carry an IdP's **session-only** SSO cookie, which the broker profile loses whenever it closes — e.g. SWITCH edu-ID: `agent_cookie_hosts = eduid.ch login.eduid.ch` plus `agent_fresh_login = true` hands the shared Chromium a live `login.eduid.ch` session, so an OIDC authorize there needs no typing. Every call is a real login and counts against the rate limiter. |
| `agent_pre_click`          | CSS selector of an element clicked as soon as it shows, before the login fields are looked for (only while the page and the element are on a fill origin; skipped when the login password field shows first). Clicked again every 3 s while it stays visible and no login field appears — a SPA can show it before its click handler is attached — e.g. Jellyfin's user picker: `.btnManual` reveals the manual login form.                                                                                                                                                                                                                                                          |

`broker-add.py` (mydotfiles `bin/`) writes these fields and the collection
membership from the command line. Agents may run it themselves once Albert has
enrolled Touch ID approval (`vault-touchid enroll -a main`, mydotfiles
`tools/vault-touchid/`): each run asks for two Touch ID touches — one to open the
main vault, one after the vault-touchid window has shown every change — and the
master password never reaches the agent. Without the enrolment it asks for the
typed master password in a terminal. `-N` (new items from the Keychain) is not
available through Touch ID; it needs `-P` in a terminal.

## Troubleshooting

**`open` / `eval` / `doctor` / `login` fail with "could not attach … within
30s" while `status` works.** One tab's renderer stopped answering CDP — seen
on 2026-09-29 with a Cloudflare Access sign-in tab stuck mid-navigation
(tp#693). Playwright's `connect_over_cdp` attaches to
EVERY tab and waits for each to answer, so that one tab blocks every Playwright
attach (Playwright's own default wait is 180 s; browser.py gives up after
`CLAUDE_BROWSER_CONNECT_TIMEOUT_S`, default 30). `status` still works because
it only reads the HTTP `/json/*` endpoints. The error names the tab (title,
origin, 8-char target id). Then:

```commands
browser.py status -p          # which tab(s) answer no CDP command (read-only probe)
browser.py close-hung         # close them — asks first; -y/--yes skips the question
```

`close-hung` closes only tabs that failed three consecutive CDP probes (the
listing, a re-probe, and one more AFTER you confirm, with an unchanged URL); a
responsive tab is never a candidate. Nothing closes a tab automatically —
reloading or closing it by hand in the window works too. The Playwright MCP
server (`browser_*` tools) attaches the same way and stalls on the same tab;
`close-hung` is the shared remedy. `doctor` probes tab responsiveness first and
skips its Playwright probe (❌) while such a tab exists.

**Every `open`/`eval` is slow (seconds to tens of seconds) and `status` lists
many tabs a tool left behind.** Each extra page target slows every Playwright
attach (tp#786). Tools that follow the consumer contract close their own tabs;
leftovers from older versions need a one-time cleanup by exact URL (query,
fragment and trailing slash are ignored; output is origin-only):

```commands
browser.py close -n https://app.smartsheet.com/login https://app.smartsheet.com/folders/personal   # dry run
browser.py close https://app.smartsheet.com/login https://app.smartsheet.com/folders/personal      # close them
```

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

**Known consumers to update for headless-by-default (tp#836):**

- `sdsc/openai-api/openai-team.py` assumes the shared browser is HEADED:
  `_open_shared_browser` returns `headed=True`, and `_ensure_logged_in` then
  waits up to 5 min for a human to finish a login on the auth screen. With the
  browser headless nobody can; it should treat a logged-out shared browser as
  "needs Albert: agent-login.py -g openai" (or `browser.py login openai` exit 4)
  instead of waiting.

## Adding a new site

Two shapes cover almost everything:

- **Credential-based, unattended** (like CSCS): a scriptable username/password (+TOTP)
  form. Store secrets via `store-creds`, fill at login, optionally extract a token.
- **Assisted / magic-link** (like claude.ai): can't be scripted from a stored secret —
  let the user complete it once, or automate end-to-end if a login email is readable.
  Gate the human step with `_guided_login_allowed(port, site, label)` and return
  `NEEDS_ALBERT_RC` (4) when it refuses: the window flow runs only inside a guided
  login (`agent-login.py -g SITE`); raise the tab only via `_bring_to_front`.

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
  failed (then run `forget-creds SITE`). "Nothing changed" is reported only when
  the first write provably changed nothing: its delete was refused, or its add
  never started. A refused add counts as a possible write (tp#509), so the set
  is cleaned up. When the first item was already missing, this only removes
  leftovers that no login could use anyway.
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
- **Native keychain prompts that remain possible** (tp#836 lists them; they are
  not changed). A SecurityAgent dialog can appear when the login keychain is
  locked, or when an item's access list does not trust `/usr/bin/security`
  (items `store-creds` wrote carry `-T /usr/bin/security` and read silently):

  | Call site                                              | `security` call                     | Reached unattended?                                   |
  | :----------------------------------------------------- | :---------------------------------- | :---------------------------------------------------- |
  | `browser.py` `_keychain_get` via `_keychain_creds`     | `find-generic-password -g`          | yes — `login cscs` (static flow, broker not listing cscs) |
  | `browser.py` `_keychain_get` in `cmd_biopolwifi_login` | `find-generic-password -g`          | yes — `login biopolwifi`                              |
  | `browser.py` `_keychain_write` (`security -i` add)     | `add-generic-password`              | no — `store-creds` only                               |
  | `browser.py` `_kc_delete`                              | `delete-generic-password`           | no — `store-creds` / `forget-creds` only              |
  | `browser.py` `_kc_target_keychain`                     | `default-keychain -d user`          | no — `store-creds` only (never prompts)               |
  | `agent_login_keychain.py` `scan`                       | `dump-keychain -a` (no secrets)     | yes — `agent-login.py -S` every 10 min (locked keychain) |

  Chrome for Testing itself reads its "Safe Storage" key from the login keychain
  at launch; after a CfT upgrade (new binary) macOS can ask once whether the new
  binary may use it. `--use-mock-keychain` would avoid that but makes every
  existing cookie unreadable (all logins lost), so it is not used for the shared
  profile (the broker's own Chromium uses it).

## License

[Apache-2.0](LICENSE).

---

## READONLY created by README-help-add.py

### `agent-login.py --help`

agent-login.py — which of Albert's logins can agents use through the login broker?

Without arguments: a health line for the broker, then every login we want agents to use, once: ✅ when it works for agents (setup complete AND the latest real check, -c/-t, passed) or ❌ with the reason. Read-only: it asks the broker for its site list (never a secret), reads the names and expiry dates (never values) of Safari's cookies, and logs into nothing unless you pass -t, -g or -c.

The marketplace sites (anibis, tutti, Ricardo, Kleinanzeigen) run on YOUR Safari session: you log in in Safari, `browser.py login SITE` copies that site's session cookies into the shared Chromium (Kleinanzeigen falls back to the broker). CSCS and Smartsheet log in through the broker. SWITCH Cloud logs in with the broker's edu-ID session plus the portal's SSO click (no window; your own login only when the broker has no usable `eduid` item). Anthropic, OpenAI and Slack need you once (email code / SSO): `-g SITE` shows the window and waits; -t and -c only check them.

Examples:

```bash
./agent-login.py              # overview
./agent-login.py -t anibis    # real test: `browser.py login` (Safari session first,
                              # then the broker), then the positive logged-in check
./agent-login.py -c           # every usable site: logged in? if not, log in
./agent-login.py -c -m        # the same, and mail Albert when a site stays logged out
./agent-login.py -t https://auth.cscs.ch   # SITE may also be a name or login address
./agent-login.py -g anibis    # guided login typed by hand in the shared Chromium
./agent-login.py -g anthropic # your login (email code) in the shown shared Chromium
./agent-login.py -P           # print the daily LaunchAgent (-I installs, -U removes)
./agent-login.py -j           # the same overview as JSON
```

#### Options

| Flag | Description |
|------|-------------|
| `-t`, `--test` `SITE` | real login test for SITE |
| `-f`, `--fingerprint` `SITE` | length + 4 hex of the SHA-256 of the broker's password for SITE (no login) |
| `-g`, `--guided` `SITE` | guided login typed by hand in the shared Chromium window |
| `-c`, `--check-all` | every usable site: logged in? if not, `browser.py login`; one line per site, exit 1 if any stays logged out |
| `-m`, `-M`, `--mail` | with -c: mail `albert.glensk@gmail.com` (gog) when a site stays logged out |
| `-r`, `--refresh` | ask the broker now (re-reads Bitwarden, ~40 s) instead of the snapshot |
| `-S`, `--snapshot` | refresh the site-list and secret-run snapshots and the agents file (which also lists the secrets agents can inject), print nothing (LaunchAgent, every 10 min) |
| `-K`, `--keychain` | rescan the login keychain (~15 s) and list every item (names only) with whether agents can read it |
| `-A`, `--agents` | print the summary agent sessions get at start (the agents file) |
| `-I`, `--install-daily` | install + load the LaunchAgents com.albert.agent-login-check (`-c -m` daily 09:15) and com.albert.agent-login-snapshot (`-S` every 10 min) |
| `-U`, `--uninstall-daily` | unload + remove both LaunchAgents |
| `-P`, `--print-plist` | print both LaunchAgent plists (writes nothing) |
| `-j`, `--json` | print the overview as JSON |
