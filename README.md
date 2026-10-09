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
browser.py open https://…     # a NEW background tab (raw CDP, no Playwright attach, no focus
                              #   steal); prints `target=<id>` — the tab you own (tp#786). Never
                              #   navigates a tab it did not create, not even a blank one (tp#863)
browser.py open -r https://…  # --reuse: navigate an existing same-URL tab instead (manual use
                              #   only; matches sans query/fragment; none → a new tab)
browser.py open -N https://…  # --new: the default, explicitly (tools pass it)
browser.py eval -T <id> 'location.host'  # --target: eval in exactly that tab over raw CDP;
                              #   exit 1 if it is gone; JSON-serialisable results only
                              #   (returnByValue — undefined prints null)
browser.py close -i <id>…     # close the tab(s) you opened (lease, re-check, never the last tab)
browser.py close [-n] URL…    # manual cleanup of leftover tabs by exact URL (query/fragment and
                              #   trailing slash ignored; http(s) only); -n = dry run;
                              #   -w lease wait (30 s), -d overall deadline (20 s)
browser.py eval 'document.title' [--url SUBSTR]   # run JS in the most recent/matched tab → JSON
                              #   evaluates only, never navigates; --url with no matching tab
                              #   exits 1 (it never falls back to another tab; the error names
                              #   the open tabs by origin only — no path, query or fragment);
                              #   another process's owned tab (about:blank#owned-…) never matches;
                              #   -t/--timeout SECONDS (default 60) is a hard deadline, attach
                              #   included: ❌ + exit 1 on expiry — JS already running in the
                              #   page is NOT stopped
browser.py eval-fresh -t 30 https://claude.ai/ 'location.host'  # JS in a FRESH tab of its own:
                              #   created, loaded (readyState complete, ≤15 s), evaluated and
                              #   closed in one run → JSON; exit 1 not ready / JS error, 2 a
                              #   non-http(s) URL, 75 busy, 124/125 its -t deadline fired
browser.py reap-owned [-n]    # close the tabs crashed/killed browser.py runs left (owned-tab
                              #   ledger, proven-dead owners only; -n = dry run); exit 0 nothing
                              #   left, 1 a tab could not be closed, 75 busy
browser.py login anthropic -e EMAIL  # (inside a guided login) assisted claude.ai login until
                              #   /api/account is EMAIL (≤15 min); 2 = another account
browser.py down [-f]          # quit the shared browser (graceful CDP close → validated escalation);
                              #   refuses while a registered client (MCP server) stays attached —
                              #   -f/--force stops anyway; a stale record with no browser is cleared
```

`up` launches the binary directly (detached) and HEADLESS — there is no window
at all — and on a cold start it **wipes stale session-restore state** so it opens
ONE clean tab instead of resurrecting every tab from last time (your logins
persist — they live in Cookies/Local Storage, not the session files). `open`
always creates a new tab via CDP `Target.createTarget` with `background: true`
— it never reuses a blank tab, which may be another client's fresh `open -N`
tab still on `about:blank` (tp#863). The only time a window exists is the FALLBACK of a
guided login you start yourself (`agent-login.py -g SITE`; see "Guided login").

**Every check and login runs in a fresh tab it owns** (tp#845): `logged-in SITE`,
`token`, `slack-session`, `eval-fresh` and every built-in `login SITE` create
their own background tab (raw `Target.createTarget {url, background}` in the
default browser context, so the tab sees the profile's cookies and storage),
drive it, and close it again with every popup it opened — never a tab picked
by URL, which could be another client's tab or a guided login's login tab.
Logins navigate that tab only under the interaction lease. Each such tab is
recorded first in the process's **owned-tab ledger** (`<cache>/owned/`, a
random marker URL `about:blank#owned-…` before the target id is known), so a
crashed or killed run cannot leak it: `browser.py reap-owned` closes the tabs
of PROVEN-dead owners only (the owner's flock is free and its pid gone or
reused; anything unreadable is left alone), descendants first; the guided
login reaps at its start, after a window-flow `login` child, and in its
watchdog. `open -N` tabs are the caller's and are never ledgered or reaped.
`status` is never destructive (it never reaps); `doctor` only reports dead
ledgers (⚠, with the `reap-owned` hint).

Env toggles: `CLAUDE_BROWSER_KEEP_TABS=1` keeps last session's tabs (skip the
wipe); `CLAUDE_BROWSER_OPEN_LAUNCH=1` launches a HEADED (guided-login) browser via
`open -g -n` instead (breaks LAN access — see below; never used for headless);
`CLAUDE_BROWSER_FOREGROUND=1` forces the direct launch;
`CLAUDE_BROWSER_CONNECT_TIMEOUT_S` (default 30) bounds every Playwright attach
(see Troubleshooting). `CLAUDE_BROWSER_LOGIN_TIMEOUT_S` (default 300; a finite
number > 0, anything else means 300) bounds every unattended `login` — its
`LoginDeadline` closes the tabs the login opened and exits 124/125; `logged-in`
gets a fixed 120 s. agent-login's runner kills `browser.py login` at this value

- 90 s as the last resort. Never applied to a guided login (`-g SITE`). `CLAUDE_BROWSER_HEADLESS` is ignored (headless is the
only mode `up` knows; `CLAUDE_BROWSER_HEADLESS=0` does NOT give a window).
Separately, the Claude Code wrapper only auto-starts the browser when
`CLAUDE_BROWSER_AUTOSTART=1` — by default it is lazy (started on first use).

## Why you never see the window

The design goal is that **driving the browser never interferes with your
desktop**: no focus steal, no window, no z-order change, no native prompt
(PLAN_focus-free-browser.md, tp#836). It is enforced by one invariant:

> **The shared browser is HEADLESS unless a live guided-login maintenance
> record of mode A exists** — written by a guided login you start yourself
> (`agent-login.py -g SITE` → `browser.py assisted-login SITE`) when its remote
> view cannot do the login. With no window, nothing can take focus, be raised
> or pop a dialog.

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
- **The maintenance record (the "headed lease").** `<cache>/maintenance.json` =
  `{owner_nonce, pid, pid_start_time, site, mode, state, owned_targets, paused,
  watchdog_pid, started, heartbeat}` — ONE record for "a guided login owns the
  browser" (see "Guided login"); Phase 2's headed lease is this record with
  `mode: "A"` (a record without a mode is A). Heartbeat every 10 s (a write
  error is retried, never fatal), removed compare-before-release. It is LIVE
  while the owner pid runs with the recorded start time (no pid reuse),
  whatever the heartbeat's age — a Mac asleep for a minute keeps it — unless
  the heartbeat is over 120 s old (a hung owner). When `ps` cannot read the
  start time of a live pid, the record counts as live (a `ps` hiccup never
  reverts a guided window). The owner exports
  `CLAUDE_BROWSER_MAINTENANCE=<nonce>`; only processes carrying that nonce (the
  guided login and its `browser.py` children) may register as clients while it
  lives, and — in mode A only — `switch headed`, run an assisted login step or
  call `bring_to_front`. Anybody else gets `switch headed` → exit 2 (`headed
  mode only inside a guided login: agent-login.py -g <site>`). The guided login
  switches back to headless at the end, and a failed switch back is a loud ❌
  plus one retry.
- **Preflight revert (best effort).** Every command that drives the browser
  (all but `status`, `journal`, `down`, `switch`, `clients`, the recovery tools
  `doctor`, `close-hung`, `close`, and the offline ones) first checks: headed
  and no live mode-A record → `switch headless` (journaled as `revert_headed`) BEFORE it
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
`register`/`unregister`, an `eval` `watchdog` exit and, for a `login`/`logged-in`,
its `login_step` breadcrumbs, the `owned_target` tabs it opened/closed and a
fired deadline's `watchdog` line (`step` = where it hung) appends one JSON line
carrying the pid, ppid and argv — lifecycle, login and raise events also the
parent chain (5 ancestors, one bounded `ps` before any lock is taken).
Redacted like `status`, fail closed: any URL is cut to its origin, an `eval`
expression to its length, a `register-exec` command to its name and argument
count. Appends are single `O_APPEND`
writes (< 4 KiB, whole lines under concurrency); past 10 MB the file rotates
to `.1`/`.2`; a journal failure warns once on stderr and never fails the
command. `browser.py journal` tails it (`-n/--lines N`, default 50, `0` = all;
`-e/--event up|switch|down|login|login_step|owned_target|watchdog|bring_to_front|register|unregister|register_refused|revert_headed|headed_lease|guided_login|maintenance|client_pause|client_resume|watchdog_recover`;
`-j/--json` raw lines).

## Guided login (assisted-login)

A login only you can do (a human check, an email code, SSO with 2FA) runs as a
**guided login**. There is exactly one entry, and only you can start it:

```bash
./agent-login.py -g slack                 # → browser.py assisted-login slack
./agent-login.py -g notion -F             # → assisted-login notion -f (past unregistered clients)
bin/browser.py assisted-login anibis -u https://www.anibis.ch/fr/user/searches
bin/browser.py assisted-login slack -a    # skip the remote view: the window (A)
```

`assisted-login SITE` opens `/dev/tty` and asks you to **type the site name** to
start. Without a controlling terminal (an agent, launchd, a pipe) it exits **2**
before touching anything — agents cannot start a guided login; they get
`needs Albert: agent-login.py -g SITE` from `login` instead. Already logged in →
✅ and exit 0 without asking. `agent-login.py -g` routes the plain human logins
here (anibis/tutti/ricardo with their start URL, openai, slack, notion); the
claude.ai accounts and SWITCH keep their own window flows (`guided_window`, now
also inside the maintenance transaction).

**B — remote view (primary).** The browser stays headless. An OWNED background
tab opens on the login URL (`open -N`), and `bin/login_viewer.py` — a loopback
relay registered via `register-exec` under the guided login's token — streams it
into a dedicated, extension-free Brave app window (`open -na "Brave Browser"
--args --user-data-dir=<cache>/viewer-profile --app=<url>`; without Brave the
default browser — `ℹ️  opening the login view in your default browser`). The
link is also printed (OSC 8). You click, type, paste and use IME there; JS
dialogs show in the view; the tab's viewport follows the view's size. OAuth popups (a new target whose `openerId` is an owned
tab) are followed and shown, and the view returns to the opener when they
close; a tab without an owned opener is never shown (one that appears right
after your input — in practice the `logged-in` probe tab below — is only noted
on the terminal and as a `popup_unowned` event, never in the view). Every 5 s
`logged-in SITE` (the site's own sentinel, in a separate background tab)
decides; on ✅ the record's state turns `succeeded`, the relay (it polls the
record every 0.5 s) shows **✅ Logged in to SITE — you can close this tab** and
exits by itself within 3 s, then the normal cleanup runs. Any other end (timeout,
owner gone, CDP lost, the transaction stopping the relay) leaves a final
`<reason> — see the terminal` in the view; a plain disconnect says `reload
within 10 s to reconnect; if the login already finished, check the terminal`.
Timeouts: 5 min with no view connected, 15 min overall.

**A — the window (fallback).** When the view meets something it cannot show —
a passkey / security-key prompt (a modal WebAuthn `get`/`create`; passkey
autofill is ignored), a permission request (notifications, location,
camera/mic, screen capture), a link to an external app — or you press **Use a
window instead**, B ends with the named reason, its tabs are closed, and the
terminal asks `switch to a visible window for this login? [y/N]`. Yes →
`switch headed` inside the SAME transaction, the old window flow (the site's own
`login SITE` flow, or an owned tab brought to the front), `switch headless` in a
`finally`. Client-certificate prompts are not exposed by CDP in headless Chrome
(it silently sends no certificate): the site's error page shows in the view, and
the button is the way out.

**The maintenance transaction** (B and A, `_maintenance` in `browser.py`):

1. Write `<cache>/maintenance.json` (state `preparing`; from now on a NEW client
   registration without `$CLAUDE_BROWSER_MAINTENANCE=<owner nonce>` exits
   **75** (EX_TEMPFAIL) with `busy: guided login for SITE in progress (until
   ~HH:MM)`; `down`/`switch` refuse the same way unless
   `-F/--force-maintenance`) and start the watchdog.
2. **Pause** every registered long-lived client: SIGUSR1 to its `register-exec`
   wrapper — only after validating its pid AND start time from its live registry
   entry; the entry goes into the record first. The wrapper SIGSTOPs its child's
   process group, releases its shared hold on the client gate and confirms
   (`paused: true`) within 5 s, or the start is refused. Measured with
   `@playwright/mcp@0.0.76` (pauses up to 5 min): the MCP's stdio session and
   CDP socket survive and every later call works; only a call that was in
   flight with a Playwright timeout (navigate 60 s, actions 5 s) can come back
   as `TimeoutError` when the pause outlasts it — the work itself is done;
   retry the call. A long-lived
   registration from before this protocol (no `kind`) refuses the start at
   once, naming its pids: restart the Claude sessions that run the Playwright
   MCP.
3. Take the client gate EXCLUSIVELY (20 s; the refusal names the holders);
   refuse while UNREGISTERED CDP peers are attached (`lsof`; `-f/--force`, or
   `agent-login.py -g SITE -F`, proceeds, they keep running unpaused); take the
   interaction lease (held for the whole session); state `active` (`succeeded`
   once B's login is done); release the gate so the transaction's own
   `browser.py` children (they carry the token) can register.
4. On ANY exit — success, timeout, decline, error, Ctrl-C: close the owned
   targets → `switch headless` if headed (one retry, loud) → release the lease →
   clear the record → resume the clients (SIGUSR2 to the validated wrapper, which
   retakes the gate and SIGCONTs). A wrapper that is gone left an ORPHAN —
   unregistered, it would fail every later switch closed — so its child group is
   stopped iff the leader still runs with the recorded start time (SIGTERM,
   SIGKILL after 5 s); `browser.py clients` does the same for any dead
   `register-exec` registration it reaps. Every step is journaled
   (`maintenance`, `client_pause`, `client_resume`, `orphan_kill`).

**Watchdog.** `browser.py maintenance-watchdog -n <nonce prefix>` (detached, own
session) polls the record every 2 s. When the owner is gone (dead pid, reused
pid, or a heartbeat older than 120 s) it closes the owned targets, reverts a
headed browser to headless, clears the record and resumes the paused clients —
in that order, because a resumed wrapper retakes the gate that the revert needs
exclusively — and journals `watchdog_recover`. It exits when the record is
cleared normally. Belt and braces: a PAUSED wrapper also resumes itself within
2 s once the record FILE that paused it is gone or names another owner — not
when the owner merely died (the watchdog needs the gate first), except after
60 s of a dead record (watchdog presumed dead) — and the relay ends itself
(`-M`) when the record or its owner disappears. Backstop for a watchdog that
died too: `agent-login.py -S` (LaunchAgent, every 10 min) first reads the
record and, when it is not live AND its `watchdog_pid` is certainly gone (pid
not running, or no pid recorded and a heartbeat older than 120 s; a live pid
or a malformed value = do nothing), runs the same recovery once
(`browser.py maintenance-watchdog -n <nonce prefix>`, killed after 120 s) and
logs one ✅/❌ line without the nonce. A live record is never touched.
`logged-in` checks never pick
an existing tab (it could be the owned login tab): they always run in a fresh
background tab of their own (tp#845), during a guided login and outside one.

Known residuals: a paused client keeps its CDP socket, but a fallback-A switch
restarts the browser, so a paused Playwright MCP finds its connection dropped
when it resumes (its next call reconnects or fails once); the surface hook is an
init script, so a passkey prompt in a cross-origin iframe or in the very first
document of a popup can go unnoticed (the button covers it); the hook wraps
`navigator.credentials`, which a page could detect.

Test hooks (honoured only with `CLAUDE_BROWSER_CACHE_DIR` set, i.e. a disposable
browser): `CLAUDE_BROWSER_TEST_SITES=<json>` adds sites
(`{name: {login_url, check_url, logged_in_selector}}`) and
`CLAUDE_BROWSER_TEST_VIEWER_URL_FILE=<path>` writes the viewer URL to a file
instead of opening a window. `tests/test_guided_login.py` (`-m browser`,
`LOGIN_BROKER_E2E=1`) runs the whole B path that way, with the view driven by a
second headless browser.

## Consumer contract (multi-client coordination)

Any number of CDP clients may READ concurrently, but the browser is shared
state — so two layers coordinate everyone (all under `~/.cache/claude-browser/`):

1. **Registration (who is attached).** Every `browser.py` command that
   connects registers itself in `clients/` (a shared flock on the registry
   gate, held for the connection's lifetime). Long-lived clients — e.g. the
   Playwright MCP server — wrap themselves in
   `browser.py register-exec -t NAME -- CMD…` so their registration lives
   exactly as long as the process (and so a guided login can PAUSE them: the
   wrapper runs CMD in its own process group and SIGSTOPs/SIGCONTs it on
   request — see "Guided login"). `switch`/`down` acquire the gate
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
| `anthropic` (`claude`) | **Magic-link, fully automatic** when `ANTHROPIC_LOGIN_EMAIL` is set and `himalaya` reads that mailbox: triggers the email, extracts the `claude.ai/magic-link#<token>` URL, opens it — only if it passes the three login-CSRF guards below. Otherwise **assisted** (you finish the email login once). `login`/`logged-in` use a fresh owned background tab, closed again (tp#845). |
| `cscs`                 | **Keycloak, unattended.** `store-creds cscs` caches username/password/TOTP-seed in the macOS keychain (from 1Password, one last Touch ID); thereafter login runs with no fingerprint. TOTP codes are generated locally with `pyotp` only once the OTP field appears (never before the password submit), waiting for the next 30 s step when the current one has under 5 s left; the 1Password fallback likewise fetches its live code at fill time. A flow Keycloak aborts with `authentication_expired` (stale `session_code` on a login page left open for hours) is retried once from a fresh page with a newly generated code; a wrong password still fails on the first attempt. After login the token is cached (0600) and checked against `/api/me/`; a network error or an unexpected answer exits 1 with a one-line reason, never a traceback. Through the login broker (`login cscs` whenever the broker lists `cscs`), the session bundle carries the portal's token for `portal.cscs.ch` localStorage: it is written by an init script BEFORE the portal app loads (a token-less portal sends the tab to Keycloak right after load, so a post-load write loses the race) and read back on the portal as proof. The broker path's logged-in check (before and after the injection) polls up to 8 s for that token while the tab is on the portal — being on `portal.cscs.ch` alone proves nothing. `login`/`logged-in` use a fresh owned background tab, closed again (tp#845). |
| `openai` (`chatgpt`)   | **Assisted.** ChatGPT Business logs in via Google SSO + 2FA, which can't be replayed from a stored secret — you complete the SSO once in the shared window; the session persists. Logged-in sentinel: the 'Invite member' button on `chatgpt.com/admin/members`. `login`/`logged-in` use a fresh owned background tab, closed again (tp#845). |
| `slack`                | **Assisted.** app.slack.com logs in via email-code / SSO; you sign in once and the session persists. Logged-in sentinel: a team with an `xoxc-` token in `localConfig_v2`. `browser.py slack-session` then prints `{token,cookie,team_domain}` (xoxc + httpOnly `d` cookie via CDP) so `slack-api` can call `users.admin.setInactive` on the Pro plan — where the API token is scope-blocked. Bearer creds → stdout only, never cached. `login`/`logged-in` use a fresh owned background tab, closed again (tp#845). |
| `notion` (`notion.so`) | **Assisted.** Notion logs in by e-mail code or SSO, which can't be replayed from a stored secret — you sign in once in the shared window (`./agent-login.py -g notion`); the session persists. Logged-in sentinel: the workspace sidebar (`.notion-sidebar` / `.notion-sidebar-switcher`) on `app.notion.com` outside `/login` — notion.so and its `/login` both redirect to that host, so the URL alone proves nothing. `logged-in notion` probes a background tab it closes again. Aliases: `app.notion.com`, `notion.com`. `login`/`logged-in` use a fresh owned background tab, closed again (tp#845). |
| `biopolwifi`           | **Keychain email+password, unattended.** SDSC Biopole WiFi units are managed via a Ruckus Cloudpath MDU portal (`cloudpath.edificom.cloud`, a plain Vue SPA). `store-creds biopolwifi` caches the portal email+password in the macOS keychain (the same items `sdsc/biopol-wifi/biopol-wifi.py` reads); login fills the form and confirms the `SDSC - Biopole` / `Properties` sentinel. No SSO, no TOTP, no token extracted. Aliases: `biopol`, `cloudpath`, `edificom`. `login`/`logged-in` use a fresh owned background tab, closed again (tp#845). |
| `switch`               | **Broker edu-ID session + SSO click, assisted fallback.** `login switch` clicks the single SWITCH edu-ID button on `/auth/login` — passwordless while the browser's edu-ID IdP session lives. When the login broker lists an `eduid` item, `login switch` first runs `login eduid` (the bundle carries the live `login.eduid.ch` session) and then clicks in a BACKGROUND tab, so it needs no window and works headless (login-log mode `broker-sso`); `agent-login.py -t switch` therefore logs in instead of only checking. Without a usable `eduid` item, or when that path does not end logged in, it falls back to the click in the shown window, and you finish the edu-ID login there once (headed only). Logged-in sentinel: on `cloud.switch.ch` outside `/auth/` with NO `/auth/openid_connect_eduid_ch` sign-in form — the anonymous root renders that form with HTTP 200, so the URL alone proves nothing. `logged-in switch` probes a background tab it closes again (never focuses the window) and exits 2 when logged out OR when it cannot tell — the `infra/status` check `switch-portal-login` runs it every 30 min. No stored credential by design: edu-ID is Albert's primary federated identity. Aliases: `switch-cloud`, `cloud.switch.ch`, `scp`. `login`/`logged-in` use a fresh owned background tab, closed again (tp#845). |

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

## Campus-only hosts (proxy PAC)

Some sites answer only from inside a campus network: `groups.epfl.ch` (needed to
read RCP group administrators) and `api.epfl.ch`, the API its pages read their
data from, time out from home. `vpn.sh epflproxy` runs an
EPFL SOCKS5 proxy on `127.0.0.1:1081` (`vpn.sh ethproxy`: ETH on `1080`). The
shared browser launches with a proxy auto-config (PAC) that sends ONLY the hosts
in `bin/pac_hosts.json` through their proxy and every other host DIRECT — no
global proxy, and never `$ALL_PROXY`:

```json
{
  "groups.epfl.ch": "SOCKS5 127.0.0.1:1081",
  "api.epfl.ch": "SOCKS5 127.0.0.1:1081"
}
```

- A key is an exact host; a leading dot (`.epfl.ch`) also matches every
  subdomain. A value is one `SOCKS5|SOCKS4|SOCKS|PROXY|HTTPS HOST:PORT`. An entry
  that is not exactly that is skipped (that host goes DIRECT) and named on
  `up`'s stderr and in `status`.
- Every proxied rule ends in `; DIRECT`: with the proxy stopped, Chrome falls
  back to a direct connection for that host (which times out off campus, as
  before) and nothing else is affected.
- `CLAUDE_BROWSER_PAC_HOSTS=<file>` replaces the committed map (same JSON
  shape; `{}` turns the PAC off). Without any host there is no proxy flag at
  all and the launch is the pre-PAC one.
- The PAC travels inline as a `data:` URL (`--proxy-pac-url=data:…`): Chrome for
  Testing 153 ignores a `file://` PAC URL (measured 2026-10-09). `up` writes a
  0600 copy of exactly what it passed to `~/.cache/claude-browser/proxy.pac`
  for reading; Chrome never reads that file.
- CDP is unaffected: clients connect to Chrome on `127.0.0.1`; the PAC only
  steers Chrome's own outgoing requests.

`browser.py status` shows the map in one line and whether the running browser
carries it:

```text
Proxy PAC: groups.epfl.ch → SOCKS5 127.0.0.1:1081 (active; DIRECT when the proxy is down)
```

The PAC is a launch flag: a change to the map (or the first deployment of this
feature) does nothing to a browser that is already running — `status` then says
`NOT in the running browser`. Apply it with a restart, when no guided login or
long-lived client is in the middle of something:

```commands
browser.py down
browser.py up
browser.py status
```

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

| Exit | Meaning                                                                        |
| :--- | :----------------------------------------------------------------------------- |
| 0    | done / logged in                                                               |
| 2    | not logged in (`logged-in`), refused, bad arguments                            |
| 3    | the login broker does not answer                                               |
| 4    | needs Albert: `agent-login.py -g SITE`                                         |
| 75   | busy: a guided login owns the browser right now — retry later; says NOTHING about the login state (`agent-login.py -c` skips such a site: no `login`, no failure mail) |
| 124  | `login`/`logged-in`/`eval-fresh` timed out; owned tabs closed; retried once by agent-login |
| 125  | timed out; tab cleanup unconfirmed; not retried                                |

`reap-owned`: 0 nothing of a dead owner left open (also: another reaper is
running, or nothing to reap), 1 a tab could not be closed (its ledger stays and
is reaped again next time), 75 busy. agent-login runs it after every run it had
to kill and at the start of the daily `-c` check.

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

The marketplace sites (anibis, tutti, Ricardo, Kleinanzeigen) run on YOUR Safari session: you log in in Safari, `browser.py login SITE` copies that site's session cookies into the shared Chromium (Kleinanzeigen falls back to the broker). CSCS and Smartsheet log in through the broker. SWITCH Cloud logs in with the broker's edu-ID session plus the portal's SSO click (no window; your own login only when the broker has no usable `eduid` item). Anthropic, OpenAI and Slack need you once (email code / SSO): `-g SITE` asks you on the terminal, then shows a remote view of a headless tab (the window only as a fallback) and waits; -t and -c only check them.

Examples:

```bash
./agent-login.py              # overview
./agent-login.py -t anibis    # real test: `browser.py login` (Safari session first,
                              # then the broker), then the positive logged-in check
./agent-login.py -c           # every usable site: logged in? if not, log in
./agent-login.py -c -m        # the same, and mail Albert when a site stays logged out
./agent-login.py -t https://auth.cscs.ch   # SITE may also be a name or login address
./agent-login.py -g anibis    # guided login: confirm, then log in via the remote view
./agent-login.py -g anthropic # your login (email code) in the shown shared Chromium
./agent-login.py -g notion -F # the same, even with unregistered CDP clients attached
./agent-login.py -P           # print the daily LaunchAgent (-I installs, -U removes)
./agent-login.py -j           # the same overview as JSON
```

#### Options

| Flag | Description |
|------|-------------|
| `-t`, `--test` `SITE` | real login test for SITE |
| `-f`, `--fingerprint` `SITE` | length + 4 hex of the SHA-256 of the broker's password for SITE (no login) |
| `-g`, `--guided` `SITE` | guided login by hand (browser.py assisted-login: confirm on the terminal, remote view of a headless tab; the window as fallback) |
| `-F`, `--force` | with -g: start even with UNREGISTERED CDP clients attached (browser.py assisted-login -f; they are not paused and keep running) |
| `-c`, `--check-all` | every usable site: logged in? if not, `browser.py login`; one line per site, exit 1 if any stays logged out |
| `-m`, `-M`, `--mail` | with -c: mail `albert.glensk@gmail.com` (gog) when a site stays logged out |
| `-r`, `--refresh` | ask the broker now (re-reads Bitwarden, ~40 s) instead of the snapshot |
| `-S`, `--snapshot` | recover a stale guided login whose watchdog died (one line), refresh the site-list and secret-run snapshots and the agents file (which also lists the secrets agents can inject), print nothing else (LaunchAgent, every 10 min) |
| `-K`, `--keychain` | rescan the login keychain (~15 s) and list every item (names only) with whether agents can read it |
| `-A`, `--agents` | print the summary agent sessions get at start (the agents file) |
| `-I`, `--install-daily` | install + load the LaunchAgents com.albert.agent-login-check (`-c -m` daily 09:15) and com.albert.agent-login-snapshot (`-S` every 10 min) |
| `-U`, `--uninstall-daily` | unload + remove both LaunchAgents |
| `-P`, `--print-plist` | print both LaunchAgent plists (writes nothing) |
| `-j`, `--json` | print the overview as JSON |
