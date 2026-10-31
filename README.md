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
browser.py eval 'document.title' [-u|--url SUBSTR]  # run JS in the most recent/matched tab → JSON
                              #   evaluates only, never navigates; several matching tabs → the
                              #   one `open` created last, plus a ⚠ line on stderr with the
                              #   count and the chosen target id (tp#1283) — address a tab you
                              #   opened with `eval -T <id>` instead; --url with no matching tab
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
(see Troubleshooting). `CLAUDE_BROWSER_LOGIN_TIMEOUT_S` (default 480; a finite
number > 0, anything else means 480) bounds every unattended `login` — its
`LoginDeadline` closes the tabs the login opened and exits 124/125; `logged-in`
gets a fixed 120 s. agent-login's runner kills `browser.py login` at this value

- 90 s as the last resort. Never applied to a guided login (`-g SITE`). `CLAUDE_BROWSER_HEADLESS` is ignored (headless is the
only mode `up` knows; `CLAUDE_BROWSER_HEADLESS=0` does NOT give a window).
Separately, the Claude Code wrapper only auto-starts the browser when
`CLAUDE_BROWSER_AUTOSTART=1` — by default it is lazy (started on first use).

## Why you never see the window

The design goal is that **driving the browser never interferes with your
desktop**: no focus steal, no window, no z-order change, no native prompt
(plans-done/PLAN_focus-free-browser_DONE.md, tp#836). It is enforced by one invariant:

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
  and no live mode-A record → revert to headless (journaled as `revert_headed`)
  BEFORE it takes the client gate, with all its output on stderr (a consumer's
  stdout — `slack-session` JSON, `token`, `open -N` — stays clean). The revert
  is a **short maintenance transaction** (`_revert_tx`, record site `revert`,
  `purpose: "revert"`, mode B): record → pause the registered long-lived
  clients exactly like a guided login (validated SIGUSR1; a paused
  `register-exec` wrapper drops its shared gate, so a Playwright MCP server no
  longer blocks the revert forever) → `switch headless` as the record's owner
  (at most 5 s for the gate, re-check under it) → record cleared → clients
  resumed (SIGUSR2). An unregistered CDP client refuses it before anything is
  paused. While the record lives, a new registration exits 75 with `busy:
  headless revert in progress (until ~HH:MM)`; a second command's preflight
  waits up to 30 s for that revert instead of starting its own, and stands
  down (`revert_skipped`, reason `busy`, no ❌, the command proceeds) when it
  outlives the wait or when a guided login owns the record. The preflight is
  skipped while another up/switch/down is in flight. A revert that fails (e.g.
  an unregistered client blocks the switch) is one ❌ line on stderr plus a
  `revert_failed` journal event — the command still runs, and the next command
  tries again. By hand: `browser.py switch headless` runs the same transaction
  (`-f` past an unregistered client); `up` on a lease-less headed browser too.
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

`assisted-login SITE` opens `/dev/tty` and asks you to **press Enter** to start
(the site name is accepted too; anything else cancels). Without a controlling terminal (an agent, launchd, a pipe) it exits **2**
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
  `eval -T <id>`, and closes it with `close -i <id>` in a `finally`.
  Never follow `open` with `eval --url`: with two tabs on the same site it
  may read the other one (tp#1283 picks the tab `open` created last and
  warns, but only `-T` is exact):

  ```commands
  tid=$(browser.py open https://example.com/ | sed -n 's/^target=//p')
  browser.py eval -T "$tid" 'document.title'
  browser.py close -i "$tid"
  ```

  Leftover tabs are not harmless: every Playwright attach waits for every page target,
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

## Tabs: who opened what, keep pins, the idle reaper (tp#1109)

Tabs outlive the agent sessions that opened them; a few days of leftovers
(ad-heavy pages, admin consoles) cost gigabytes and a busy main process. Three
commands keep that visible and bounded. Their state is
`<cache>/tabs.json` (per instance, 0600): who opened a tab, when browser.py last
used it, the pins, and when `tabs`/`reap-idle` first saw it or saw its URL
change — a hash of the URL only, never the URL.

```commands
browser.py tabs                     # every tab of every running instance
browser.py tabs -1 -j               # this instance, JSON (origins only; -f raw URLs)
browser.py open -N -k https://app.example.com/   # open AND pin
browser.py keep <target-id>         # pin a tab (full id or ≥ 8-char prefix)
browser.py keep -o https://app.example.com       # pin every tab of an origin
browser.py keep -r <target-id>      # release a pin;  keep -l lists the pins
browser.py reap-idle -A -n          # what the reaper would close (dry run)
```

- **`tabs`** shows per tab: the opener (agent session id + cwd, recorded by
  `open`; `unknown` for tabs created by anything else, e.g. the Playwright MCP),
  age, LOADED (`performance.timeOrigin`, diagnostic only), IDLE and the flags
  `keep`/`keep-origin`, `attached` (a CDP client is attached right now) and
  `owned` (an owned-tab ledger names it). Its header lists the registered
  clients with their session (`register-exec` records it).
- **Idle** = time since the latest of: browser.py opened the tab, `eval`
  (`-T` or `--url`) used it, its URL (without fragment) changed between two
  samples, or it was first seen. A tab first seen now is never idle — the
  reaper's own runs record the samples.
- **`reap-idle`** closes a page only when it is http(s), not pinned (tab or
  origin), not in an owned-tab ledger (nor a popup of one), idle at least the
  threshold (`-I HOURS`, else `$CLAUDE_BROWSER_TAB_IDLE_H`, default 2 h, floor
  15 min), and — re-read right before its close — still not attached, its URL
  unchanged, still unpinned, and not the last page of the browser. It runs
  only with NO client attached: it takes the registry gate exclusively (any
  registered client, e.g. a live `register-exec` Playwright MCP → exit 75),
  refuses when an unregistered client is attached or `lsof` is missing (75),
  when any maintenance record exists (75), then takes the interaction lease.
  The whole pass is kept short (a few seconds: every client that registers
  meanwhile waits for the gate); what it did not reach is closed next time.
  At most `-m` (20) closes per run; each is journaled (`tab_reaped`: origin,
  idle, opener session). `-n` takes no lock and writes nothing.
- **Schedule**: LaunchAgent `com.albert.browser-tab-reaper` runs
  `browser.py reap-idle -A -q` every 15 min over every running instance (it
  never starts one); log `~/Library/Logs/com.albert.browser-tab-reaper.log`
  (quiet: only closes and failures). It is one of `agent-login.py`'s
  LaunchAgents (`agent_login_jobs.agent_plists()`).
- **Agents that need a tab for long** (a dashboard they come back to) pin it:
  `open -N -k URL`, `keep <id>` or `keep -o <origin>`. A closed tab costs only
  a reload — the session lives in the profile's cookies.

## Multi-site login

A **site** is one entry in the `SITES` registry inside `browser.py`. Generic
subcommands dispatch through it:

```commands
browser.py login SITE         # ensure logged in; exit 4 + "needs Albert: agent-login.py -g SITE"
                              #   when only you can finish it (never opens a window itself)
browser.py logged-in SITE     # exit 0 if logged in, 2 if not (no login attempted)
browser.py login SITE -G      # broker site: plus value-free cookie diagnostics (below)
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
is an SSO button click that completed with no password; `sso-background` and
`broker-sso` are the same click in a background tab, on the browser's own IdP
session and on the broker's one). Read it with
`browser.py login-log` — **no arg = a live aggregate across every tool** (total real
logins, how many you had to sign in for, per-site breakdown, recent events); add a
SITE for just one. That's how you measure how often re-auth — and specifically a
manual sign-in — actually happens.

### Bundled sites

| Site                   | Login style                                                           |
| :--------------------- | :------------------------------------------------------------------- |
| `anthropic` (`claude`) | **Magic-link, fully automatic** when `ANTHROPIC_LOGIN_EMAIL` is set and `himalaya` reads that mailbox: triggers the email, extracts the `claude.ai/magic-link#<token>` URL, opens it — only if it passes the three login-CSRF guards below. Otherwise **assisted** (you finish the email login once). `login`/`logged-in` use a fresh owned background tab, closed again (tp#845). |
| `cscs`                 | **Keycloak, unattended.** `store-creds cscs` caches username/password/TOTP-seed in the macOS keychain (from 1Password, one last Touch ID); thereafter login runs with no fingerprint. TOTP codes are generated locally with `pyotp` only once the OTP field appears (never before the password submit), waiting for the next 30 s step when the current one has under 5 s left; the 1Password fallback likewise fetches its live code at fill time. A flow Keycloak aborts with `authentication_expired` (stale `session_code` on a login page left open for hours) is retried once from a fresh page with a newly generated code; a wrong password still fails on the first attempt. After login every token candidate (`waldur/auth/token` first) is checked against `/api/users/me/` and only a validated one is cached (0600): a rejected token exits 2 (log in again), a network error or an unexpected answer exits 1 with a one-line reason, never a traceback. Through the login broker (`login cscs` whenever the broker lists `cscs`), the session bundle carries `waldur/auth/token` (+ `token_expires_at`, `method`) for `portal.cscs.ch` localStorage — the broker reads it on `/profile/` in the same step that server-validated it, and a bundle without it is refused (`bundle_export`, nothing injected); the client re-checks the token against the API before touching any cookie, writes it with an init script BEFORE the portal app loads on `/profile/` (never `/`, where boot-redirect.js runs) and reads it back. The logged-in proof (broker and client) is a SERVER proof: from the portal page it asks `/api/users/me/` with the stored token (the app's own scheme) — 200 with an identity is logged in, 401/403 is not, a timeout/5xx is undecided; a token's shape proves nothing (an expired one looks the same). It is strict without a DOM sentinel. `login`/`logged-in` use a fresh owned background tab, closed again (tp#845). |
| `openai` (`chatgpt`)   | **Assisted.** ChatGPT Business logs in via Google SSO + 2FA, which can't be replayed from a stored secret — you complete the SSO once in the shared window; the session persists. Logged-in sentinel: the 'Invite member' button on `chatgpt.com/admin/members`. `login`/`logged-in` use a fresh owned background tab, closed again (tp#845). |
| `console` (`platform.claude.com`) | **Magic link, fully automatic** (like `anthropic`). The Claude Console (platform.claude.com) has a login separate from claude.ai's. `login console` with `$CONSOLE_LOGIN_EMAIL` set clicks "Continue with email" (never the Google button, never a password), reads the `platform.claude.com/magic-link#…` mail via himalaya (`$ANTHROPIC_LOGIN_HIMALAYA_ACCOUNT`, folders `$ANTHROPIC_LOGIN_MAIL_FOLDERS`, default `INBOX,Archive`) under claude.ai's three guards (sender allow-list, pre-trigger baseline, the link's own e-mail) and opens it; otherwise exit 4. `./agent-login.py -L console` (work, epfl mailbox, shared browser) / `-L console-private` (gmail mailbox `INBOX`, private instance, CDP 9223) set all of that; `-g` is the hand login. `logged-in console` is tri-state from the Console's own `/api/account` (401/403 = logged out); agent-login checks WHICH account each instance holds. Read by `console-balance.py` (below). |
| `slack`                | **Assisted.** app.slack.com logs in via email-code / SSO; you sign in once and the session persists. Logged-in sentinel: a team with an `xoxc-` token in `localConfig_v2`. `browser.py slack-session` then prints `{token,cookie,team_domain}` (xoxc + httpOnly `d` cookie via CDP) so `slack-api` can call `users.admin.setInactive` on the Pro plan — where the API token is scope-blocked. Bearer creds → stdout only, never cached. `login`/`logged-in` use a fresh owned background tab, closed again (tp#845). |
| `notion` (`notion.so`) | **Assisted.** Notion logs in by e-mail code or SSO, which can't be replayed from a stored secret — you sign in once in the shared window (`./agent-login.py -g notion`); the session persists. Logged-in sentinel: the workspace sidebar (`.notion-sidebar` / `.notion-sidebar-switcher`) on `app.notion.com` outside `/login` — notion.so and its `/login` both redirect to that host, so the URL alone proves nothing. `logged-in notion` probes a background tab it closes again. Aliases: `app.notion.com`, `notion.com`. `login`/`logged-in` use a fresh owned background tab, closed again (tp#845). |
| `biopolwifi`           | **Env email+password, no keychain.** SDSC Biopole WiFi units are managed via a Ruckus Cloudpath MDU portal (`cloudpath.edificom.cloud`, a plain Vue SPA). Run `env-profile-run.py biopol-wifi -- browser.py login biopolwifi`: the profile injects `BIOPOLWIFI_EMAIL` / `BIOPOLWIFI_PASSWORD` from the vault item `biopol-wifi` (the same variables `sdsc/biopol-wifi/biopol-wifi.py` reads); without them `login` exits 1 naming the missing variable, and `store-creds` / `forget-creds biopolwifi` only print that hint. Login fills the form and confirms the `SDSC - Biopole` / `Properties` sentinel. No SSO, no TOTP, no token extracted. Aliases: `biopol`, `cloudpath`, `edificom`. `login`/`logged-in` use a fresh owned background tab, closed again (tp#845). **The portal's session is per tab** (a ~5-min token in the tab's sessionStorage, no session cookie), so it ends with the `login` tab: `login` proves the credential, and `logged-in` answers 2 afterwards, naming that reason when it finds the login form (tp#1059). |
| `switch`               | **SSO click, then broker edu-ID session + SSO click, assisted fallback.** `login switch` clicks the single SWITCH edu-ID button on `/auth/login` — passwordless while the browser's edu-ID IdP session lives. A cold portal session tries, in order: (1) that click alone in a BACKGROUND tab on the profile's own edu-ID session (login-log mode `sso-background`) — it gives up within ~2 s once the tab settles on the `login.eduid.ch` login form (no live IdP session), so it costs little when it cannot work; (2) when the login broker lists an `eduid` item, `login eduid` (the bundle carries a live `login.eduid.ch` session) and the click again in a background tab (mode `broker-sso`). Neither needs a window, so both work headless — and the first works even while the broker is in a cooldown; `agent-login.py -t switch` therefore logs in instead of only checking. When both fail, it falls back to the click in the shown window, and you finish the edu-ID login there once (headed only, inside `agent-login.py -g switch`); outside a guided login it exits 4, and when the broker refused as rate limited the `needs Albert` line says so (`(or wait: the broker rate-limits eduid — cooldown after a failed login: retry in 1487s)`). Logged-in sentinel: on `cloud.switch.ch` outside `/auth/` with NO `/auth/openid_connect_eduid_ch` sign-in form — the anonymous root renders that form with HTTP 200, so the URL alone proves nothing. `logged-in switch` probes a background tab it closes again (never focuses the window) and exits 2 when logged out OR when it cannot tell — the `infra/status` check `switch-portal-login` runs it every 30 min. No stored credential by design: edu-ID is Albert's primary federated identity. Aliases: `switch-cloud`, `cloud.switch.ch`, `scp`. `login`/`logged-in` use a fresh owned background tab, closed again (tp#845). |

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

| Field                      | Meaning                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| :------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `agent_fill_origins`       | **Required.** Exact `https://host[:port]` origins (comma/newline separated) where the broker may type the secrets; re-checked before every fill and submit.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `agent_site`               | Short site id (default: the item name as a slug).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `agent_check_url`          | Page that needs the login: where the positive proof runs (built-in defaults for known sites).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `agent_logged_in_selector` | **Required for scheduled logins and promotion** — except for a site with a registered SERVER proof (`recipes.PROOFS`: `cscs` asks its API with the stored token; the sentinel is then an optional extra). CSS sentinel (plain CSS, no Playwright `text=`/`xpath=`/`>>`) visible only when logged in. The strict proof: HTTP status < 400, the page on the check URL's origin (or `agent_proof_origins`), and this sentinel visible. Without it, manual logins and checks keep the old, weaker proof (off the fill origins, no password field — an Access-Denied page passes that): agent-login flags the row `needs sentinel (old proof)`, `-c` never logs it in, `-p` refuses it, and a scheduled request gets `needs_sentinel`. Find one with `browser.py logged-in SITE -x 'CSS'` (two-sided: present here, absent in a fresh logged-out broker profile); for a site logged out everywhere, one approved `browser.py login SITE -x 'CSS'` (plain broker sites and cscs only). |
| `agent_login_url`          | Where the login starts (default: the check URL, which redirects to the login with its state).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `agent_cookie_hosts`       | Hosts (and their subdomains) whose cookies leave the broker in the bundle. An identity-provider host (`login.eduid.ch`, `auth.cscs.ch`, `idp.*`, …) is exported only when listed exactly.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `agent_cookie_names`       | Optional cookie-name allowlist within those hosts.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `agent_storage_keys`       | JSON `{origin: [keys]}`: localStorage keys handed over too.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `agent_otp_label`          | Which authenticator to answer when the account offers several (substring of its label).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `agent_fresh_login`        | `true` (also `1`/`yes`/`on`; default `false`): every login first deletes the broker profile's cookies for the cookie hosts and fill origins (host, subdomains, parent domains), skips the "profile still logged in" shortcut and runs the full login (e-mail, password, TOTP). Needed when the bundle must carry an IdP's **session-only** SSO cookie, which the broker profile loses whenever it closes — e.g. SWITCH edu-ID: `agent_cookie_hosts = eduid.ch login.eduid.ch` plus `agent_fresh_login = true` hands the shared Chromium a live `login.eduid.ch` session, so an OIDC authorize there needs no typing. Every call is a real login and counts against the rate limiter.                                                                                                                                    |
| `agent_pre_click`          | CSS selector of an element clicked as soon as it shows, before the login fields are looked for (only while the page and the element are on a fill origin; skipped when the login password field shows first). Clicked again every 3 s while it stays visible and no login field appears — a SPA can show it before its click handler is attached — e.g. Jellyfin's user picker: `.btnManual` reveals the manual login form.                                                                                                                                                                                                                                                                                                                                                                                             |
| `agent_proof_origins`      | Further `https://host` origins (besides the check URL's) where the proof page may end after redirects.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `agent_attempt_group`      | Opaque slug shared by items that log into ONE account (e.g. two shop domains on one identity provider): the broker limiter then enforces interval, cooldown, caps and the hard block on `group:<id>` too. Must not contain the account name. Reset: `sudo install/install.sh -r group:<id>`, or `-r SITE -G`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `agent_no_submit`          | `true` (default `false`): the broker's login NEVER asks for this item's secret, so it never types or submits its password — a login answers `submit_disabled` (phase `vault`, nothing reserved); a still-valid broker profile is exported as before. For IdPs whose bot check rejects the headless broker (every submit risks a vendor lock): agents use Albert's session there (Safari import, `agent-login.py -g SITE` in the window), and `agent-login.py` shows the site as your login. Built in, and not lifted by `false`: the sites `galaxus` and `galaxus-de` (`vault.NO_SUBMIT_SITES`) and every item with a fill origin on a Digitec Galaxus domain (`vault.NO_SUBMIT_DOMAINS`, whatever the item is called). The secret ops (`secret-run`) never expose such an item either.                                 |
| `agent_max_session_days`   | Whole days (1–365), only together with `agent_fresh_login = true`: renew the session with a fresh login once the last proven fresh broker login is this many days old, while the session still works. For servers that end a session a fixed time after its login however much it is used — Calibre-Web Automated: 31 days, so set `28` (the daily check then has 3 days to succeed). The age counts from this client's last PROVEN fresh broker login (`~/.cache/claude-browser/session-age/SITE.json`, written once a fresh broker login was injected and verified); with none on record, from the first check that saw the session — a lost or unreadable record means "age unknown", never a renewal loop. One renewal attempt per 20 h at most (claimed under a per-site lock before it starts), whatever its outcome. `browser.py login` and `agent-login.py -c` renew under the usual gates (pending, quarantined, locked … → only a note); a failed renewal keeps the working session (exit 0, `renewal: failed` in the result record). |
| `agent_login_mode`         | `password` (default) or `username-only`: the item's USERNAME alone is the credential (Mullvad's account number, no password on the item). The broker types it into the login form's only field (a masked one like Mullvad's `input[type=password][name=account_number]`, else a username / account-number field) and submits it under every password rule: tripwire armed first, buttons read fail-closed, submit marker right before the click, proof by the sentinel; same attempt / limiter / quarantine semantics. A form that asks for more (a password too) gets nothing typed (`recipe`, not submitted). Such a username is a secret: masked in diagnostics (also when the page shows it in groups), no failure screenshot is ever taken, no report shows its length or a hash, a page that submits it by itself is marked submitted before the request leaves and never submitted twice, and the secret ops (`secret-run`) never expose an item that carries this field. Only for sites on the generic recipe. An item without a password in `password` mode now fails with `no_password` ("set agent_login_mode=username-only, or check the item / the collection permission"), a username-only item without a username with `no_username`. |
| `agent_safari_fill`        | `true` (default `false`; any other value refuses the item): the broker's `safari_fill` op may hand this item's username / password, or its TOTP code, to Albert's uid so an agent fills it into his own Safari (`safari.py -L`) — only for one of the item's fill origins, only while the console is unlocked and used within 15 min, rate-limited (10/h per item, 15 distinct items a day), leak-registered and audited. No-submit items may opt in, username-only items never. Set it with mydotfiles `broker-add.py` (Touch ID approval). Threat model: it contains accidental leaks and shrinks exposure from the whole unlocked vault tab to the opted-in items; it is no barrier against a hostile process running as Albert. |
| `agent_fill_only`          | `true` (default `false`; any other value refuses the item): a FILL-ONLY item (tp#1082) — the broker never logs in, checks, probes, challenges, schedules or exports it; every such op answers `fill_only` (a skip: no limiter charge, quarantine or failure mail), and only `safari_fill` serves it (it implies `agent_safari_fill`). It needs only `agent_fill_origins` (required): no check URL or sentinel, because nothing is ever proven logged in; check / login / cookie / storage / identity fields on it are ignored and the `sites` view shows them empty. Never a `secret-run` value (gate code `fill_only`), no ✅/❌ row in `agent-login.py` (the agents file has one line with the count; `agent-login.py -l` lists every fillable item). Onboard with mydotfiles `broker-add.py NAME -Z` (Touch ID approval). |

### Submit safety: never a guess, never a secondary action (WS2-calibre)

Calibre-Web Automated puts its `Forgot Password?` submit button BEFORE `Login`;
Enter in the password field fired it and reset the admin password (2026-10-08).
The generic recipe now:

- **fails closed**: the form's submit buttons are read first; when they cannot
  be read, or only secondary buttons (forgot, register, show password, delete
  account, log out …, also by a button's `value` or `formaction`) show,
  nothing is submitted (`recipe` ·
  `submit_unidentified`, before the submit marker). Enter is pressed only for a
  form without submit buttons or when its default button is a login button;
  otherwise the login button is clicked. The username step of an
  identifier-first login and the OTP step follow the same rule; Keycloak's
  generic fallback button and Smartsheet's sign-in are a known login button or
  nothing (on the broker path guarded like every submit: frame, `formaction`,
  page origin).
- **screens every submit** with a tripwire (`recipes.SubmitTripwire`, a
  Playwright route on the fill origins, context-wide so popups count, from
  the first submit on). Screened are form navigations (a navigation with a
  body, or a GET form) until the login went out, and every request that
  carries the username / password / OTP field — after the login, the app's
  own traffic is left alone. One that names a secondary action — the
  (name, value) a secondary button of THIS step posts (a name a login button
  shares never counts: Rails `commit`, Auth0 `action`),
  `forgot`/`reset`/`register`/`signup`/`resend` as a top-level key (not when
  its value says `false`/`0`) or as the value of `action`/`submit`/…, or such
  a URL path — is aborted inside the browser (`submit` ·
  `secondary_action_blocked`, and the site is quarantined: the broker
  misreads its form; the route then stays until the context closes). The
  attempt counts as `not_submitted` only with proof that nothing left: the
  tripwire was armed before the password was typed, no service worker of a
  fill origin ran, and every request of the whole browser context that could
  carry the password (body, query, `Authorization` header) is one it aborted
  (by request identity).
- **the OTP step** submits like the password (a "Resend code" default button
  is never pressed: Verify is clicked), under the tripwire; a page that posts
  the code by itself (GitHub) is marked submitted and left to the settle loop.
- **ticks a session "remember me"** (`Remember me`, `keep me signed in`,
  `angemeldet bleiben`, `rester connecté` …, or a `remember_me`-like name)
  before typing the password — never a box about a device, a browser, a choice
  or the user name (a trusted device is another policy); a hidden styled box
  through its visible label. Apps that bind a session to IP + User-Agent keep
  an injected session only through it.
- **stops at Cloudflare Access**: a check or login page on
  `*.cloudflareaccess.com` or under `/cdn-cgi/access/` (off-LAN) is
  `precheck` · `access_gated` — nothing reserved, typed or submitted, and
  agent-login reports the site as "unreachable off-LAN", never ❌. Before a
  login the broker loads the login page first (before anything is reserved);
  one that answers HTTP 401/403 is `precheck` · `login_blocked` (an Access
  block page or an IP gate has no login form of the site's) — unless it is a
  bot challenge (`cf-mitigated: challenge`, "Just a moment", a captcha): that
  is `needs_human` (exit 4).

### Where a login broke, and why the daily check never burns the limiter (WS1a)

Every `browser.py login`/`logged-in` can write a result record (`-R PATH`): the
PHASE it stopped at (`precheck`, `limiter`, `vault`, `recipe`, `submit`,
`profile-proof`, `broker-proof`, `bundle-export`, `cookie-inject`,
`storage-inject`, `client-proof`, `consumer-followup`, `safari-source`,
`unknown`; vocabulary in `broker/phases.py`), a fixed code, a redacted detail,
the broker's failure screenshot and the limiter state with the exact reset
command. `agent-login.py` stores it in `~/.local/state/agent-login/checks.json`
and shows `phase · reason — detail 📷 screenshot` per ❌ row. `agents.md` only
ever shows the fixed phase/code texts (no page text). `last-check.json` stays
as a legacy projection (`ok`, `how`, `at`) for infra/status: `ok=false` is red;
a check that could not tell (offline, busy) is `ok=false` and does not move `at`.
Each record also keeps `identity_history`: the last 10 identity proofs that did
not come back `match` (when, state, verdict, the recipe's fixed `why` word, HTTP
status, code, redacted detail), because the next check overwrites `detail`.
`agent-login.py -H [SITE]` lists them (`-j`: JSON); `-t SITE` prints the newest
three after its verdict.

`browser.py login SITE -G` (`--diag`) asks the broker for `bundle_diag` (request
field `"diag": true`, audit-logged as `diag`): every cookie its profile holds on,
under or above the item's scope hosts — domain, path, name, session, httpOnly,
secure, sameSite, partitioned, kept or `why_dropped` (`out_of_path`,
`out_of_scope`, `parent_domain`, `idp_host`, `not_in_cookie_names`, `no_name`;
at most 64) — plus `via` (`login`, `profile`, `sso`) and the localStorage /
sessionStorage key names and IndexedDB names of the broker pages already open on
the item's origins. The client adds `inject_diag`: per host the cookies handed
to `add_cookies` and the ones the browser holds afterwards, the cookies its own
scope filter dropped, and every cookie the browser silently did not keep (with
a likely reason: Chromium's `Storage.setCookies` drops a `SameSite=None` cookie
without `Secure` without an error). Both are printed and written to the `-R`
record. Never a value, a digest or a length of one. Only a broker login carries
them: an already logged-in site makes no broker request.

A broker profile REUSE (`via` `profile` or `sso`) runs in a freshly launched
Chromium, which restores no session cookie (no `Expires`/`Max-Age`). Keycloak's
`KEYCLOAK_IDENTITY` is one (without "remember me"), its `KEYCLOAK_SESSION` is
not — so a reused profile exports `KEYCLOAK_SESSION` without the SSO cookie
behind it. An item whose session needs the IdP's SSO cookie sets
`agent_fresh_login = true`.

A site without a sentinel keeps working with the old proof (a warning, never a ❌ by
itself); `agent-login.py -x` also lists sites whose last check ended on another origin than
the check URL's (set `agent_proof_origins` for them), and `agent-login.py -V` runs the
onboarding review over every listed item (below). A ✅ is a proven check no older than 36 h (`AGENT_LOGIN_MAX_STATUS_AGE_S`);
older reads ❓ stale. Broker sites start **pending**: the daily `-c` (no mail —
logged-out sites are an infra/status item) only probes them until
`agent-login.py -p SITE` promotes them — for their current configuration only
(see "Adding a site to the broker"). A login that may have submitted the password
and failed **quarantines** the site for every client until
`agent-login.py -Q SITE`; the broker itself refuses a scheduled login while any
of the site's keys has an unresolved failure. `-c` never logs in a pending,
quarantined, locked, cooling-down or sentinel-less site, and never retries
after the broker request started. The limiter is consulted only when the
secret is needed: a still-valid broker profile is re-exported even during a
cooldown, and the attempt counts as post-submit only once the password reached
the page. `agent-login.py -x` prints the acceptance matrix (consumer,
privilege, sentinel, scope, attempt group, refresh policy, stage, limit, last
phase).

`broker-add.py` (mydotfiles `bin/`) writes these fields and the collection
membership from the command line. Agents may run it themselves once Albert has
enrolled Touch ID approval (`vault-touchid enroll -a main`, mydotfiles
`tools/vault-touchid/`): each run asks for two Touch ID touches — one to open the
main vault, one after the vault-touchid window has shown every change — and the
master password never reaches the agent. Without the enrolment it asks for the
typed master password in a terminal. `-N` (new items from the Keychain) is not
available through Touch ID; it needs `-P` in a terminal. On an item that
already carries `agent_fill_origins` / `agent_check_url` / `agent_cookie_hosts`,
a run that derives the login fields (a derive option, a batch row with a
`site` cell, `-Z`) keeps them unless `-o` / `-c` / `-k` name new ones. A run
that would drop a fill origin without `-o`, or move the check URL without
`-c`, is refused (exit 2, nothing written). A re-derivation once moved the
CSCS check URL onto its Keycloak login origin and broke the broker login
(tp#1133).

### Adding a site to the broker (WS3)

Every item goes through the same four steps. Each guards against a failure
that actually happened in October 2026.

1. **Review before the write.** Dry-run the item (`broker-add.py NAME … -n`),
   put its planned `agent_*` fields into a manifest
   (`{"name": …, "fields": {"agent_site": …, …}}`; add `"replaces": SITE` to
   change an item that is already listed; never a password), and run
   `./agent-login.py -V -i planned.json`. With the manifest's
   `"collections": {"login": ID, "secrets": ID}` (or `{"login": ID}` alone:
   one collection) the review also judges each item's collection membership
   with the broker's own rule (`vault.collection_membership`), for the gate
   mode the broker reports (`secrets` answer, saved in the secrets snapshot):
   under `collections` an item whose `collectionIds` name both collections
   is `refused` (a new item without `collectionIds` goes into the login
   collection only); under `agent_script` it is fine. A malformed
   `agent_script` is `refused`, `agent_script=true` on an
   `agent_privilege=admin` item is a `risk`, and a gate the review cannot
   read blocks (`gate_unknown`).
   - It is the broker's own code (`vault.site_item_from_json` and
     `identity_rules` over the whole collection, `broker/onboarding.py`), so it
     says exactly what the broker will refuse.
   - It also shows every established item the change would refuse
     (`displaced`) or turn into an unprovable multi-account item
     (`made_unproven`). Example: the in-instance rule refuses the LATER site id,
     so a new item can knock out an old one.
   - Levels: `refused` (the broker refuses it), `unusable` (it can never be a
     proven ✅: no sentinel or server proof, an account the client cannot
     prove, a username-dependent field it could not check), `risk` (a cookie
     host that is a public suffix per the vendored Public Suffix List, a scope
     or storage origin unrelated to the item, malformed storage keys) and
     `hint` (an attempt group for a same-account pair, a refresher for a
     storage token, a wide or IdP scope).
   - `refused` / `unusable` / `risk` block `-p`. `risk` also keeps `-c` from
     logging the site in. `./agent-login.py -V` reviews every listed item.
2. **Write, then refresh:** `broker-add.py NAME …`, then `./agent-login.py -S`.
3. **Find the sentinel.**
   - Logged in somewhere: `browser.py logged-in SITE -x 'CSS'` (two-sided:
     present here, absent in a fresh logged-out profile).
   - Logged out everywhere: ONE approved `browser.py login SITE -x 'CSS'`.
   - Then `broker-add.py NAME -L 'CSS'`.
4. **Promote:** `./agent-login.py -p SITE` is the one promotion transaction.
   - It needs a fresh listing, a strict proof and no blocking finding.
   - A fresh strict ✅ of the item's CURRENT configuration on record promotes
     at once.
   - Otherwise it runs ONE `browser.py login SITE`, with no retry. That run's
     own free check is the probe, and its own verify is the proof.
   - That login is the site's promotion budget, claimed atomically in
     `site-state.json`. It is refunded only when the record proves the
     password was never sent. `./agent-login.py -E SITE` re-arms it after a
     review (audited; `-Q` releases only a quarantine).
   - `-t SITE` on a site that is not usable takes the same budget.
   - A promotion holds for ONE configuration: the digest of what the vault
     item says (`onboarding.config_canon`, versioned `CONFIG_V`; never a
     view-format detail or a flag the broker's code derives, so a broker
     release does not change it). Opting an item in to Safari fill
     (`agent_safari_fill`) is not part of it: it changes nothing the
     broker's own login does. A changed item (another sentinel, scope,
     URL, instance …) is `changed` and not logged in by `-c` until it is
     promoted again. A promotion of an older (or no) digest version is
     `config_unknown` and adopts the current digest at the next `-S`: at
     once when the item's config is unchanged (its digest recomputed under
     the old version matches, whatever the last check said), else only
     while its latest check is a fresh strict ✅.
   - The client state (stage, budget, quarantine) is policy and audit, not a
     security boundary: every same-uid agent can write it. The boundary is
     the broker's limiter (root-only reset).

**Removing a site** (e.g. docker / docker-hub):

1. `./agent-login.py -D SITE` while the item is still listed. It demotes the
   site to pending and runs `browser.py logout SITE` in its instance, which
   removes the broker's profile, the scoped cookies and the declared
   localStorage keys (read back; a failure stops here). When another
   account's item shares the scope in the same browser (abs-root /
   abs-albert) it does NOT log out — that would end the other session — and
   says so; `-F` forces it (docker / docker-hub, which both leave).
2. Take the item out of `agent-login` (`broker-add.py NAME -D` once it
   exists, else the web vault).
3. `./agent-login.py -D SITE` again. The broker's `forget` op, run by the live
   daemon under the site's lock after its own fresh vault read (refused when
   that read is empty or shrank below half, or when any item — refused ones
   too — still resolves to the id), drops the site's limiter key and bindings
   (a group key only when nothing else uses or declares it), its
   identity-guard entry, its profile and its failure screenshot. A removal
   never lifts a block: a locked / cooling-down / quarantined limiter key
   and an identity lockout stay, reported for `sudo install/install.sh -r
   SITE`.
   The client deletes its `checks.json`, `last-check.json` and
   `site-state.json` entries (quarantine and audit included) and its
   session-age (data only; an empty lock file stays) and login-log files in
   every instance's cache dir.
4. One line in `~/.local/state/agent-login/audit.jsonl` (and the broker's
   audit.log) is all that stays.

**Failure modes learned** (symptom → what to do):

| Failure                         | Symptom                                                                    | Do                                                                                                                                                                                                                       |
| :------------------------------ | :------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Stale vault password            | `submit` "still on login page" right after a rotation (npm, runai-test3)   | Before ANY submit: `./agent-login.py -f SITE` (length + 4 hex) against the authoritative copy (SOPS, the server's hash). Fix the vault item, never retry blindly.                                                          |
| SPA stale cache                 | blank page, `indeterminate` after an app upgrade (NPM)                     | Nothing per site: every broker launch clears its HTTP cache, the client's proof tabs bypass it. A blank page is never "logged out".                                                                                      |
| Hash-only check route           | `goto` returns no response, status 0 → `indeterminate` (portainer, jellyfin) | The proof loads the check page fresh (about:blank first); keep `agent_check_url` on the route that needs a login.                                                                                                       |
| Token-rotating / expiring SPA   | exact read-back fails (navidrome), or a daily password submit (NPM JWT)    | Storage writes are proven at document start; declare `agent_session_refresh` when a refresher exists (`hint storage_no_refresher`).                                                                                     |
| Invisible captcha               | a false `needs_human` on a self-submitting reCAPTCHA page (myfritz)        | Already classified: an invisible anchor is not a challenge; a checkbox / popup is. Never click a challenge.                                                                                                             |
| Username-only login             | `no_password` (Mullvad's account number)                                   | `agent_login_mode=username-only`; the username is then the secret (masked, no screenshot).                                                                                                                               |
| Multi-account scope conflict    | every sibling ✅ while the browser holds ANOTHER account (gitlab-sdsc)      | `-V -i` shows `account_unproven` / `displaced`: set `agent_instance`, `agent_privilege`, `agent_identity` (a usable recipe) or `agent_same_account_as` on both.                                                          |
| Path-scoped Keycloak realms     | two realms on one host clear each other (custos-admin vs runai)            | `agent_cookie_scopes` (`[{"host": H, "path": "/realms/R/"}]`) instead of a host-wide scope.                                                                                                                              |
| Enter-key forgot-password trap  | a submit pressed `forgot` and reset the password (calibre)                 | Submits read the form's buttons first and fail closed; the tripwire aborts a secondary action. A new recipe uses the same helpers; audit a form with secondary buttons before its first login.                          |

### Accounts that share a site (WS5)

One cookie scope holds one account per browser. Two items that log into
different accounts on the same site (gitlab-sdsc glensk vs admin, dsm albert
vs readonly) would silently overwrite each other's session while both still
read ✅ (tp#833). So each such account lives in its own browser instance:

| Instance  | CDP port | Holds                                                               |
| :-------- | :------- | :------------------------------------------------------------------ |
| (default) | 9222     | the default account of every site                                   |
| `private` | 9223     | Albert's private claude.ai account                                  |
| `admin`   | 9224     | admin accounts (`gitlab-sdsc-admin`, `runai-admin`, `dsm-albert` …) |
| `alt`     | 9225     | a further account that conflicts with both (`custos-admin`)         |

Item fields (`broker/vault.py`; written with mydotfiles `broker-add.py`):

| Field                   | Meaning                                                                                               |
| :---------------------- | :---------------------------------------------------------------------------------------------------- |
| `agent_instance`        | the instance the item lives in (`""` = 9222, `admin`, `alt`)                                          |
| `agent_privilege`       | `admin` / `user` / `readonly`; mandatory on a multi-account item and with `agent_identity`            |
| `agent_identity`        | the reviewed recipe (`identity.IDENTITIES`) that proves WHICH account a session holds                 |
| `agent_same_account_as` | the site id of an item that logs into the SAME account; declared on both items, else both are refused |
| `agent_alias`           | a short name the group's default member also answers to (`gitlab-sdsc` → `gitlab-sdsc-glensk`)        |
| `agent_cookie_scopes`   | path-scoped cookies (`[{"host": H, "path": "/realms/R/"}]`) for realms that share a host              |

The broker refuses an item that would put a second account into a scope of
the same instance (`identity_rules`). A multi-account item passes `browser.py logged-in`
only with the **server identity proof**: the item's reviewed recipe (gitlab,
audiobookshelf, navidrome, dsm, authentik, runai, keycloak-admin) asks the
site's own API in an isolated world of the probe tab, against a one-use broker
challenge; only a digest crosses CDP or the socket, never a username or token.
Without a usable recipe the item reads `identity_unproven` and is never logged
in. A check that finds a foreign account's session in the item's instance
(`wrong_account`) clears that session's cookies (and, for storage-token apps,
its declared storage keys) in that instance only, never the broker's profile;
the next login then starts logged out.

`login` / `logged-in` of an item re-run themselves in its instance; a run
pinned to another instance or port refuses (`wrong_instance`). Role instances
start on demand (`CLAUDE_BROWSER_INSTANCE=admin browser.py up`, then `down`);
the Playwright MCP reaches `admin` only through the opt-in `playwright-admin`
config. `agents.md` groups such items under "one site, several accounts —
never two in one browser; pick the account the task needs (ADMIN = admin
rights)": the default member (or its alias) for ordinary work, the ADMIN
member only when the task needs admin rights, with the instance prefix shown
on its line.

### Credential rotation safety (tp#965)

A credential's master is a Vaultwarden item that mydotfiles `credctl rotate`
rotates (tp#889). The broker takes three precautions so a rotation can never
leak a password, lock an account or race a login:

- **No password oracle.** The old `fingerprint` op (length + 4 hex of the
  password's SHA-256, also printed as `password_check` in every failure report
  and by `agent-login.py -f`) was an offline verifier: it is removed. The op
  answers `{"ok": false, "error": "removed"}` for one release, then it is an
  unknown op. To check whether two copies hold the same password, use
  `credctl.py check -T` in mydotfiles (Touch ID window).
- **Usernames are not inventoried (tp#1138).** Every value the broker serves
  (`secret-run`, `safari_fill`) is registered with the secretkeeper's
  live-credential inventory, which the global `secret-check-index` pre-commit
  hook reads — except a field named `username`: it identifies an account and
  appears in commits on purpose (a Gmail login). An item whose username IS the
  credential (an account number, an application key) carries the custom field
  `agent_secret_username_is_credential = true` and keeps it inventoried; any
  value other than `true`/`false` refuses the item. The broker re-pushes its
  labels once at start and then every 10 min.
- **One item, one collection — the `agent_script` gate (tp#991).** ONE
  Vaultwarden collection holds every agent-usable item. The browser fill is
  unchanged (items with `agent_fill_origins` / `agent_site`, origin binding,
  limiter). `secret-run` injects an item only when it carries the custom
  field `agent_script = true`; a missing, `false` or malformed value is a
  refusal (fail closed). The flag authorizes handing the RAW value to any
  child process an agent picks — masking is output hygiene, not a boundary —
  so it goes only on credentials a script really reads; admin website logins
  without a script (authentik, DSM, GitLab admin, …) never get it, and the
  onboarding review flags `agent_script` on an `agent_privilege=admin` item
  as a `risk`. The gate is staged by the bootstrap key `secret_gate`
  (`sudo install/install.sh -W MODE`, rollback `-W collections` or `-B`;
  `secret_gate_since` records the switch):

  | Mode                      | What `secret-run` reads                                                                                                                                                                                                                                                                                                                                  |
  | :------------------------ | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
  | `collections` (default)   | the legacy secrets collection (`secrets_collection_id`), exactly as before; an item listed in BOTH collections is refused on both sides by its own item id (`in both agent-login and agent-secrets: split it`)                                                                                                                                           |
  | `report`                  | the same, plus ONE `gate_would_refuse` audit line per issued item that mode `agent_script` would refuse (item id + `gate_code`, never a value) — the soak before the flip                                                                                                                                                                                |
  | `agent_script` (enforced) | the login collection AND, until `install.sh -D` drops it, the legacy secrets collection, merged by item id; only flagged items are served; an item in both is no refusal; an item with neither `agent_site` nor `agent_fill_origins` is a script-only item (no site), flagged or not — unflagged it is still refused by `secret-run` (`no_agent_script`) |

  Every item of either read must carry `collectionIds` as a list of strings
  (else `collection membership unreadable`, refused in every mode). Every
  `secrets` row carries `kind` (`secret` = legacy collection, `login`),
  `agent_script` (true / false / `malformed`) and `gate_code`, a closed set
  — `ok`, `no_agent_script` (text: `script read without agent_script`),
  `bad_agent_script`, `held`, `no_submit`, `username_only`, `fill_only`, `duplicate_id`,
  `membership_unreadable`, `invalid_item` — which in the first two modes is
  what mode `agent_script` WOULD answer; a refused `secret`/`totp` request
  carries the item's code. Ids: a legacy item keeps `agent_secret_id` → the
  name slug in every mode; a login-collection item uses `agent_secret_id` →
  `agent_site` → the slug; two FLAGGED items claiming one id are both
  refused (`duplicate_id`), an unflagged login claims none. A flagged
  username-only login exposes its username as `password`; no-submit, fill-only
  and held items are never injected. An unknown `secret_gate` refuses `secrets`,
  `secret` and `totp` (`bad_secret_gate`) while logins, `secret_done`,
  `audit` and `invalidate` keep working. No comparison op exists: credctl
  compares a flagged item's copies inside its own compare child, started by
  `secret-run -s` (plan `PLAN_cred-one-collection.md`, "Compare interface").

  **Service-bound items (tp#1303, mydotfiles `PLAN_mem-hmac-key.md`):** the
  root-installed table `broker/vault.py` `SERVICE_ITEMS` (today only
  `mem-service-hmac` → `com.albert.mem-serve`) binds an item to ONE service.
  Such an item is refused by `secret` / `totp` in every mode, whatever its
  `agent_script` says (`gate_code` `service_only`), and is left out of
  `secrets` (so `secret-run -l` never shows it). Only the op
  `service_secret {item, field, service}` returns it, to the configured uid,
  for its bound `service` (else `forbidden_service`), never while the item
  carries `agent_hold` (`held`), at most 6 per hour / 24 per day
  (`service:<item>`, plus the global cap), after the leak check registered
  it. Its audit line carries the item, the service and value-free telemetry
  (`peer_pid`, `peer_ppid`, `peer_exe` from `/bin/ps`) that `mem doctor`
  checks. This is NOT an authorization boundary: any process of the
  configured uid that names both gets the value; the gain is that no agent
  tool hands it out and every grant is one line in a log the broker's uid
  owns. Changing the table needs a reviewed release (`sudo install/install.sh`).

  | Tool                                  | What it shows                                                                                                                                                          |
  | :------------------------------------ | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
  | `sudo install/install.sh -M`          | membership defects only (dual / unreadable): side, status, safe name, item id; exit 0 none, 3 some                                                                     |
  | `sudo install/install.sh -g`          | the gate report: items `secret-run` serves TODAY that mode `agent_script` would refuse, plus malformed flags (kind, code, id, safe name, item id); exit 0 none, 3 some |
  | `daemon.py -g -j` (as the broker uid) | every row mode `agent_script` would list, one JSON object each — what `install.sh -D` checks                                                                           |
  | `secret-run -V`                       | `{"v": 1, "gate": …, "features": […]}`; exit 125 for `bad_secret_gate` / `unknown`                                                                                     |
  | `secret-run -l` / `-l -j`             | injectable items; unflagged logins folded into ONE line / every row with `kind`, `agent_script`, `gate_code`                                                           |

  **The flip (main session, parent plan tp#889 R7g/R7m/R7h):** list what
  consumers read (`install.sh -g`, `secret-run -l -j`); set
  `agent_script=true` on each, in place (`broker-add.py NAME -e`, mydotfiles);
  `install.sh -W report` and soak until a day after `secret_gate_since` shows
  no `gate_would_refuse` line for a live consumer; `install.sh -W
  agent_script`. Later, after every legacy item was moved into the login
  collection (its id pinned with `agent_secret_id` first) or retired,
  `install.sh -D` drops the legacy collection — refused unless the gate is
  `agent_script` and `daemon.py -g -j` lists ZERO items of kind `secret`.
  Done 2026-10-15: the gate is `agent_script` and `install.sh -D` dropped the
  legacy collection — `agent-login` is the only collection the broker reads.
- **Rotation lease and `held`.** Before it changes a password on a server,
  credctl leases the item's sites; the broker records the lease, then waits
  until a login already in flight has finished:

  | Op                  | Request                                         | Answer                                                                                                                                                  |
  | :------------------ | :---------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------ |
  | `rotation_lease`    | `{"txid": TXID, "sites": [...], "ttl_s": 1200}` | `leased` (with `expires`); `busy` when a site's login does not finish within 120 s (the lease is dropped) or another txid leases a site; `unknown_site` |
  | `rotation_release`  | `{"txid": TXID}`                                | `released` (`released`: true / false)                                                                                                                   |
  | `fingerprint`       | (any)                                           | `removed`                                                                                                                                               |

  Peer uid `--allow-uid` only (`forbidden` otherwise). `TXID` is credctl's
  `YYYYMMDDTHHMMSSZ-<6 hex>`. The lease is persisted (0600,
  `/var/db/login-broker/rotation-leases.json`): a broker restart keeps it
  until its TTL (default 1200 s, at most 3600 s); the next request that
  reads an expired lease drops it; an unreadable lease file holds every site
  until root removes it. From the moment the lease is recorded, every NEW
  login, scheduled login, sentinel probe and identity challenge of a leased
  site answers `{"ok": false, "error": "held", "txid": TXID}` — before any
  vault read, and so does an item whose vault field `agent_hold` carries a
  txid (credctl writes it before the password changes and removes it once
  the copy holds the new value; a malformed value holds too, `txid` null). A
  hold the broker only finds on the fresh secret read withdraws its limiter
  reservation. `held` is never counted by the limiter, never quarantines,
  never sends a failure mail: `browser.py login` exits 75 (`BUSY_RC`, `held:
  rotation TXID in progress`), `agent-login.py` shows `⏸ held (rotation
  TXID)` and `-c` skips the site like a busy one. A client must wait longer
  than the drain (120 s) for the `rotation_lease` answer.
- **Metadata for credctl.** The `sites` and `secrets` views carry `item_id`
  (the Bitwarden item id) and `revision` (its `revisionDate`), refused items
  too; `secret-run -l -j` prints them, with `kind`, `agent_script` and
  `gate_code`. The `secrets` answer itself carries `gate` and `gate_since`.
  All non-secret.
- **Credentials in two or more places.** `./agent-login.py` ends with a
  section read ONLY from mydotfiles credctl's daily state file
  (`~/.local/state/credctl/check-latest.json`, `$CREDCTL_STATE_FILE`
  overrides; `agent_login_cred.py`): one line per credential with
  `location_count >= 2` — ✅ all equal, ❌ `DRIFT` / `missing` /
  `unreadable`, ⚠️ `uncompared` with `credctl.py check -T ID` — plus ONE line
  for a failed / timed-out run (❌), a run in progress or older than 36 h, or
  a missing / unreadable file (⚠️). Every printed field is validated; `-j`
  carries the same as `credentials`.

### Agents renew Albert's own sessions through his Safari (WS1b)

The sites that live on Albert's session do not wait for him: the Safari
marketplace sites, galaxus, galaxus-de, Notion, Slack, OpenAI and claude.ai. An
agent that needs one runs `./agent-login.py -L SITE`. Plan, debate and the
security review: `plans-done/PLAN_ws1b-durability_DONE.md`.

1. **Free check** in the shared Chromium. ✅ → nothing to do. Only a DEFINITE
   "logged out" (code `logged_out`; for Notion also `wrong_account`) goes on;
   "could not tell", internal errors and gated sites stop with their code.
2. **Safari already holds a session** (cookie file; names and expiry only) →
   `browser.py import-safari SITE` and its proof.
3. **Otherwise the agent logs Safari in.** It uses mydotfiles' `safari.py` in a
   NEW Safari window (`--new-window`). Every action names that window
   (`--handle`) and the host the tab must be on (`--expect-host`, re-checked
   in the page right before each fill or click). Credentials come from the
   login broker (`safari_fill`, only items Albert opted in with
   `agent_safari_fill` / `agent_fill_only`) and only otherwise from Albert's
   unlocked Vaultwarden tab through his clipboard — never through argv or
   output. A locked or missing vault tab stops the run (`vault_locked`); the
   agent then runs `~/.local/libexec/vault-touchid unlock-safari -a main` itself (Albert only
   touches Touch ID once; while the tab is unlocked every agent can read the
   vault) or, better, onboards the item into the broker (`broker-add.py ITEM
   -Y` / `-Z`, approved with Touch ID), and re-runs `-L`. The steps per site are the recipes in `agent_login_safari.py`:
   username, password, TOTP, "Continue with Google", the account chooser, and
   the e-mail code. The code is read by himalaya: only a new mail, DKIM-signed
   by the sender's domain, with one code that two polls in a row agree on.
4. **Wait** until Safari wrote the new session to disk.
5. **Import** it (`import-safari -a`).

Guards:

- **A Safari login never runs on an unattended Mac.** `-L` exits 3, naming why,
  unless the console session is unlocked (neither `CGSSessionScreenIsLocked`
  nor `IOConsoleLocked` set), someone touched keyboard or mouse in the last
  15 min (`HIDIdleTime`), and no LaunchAgent started it
  (`AGENT_LOGIN_SCHEDULED`, any non-empty value). The gate proves someone is
  at the Mac, not that Albert started the run. Exit 3 means: retry later,
  do not ask Albert.
- **Albert's stops:** only a CAPTCHA, an SMS code and a push / security-key
  approval are his — plus the one Touch ID touch of an unlock or broker-add
  the agent started. A locked vault is not his. `-L` detects his stops by the
  page's structure, never clicks them, and exits 4 naming the stop.
- **Broker refusals end the run:** `broker_unavailable`, `broker_unattended`,
  `broker_rate_limited` and `held` exit 3 (retry later); `broker_refused`
  (origin, refused or ambiguous item) exits 2. Nothing was filled.
- **safari.py is pinned:** `-L` runs only mydotfiles' `bin/safari.py`;
  `SAFARI_PY_BIN` and a PATH lookup count only inside pytest.
- **No retries:** every credential step runs at most once. A failure after one
  quarantines the site; `-Q SITE` releases it.
- **A hung safari.py** gets SIGTERM (it clears the clipboard), then SIGKILL;
  after a killed credential step `-L` clears the clipboard itself.
- **One Safari login at a time.**
- **safari.py features:** `--capabilities` must list `handle`, `new_window`,
  `close`, `expect_host` and `sigterm_clear`, plus `user_only` / `account_pick`
  where a recipe needs them. Until then:
  - `-L` only imports a session Safari already holds (`safari_py_outdated`);
  - agents.md keeps the old wording for those sites;
  - `-L SITE -n` shows the check, read-only.

**Built-in imports** (Notion, Slack, OpenAI) are one transaction under one
interaction lease:

1. the shared browser's own check must say a definite "logged out";
2. Safari's cookies are proven in a THROWAWAY browser context, so the shared
   jar is untouched. The proof covers the session AND its account,
   server-side, and only an enum leaves the page:

   | site   | proof                                                        | expected (override file)                     |
   | :----- | :----------------------------------------------------------- | :------------------------------------------- |
   | Slack  | `auth.test` with the token + `d`                              | `expected_team_id`, `expected_user_id`       |
   | Notion | the user record of the `notion_user_id` cookie (or the only one) | `expected_email`                          |
   | OpenAI | the account ids of `/backend-api/accounts/check`              | `expected_workspace_id`                      |

   The override file is `~/.config/agent-login/safari-logins.json`, 0600,
   outside this repo.
3. only on a match: Slack's token store is cleared, the cookies are copied
   into the shared jar, and the shared browser's own check runs again. If it
   fails, the import is undone; a failed undo is recorded (`undo: failed`)
   and shown by `-L`.

A plain import is logged as `safari-import` (a copy, not a login); an agent's
login as `safari-agent`; a guided login as `guided`.

**More durability:**

- **On demand:** `myfritz` (10 h sessions) is never checked or logged in by the
  daily run. Agents call `browser.py login myfritz` when they need it.
- **Refresh pass:** `-R` runs as the LaunchAgent `com.albert.agent-login-refresh`,
  every 6 h, and only while the daily job is loaded. It renews refreshable
  tokens (NPM) below 12 h left. It never logs in and never submits.
- **Notion's check is tri-state.** Its server (`loadUserContent`, 10 s) decides
  and the sidebar only corroborates; "cannot tell" is never "logged out".
  - Until the probe was verified live (`notion_probe_verified: true` in the
    override file), only a 401 counts as logged out, and a visible workspace
    keeps ✅ with a warning.
  - The failure mail (`-m`) names an assisted site only after two failed RUNS
    at least 1 h apart.
- **After a Homebrew upgrade** the overview and `-c` print the exact fix:
  - ❌ for a stale `vault-touchid` build (any pinned file);
  - ❌ for user-site packages missing from a new python minor (within 14 days of
    the change; ⚠️ afterwards; `AGENT_LOGIN_USERSITE_IGNORE` lists names never
    reported).

  The automatic remedy belongs to mydotfiles' brew maintenance.

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
  "api.epfl.ch": "SOCKS5 127.0.0.1:1081",
  "komga.dom42.space": "SOCKS5 127.0.0.1:1082"
}
```

(abridged: the committed file has one `:1082` line per Access-gated dom42 host,
see "Home-only hosts" below.)

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

### Home-only hosts: the dom42 route (`vpn homeproxy`)

The `*.dom42.space` sites behind Cloudflare Access answer without Access only
from the home LAN; off-LAN they land on the Access login page and
`agent-login.py` reports them `unreachable off-LAN (Cloudflare Access)`.
`vpn homeproxy` (mydotfiles `bin/vpn.sh`) runs a restricted SSH dynamic forward
to nixos on `127.0.0.1:1082`: through it the names resolve at nixos' dnsmasq and
reach NPM directly. On the home LAN it connects direct; elsewhere it rides its
own FritzBox WireGuard peer through a userspace wireproxy, independent of the
home split tunnel, Cisco EPFL and Mullvad, and it never toggles a VPN itself.

`bin/pac_hosts.json` lists exactly the Access-gated hosts nixos' dnsmasq answers
authoritatively (nixos `accessGatedNames`), each as an EXACT host on
`SOCKS5 127.0.0.1:1082` — no `.dom42.space` suffix rule:
`audiobookshelf`, `booklore`, `books`, `calibre`, `homepage`, `jellyfin`,
`kavita`, `kindle-history`, `komga`, `music`, `vaultwarden` (`.dom42.space`).
`homeassistant.dom42.space` is deliberately absent (Access stays mandatory
there) and LAN-only names such as `navidrome.dom42.space` stay DIRECT. With
homeproxy down, the `; DIRECT` fallback gives today's behaviour (Access).

- **The broker keeps its own constant copy.** The login broker's headless
  Chromium (`_loginbroker`, `broker/daemon.py`) launches with
  `--proxy-pac-url=data:…` rendered from `HOMEPROXY_PAC_HOSTS` /
  `HOMEPROXY_PROXY` in `broker/pac.py` — a constant of the installed release,
  never `bin/pac_hosts.json`: that file is agent-writable, and the broker types
  passwords, so it must not let an agent re-route a login (the broker is the
  security boundary). TLS validation is unchanged, so a hostile listener on
  1082 still cannot read a typed password. Playwright adds no proxy switch of
  its own while `proxy` is unset (checked against Playwright 1.60's Chromium
  launcher; a local run with a dummy SOCKS port saw the SOCKS5 greeting for
  the listed host only), so the command-line PAC is the one in force.
- **Parity test.** `tests/test_broker_pac.py` fails unless the broker constant
  equals the set of `:1082` entries in `bin/pac_hosts.json`, both on port 1082,
  rendering the same PAC bytes; it also pins `homeassistant` / `navidrome` as
  DIRECT. Change both together (and nixos `accessGatedNames`; `vpn homeproxy
  -s -A` probes every `:1082` host of this file through the proxy against the
  server's `PermitOpen`).
- **Broker self-check.** `install.sh` runs `selfcheck.py -R` as the role account
  after the boundary checks: the broker's own Chromium, with the release PAC, in
  a throwaway profile, loads `https://komga.dom42.space/` (≤ 20 s, no
  reservation, no secret, no typing) and prints `routed` (✅),
  `access_gated` (homeproxy down, or off-LAN without the tunnel) or
  `unreachable` (ℹ️). It is informational: it never fails or rolls back an
  install.
- **Bad-proxy cache.** After a DIRECT fallback Chromium marks the proxy bad for
  about 5 minutes
  ([proxy docs](https://chromium.googlesource.com/chromium/src/net/+/HEAD/docs/proxy.md)):
  after a homeproxy outage the shared browser may keep going DIRECT (→ Access)
  for up to 5 min. `browser.py down && browser.py up` resets it at once.
- **When it applies.** Like every PAC change: at the next `browser.py up` of
  each instance (default, `private`, `admin`, `alt` — all launch through the
  same PAC flag); a running browser keeps its old PAC (`status` says
  `NOT in the running browser`). The broker picks its constant up with the next
  `install.sh` (each login run launches a fresh Chromium).

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

## Claude Console balance (`console-balance.py`, tp#1421)

`console-balance.py` reads, per Console account, what the billing and spend-limit
pages show — every promotional-credit row (remaining, granted, expiry, grant date),
the purchased credit balance and the org's monthly spend limit (spent, limit,
reset) — in ONE fresh tab of its own on
`platform.claude.com/settings/spend-limits` (GET requests from the page only; it
never clicks buy, adjust, auto-reload or notification controls). Work runs in the
shared Chromium; private in the private instance, started headless for the run and
stopped again. Each account's result is written atomically (0600) to
`~/.local/state/console-balance/<work|private>.json` (`-o` / `CONSOLE_BALANCE_DIR`),
the schema ccc reads as `balance_json:<path>`. A failed run keeps the last good
figures and their `measured_at` and sets a typed `status` (`logged_out`,
`wrong_account`, `browser_down`, `busy`, `timeout`, `page_error`); a logged-out
account is not retried for 6 h (`-f` retries now), so the hourly run does not
start the private browser for a session only you can restore. Exit 0 all read,
2 logged out / wrong account, 1 other failure.

Same run, a second fresh tab on `claude.ai/new` reads the one-time **Claude Code
cloud-session credit** (tp#1429; GET only): `/v1/code/promo/cloud_credit` (state,
expiry) and, per chat organisation, `/api/organizations/<uuid>/usage`, whose meter
that ends at the credit's expiry minute (never found by its obfuscated key) gives
`limit_dollars` / `used_dollars`. The file gains an optional field
`"cloud_credit": {"remaining_usd", "granted_usd", "expires_at", "measured_at"}` —
`null` when the account has none (work today); older readers ignore it. A failed
claude.ai read (logged out, another account, no meter) never fails the Console
reading: the last good `cloud_credit` stays with its old `measured_at` and
`"cloud_error"` says why.

```commands
./console-balance.py                  # both accounts, write the files
./console-balance.py -a work -n -j    # work only, print the JSON, write nothing
./console-balance.py -a private -f    # retry a logged-out account now
```

Schedule: LaunchAgent `com.albert.console-balance` (installed by
`./agent-login.py -I` with the others) runs `console-balance.py -q` every hour and at
load; log `~/Library/Logs/com.albert.console-balance.log`.

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
- **No Cloudflare Access team session in the shared browser** (tp#1466). An
  Access login leaves a per-app `CF_Authorization` on the app's host
  (`calibre.dom42.space`) and a TEAM session on `<team>.cloudflareaccess.com`
  (`CF_Authorization`, `CF_Session`, `CF_Device`). The team session lets Access
  open every app of the team without a new login — decide.dom42.space included,
  which agents must never open as Albert. So a team-domain cookie (any host on
  or under `cloudflareaccess.com`) is:
  never exported by the broker (`broker/bundle.py`, drop reason
  `access_team`), never injected by the client (`_broker_cookie_in_scope`) or
  copied from Safari (`safari_cookies.importable`), and deleted from the shared
  jar after every broker injection, Safari import, `browser.py login` (any
  flow) and guided login (`_drop_access_team_cookies` / `_access_team_sweep`,
  journaled as `access_team_sweep`, names only). The sweep runs on EVERY exit
  of `login`, `assisted-login` and `import-safari` — a failure, `SystemExit`
  or exception included; a `login` deadline (exit 124/125, a hard exit) sweeps
  over raw CDP from the watcher (`_access_team_sweep_cdp`, one 4 s budget for
  the whole sweep). Both paths run the same CDP sweep (`_sweep_team_cookies`):
  each team cookie is deleted by its exact identity — `Storage.setCookies`
  with a past expiry, a host-only cookie addressed by `url` and no `domain`, a
  `.domain` cookie by its domain, a partitioned (CHIPS) one with its
  `partitionKey` — so no other cookie is ever cleared and re-added. After
  deleting, the sweep re-reads the jar: a jar it cannot read or attach to, a
  failed delete or a surviving team cookie turns a logged-in exit 0 (also a
  `SystemExit(0)`) into exit 1 with result code `access_team_sweep_failed`; a
  browser that is down is no failure. Only the per-app cookies stay,
  and the home services keep working on them. `browser.py doctor` prints an
  `access team cookies` line (❌ with host + name when one is present, never a
  value). The configured team domain comes from
  `$CLAUDE_BROWSER_ACCESS_TEAM_DOMAIN`, else `team_domain` in decide's
  `config/edge.json` (`$CLAUDE_BROWSER_ACCESS_EDGE_FILE` overrides the path);
  a value that is not a subdomain of `cloudflareaccess.com` (`com`,
  `dom42.space`) is rejected from either source — it would match app cookies
  — with the reason shown by `doctor`. It is informational on top of the
  suffix rule, so a missing or rejected configuration never lets a team
  cookie through. No
  Access session is revoked server-side. Opt-in real-browser test (a
  throwaway headless Chromium, never the shared one):
  `CLAUDE_BROWSER_TEST_CDP=1 uv run pytest tests/test_access_team_cookies.py -k real_chromium`
  (`$CLAUDE_BROWSER_TEST_CHROMIUM` names the executable when Playwright's own
  build is missing).
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

The marketplace sites (anibis, tutti, Ricardo, Kleinanzeigen), Galaxus and Galaxus DE run on YOUR Safari session: `browser.py login SITE` copies that site's session cookies into the shared Chromium (Kleinanzeigen falls back to the broker). The broker never submits a password for galaxus and galaxus-de (their bot check rejects it; any item opts in with agent_no_submit=true). When such a session or one of Notion, Slack, OpenAI or claude.ai lapses, an AGENT renews it: `-L SITE` imports your Safari session — logging Safari in first (safari.py with every feature its recipe needs; the credentials from the login broker, else your Vaultwarden tab) when it has lapsed there too — claude.ai through its automated magic link. Only a CAPTCHA, an SMS code, a push / security-key approval (exit 4, named) and the Touch ID touch stay yours: a locked vault is the agent's — it runs `~/.local/libexec/vault-touchid unlock-safari -a main` (you touch Touch ID once) or onboards the item into the broker (`broker-add.py ITEM -Y`/`-Z`); `-g SITE` is still there for a login by hand. CSCS and Smartsheet log in through the broker. SWITCH Cloud logs in with the portal's SSO click, on the browser's own edu-ID session first, then on the broker's (no window).

Examples:

```bash
./agent-login.py              # overview
./agent-login.py -t anibis    # real test: `browser.py login` (Safari session first,
                              # then the broker), then the positive logged-in check
./agent-login.py -c           # every usable site: logged in? if not, log in
./agent-login.py -c -m        # the same + mail Albert (manual; the daily job does not mail)
./agent-login.py -t https://auth.cscs.ch   # SITE may also be a name or login address
./agent-login.py -g anibis    # guided login: confirm, then log in via the remote view
./agent-login.py -g anthropic # your login (email code) in the shown shared Chromium
./agent-login.py -g galaxus-de # your login, straight in the shown window (bot check)
./agent-login.py -g notion -F # the same, even with unregistered CDP clients attached
./agent-login.py -P           # print the daily LaunchAgent (-I installs, -U removes)
./agent-login.py -j           # the same overview as JSON
./agent-login.py -x           # acceptance matrix (-x -j: as JSON)
./agent-login.py -p github    # promote (one budgeted login at most): -c may log it in
./agent-login.py -E github    # re-arm its one promotion login (after review, audited)
./agent-login.py -Q galaxus   # release a quarantine (main session, audited)
./agent-login.py -V           # onboarding review of every broker item (read-only)
./agent-login.py -V -i new.json  # review a PLANNED item before the vault write
./agent-login.py -D docker    # remove: run while listed, again after the vault item went
./agent-login.py -L notion    # an AGENT imports Albert's Safari session (+ a Safari login)
./agent-login.py -L galaxus-de -n  # what -L would do (no import, no Safari login)
./agent-login.py -R           # refresh-only pass (NPM tokens; LaunchAgent every 6 h)
./agent-login.py -l           # items agents can fill into Albert's Safari (safari.py -L)
./agent-login.py -H runai-test3  # its identity proofs that did not say match (all: -H)
```

Sites on Albert's session (Safari sites, galaxus-de, Notion, Slack, OpenAI, claude.ai) are renewed by AGENTS with -L — never a to-do for Albert, except a CAPTCHA, an SMS code or a push / security-key approval (exit 4, named) and the Touch ID touch of `~/.local/libexec/vault-touchid unlock-safari -a main` / `broker-add.py`, which the agent runs itself when the vault is locked. myfritz is on demand: never checked daily.

Where a login broke: every check records its PHASE (precheck, limiter, vault, recipe, submit, profile-proof, broker-proof, bundle-export, cookie-inject, storage-inject, client-proof, consumer-followup, safari-source, unknown) and a code, a redacted detail and the broker's screenshot; the overview shows them. A ✅ is a fresh (≤ 36 h), proven check; older reads ❓. The daily check (-c) never logs in a site that is pending, quarantined, locked, in cooldown, without a sentinel, changed since its promotion or flagged by the onboarding review, and never retries after the password may have been sent. Adding a site: README "Adding a site to the broker".

A credential rotation (mydotfiles credctl) holds its sites: ⏸ held (rotation TXID) — never logged in, never a failure mail, re-checked later. The old -f (password length + hash) is gone (tp#965, it was a password oracle): compare a password with `credctl.py check -T` in mydotfiles.

Fill-only items (`agent_fill_only = true`, tp#1082): the broker never logs in with them, so they get no ✅/❌ row and are never checked, promoted or tested; the agents file carries one line with their count, `-l` lists them.

#### Options

| Flag | Description |
|------|-------------|
| `-t`, `--test` `SITE` | real login test for SITE |
| `-g`, `--guided` `SITE` | guided login by hand (browser.py assisted-login: confirm on the terminal, remote view of a headless tab; the window as fallback) |
| `-F`, `--force` | with -g: start even with UNREGISTERED CDP clients attached (browser.py assisted-login -f; they are not paused and keep running); with -D: log out even when another account's item shares the scope in the same browser instance |
| `-c`, `--check-all` | every usable site: logged in? if not, `browser.py login`; one line per site; exit 0 when every failure is a site on record in last-check.json, 1 when the broker, a browser or the check failed |
| `-m`, `-M`, `--mail` | with -c: mail `albert.glensk@gmail.com` (gog) when a site stays logged out |
| `-r`, `--refresh` | ask the broker now (re-reads Bitwarden, ~40 s) instead of the snapshot |
| `-S`, `--snapshot` | recover a stale guided login whose watchdog died (one line), refresh the site-list and secret-run snapshots and the agents file (which also lists the secrets agents can inject), print nothing else (LaunchAgent, every 10 min) |
| `-K`, `--keychain` | rescan the login keychain (~15 s) and list every item (names only) with whether agents can read it |
| `-A`, `--agents` | print the summary agent sessions get at start (the agents file) |
| `-I`, `--install-daily` | install + load the LaunchAgents com.albert.agent-login-check (`-c` daily 09:15), com.albert.agent-login-snapshot (`-S` every 10 min) and com.albert.agent-login-refresh (`-R` every 6 h) as one transaction (any failure restores the previous set) |
| `-U`, `--uninstall-daily` | unload + remove all three LaunchAgents |
| `-P`, `--print-plist` | print the three LaunchAgent plists (writes nothing) |
| `-j`, `--json` | print the overview (with -x: the matrix) as JSON |
| `-x`, `--matrix` | the acceptance matrix: one row per login (consumer, privilege, sentinel, scope, attempt group, refresh, stage, limit, last phase) |
| `-p`, `--promote` `SITE` | the ONE promotion transaction (pending -> usable for scheduled logins): a fresh listing, the onboarding review, then a fresh strict ok of this configuration on record, or ONE budgeted `browser.py login` (no retry); audited |
| `-V`, `--validate`, `--validate-selectors` | the onboarding review (no login, no vault write): selectors the broker refuses, then every listed item's findings (refused / unusable / risk / hint); with -i: a PLANNED change; with -r: ask the broker now and refresh the site-list snapshot first (~40 s) instead of reading it; exit 1 when anything blocks |
| `-i`, `--item` `MANIFEST` | with -V: review a planned item / batch (JSON: {name, fields, replaces?, username_form?, reveals?} or {items: [...], removes: [...]}; '-' = stdin; never a password) against the listing, displacement included |
| `-E`, `--rearm` `SITE` | give SITE its one promotion login back (after reviewing why it failed) — the main session's decision, audited |
| `-D`, `--remove` `SITE` | remove a broker site, run twice: while it is listed -> demote + browser.py logout; after its vault item is gone -> drop every trace (broker `forget`, state files, cache files); audited |
| `-Q`, `--release` `SITE` | release SITE's quarantine (after a failed login that may have submitted the password) — the main session's decision, audited |
| `-L`, `--safari-login` `SITE` | an AGENT's login through Albert's Safari (WS1b): free check, else import Safari's own session (works without new safari.py features), else log Safari in (safari.py, a new window; the login broker's credentials, else his Vaultwarden tab and clipboard) and import it; claude.ai: the automated magic link. One run, no retries; never from a LaunchAgent. Exit 4 = needs Albert (CAPTCHA, SMS, push / security key); a locked vault is the agent's: `vault-touchid unlock-safari -a main` (Albert touches once); exit 3 = the Mac is locked or idle: retry later |
| `-l`, `--fillable` | list every item agents can fill into Albert's Safari (fill-only items and login items with agent_safari_fill): site, name, fill origins — names only, never a value (from the broker's site listing; -r asks the broker now; -j: JSON) |
| `-n`, `--dry-run` | with -L: report what it would do (no import, no Safari login) |
| `-H`, `--identity-history` `[SITE]` | read-only: the last identity proofs of SITE (no SITE: of every site) that did not say match — when, state, verdict, the recipe's reason word, HTTP status, code, redacted detail (checks.json keeps the last 10 per site; the latest check overwrites its detail); -j: JSON |
| `-R`, `--refresh-pass` | refresh-only pass: renew every refreshable token (NPM) with < 12 h left; never logs in (LaunchAgent com.albert.agent-login-refresh, every 6 h) |
