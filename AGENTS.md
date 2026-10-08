# AGENTS.md

Conventions for AI coding agents (and humans) working in this repo.

## What this is

A single shared, logged-in Chromium (`bin/browser.py`) that CLI tools and AI agents
drive over the Chrome DevTools Protocol (CDP), plus a generic multi-site auto-login
framework. It is a **provider**: other repos depend on it, not the reverse. See
`README.md` for the full story.

## Environment

- Python via **`uv`** (preferred over Homebrew/system installs): `uv sync` for a
  project-local venv. But note `bin/browser.py` **self-bootstraps** its own isolated
  venv at `~/.cache/claude-browser/venv` on first run, so usually you just run it.
- One-time browser binary: `uv run playwright install chromium`.
- Secrets live in the macOS keychain / 1Password and are read at runtime — **never**
  in `.env` or the source. `.env` is gitignored; `.env.example` documents env vars.

## Build / test / lint

- Python: `ruff format bin/ && ruff check bin/ && mypy bin/browser.py && uv run pylint bin/browser.py`
  (`uv sync` first — pylint has to run inside the project venv so the deferred
  playwright/pyotp/requests imports resolve).
- Shell: `shellcheck` (no shell scripts currently)
- Pre-commit: `pre-commit run --all-files` (gitleaks secret scan)
- Smoke test: `bin/browser.py -h` must exit 0; `browser.py up && browser.py status`.
- Full health check: `browser.py doctor` (bounded probe on a disposable tab;
  asserts the desktop is left untouched; certifies mode=headless, the desired
  mode and the headed lease). Run it after changes to launch, lifecycle, or
  coordination code — against a DISPOSABLE instance
  (`CLAUDE_BROWSER_CACHE_DIR=<tmp> browser.py --cdp-port <free port> up`, then
  `down`), never the live 9222/9223 browser.

## Conventions

- Every subcommand supports `-h/--help`; every CLI flag has a short and long form.
- **Consumers own tabs by target id** (tp#786): `open -N URL` → `eval -T <id>` →
  `close -i <id>` (in a `finally`). Never navigate "the oldest tab on this URL"
  or pick a tab by URL substring in new code — a redirect or a user's own tab on
  the same URL defeats URL matching; the target id cannot be impersonated.
- This repo declares **no** `EXTERNAL_DEPS` registry (extdeps package) — it is a
  provider, not a consumer. Its own external tools (`op`, `himalaya`, `security`, Playwright) are
  **optional** and degrade gracefully (assisted fallback); they are documented in
  `README.md` (Requirements), not enforced with fail-loud checks.
- The CDP endpoint is always `http://127.0.0.1:<port>` — never `localhost` (Chrome's
  debug port is IPv4-only; `localhost`→`::1` stalls on macOS).
- A site's `logged_in` check must read a DOM sentinel on a stable post-login surface,
  not "the URL isn't `/login`".
- Tab URLs and titles in any captured output (`status`, error lines) go through
  `_tab_hint`/`_tab_title` — origins only, fail closed; raw URLs are opt-in
  (`status --full-urls`) and never the default.
- **Headless by default — the invariant** (tp#836): the shared browser is
  headless unless a live HEADED LEASE exists (`<cache>/headed-lease.json`,
  `_headed_lease(site)`), held only by a guided login Albert starts
  (`agent-login.py -g SITE` → `agent_login_jobs.guided_window`). `up` always
  launches headless (`up -H` is a no-op; there is no `up --headed`, and
  `CLAUDE_BROWSER_HEADLESS` is ignored); `switch headed` exits 2 unless the
  caller carries the lease nonce (`$CLAUDE_BROWSER_HEADED_LEASE`); every
  connecting command reverts a lease-less headed browser first (`_preflight`
  in `main`, before any gate; output to stderr only; best effort — a failed
  revert warns and the command proceeds; `doctor`/`close`/`close-hung` never
  revert). Never add a way around it.
- **Never interfere with the user's desktop**: no app activation, no window
  raising. `_bring_to_front` is a journaled no-op outside the lease holder's
  headed browser; never call `page.bring_to_front()` directly. A login step
  that needs Albert goes through `_guided_login_allowed` and returns
  `NEEDS_ALBERT_RC` (4, "needs Albert: agent-login.py -g SITE") — no TTY or
  env heuristics, no window flow outside the lease, no `op`/Touch-ID fallback
  in unattended paths. Interactive flows hold the interaction lease;
  long-lived CDP clients register via `register-exec`; `switch` fails closed
  on unregistered clients. Full contract: README "Why you never see the
  window" and "Consumer contract".
- **No `--remote-allow-origins`**: CDP WebSocket clients send NO `Origin`
  header (Chrome then answers 403); new `websockets` clients pass
  `origin=None` explicitly.
- **A Playwright attach is bounded and can be blocked by ONE tab** (tp#693):
  `connect_over_cdp` waits for every page target, so `_connect` passes
  `timeout=CONNECT_TIMEOUT_S` and turns a timeout into `BrowserAttachTimeout`
  naming the wedged tab. Anything that must work while a tab is wedged
  (`_cdp_browser_close`, `_probe_targets`, `close-hung`, doctor's probe-tab
  cleanup) uses the raw CDP helper `_cdp_ws_call` (one websocket, one command,
  one monotonic deadline) — never Playwright. The raw helpers are
  registration-free (shutdown calls them while holding the gate exclusively);
  the COMMANDS built on them register a client and, for `close-hung` and
  `close`, take the interaction lease. Nothing closes a real tab without
  `close-hung`'s three-probe + confirmation contract — with ONE exception
  (tp#786): `close -i TID…` closes target ids the caller was handed by
  `open -N`, which is proof of ownership, not a heuristic. Its URL mode
  (`close URL…`, exact match sans query/fragment, http(s) only) is manual
  cleanup of leftover tabs only; no tool uses it. Both modes re-read
  `/json/list` under the lease right before each `Target.closeTarget`, never
  close the last page (a blank keep-alive first, tp#317), and run over raw CDP
  under one deadline. `open -N` and `eval -T` are raw CDP too (no Playwright
  attach).
- **`security` (keychain) calls go through `_security_run` only**: new session, no
  timeout, never `kill`/`terminate` — killing a client mid-dialog crashed
  `securityd` (tp#504). Writes are delete-then-add pinned to the default keychain,
  never `add-generic-password -U`. Reads wait for a locked keychain.
- The shared browser is LIVE infrastructure with the user's real sessions:
  never `down`/`switch`/`login` it casually, and never edit `bin/browser.py`
  in place from a subagent while consumers may exec it — use a worktree.
- **Headless = plain Chrome UA**: `--headless=new` says `HeadlessChrome`, which
  Cloudflare challenges (claude.ai, chatgpt.com); headless launches pass
  `--user-agent` from `_headless_user_agent`, so `_browser_mode` also reads the
  root process's `--headless` flag. Keep both in sync.
- **Instances**: `CLAUDE_BROWSER_INSTANCE=private` runs a second shared browser
  (own profile `~/.cache/claude-browser-private`, CDP 9223, own coordination
  files) — for Albert's private claude.ai account, since one profile holds one
  claude.ai session. Known instances: `INSTANCE_PORTS` in `bin/browser.py`.
- **Keychain list = names only**: `agent_login_keychain.py` reads attributes and
  access lists (`dump-keychain -a`, never `-d`), and masks any service/account
  name that looks like a secret value (`safe_name`) — some items store the
  secret AS their name. Never print raw keychain attribute dumps.
- **What agents can use** = `agent-login.py -A` (the file
  `~/.local/state/agent-login/agents.md`, refreshed by `-S` every 10 min and by
  every `agent-login.py` run; a SessionStart hook in mydotfiles' Claude
  settings prints it into each session).
- **No secrets, ever** — this is a public repo. Configuration is env vars + keychain
  *labels* only. gitleaks must stay clean.

## Where things live

- The tool: `bin/browser.py` (single file).
- Cross-repo overview of who consumes it: `~/obsidian/42-Git/README_AUTOLOGIN.md`.
- Private/local notes: `CLAUDE.local.md` (gitignored); `CLAUDE.md` is a gitignored
  shim that imports this file.
