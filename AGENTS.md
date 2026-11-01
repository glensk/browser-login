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
  asserts the desktop is left untouched). Run it after changes to launch, lifecycle,
  or coordination code — against a DISPOSABLE instance
  (`CLAUDE_BROWSER_CACHE_DIR=<tmp> browser.py --cdp-port <free port> up`, then
  `down`), never the live 9222/9223 browser.

## Hard rules (one line each; details in the reference)

- **No secrets, ever** — this is a public repo. Configuration is env vars + keychain
  *labels* only. gitleaks must stay clean.
- The shared browser is LIVE infrastructure with the user's real sessions: never
  `down`/`switch`/`login` it casually, and never edit `bin/browser.py` in place from a
  subagent while consumers may exec it — use a worktree.
- Every subcommand supports `-h/--help`; every CLI flag has a short and long form.
- Consumers own tabs by target id: `open -N URL` → `eval -T <id>` → `close -i <id>`
  (in a `finally`). Never pick a tab by URL or URL substring in new code.
- Headless by default is an invariant: never add a way to launch/switch headed without a
  live guided-login mode-A maintenance record; `up` is always headless.
- A live maintenance record (guided login) makes new registrations and `down`/`switch`
  exit 75 (`BUSY_RC`); 75 is NOT "logged out" — skip and re-check, never `login`, never
  a failure mail. Never add an exemption or a non-interactive way into `assisted-login`.
- Never interfere with the user's desktop: no app activation, no window raising, never
  call `page.bring_to_front()` directly; a step that needs Albert returns
  `NEEDS_ALBERT_RC` (4) via `_guided_login_allowed`.
- CDP endpoint is always `http://127.0.0.1:<port>`, never `localhost`; WebSocket clients
  pass `origin=None`; no `--remote-allow-origins`.
- A `logged_in` check reads a DOM sentinel on a stable post-login surface, not "URL isn't
  `/login`"; tab URLs/titles in captured output go through `_tab_hint`/`_tab_title`.
- Tests never leave a real Chrome (`tests/conftest.py` sets
  `CLAUDE_BROWSER_TEST_NO_LAUNCH=1`); a launching test carries
  `@pytest.mark.launches_chrome` and stops it.
- `bin/login_viewer.py` stays an allowlist relay (`ALLOWED_METHODS`, typed messages only,
  CDP-sending event handlers run as tasks).
- Proxy = one inline `data:` per-host PAC (`bin/pac_hosts.json`) only; never a global
  `--proxy-server` or `$ALL_PROXY`.
- Playwright attaches are bounded; anything that must work with a wedged tab uses raw CDP
  (`_cdp_ws_call`). Nothing closes a real tab outside `close-hung`'s contract or
  `close -i` on ids from `open -N`.
- Unattended `login`/`logged-in` run under a `LoginDeadline`; runner calls
  (`run_browser`/`_browser`) always pass an explicit `timeout_s`.
- Login recipes: call `attempt.entered()` before typing the password and
  `attempt.mark_submitted()` right before the submit; never guess a submit (no Enter
  fallback); never retry after phase `submit`/`unknown`; a token's shape proves nothing.
- The broker has NO password oracle: never add an op/field/CLI answering a secret's
  length, hash or any comparison. Never duplicate a broker refusal rule in a review.
- `agent-login.py -L` is agent-invoked ONLY (never from `-c`/`-S`/`-R`); it goes on only
  from a definite logged-out; Safari is driven only through `safari.py` by long options.
- `security` (keychain) calls go through `_security_run` only: new session, no timeout,
  never `kill`/`terminate` (tp#504); writes are delete-then-add, never
  `add-generic-password -U`.
- Never print raw keychain attribute dumps (names only, `safe_name`).
- No Cloudflare Access team session (`cloudflareaccess.com` cookies) in the shared
  browser: never export/inject/copy; new cookie-writing paths sweep after, in a `finally`.
- One cookie scope in one instance holds at most one account; instances
  (`private` 9223, `admin` 9224, `alt` 9225) are selected via `CLAUDE_BROWSER_INSTANCE`.
- This repo declares **no** `EXTERNAL_DEPS` registry; its external tools are optional.
- Agents see what they can use via `agent-login.py -A`
  (`~/.local/state/agent-login/agents.md`).

## Read before you... (reference: `docs/AGENTS_REFERENCE.md`, bullet names are bold there)

- Touch tab ownership, `open`/`eval`/`close`, or the owned-tab ledger: §Conventions
  "Consumers own tabs by target id", "Owned-tab ledger", "Idle-tab reaper and keep pins".
- Touch launch, `up`/`switch`, headless/headed, or the user-agent: §Conventions
  "Headless by default — the invariant", "Headless = plain Chrome UA".
- Touch guided login, maintenance records, pause protocol, watchdog: §Conventions
  "Guided login = one maintenance transaction".
- Touch `login_viewer.py`, desktop/focus behaviour, proxy/PAC, CDP attach/close:
  §Conventions "`bin/login_viewer.py` stays an allowlist relay", "Never interfere with
  the user's desktop", "Proxy = per-host PAC only", "A Playwright attach is bounded…".
- Touch `login`/`logged-in` deadlines, phases, limiter, proofs, sentinels, submits,
  tripwire, username-only mode: §Conventions "Every unattended `login`/`logged-in`…",
  "Login phases and limiter safety", "A token's shape proves nothing", "Sentinel proofs
  poll", "A submit is never a guess".
- Touch `broker/authentik.py` or any form-less API recipe: §Conventions "API recipes log
  in without a form".
- Onboard/promote/remove a broker item (`-V`, `-p`, `-D`): §Conventions "Onboarding guard".
- Touch credential rotation, the `agent_script` gate, held items: §Conventions
  "Credential rotation safety", "The `agent_script` gate".
- Touch Safari renewal (`-L`), `SAFARI_BUILTIN`, the proof context: §Conventions "Agents
  renew Albert's own sessions through his Safari".
- Touch `security`/keychain code or the keychain list: §Conventions "`security`
  (keychain) calls…", "Keychain list = names only".
- Touch instances, role instances, multi-account items, `wrong_account`: §Conventions
  "Instances".
- Write cookies into the shared browser or the access sweep: §Conventions "No Cloudflare
  Access team session…".
- Need the full text of any hard rule above (including the full health-check wording):
  `docs/AGENTS_REFERENCE.md` (original sections verbatim, with a rule ledger on top).

## Where things live

- The tool: `bin/browser.py` (single file).
- Cross-repo overview of who consumes it: `~/obsidian/42-Git/README_AUTOLOGIN.md`.
- Private/local notes: `CLAUDE.local.md` (gitignored); `CLAUDE.md` is a gitignored
  shim that imports this file.
