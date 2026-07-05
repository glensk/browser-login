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

- Python: `ruff format bin/ && ruff check bin/ && mypy bin/browser.py && pylint bin/browser.py`
- Shell: `shellcheck` (no shell scripts currently)
- Pre-commit: `pre-commit run --all-files` (gitleaks secret scan)
- Smoke test: `bin/browser.py -h` must exit 0; `browser.py up && browser.py status`.

## Conventions

- Every subcommand supports `-h/--help`; every CLI flag has a short and long form.
- This repo declares **no** `EXTERNAL_DEPS` registry (extdeps package) — it is a
  provider, not a consumer. Its own external tools (`op`, `himalaya`, `security`, Playwright) are
  **optional** and degrade gracefully (assisted fallback); they are documented in
  `README.md` (Requirements), not enforced with fail-loud checks.
- The CDP endpoint is always `http://127.0.0.1:<port>` — never `localhost` (Chrome's
  debug port is IPv4-only; `localhost`→`::1` stalls on macOS).
- A site's `logged_in` check must read a DOM sentinel on a stable post-login surface,
  not "the URL isn't `/login`".
- **No secrets, ever** — this is a public repo. Configuration is env vars + keychain
  *labels* only. gitleaks must stay clean.

## Where things live

- The tool: `bin/browser.py` (single file).
- Cross-repo overview of who consumes it: `~/obsidian/42-Git/README_AUTOLOGIN.md`.
- Private/local notes: `CLAUDE.local.md` (gitignored); `CLAUDE.md` is a gitignored
  shim that imports this file.
