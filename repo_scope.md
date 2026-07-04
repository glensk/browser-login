# browser-login

## Purpose

Launches a single Chromium with a dedicated profile and remote debugging (CDP) on a fixed port so that multiple CLI tools and AI agents share one logged-in browser session. A built-in site registry handles automated or assisted login for services like CSCS (Keycloak + TOTP), Anthropic/Claude (magic-link), OpenAI/ChatGPT (assisted SSO), Slack (assisted + xoxc token extraction), and Biopole WiFi (keychain credentials). Credentials live in the macOS keychain or 1Password — never in source. Downstream consumers shell out to `browser.py` and react to exit codes instead of reimplementing auth.

## Key Capabilities

- Persistent logged-in Chromium with CDP on a fixed port; sessions survive restarts via a dedicated profile
- Multi-site login framework: automated (keychain/TOTP/magic-link) or assisted (user completes SSO once) with per-site `logged_in` DOM-sentinel checks
- Credential management via macOS keychain (`store-creds` / `forget-creds`); TOTP generation with `pyotp`
- Token/session extraction: CSCS Waldur bearer token (`browser.py token`), Slack xoxc+cookie JSON (`browser.py slack-session`)
- Login audit log (`login-log`): JSONL records of every real login with assisted-vs-auto breakdown and live aggregate view
- Self-bootstrapping: creates its own isolated venv via `uv` on first run — no manual install step

## Tech Stack

Python 3.10+, Playwright (Chromium), Chrome DevTools Protocol (CDP), macOS keychain (`security` CLI)

## Key Scripts / Files

| File                     | Purpose                                                                                         |
| :----------------------- | :---------------------------------------------------------------------------------------------- |
| `bin/browser.py`         | Single-file CLI: browser lifecycle (`up`/`down`/`status`), tab control, JS eval, multi-site login, credential and token management |
| `pyproject.toml`         | Project metadata and dependencies (playwright, pyotp, requests); `uv` config                    |
| `.env.example`           | Documents supported environment variables (e.g. `ANTHROPIC_LOGIN_EMAIL`, `BROWSER_CDP_PORT`)    |
| `.pre-commit-config.yaml`| gitleaks secret scanning hook                                                                   |
| `AGENTS.md`              | Public conventions for AI agents and humans: build/test/lint commands, coding standards          |
