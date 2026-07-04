# browser-login

A single persistent, logged-in Chromium instance that CLI tools and AI agents share over the Chrome DevTools Protocol (CDP), plus a generic multi-site auto-login framework. Authenticate once (SSO, 2FA, magic-link); every consumer — Playwright MCP, shell scripts, billing scrapers — reuses the same session without re-implementing auth.

Key tools: `bin/browser.py` (launch/manage the shared Chromium, run JS in tabs, dispatch multi-site login/logout/token commands)

Stack: Python 3.10+, Playwright Chromium, CDP | Deps: playwright, pyotp, requests
