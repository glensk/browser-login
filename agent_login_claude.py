"""claude.ai accounts and browser instances for agent-login.py.

One browser profile holds ONE claude.ai session, so the work and the private
account live in different browser.py instances (CLAUDE_BROWSER_INSTANCE).
"""

from __future__ import annotations

import contextlib
import json
import os
import subprocess
import sys
import time
from collections.abc import Iterator

from agent_login_jobs import BROWSER_PY, _browser, browser_mode

# The claude.ai accounts: one browser profile holds ONE claude.ai session, so the
# logged-in account's email decides which line is ✅.
CLAUDE_ACCOUNTS = {
    "anthropic": os.environ.get("ANTHROPIC_WORK_EMAIL", "albert.glensk@epfl.ch"),
    "anthropic-private": os.environ.get(
        "ANTHROPIC_PRIVATE_EMAIL", "albert.glensk@gmail.com"
    ),
}
_CLAUDE_ACCOUNT_JS = (
    'fetch("/api/account").then(r => r.ok ? r.json() : {})'
    ".then(a => a.email_address || '')"
)


# Sites that live in their own browser instance (browser.py CLAUDE_BROWSER_INSTANCE).
SITE_INSTANCE = {"anthropic-private": "private"}
CLAUDE_LOGIN_WAIT_S = 15 * 60


@contextlib.contextmanager
def site_instance(site: str) -> Iterator[None]:
    """Point every browser.py call inside at `site`'s browser instance."""
    inst = SITE_INSTANCE.get(site, "")
    old = os.environ.get("CLAUDE_BROWSER_INSTANCE")
    os.environ["CLAUDE_BROWSER_INSTANCE"] = inst
    try:
        if inst and browser_mode() is None:  # started lazily, headless
            _browser("up", "-H", quiet=True)
        yield
    finally:
        if old is None:
            os.environ.pop("CLAUDE_BROWSER_INSTANCE", None)
        else:
            os.environ["CLAUDE_BROWSER_INSTANCE"] = old


def browser_site(site: str) -> str:
    """The browser.py site name for an agent-login site id."""
    return "anthropic" if site in CLAUDE_ACCOUNTS else site


def claude_account_email() -> str | None:
    """Email of the claude.ai account the shared Chromium is logged into, or None."""
    for attempt in range(2):
        res = subprocess.run(
            [sys.executable, str(BROWSER_PY), "eval", "--url", "claude.ai", "-t", "30"]
            + [_CLAUDE_ACCOUNT_JS],
            check=False,
            capture_output=True,
            text=True,
        )
        if res.returncode == 0:
            lines = res.stdout.strip().splitlines()
            try:
                email = json.loads(lines[-1]) if lines else ""
            except ValueError:
                email = ""
            return str(email).lower() or None
        if attempt == 0:  # no claude.ai tab yet
            _browser("open", "https://claude.ai/", quiet=True)
            time.sleep(5)
    return None


def claude_login_by_hand(site: str) -> None:
    """Open claude.ai/login in the shown window and wait until the account is
    `site`'s (browser.py's own login waits for the Team admin page instead)."""
    _browser("open", "https://claude.ai/login", quiet=True)
    want = CLAUDE_ACCOUNTS[site].lower()
    print(
        f"👤 In the Chromium window: log in to claude.ai as {want} (email code). "
        f"Waiting up to {CLAUDE_LOGIN_WAIT_S // 60} min …"
    )
    deadline = time.monotonic() + CLAUDE_LOGIN_WAIT_S
    while time.monotonic() < deadline:
        time.sleep(10)
        if claude_account_email() == want:
            return
