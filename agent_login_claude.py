"""claude.ai accounts and browser instances for agent-login.py.

One browser profile holds ONE claude.ai session, so the work and the private
account live in different browser.py instances (CLAUDE_BROWSER_INSTANCE).
"""

from __future__ import annotations

import contextlib
import json
import os
from collections.abc import Iterator

from agent_login_jobs import _browser, browser_mode, browser_timeout, run_browser

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
    """Point every browser.py call inside at `site`'s browser instance.

    A named instance that is down is started headless for the duration and
    stopped again afterwards: its sessions live in its profile on disk, so it
    needs to run only while something uses it.
    """
    inst = SITE_INSTANCE.get(site, "")
    old = os.environ.get("CLAUDE_BROWSER_INSTANCE")
    os.environ["CLAUDE_BROWSER_INSTANCE"] = inst
    started = False
    try:
        if inst and browser_mode() is None:
            started = _browser("up", quiet=True, timeout_s=browser_timeout("up")) == 0
        yield
    finally:
        if started:
            _browser("down", quiet=True, timeout_s=browser_timeout("down"))
        if old is None:
            os.environ.pop("CLAUDE_BROWSER_INSTANCE", None)
        else:
            os.environ["CLAUDE_BROWSER_INSTANCE"] = old


def browser_site(site: str) -> str:
    """The browser.py site name for an agent-login site id."""
    return "anthropic" if site in CLAUDE_ACCOUNTS else site


def claude_account_email() -> str | None:
    """Email of the claude.ai account the shared Chromium is logged into, or None.

    Asked in a fresh tab of its own (`browser.py eval-fresh`, tp#845): it is
    created, loaded, evaluated and closed inside that one run — no tab picked
    by URL, none left behind. None on any failure: exit != 0 (incl. 75 busy),
    a killed run, or a last stdout line that is not a JSON string.
    """
    run = run_browser(
        "eval-fresh",
        "-t",
        "30",
        "https://claude.ai/",
        _CLAUDE_ACCOUNT_JS,
        timeout_s=browser_timeout("eval-fresh"),
        capture=True,
    )
    if run.killed or run.rc != 0:
        return None
    lines = run.stdout.strip().splitlines()
    if not lines:
        return None
    try:
        email = json.loads(lines[-1])
    except ValueError:
        return None
    if not isinstance(email, str):
        return None
    return email.strip().lower() or None


def claude_login_by_hand(site: str) -> None:
    """Log the shown window into `site`'s claude.ai account (inside
    `guided_window`): `browser.py login anthropic -e EMAIL` opens its own tab,
    brings it to the front under the headed lease, waits (≤ 15 min) until
    claude.ai says the account is EMAIL, and closes the tab again (tp#845)."""
    want = CLAUDE_ACCOUNTS[site].lower()
    print(
        f"👤 In the Chromium window: log in to claude.ai as {want} (email code). "
        f"Waiting up to {CLAUDE_LOGIN_WAIT_S // 60} min …"
    )
    # Guided: browser.py bounds the wait itself (CLAUDE_LOGIN_WAIT_S) — no limit.
    run_browser("login", "anthropic", "-e", want, timeout_s=None)
