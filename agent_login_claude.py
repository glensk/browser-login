"""claude.ai accounts and browser instances for agent-login.py.

One browser profile holds ONE claude.ai session, so the work and the private
account live in different browser.py instances (CLAUDE_BROWSER_INSTANCE).
"""

from __future__ import annotations

import contextlib
import json
import os
import time
from collections.abc import Iterator
from dataclasses import dataclass, field

from agent_login_jobs import (
    _browser,
    _browser_module,
    browser_mode,
    browser_timeout,
    run_browser,
)

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


# The Claude Console (platform.claude.com) accounts: a login of its own (separate
# from claude.ai's), one per browser profile like claude.ai — the work Console in
# the shared browser, the private one next to the private claude.ai session.
CONSOLE_ACCOUNTS = {
    "console": CLAUDE_ACCOUNTS["anthropic"],
    "console-private": CLAUDE_ACCOUNTS["anthropic-private"],
}
# The Console's account endpoint, asked from a fresh Console tab: the logged-in
# e-mail, "" when the endpoint refuses (401/403 = logged out), "?" when it cannot
# tell (any other answer). Only that string leaves the page.
_CONSOLE_ACCOUNT_JS = (
    'fetch("/api/account").then(r => r.ok ? r.json().then(a => a.email_address || "?")'
    ' : (r.status === 401 || r.status === 403 ? "" : "?")).catch(() => "?")'
)
CONSOLE_URL = "https://platform.claude.com/settings/billing"
# The Console SPA takes 30-40 s to load in the headless shared browser (measured
# 2026-10-29) — longer than the generic eval-fresh budget.
CONSOLE_EVAL_S = 90.0


# Sites that live in their own browser instance (browser.py CLAUDE_BROWSER_INSTANCE).
SITE_INSTANCE = {"anthropic-private": "private", "console-private": "private"}
CLAUDE_LOGIN_WAIT_S = 15 * 60


@contextlib.contextmanager
def site_instance(site: str) -> Iterator[None]:
    """Point every browser.py call inside at `site`'s browser instance
    (`instance_session`)."""
    with instance_session(SITE_INSTANCE.get(site, "")):
        yield


def instance_users() -> tuple[str, str] | None:
    """Who uses the CURRENT browser instance ($CLAUDE_BROWSER_INSTANCE) right
    now: ``("busy", why)`` for its registered CDP clients (an MCP server or
    another wrapper started with `browser.py register-exec`, a running
    browser.py) or unregistered ones (lsof), ``("unreadable", why)`` when that
    cannot be told, None when nobody. Asked in-process through browser.py's
    own registry (`_registry_live_clients`, which also reaps dead entries).
    Callers never stop an instance on either answer — stopping a browser
    under a client breaks it, leaving it up only costs memory."""
    try:
        mod = _browser_module()
        live = mod._registry_live_clients()  # pylint: disable=protected-access
        unknown = mod._unknown_cdp_clients(mod.DEFAULT_CDP_PORT)  # pylint: disable=protected-access
    except Exception as exc:  # pylint: disable=broad-exception-caught
        return "unreadable", f"its clients cannot be listed ({type(exc).__name__})"
    if live:
        tools = sorted({str(rec.get("tool") or "?") for rec in live})
        return "busy", f"{len(live)} registered client(s): {', '.join(tools)}"
    if unknown is None:
        return "unreadable", "its CDP clients cannot be verified (no lsof)"
    if unknown:
        return "busy", f"{len(unknown)} unregistered CDP client(s)"
    return None


@dataclass
class InstanceSession:
    """What `instance_session` yields: is the instance up, and what went
    wrong around it (a failed stop, an unreadable client list) — for the
    caller's failure list and mail."""

    up: bool = True
    problems: list[str] = field(default_factory=list)


# After an `up` attempt: how long a slow Chrome may take to answer before the
# instance counts as "did not start" (it is then still stopped at the end
# once it answers).
UP_SETTLE_S = 10.0
UP_POLL_S = 1.0


def _came_up() -> bool:
    """Does the current instance run, polled for up to UP_SETTLE_S?"""
    deadline = time.monotonic() + UP_SETTLE_S
    while True:
        if browser_mode() is not None:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(UP_POLL_S)


@contextlib.contextmanager
def instance_session(inst: str) -> Iterator[InstanceSession]:
    """Point every browser.py call inside at browser instance `inst` ('' =
    the shared one); yields an `InstanceSession` (`up`; `problems` filled on
    the way out).

    A named instance that is down is started headless for the duration and
    stopped again afterwards — its sessions live in its profile on disk, so it
    runs only while something uses it, and an admin session is not left in a
    running browser between uses. "Started here" = it was down before and a
    browser runs after the `up` attempt (an `up` that timed out while Chrome
    came up is still stopped). Never stopped while something else uses it
    (`instance_users`): then it stays up and the reason is printed; an
    unreadable client list or a failed stop also lands in `problems`. An
    instance that was already up is never stopped here.
    """
    old = os.environ.get("CLAUDE_BROWSER_INSTANCE")
    os.environ["CLAUDE_BROWSER_INSTANCE"] = inst
    session = InstanceSession()
    started = False
    try:
        if inst and browser_mode() is None:
            _browser("up", quiet=True, timeout_s=browser_timeout("up"))
            started = _came_up()
            session.up = started
        yield session
    finally:
        if started:
            users = instance_users()
            if users is not None:
                print(f"⏸  the {inst} browser stays up — {users[1]}")
                if users[0] == "unreadable":
                    session.problems.append(f"the {inst} browser stays up: {users[1]}")
            elif _browser("down", quiet=True, timeout_s=browser_timeout("down")) != 0:
                session.problems.append(
                    f"the {inst} browser did not stop (browser.py down)"
                )
        if old is None:
            os.environ.pop("CLAUDE_BROWSER_INSTANCE", None)
        else:
            os.environ["CLAUDE_BROWSER_INSTANCE"] = old


def browser_site(site: str) -> str:
    """The browser.py site name for an agent-login site id."""
    if site in CONSOLE_ACCOUNTS:
        return "console"
    return "anthropic" if site in CLAUDE_ACCOUNTS else site


def console_account_email() -> str | None:
    """The Claude Console account the CURRENT browser instance is logged into:
    its e-mail (lower case), "" when the Console says logged out, None when it
    cannot be told (browser error, busy, an unexpected answer). Asked in a fresh
    tab of its own (`browser.py eval-fresh`), read-only."""
    run = run_browser(
        "eval-fresh",
        "-t",
        str(int(CONSOLE_EVAL_S)),
        CONSOLE_URL,
        _CONSOLE_ACCOUNT_JS,
        timeout_s=CONSOLE_EVAL_S + 15.0,
        capture=True,
    )
    if run.killed or run.rc != 0:
        return None
    lines = run.stdout.strip().splitlines()
    try:
        email = json.loads(lines[-1]) if lines else None
    except ValueError:
        return None
    if not isinstance(email, str) or email == "?":
        return None
    return email.strip().lower()


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
