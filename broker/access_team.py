"""Cloudflare Access TEAM-domain cookies never live in the shared browser (tp#1466).

An Access login leaves two kinds of cookies: the per-app ``CF_Authorization``
on the app's own host (``calibre.dom42.space``) and a team session on the
team domain ``<team>.cloudflareaccess.com`` (``CF_Authorization``,
``CF_Session``, ``CF_Device``). The team session lets Access sign the browser
into EVERY app of the team without a new login — decide.dom42.space included,
which the shared agent Chromium must never open as Albert. So the broker
never exports, and the client never injects or keeps, a cookie on the team
domain; the per-app cookies stay and the home services keep working.

The rule needs no configuration: Cloudflare puts every team domain under
``cloudflareaccess.com``, so any cookie on that domain or a subdomain of it
is a team cookie. The CONFIGURED team domain (decide's ``config/edge.json``
``team_domain``, or ``$CLAUDE_BROWSER_ACCESS_TEAM_DOMAIN``) is only added on
top — it is shown by ``browser.py doctor`` and would cover a team domain
outside that suffix. A missing or unreadable configuration therefore never
lets a team cookie through (fail safe); it is reported, never fatal.

Leaf module: stdlib only, no browser and no secrets — names and hosts in,
booleans out.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from broker.origins import ACCESS_GATE_SUFFIX

#: Every Cloudflare Access team domain is ``<team>.cloudflareaccess.com``.
ACCESS_TEAM_PARENT = ACCESS_GATE_SUFFIX.lstrip(".")
#: Explicit team domain (overrides the edge file).
TEAM_DOMAIN_ENV = "CLAUDE_BROWSER_ACCESS_TEAM_DOMAIN"
#: Path of the edge file to read ``team_domain`` from (default below).
EDGE_FILE_ENV = "CLAUDE_BROWSER_ACCESS_EDGE_FILE"
#: decide's edge configuration: the one place the team domain is written down.
DEFAULT_EDGE_FILE = Path.home() / "obsidian/42-Git/infra/decide/config/edge.json"


def _norm(host: str) -> str:
    return str(host or "").strip().lstrip(".").lower()


def configured_team_domain() -> tuple[str | None, str]:
    """(team domain, where it came from) — (None, why) when there is none.

    ``$CLAUDE_BROWSER_ACCESS_TEAM_DOMAIN`` first, else ``team_domain`` of the
    edge file (``$CLAUDE_BROWSER_ACCESS_EDGE_FILE`` or decide's
    ``config/edge.json``). Never raises."""
    env = _norm(os.environ.get(TEAM_DOMAIN_ENV, ""))
    if env:
        return env, f"${TEAM_DOMAIN_ENV}"
    path = Path(os.environ.get(EDGE_FILE_ENV) or DEFAULT_EDGE_FILE).expanduser()
    try:
        stamp = path.stat().st_mtime_ns
    except FileNotFoundError:
        return None, f"{path} missing"
    except OSError as exc:
        return None, f"{path} unreadable ({type(exc).__name__})"
    key = (str(path), stamp)
    if key not in _CACHE:
        _CACHE.clear()
        _CACHE[key] = _read_edge(path)
    return _CACHE[key]


# (edge file, mtime_ns) → its verdict: a cookie loop reads the file once.
_CACHE: dict[tuple[str, int], tuple[str | None, str]] = {}


def _read_edge(path: Path) -> tuple[str | None, str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return None, f"{path} unreadable ({type(exc).__name__})"
    team = _norm(data.get("team_domain", "")) if isinstance(data, dict) else ""
    if not team or "." not in team:
        return None, f"{path} has no team_domain"
    return team, str(path)


def is_team_host(domain: str, team: str | None = None) -> bool:
    """True when a cookie stored for `domain` (host-only or ``.domain``) is
    a Cloudflare Access team cookie: on ``cloudflareaccess.com`` or a
    subdomain of it, or on the configured team domain `team` (looked up when
    None) or a subdomain of it."""
    d = _norm(domain)
    if not d:
        return False
    if d == ACCESS_TEAM_PARENT or d.endswith("." + ACCESS_TEAM_PARENT):
        return True
    if team is None:
        team, _why = configured_team_domain()
    t = _norm(team or "")
    return bool(t) and (d == t or d.endswith("." + t))


def team_cookie_labels(
    cookies: list[dict[str, Any]], team: str | None = None
) -> list[str]:
    """``"<domain> <name>"`` of every team cookie in `cookies` (dicts with
    ``domain`` and ``name``, as CDP / Playwright return them) — names and
    hosts only, NEVER a value; sorted, unique."""
    if team is None:
        team, _why = configured_team_domain()
    return sorted(
        {
            f"{c.get('domain')} {c.get('name')}"
            for c in cookies
            if isinstance(c, dict) and is_team_host(str(c.get("domain") or ""), team)
        }
    )
