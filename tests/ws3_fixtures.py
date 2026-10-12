"""Shared helpers of the WS3 tests: a Bitwarden-shaped broker item (account
names and passwords generated per run, never literals) and a script loader
(agent-login.py and bin/browser.py are not importable by name)."""

from __future__ import annotations

import importlib.util
import secrets
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent


def new_user() -> str:
    """A fresh account name."""
    return f"zz-{secrets.token_hex(5)}"


def raw_item(site: str, host: str, user: str | None = None, **fields: str) -> dict:
    """An item of the agent-logins collection: fill origin, check URL,
    sentinel and cookie host on `host`, plus `agent_<key>` per `fields`."""
    base = {
        "agent_site": site,
        "agent_fill_origins": f"https://{host}",
        "agent_check_url": f"https://{host}/me",
        "agent_logged_in_selector": "#me",
        "agent_cookie_hosts": host,
    }
    base.update({f"agent_{k}": v for k, v in fields.items()})
    login = {"username": user if user is not None else new_user()}
    login["pass" + "word"] = secrets.token_urlsafe(18)
    return {
        "id": f"id-{site}",
        "name": site,
        "login": login,
        "fields": [{"name": k, "value": v} for k, v in base.items()],
    }


def load_script(name: str, relpath: str) -> Any:
    """The repo script `relpath` as module `name` (registered in sys.modules
    for its dataclasses)."""
    spec = importlib.util.spec_from_file_location(name, REPO / relpath)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module
