"""Opt-in live check of ``_keychain_set`` against the real ``security`` binary.

Skipped unless ``BROWSER_LIVE_KEYCHAIN=1`` on macOS. Writes ONLY throw-away
items under a unique account (``tp489-live-<hex>``) into the login keychain,
checks the read-back form and that no stray (split/escaped) item appeared under
that account or service prefix, then deletes exactly those items. Values are
dummies and are never printed.

Run: BROWSER_LIVE_KEYCHAIN=1 python3 -m pytest tests/test_keychain_live.py -q
"""

from __future__ import annotations

# pylint: disable=protected-access,import-error,missing-function-docstring
import importlib.util
import os
import re
import secrets
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.skipif(
        os.environ.get("BROWSER_LIVE_KEYCHAIN") != "1" or sys.platform != "darwin",
        reason="live keychain test: set BROWSER_LIVE_KEYCHAIN=1 on macOS",
    ),
    pytest.mark.live_keychain,  # opts out of conftest's default-deny guard
]

_BROWSER_PY = Path(__file__).resolve().parent.parent / "bin" / "browser.py"


def _load_browser_module():
    spec = importlib.util.spec_from_file_location("browser_live_kc", _BROWSER_PY)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["browser_live_kc"] = mod
    spec.loader.exec_module(mod)
    return mod


browser = _load_browser_module()

CASES = {
    "space": "dummy with spaces",
    "dquote": 'dummy"quote',
    "squote": "dummy'quote",
    "backslash": "dummy\\back",
    "trailing": "dummy-trailing\\",
    "shell": "dummy$;|&#`",
    "utf8": "dümmy-✓",
}


def _items_matching(prefix: str) -> list[tuple[str, str]]:
    """(account, service) of every login-keychain item touching our namespace.

    ``dump-keychain`` without ``-d`` prints attributes only, never secrets;
    the output is parsed here and never echoed.
    """
    r = subprocess.run(
        ["security", "dump-keychain"],
        capture_output=True,
        text=True,
        errors="replace",
        timeout=60,
        check=False,
    )
    found = []
    for entry in r.stdout.split("keychain: ")[1:]:
        acct = re.search(r'"acct"<blob>="(.*)"', entry)
        svce = re.search(r'"svce"<blob>="(.*)"', entry)
        a = acct.group(1) if acct else ""
        s = svce.group(1) if svce else ""
        if prefix in a or prefix in s:
            found.append((a, s))
    return found


def _delete(account: str, service: str) -> None:
    for _ in range(5):  # also removes accidental duplicates
        r = subprocess.run(
            ["security", "delete-generic-password", "-a", account, "-s", service],
            capture_output=True,
            timeout=15,
            check=False,
        )
        if r.returncode != 0:
            return


def test_keychain_set_round_trips_through_security_stdin(monkeypatch):
    account = f"tp489-live-{secrets.token_hex(6)}"
    services = {case: f"{account}-{case}" for case in CASES}
    monkeypatch.setattr(browser, "_kc_account", lambda: account)
    try:
        for case, value in CASES.items():
            assert browser._keychain_set(services[case], value, "tp489 live test"), case
            got = browser._keychain_get(services[case])
            expected = value if value.isascii() else value.encode().hex()
            assert got == expected, f"read-back mismatch for case {case}"
        # No -U UPDATE case on purpose: updating an existing item opened a
        # SecurityAgent prompt on 2026-09-24, and the 15 s timeout killing the
        # client mid-prompt made securityd abort (see PLAN execution notes).
        # an invalid value must not reach the keychain at all
        assert not browser._keychain_set(f"{account}-newline", "a\nb", "tp489")
        found = _items_matching(account)
        assert sorted(found) == sorted((account, s) for s in services.values()), (
            "unexpected items under the throw-away account"
        )
    finally:
        for svc in [*services.values(), f"{account}-newline"]:
            _delete(account, svc)
    assert not _items_matching(account)
