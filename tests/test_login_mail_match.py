#!/usr/bin/env python3
"""Regression guard for Anthropic magic-link mail selection (browser.py).

The bug: `_himalaya_latest_login_mail` filtered envelopes on the subject
substring "log in to Claude.ai". Anthropic's real subject is
"Your secure link to Claude.ai is here | <timestamp>" — the old string has
never appeared in either mail folder, so `browser.py login anthropic` silently
never auto-logged in and always fell back to assisted login.

Run: python3 -m pytest tests/ -q     (from the repo root)
"""

from __future__ import annotations

# Tests reach into browser.py's private helpers on purpose (it is a script, not
# a package, so there is no public API), and build throwaway stub classes and
# late imports for monkeypatching.
# pylint: disable=protected-access,import-outside-toplevel,too-few-public-methods
# pylint: disable=unused-argument,missing-function-docstring,import-error
import importlib.util
import sys
from pathlib import Path

import pytest

_BROWSER_PY = Path(__file__).resolve().parent.parent / "bin" / "browser.py"


def _load_browser_module():
    """Import bin/browser.py as a module (it has no module-level playwright import)."""
    spec = importlib.util.spec_from_file_location("browser_under_test", _BROWSER_PY)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["browser_under_test"] = mod
    spec.loader.exec_module(mod)
    return mod


browser = _load_browser_module()


def _env(subject: str, sender: str = "", to: str = "", date: str = "") -> dict:
    return {
        "subject": subject,
        "from": {"addr": sender},
        "to": {"addr": to},
        "date": date,
        "id": "1",
    }


# --- the actual regression: the real subject must match ----------------------


def test_real_2026_subject_matches():
    """The observed live subject. FAILS against the old 'log in to Claude.ai' filter."""
    e = _env(
        "Your secure link to Claude.ai is here | 2026-08-26 12:05:31",
        sender="no-reply-xCjLDakKXejRFocOIoK03g@mail.anthropic.com",
    )
    assert browser._is_claude_login_mail(e)


def test_legacy_subject_still_matches():
    """Do not regress whatever the old string was written for."""
    assert browser._is_claude_login_mail(_env("Please log in to Claude.ai now"))


def test_randomised_sender_localpart_is_tolerated():
    """The localpart differs per message; only the domain is stable."""
    a = _env(
        "Your secure link to Claude.ai is here | 1",
        sender="no-reply-AAA@mail.anthropic.com",
    )
    b = _env(
        "Your secure link to Claude.ai is here | 2",
        sender="no-reply-ZZZ@mail.anthropic.com",
    )
    assert browser._is_claude_login_mail(a)
    assert browser._is_claude_login_mail(b)


# --- false positives: same sender domain, not a login mail -------------------


@pytest.mark.parametrize(
    "subject",
    [
        "You have new requests from your team",
        "SDSC Claude Team - your seat is ready (activation steps)",
        "Your Anthropic invoice is available",
    ],
)
def test_anthropic_product_mail_is_not_a_login_mail(subject):
    """Sender alone must not qualify — these live in the same mailbox and would
    otherwise out-rank the real login mail and starve auto-login."""
    e = _env(subject, sender="no-reply-ASDA1lStqbAc4jA92NegzA@mail.anthropic.com")
    assert not browser._is_claude_login_mail(e)


def test_unrelated_sender_and_subject_rejected():
    assert not browser._is_claude_login_mail(_env("Lunch?", sender="a@example.com"))


def test_empty_envelope_is_rejected_not_crashing():
    assert not browser._is_claude_login_mail({})
    assert not browser._is_claude_login_mail({"subject": None, "from": None})


# --- diagnostics: every silent skip must be explainable ----------------------


def test_diag_dedupes_and_appends():
    sink: list[str] = []
    browser._diag(sink, "same")
    browser._diag(sink, "same")
    browser._diag(sink, "other")
    assert sink == ["same", "other"]


def test_diag_tolerates_no_sink():
    browser._diag(None, "dropped")  # must not raise


# --- ranking: an undated candidate must never beat a dated one ---------------


def test_undated_mail_ranks_below_dated(monkeypatch):
    """`_himalaya_date_epoch` returning 0.0 used to be falsy, so an unparsable
    date skipped the freshness guard AND beat best_ts=-1.0 — silently selecting
    an arbitrary old mail. A dated candidate must always win."""
    subject = "Your secure link to Claude.ai is here | x"
    undated = _env(subject, sender="no-reply-A@mail.anthropic.com", date="not-a-date")
    undated["id"] = "undated"
    dated = _env(
        subject, sender="no-reply-B@mail.anthropic.com", date="2026-08-26T10:05:00Z"
    )
    dated["id"] = "dated"

    import json as _json
    import subprocess as _sp

    class _Res:
        returncode = 0
        stderr = ""

        def __init__(self, payload):
            self.stdout = _json.dumps(payload)

    def fake_run(argv, **kwargs):
        folder = argv[argv.index("--folder") + 1]
        return _Res([undated, dated] if folder == "INBOX" else [])

    monkeypatch.setattr(_sp, "run", fake_run)
    monkeypatch.setattr(browser, "subprocess", _sp)
    monkeypatch.setattr(
        browser,
        "_himalaya_date_epoch",
        lambda s: 0.0 if s == "not-a-date" else 1_756_200_000.0,
    )

    hit = browser._himalaya_latest_login_mail("himalaya", "", 0.0)
    assert hit == ("INBOX", "dated")


def test_himalaya_failure_is_reported_not_silent(monkeypatch):
    """A non-zero himalaya exit used to `continue` with no message at all."""
    import subprocess as _sp

    class _Res:
        returncode = 1
        stdout = ""
        stderr = "Error: cannot refresh OAuth token"

    monkeypatch.setattr(_sp, "run", lambda *a, **k: _Res())
    monkeypatch.setattr(browser, "subprocess", _sp)

    diag: list[str] = []
    assert browser._himalaya_latest_login_mail("himalaya", "", 0.0, diag=diag) is None
    assert any("exited 1" in d and "OAuth" in d for d in diag)


def test_account_flag_is_passed_when_set(monkeypatch):
    """The himalaya account was implicit (default); a default flip broke it silently."""
    import subprocess as _sp

    seen: list[list[str]] = []

    class _Res:
        returncode = 0
        stdout = "[]"
        stderr = ""

    def fake_run(argv, **kwargs):
        seen.append(argv)
        return _Res()

    monkeypatch.setattr(_sp, "run", fake_run)
    monkeypatch.setattr(browser, "subprocess", _sp)

    browser._himalaya_latest_login_mail("himalaya", "", 0.0, account="epfl")
    assert all("-a" in argv and argv[argv.index("-a") + 1] == "epfl" for argv in seen)

    seen.clear()
    browser._himalaya_latest_login_mail("himalaya", "", 0.0)
    assert all("-a" not in argv for argv in seen)
