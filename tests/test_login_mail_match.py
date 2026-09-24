#!/usr/bin/env python3
"""Regression guard for Anthropic magic-link mail selection (browser.py).

The bug: `_himalaya_latest_login_mail` (now `_himalaya_login_mail_candidates`)
filtered envelopes on the subject
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


@pytest.mark.parametrize("sender", ["", "attacker@evil.example"])
def test_legacy_subject_from_unknown_sender_is_rejected(sender):
    """tp#490: a known subject used to win outright, before the sender was
    looked at — so anyone could mail a login link for THEIR account."""
    assert not browser._is_claude_login_mail(
        _env("Please log in to Claude.ai now", sender=sender)
    )
    assert not browser._is_claude_login_mail(
        _env("Your secure link to Claude.ai is here | x", sender=sender)
    )


def test_legacy_subject_from_anthropic_still_matches():
    assert browser._is_claude_login_mail(
        _env("Please log in to Claude.ai now", sender="no-reply-X@mail.anthropic.com")
    )


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

    hit = browser._himalaya_login_mail_candidates("himalaya", "", 0.0)
    assert hit == [("INBOX", "dated"), ("INBOX", "undated")]


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
    assert browser._himalaya_login_mail_candidates("himalaya", "", 0.0, diag=diag) == []
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

    browser._himalaya_login_mail_candidates("himalaya", "", 0.0, account="epfl")
    assert all("-a" in argv and argv[argv.index("-a") + 1] == "epfl" for argv in seen)

    seen.clear()
    browser._himalaya_login_mail_candidates("himalaya", "", 0.0)
    assert all("-a" not in argv for argv in seen)


# --- tp#490: sender allow-list ------------------------------------------------


def _serve(monkeypatch, inbox: list[dict], archive: list[dict] | None = None):
    import json as _json

    class _Res:
        returncode = 0
        stderr = ""

        def __init__(self, payload):
            self.stdout = _json.dumps(payload)

    def fake_run(argv, **kwargs):
        folder = argv[argv.index("--folder") + 1]
        return _Res(inbox if folder == "INBOX" else (archive or []))

    monkeypatch.setattr(browser.subprocess, "run", fake_run)


def test_foreign_sender_is_not_a_candidate_and_is_reported(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_LOGIN_MAIL_SENDERS", raising=False)
    evil = _env("Your secure link to Claude.ai is here | x", sender="a@evil.example")
    _serve(monkeypatch, [evil])
    rejected: list[str] = []
    got = browser._himalaya_login_mail_candidates(
        "h", "", 0.0, rejected_senders=rejected
    )
    assert got == []
    assert len(rejected) == 1
    assert "a@evil.example" in rejected[0]
    assert "mail.anthropic.com" in rejected[0]


def test_rejected_senders_are_sanitized_and_capped(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_LOGIN_MAIL_SENDERS", raising=False)
    subject = "Your secure link to Claude.ai is here | x"
    envs = [_env(subject, sender="x\x1b[31m@evil.example\r\nFAKE")]
    envs += [_env(subject, sender=f"a{i}@evil.example") for i in range(10)]
    _serve(monkeypatch, envs)
    rejected: list[str] = []
    browser._himalaya_login_mail_candidates("h", "", 0.0, rejected_senders=rejected)
    assert len(rejected) == 5
    assert all(c.isprintable() for line in rejected for c in line)
    assert "x[31m@evil.examplefake" in rejected[0]


def test_printable_drops_controls_and_truncates():
    assert browser._printable("a\x1b\r\n‎b\tc") == "abc"
    assert browser._printable("x" * 200, limit=10) == "x" * 9 + "…"


@pytest.mark.parametrize(
    "raw, want",
    [
        (None, ("mail.anthropic.com",)),
        ("   ", ("mail.anthropic.com",)),
        ("No-Reply@Mail.Example.com", ("no-reply@mail.example.com",)),
        ("@mail.example.com", ("mail.example.com",)),
        (" mail.example.com , a@b.example ", ("mail.example.com", "a@b.example")),
    ],
)
def test_sender_allow_list_parsing(monkeypatch, raw, want):
    if raw is None:
        monkeypatch.delenv("ANTHROPIC_LOGIN_MAIL_SENDERS", raising=False)
    else:
        monkeypatch.setenv("ANTHROPIC_LOGIN_MAIL_SENDERS", raw)
    assert browser._login_mail_senders() == (want, None)


@pytest.mark.parametrize(
    "raw",
    [
        "mail.anthropic.com, bad entry",
        "@",
        "a@@b.example",
        "a b@c.example",
        "localhost",
        "-x.example",
        "x-.example",
        "@a@b.example",
        ",,",
        "mail.anthropic.com,\x1b[31mevil",
    ],
)
def test_invalid_sender_allow_list_is_a_config_error(monkeypatch, raw):
    monkeypatch.setenv("ANTHROPIC_LOGIN_MAIL_SENDERS", raw)
    allow, err = browser._login_mail_senders()
    assert allow == ()
    assert err and "ANTHROPIC_LOGIN_MAIL_SENDERS" in err
    assert "\x1b" not in err
    # an invalid override allows nobody, not the default
    assert not browser._is_claude_login_mail(
        _env("Your secure link to Claude.ai is here", sender="n@mail.anthropic.com")
    )


@pytest.mark.parametrize(
    "addr, ok",
    [
        ("no-reply-abc@mail.anthropic.com", True),
        ("NO-REPLY@MAIL.ANTHROPIC.COM", True),
        ("x@evilmail.anthropic.com", False),
        ("x@mail.anthropic.com.evil", False),
        ("x@sub.mail.anthropic.com", False),
        ("mail.anthropic.com", False),
        ("a@b@mail.anthropic.com", False),
        ("", False),
    ],
)
def test_sender_match_is_exact_domain(addr, ok):
    assert browser._sender_allowed(addr, ("mail.anthropic.com",)) is ok


def test_sender_match_exact_address():
    allow = ("login@example.org",)
    assert browser._sender_allowed("Login@Example.org", allow)
    assert not browser._sender_allowed("other@example.org", allow)


def test_address_override_replaces_default(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_LOGIN_MAIL_SENDERS", "login@example.org")
    subject = "Your secure link to Claude.ai is here"
    assert browser._is_claude_login_mail(_env(subject, sender="login@example.org"))
    assert not browser._is_claude_login_mail(
        _env(subject, sender="no-reply@mail.anthropic.com")
    )


def test_candidates_are_newest_first_dated_before_undated(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_LOGIN_MAIL_SENDERS", raising=False)
    s = "Your secure link to Claude.ai is here | x"
    a = _env(s, sender="n@mail.anthropic.com", date="1970-01-01 00:10+00:00")
    b = _env(s, sender="n@mail.anthropic.com", date="1970-01-01 00:12+00:00")
    c = _env(s, sender="n@mail.anthropic.com", date="garbage")
    a["id"], b["id"], c["id"] = "a", "b", "c"
    _serve(monkeypatch, [c, a], archive=[b])
    assert browser._himalaya_login_mail_candidates("h", "", 0.0) == [
        ("Archive", "b"),
        ("INBOX", "a"),
        ("INBOX", "c"),
    ]


# --- tp#490: the account a magic link names ------------------------------------


@pytest.mark.parametrize(
    "link, want",
    [
        (
            "https://claude.ai/magic-link#tok:dXNlckBleGFtcGxlLmNvbQ==",
            "user@example.com",
        ),
        ("https://claude.ai/magic-link#tok:dXNlckBleGFtcGxlLmNvbQ", "user@example.com"),
        (
            "https://claude.ai/magic-link#a:b:dXNlckBleGFtcGxlLmNvbQ==",
            "user@example.com",
        ),
        # URL-safe alphabet: "user?>@x.io" encodes with '_' and '-'
        ("https://claude.ai/magic-link#t:dXNlcj8-QHguaW8=", "user?>@x.io"),
        ("https://claude.ai/magic-link#t:VVNFUkBFWEFNUExFLkNPTQ==", "user@example.com"),
        ("https://claude.ai/magic-link#tok", None),
        ("https://claude.ai/magic-link#tok:", None),
        ("https://claude.ai/magic-link#tok:!!!", None),
        ("https://claude.ai/magic-link#tok:bm8tYXQtc2lnbg==", None),  # no-at-sign
        ("https://claude.ai/magic-link#tok:YUBiQGM=", None),  # a@b@c
        ("https://claude.ai/magic-link#tok:/w==", None),  # not UTF-8
        ("https://evil.example/magic-link#tok:dXNlckBleGFtcGxlLmNvbQ==", None),
        ("", None),
    ],
)
def test_magic_link_email(link, want):
    assert browser._magic_link_email(link) == want


# --- tp#491 D4: himalaya envelope field shapes vary -----------------------------

_SUBJ = "Your secure link to Claude.ai is here | x"
_GOOD = "no-reply-abc@mail.anthropic.com"


@pytest.mark.parametrize(
    "sender, ok",
    [
        (_GOOD, True),  # plain string
        (f"Anthropic <{_GOOD}>", True),  # display-name string
        (f"ANTHROPIC <{_GOOD.upper()}>", True),  # mixed case
        ([{"name": "A", "addr": _GOOD}], True),  # list of dicts
        ([_GOOD], True),  # list of strings
        ({"addr": _GOOD}, True),
        ([{"addr": _GOOD}, {"addr": "x@evil.example"}], False),  # two senders
        (f"{_GOOD}, x@evil.example", False),  # two senders in one string
        (None, False),
        (42, False),
        ({"addr": 42}, False),  # non-string addr
        ({"name": "no addr"}, False),
        ([{"addr": _GOOD}, 7], False),  # a bad element taints the list
        ("not an address", False),
    ],
)
def test_sender_shapes_never_crash_and_only_one_valid_sender_passes(sender, ok):
    env = {"subject": _SUBJ, "from": sender, "id": "1"}
    assert browser._is_claude_login_mail(env) is ok


@pytest.mark.parametrize(
    "to, ok",
    [
        (None, True),  # absent: no recipient check (as before)
        ([], True),
        ("me@example.org", True),
        ("ME@Example.ORG", True),
        ("Me <me@example.org>, other@example.org", True),  # comma-separated
        ([{"addr": "other@example.org"}, {"addr": "me@example.org"}], True),
        ([{"addr": "other@example.org"}], False),
        ("other@example.org", False),
        ([{"addr": "me@example.org"}, 5], False),  # mixed valid/invalid → malformed
        ({"addr": None}, False),
        (3.5, False),
    ],
)
def test_recipient_shapes(monkeypatch, to, ok):
    monkeypatch.delenv("ANTHROPIC_LOGIN_MAIL_SENDERS", raising=False)
    env = {"subject": _SUBJ, "from": {"addr": _GOOD}, "to": to, "id": "7"}
    _serve(monkeypatch, [env])
    diag: list[str] = []
    got = browser._himalaya_login_mail_candidates("h", "me@example.org", 0.0, diag=diag)
    assert (got == [("INBOX", "7")]) is ok


@pytest.mark.parametrize("subject", [5, None, ["Claude link"], {"s": 1}])
def test_non_string_subject_is_not_a_login_mail(subject):
    env = {"subject": subject, "from": {"addr": _GOOD}}
    assert browser._looks_like_claude_login_mail(env) is False


@pytest.mark.parametrize("date", [12345, None, ["2026-09-24 10:00+00:00"], "garbage"])
def test_odd_date_ranks_as_undated_without_crashing(monkeypatch, date):
    monkeypatch.delenv("ANTHROPIC_LOGIN_MAIL_SENDERS", raising=False)
    env = {"subject": _SUBJ, "from": {"addr": _GOOD}, "date": date, "id": "9"}
    _serve(monkeypatch, [env])
    assert browser._himalaya_login_mail_candidates("h", "", 0.0) == [("INBOX", "9")]


def test_malformed_sender_is_reported_not_silent(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_LOGIN_MAIL_SENDERS", raising=False)
    env = {"subject": _SUBJ, "from": [{"addr": _GOOD}, {"addr": _GOOD}], "id": "1"}
    _serve(monkeypatch, [env])
    rejected: list[str] = []
    got = browser._himalaya_login_mail_candidates(
        "h", "", 0.0, rejected_senders=rejected
    )
    assert got == [] and len(rejected) == 1
    assert "<no single valid sender>" in rejected[0]
