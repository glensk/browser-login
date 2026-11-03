"""tp#1643: the REAL Notion Safari recipe against the page it lands on.

The login page moved to app.notion.com/login; the recipe's step still named
www.notion.so, so every run ended `recipe_stuck` before the e-mail fill. These
tests drive `RECIPES["notion"]` itself (not a synthetic recipe): its detector
and fills on a hand-written fixture of the new page in a throwaway headless
Chromium (skipped without Playwright's Chromium), and the Machine through a
scripted safari.py whose tabs report the app.notion.com host. Hermetic: no
network, no real Safari, no real mailbox; codes are generated per run.
"""

from __future__ import annotations

# pylint: disable=missing-function-docstring,import-error,wrong-import-position
# pylint: disable=protected-access,redefined-outer-name
import json
import secrets
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

sys.path[:0] = [
    str(Path(__file__).resolve().parent.parent),
    str(Path(__file__).resolve().parent),
]

import chromium_page  # noqa: E402
import test_ws1b_safari as w  # noqa: E402

import agent_login_safari as s  # noqa: E402

browser = chromium_page.load_script("bin/browser.py", "browser_tp1643_recipe_test")
al = chromium_page.load_script("agent-login.py", "agent_login_tp1643_recipe_test")

NOTION = s.RECIPES["notion"]
STEP = NOTION.steps[0]
LOGIN_URL = "https://app.notion.com/login"
HOME_URL = "https://app.notion.com/"
ME = "me@example.org"

# The new login page's STRUCTURE (read-only probe, 2026-11-03): one form, one
# visible input[type=email] (autocomplete=username, no name), a password-
# manager helper inside an aria-hidden container, ONE div[role=button]
# "Continue", the provider buttons. No ids, tokens or URLs from the real tab.
LOGIN_PAGE = """<!doctype html><html><body>
<h1>Think it. Make it.</h1>
<p>Log in to your Notion account</p>
<div role="button">Google</div>
<div role="button">ChatGPT</div>
<div role="button">Apple</div>
<div role="button">Microsoft</div>
<div role="button">Passkey</div>
<div role="button">SSO</div>
<form onsubmit="event.preventDefault()">
  <label>Work email</label>
  <input type="email" autocomplete="username" placeholder="Enter your email address">
  <div aria-hidden="true">
    <input type="password" autocomplete="current-password" tabindex="-1">
  </div>
  <div role="button" tabindex="0">Continue</div>
</form>
<div role="button">Language: English (US)</div>
</body></html>"""
# The code page: UNVERIFIED shape (needs a sent code), mirrors what the
# headless fill matched live: a one-time-code input and a "Continue" button.
CODE_PAGE_HTML = """<!doctype html><html><body>
<script>window.sent = 0; window.go = () => { window.sent += 1; };</script>
<p>We just sent you a temporary login code. Please check your inbox.</p>
<form onsubmit="event.preventDefault()">
  <input type="text" autocomplete="one-time-code" inputmode="text">
  <div role="button" tabindex="0" onclick="go()">Continue</div>
</form>
</body></html>"""

CHROME = pytest.mark.skipif(
    not chromium_page.chromium_available(), reason="Playwright Chromium missing"
)


# ---------------------------------------------------------------------------
# (1) (2) the detector and the fills on the fixture pages (one Chromium)
# ---------------------------------------------------------------------------


@pytest.mark.launches_chrome
@CHROME
def test_detector_and_fills_on_the_new_login_and_code_pages() -> None:
    pages = {LOGIN_URL: LOGIN_PAGE, LOGIN_URL + "?code": CODE_PAGE_HTML}

    def handler(route: Any) -> None:
        body = pages.get(route.request.url)
        if body is None:
            route.abort()
            return
        route.fulfill(status=200, content_type="text/html", body=body)

    detector = "() => " + s.detector_js(NOTION, NOTION.sentinel)
    code = secrets.token_hex(3)
    with chromium_page.routed_context(handler) as context:
        page = context.new_page()
        page.goto(LOGIN_URL)
        login = s.parse_page(page.evaluate(detector), len(NOTION.steps))
        assert login is not None
        assert login["user"] is True
        assert login["steps"] == [(True, False)]  # when fits, no unless
        assert login["sentinel"] is False and login["code"] is False
        assert not any(login[flag] for flag in s.ALBERT_STOPS)
        params = {"field": STEP.email_field, "email": ME}
        got = json.loads(
            page.evaluate(
                "() => " + s.EMAIL_FILL_JS.replace("__PARAMS__", json.dumps(params))
            )
        )
        assert got == {"ok": True}
        assert page.evaluate("document.querySelector('input[type=email]').value") == ME

        page.goto(LOGIN_URL + "?code")
        codepage = s.parse_page(page.evaluate(detector), len(NOTION.steps))
        assert codepage is not None and codepage["code"] is True
        assert codepage["email_code"] is True and codepage["sentinel"] is False
        body = s.CODE_FILL_JS.replace(
            "__PARAMS__",
            json.dumps(
                {
                    "otp": s._OTP_FIELD,
                    "code": code,
                    "submit": STEP.submit,
                    "alts": list(s.CODE_SUBMIT_VARIANTS),
                }
            ),
        )
        got = json.loads(page.evaluate("() => " + body))
        assert got["ok"] is True and got["clicked"] is True
        assert code not in json.dumps(got)
        assert page.evaluate("window.sent") == 1


# ---------------------------------------------------------------------------
# the Machine with the real recipe and a scripted safari.py
# ---------------------------------------------------------------------------

LOGIN = (LOGIN_URL, w._page(user=True, password=True, steps=[[True, False]]))
CODE = (LOGIN_URL, w._page(code=True, email_code=True, steps=[[False, False]]))
HOME = (HOME_URL, w._page(sentinel=True))
GONE: tuple[str, dict] = ("", {})  # the login window is no longer in --tabs
# one script entry: (tab url, detector page, reads on it or None)
Entry = tuple[str, dict, int | None]


class NotionSafari(w.FakeSafari):
    """safari.py for the real recipe. Each script entry is (url, page,
    reads): `reads` detector reads on that page, then the next entry (None:
    until an action). The trigger click and the code fill move on."""

    def __init__(self, script: Sequence[Entry], code: str) -> None:
        super().__init__(NOTION, [(u, p) for u, p, _r in script])
        self.reads = [r for _u, _p, r in script]
        self.seen = 0
        self.code = code
        self.order: list[str] = []

    def _advance(self) -> None:
        self.pos += 1
        self.seen = 0

    def __call__(self, args: list[str]) -> s.Reply:
        assert self.code not in " ".join(args)  # never on argv
        if args[0] == "--tabs" and not self._now()[0]:
            self.calls.append(list(args))
            return s.Reply(0, {"ok": True, "tabs": [{"window_id": 7, "url": HOME_URL}]})
        if args[0] == "--click":
            self.calls.append(list(args))
            self.order.append(f"click:{args[1]}")
            self._advance()
            return s.Reply(0, {"ok": True})
        if args[0] != "--eval":
            return super().__call__(args)
        body = Path(args[1]).read_text(encoding="utf-8")
        if "agent-login:email" in body:
            self.calls.append(list(args))
            self.order.append("email")
            return s.Reply(0, {"result": json.dumps({"ok": True})})
        if "agent-login:code" in body:
            self.calls.append(list(args))
            self.order.append("code")
            self._advance()
            return s.Reply(0, {"result": json.dumps({"ok": True, "clicked": True})})
        reply = super().__call__(args)  # the detector
        self.seen += 1
        limit = self.reads[min(self.pos, len(self.reads) - 1)]
        if limit is not None and self.seen >= limit and self.pos < len(self.reads) - 1:
            self._advance()
        return reply


class Clock:
    """A fake monotonic clock that the fake sleep advances."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _run(
    script: Sequence[Entry],
    hook: Any = None,
) -> tuple[s.Outcome, NotionSafari, w.FakeMailbox]:
    box = w.FakeMailbox()
    code = f"{secrets.randbelow(900000) + 100000}"
    fake = NotionSafari(script, code)
    clock = Clock()

    def sleep(secs: float) -> None:
        clock.now += secs
        if not box.mails:
            box.add(
                "INBOX",
                "9",
                f"Your login code\n\n{code}\n",
                auth="mx.example.net; dkim=pass header.d=updates.notion.com",
                **{"from": {"addr": "notify@updates.notion.com"}},
            )

    plan = s.Plan(
        start_url=NOTION.start_url,
        sentinel=NOTION.sentinel,
        expected_email=ME,
        mail=w._reader(box),
    )
    out = s.Machine(
        NOTION, plan, fake, sleep=sleep, clock=clock, before_trigger=hook
    ).run()
    return out, fake, box


def test_the_real_recipe_logs_in_on_app_notion_com() -> None:
    """(3) e-mail fill → hook → Continue → code fill, every action pinned to
    app.notion.com."""
    order: list[str] = []

    def hook() -> None:
        order.append("hook")

    script = [(*LOGIN, None), (*CODE, None), (*HOME, None)]
    out, fake, box = _run(script, hook)
    assert out.ok and out.code == "ok" and out.credential
    assert fake.order == ["email", "click:Continue", "code"]
    assert order == ["hook"]
    assert fake.calls[0][:2] == ["--open", "https://app.notion.com/login"]
    hosts = [
        c[c.index("--expect-host") + 1] for c in fake.calls if "--expect-host" in c
    ]
    assert hosts and set(hosts) == {"app.notion.com"}
    assert out.mail_archived == "ok" and box.moves == [
        ["--folder", "INBOX", "Archive", "9"]
    ]


def test_the_step_host_and_start_url_are_the_login_page() -> None:
    """(4) (10) regression guards against a stale host / start URL."""
    assert STEP.host == browser.NOTION_APP_HOST
    assert NOTION.start_url == browser.NOTION_LOGIN_URL
    for recipe in s.RECIPES.values():
        for step in recipe.steps:
            assert step.host in recipe.hosts, (recipe.site, step.kind)


def test_a_host_without_a_step_is_named_and_nothing_is_typed() -> None:
    """(5) the old redirect host: stuck, the reason and host named, no fill."""
    page = ("https://www.notion.so/login", LOGIN[1], None)
    out, fake, _box = _run([page])
    assert (out.rc, out.code) == (2, "recipe_stuck")
    assert (out.stuck, out.stuck_host) == ("no_step_for_host", "www.notion.so")
    # no e-mail fill, no click, no code fill (the fake records each one)
    assert not fake.order and not out.credential
    assert not [c for c in fake.calls if c[0] == "--click"]


def test_a_code_field_that_never_shows_stops_without_a_quarantine(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """(6) (7) the code mail came, the code page never did: no credential, no
    code fill, the unused mail archived once, no quarantine, the ❌ line names
    the reason; the code never in output or argv."""
    script = [(*LOGIN, None), (*LOGIN, None)]  # the click leads nowhere new
    out, fake, box = _run(script)
    assert (out.rc, out.code) == (2, "recipe_stuck")
    assert (out.stuck, out.stuck_host) == ("code_field", "app.notion.com")
    assert not out.credential and "code" not in fake.order
    assert len(box.moves) == 1 and out.mail_archived == "ok"

    quarantined: list[tuple] = []
    records: list[dict] = []
    monkeypatch.setattr(al.als, "quarantine", lambda *a: quarantined.append(a))
    monkeypatch.setattr(
        al,
        "record_check",
        lambda site, ok, how, result=None, **_k: records.append(result),
    )
    rc = al._safari_fail("notion", out, "Safari login stopped — recipe_stuck")
    assert rc == 2 and not quarantined
    assert records and records[0]["detail"] == "code_field"
    printed = capsys.readouterr()
    assert "(code_field on app.notion.com)" in printed.out
    assert "quarantined" not in printed.out
    for text in (printed.out, printed.err):
        assert fake.code not in text


def test_the_code_page_lingering_after_the_submit_is_waited_for() -> None:
    """(8) the code page stays for 3 reads after the submit, then the home."""
    script = [(*LOGIN, None), (*CODE, None), (*CODE, 3), (*HOME, None)]
    out, fake, _box = _run(script)
    assert out.ok and out.code == "ok" and out.stuck == ""
    assert fake.order == ["email", "click:Continue", "code"]


def test_a_code_page_held_past_the_post_submit_wait_is_after_submit() -> None:
    """(8) held past POST_SUBMIT_S: stuck `after_submit`, credential kept."""
    script = [(*LOGIN, None), (*CODE, None), (*CODE, None)]
    out, _fake, _box = _run(script)
    assert (out.rc, out.code) == (2, "recipe_stuck")
    assert out.stuck == "after_submit" and out.credential


def test_the_window_vanishing_during_the_code_field_wait_is_tab_moved() -> None:
    """(9) the login window left --tabs: safari_tab_moved, not code_field."""
    script = [(*LOGIN, None), (GONE[0], GONE[1], None)]
    out, fake, _box = _run(script)
    assert out.code == "safari_tab_moved" and out.stuck == ""
    assert not out.credential and "code" not in fake.order
