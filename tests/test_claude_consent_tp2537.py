"""tp#2537 B4: claude.ai's cookie-consent banner is dismissed before the login proceeds.

Mocked pages only — no browser, no mail, no real waits.

Run: uv run pytest -q tests/test_claude_consent_tp2537.py   (from the repo root)
"""

from __future__ import annotations

# Tests reach into browser.py's private helpers on purpose (it is a script, not
# a package, so there is no public API), and build throwaway stub classes.
# pylint: disable=protected-access,too-few-public-methods
# pylint: disable=missing-function-docstring,missing-class-docstring
# pylint: disable=unused-argument,too-many-instance-attributes
import importlib.util
import sys
from pathlib import Path

import pytest

_BROWSER_PY = Path(__file__).resolve().parent.parent / "bin" / "browser.py"


def _load_browser_module():
    """Import bin/browser.py as a module (it has no module-level playwright import)."""
    spec = importlib.util.spec_from_file_location("browser_consent_test", _BROWSER_PY)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["browser_consent_test"] = mod
    spec.loader.exec_module(mod)
    return mod


browser = _load_browser_module()


class _Button:
    def __init__(self, page):
        self.page = page

    @property
    def first(self):
        return self

    def count(self):
        return 1 if self.page.banner else 0

    def click(self, timeout=None):
        self.page.pw_clicks.append(timeout)
        if self.page.pw_click_raises:
            raise TimeoutError("Locator.click: Timeout exceeded")
        if self.page.pw_click_works:
            self.page.banner = False


class ConsentPage:
    """A page whose banner is `banner`; the Playwright click and the DOM click
    each either remove it or not."""

    def __init__(
        self,
        *,
        banner=True,
        pw_click_raises=False,
        pw_click_works=True,
        dom_click_works=True,
        has_button=True,
        text="",
    ):
        self.banner = banner
        self.pw_click_raises = pw_click_raises
        self.pw_click_works = pw_click_works
        self.dom_click_works = dom_click_works
        self.has_button = has_button
        self.text = text
        self.pw_clicks: list = []
        self.dom_clicks = 0
        self.waited_ms = 0
        self.url = "https://claude.ai/login"

    def evaluate(self, js, arg=None):
        if js != browser._CONSENT_JS:
            return self.text
        if not self.banner:
            return {"present": False, "clicked": None}
        if not arg:
            return {"present": True, "clicked": None}
        if not self.has_button:
            return {"present": True, "clicked": None}
        self.dom_clicks += 1
        if self.dom_click_works:
            self.banner = False
        return {"present": True, "clicked": "Reject all cookies"}

    def locator(self, sel):
        assert sel == browser._CONSENT_REJECT_SEL
        return _Button(self)

    def wait_for_timeout(self, ms):
        self.waited_ms += ms


def test_no_banner_is_a_no_op():
    page = ConsentPage(banner=False)
    assert browser._claude_dismiss_consent(page) is None
    assert not page.pw_clicks and page.dom_clicks == 0


def test_playwright_reject_click_dismisses():
    page = ConsentPage()
    assert browser._claude_dismiss_consent(page) is True
    assert page.pw_clicks == [3000]  # bounded click
    assert page.dom_clicks == 0


def test_click_timeout_falls_back_to_dom_click():
    """The tp#2537 symptom: the role click times out on actionability."""
    page = ConsentPage(pw_click_raises=True)
    assert browser._claude_dismiss_consent(page) is True
    assert page.dom_clicks == 1


def test_ignored_click_falls_back_to_dom_click_after_bounded_wait():
    page = ConsentPage(pw_click_works=False)
    assert browser._claude_dismiss_consent(page) is True
    assert page.dom_clicks == 1
    assert page.waited_ms <= 5000


def test_stuck_banner_returns_false_bounded():
    page = ConsentPage(pw_click_works=False, dom_click_works=False)
    assert browser._claude_dismiss_consent(page) is False
    assert page.waited_ms <= 10000  # two bounded waits, never a hang


def test_banner_without_a_safe_button_returns_false():
    page = ConsentPage(pw_click_raises=True, has_button=False)
    assert browser._claude_dismiss_consent(page) is False


def test_evaluate_failure_reads_as_no_banner():
    class Broken:
        def evaluate(self, js, arg=None):
            raise RuntimeError("target closed")

    assert browser._claude_dismiss_consent(Broken()) is None


def test_consent_js_never_accepts_all():
    js = browser._CONSENT_JS
    assert "consent-accept" not in js
    assert "accept all" not in js.lower()


@pytest.mark.parametrize(
    ("text", "loading"),
    [
        ("Cookie settings\nReject all cookies\nLoading...", True),
        ("Loading…", True),
        ("Couldn’t verify this link\nTry again", False),
        ("Loading your chats is fast", False),
    ],
)
def test_page_loading(text, loading):
    assert browser._claude_page_loading(ConsentPage(text=text)) is loading


def test_fill_dismisses_banner_before_typing(monkeypatch):
    calls: list[str] = []

    class Field:
        def fill(self, value):
            calls.append("fill")

    class Btn:
        first = property(lambda self: self)

        def count(self):
            return 1

        def click(self, **kwargs):
            calls.append("continue")

    class FormPage:
        def wait_for_selector(self, sel, **kwargs):
            return Field()

        def get_by_role(self, role, name=None):
            return Btn()

    monkeypatch.setattr(
        browser, "_claude_dismiss_consent", lambda page: calls.append("dismiss")
    )
    assert browser._claude_fill_email_and_continue(FormPage(), "me@example.com")
    assert calls == ["dismiss", "fill", "continue"]
