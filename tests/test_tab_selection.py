#!/usr/bin/env python3
"""Unit tests for tab selection and the zero-tab guard (tp#317).

Two failure modes are pinned here:

* ``eval --url SUBSTR`` used to fall back to an arbitrary tab when nothing
  matched — a SharePoint query then ran inside the Slack tab and returned
  Slack's HTML, which reads like an API error instead of a wrong-tab result.
  `_pick_page(..., require_match=True)` must return no page at all.
* A Chromium whose last tab was closed keeps running with zero page targets,
  and `connect_over_cdp` then fails for every consumer. `_ensure_page_target`
  creates exactly one blank tab first — and creates none when a tab exists.

Run: python3 -m pytest tests/ -q     (from the repo root)
"""

from __future__ import annotations

# Tests reach into browser.py's private helpers on purpose (it is a script, not
# a package, so there is no public API), and build throwaway stub classes.
# pylint: disable=protected-access,too-few-public-methods
# pylint: disable=missing-function-docstring,missing-class-docstring,import-error
# pylint: disable=unused-argument
import importlib.util
import sys
from pathlib import Path

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


class _Page:
    def __init__(self, url: str) -> None:
        self.url = url


class _Ctx:
    def __init__(self, urls: list[str]) -> None:
        self.pages = [_Page(u) for u in urls]
        self.created = 0

    def new_page(self) -> _Page:
        self.created += 1
        page = _Page("about:blank")
        self.pages.append(page)
        return page


class _Browser:
    def __init__(self, urls: list[str]) -> None:
        self.contexts = [_Ctx(urls)]


# --- _pick_page -------------------------------------------------------------


def test_require_match_refuses_a_non_matching_tab():
    br = _Browser(["https://app.slack.com/client/T1/C1"])
    ctx, page = browser._pick_page(br, "epflch.sharepoint.com", require_match=True)
    assert page is None
    assert ctx.created == 0  # and it did not open one either


def test_require_match_still_returns_the_matching_tab():
    br = _Browser(["https://app.slack.com/client/T1", "https://portal.cscs.ch/"])
    _ctx, page = browser._pick_page(br, "portal.cscs.ch", require_match=True)
    assert page is not None and page.url == "https://portal.cscs.ch/"


def test_default_fallback_is_unchanged_for_the_site_flows():
    # The in-repo site flows (cscs, slack, claude.ai, …) pick a reusable tab and
    # NAVIGATE it — they must keep getting a page when nothing matches.
    br = _Browser(["about:blank", "https://app.slack.com/client/T1"])
    _ctx, page = browser._pick_page(br, "portal.cscs.ch")
    assert page is not None and page.url == "https://app.slack.com/client/T1"


def test_no_substring_prefers_a_content_tab_over_a_blank_one():
    br = _Browser(["https://example.com/", "about:blank"])
    _ctx, page = browser._pick_page(br, None)
    assert page is not None and page.url == "https://example.com/"


# --- the zero-tab guard -----------------------------------------------------


def test_page_targets_ignores_non_page_targets(monkeypatch):
    targets = [
        {"type": "service_worker", "url": "chrome-extension://x/sw.js"},
        {"type": "browser_ui", "url": "chrome://webui-toolbar.top-chrome/"},
        {"type": "page", "url": "about:blank"},
    ]
    monkeypatch.setattr(browser, "_cdp_get", lambda *a, **k: targets)
    assert [t["url"] for t in browser._page_targets(9222)] == ["about:blank"]


def test_page_targets_on_an_unreachable_browser(monkeypatch):
    monkeypatch.setattr(browser, "_cdp_get", lambda *a, **k: None)
    assert browser._page_targets(9222) == []


def test_ensure_page_target_creates_one_tab_when_there_are_none(monkeypatch):
    state: dict = {"pages": [], "created": 0}

    def _new_tab(port: int, url: str = "about:blank", timeout: float = 5.0) -> bool:
        state["created"] += 1
        state["pages"] = [{"type": "page", "url": url}]
        return True

    monkeypatch.setattr(browser, "_cdp_get", lambda *a, **k: state["pages"])
    monkeypatch.setattr(browser, "_cdp_new_tab", _new_tab)
    browser._ensure_page_target(9222)
    assert state["created"] == 1


def test_ensure_page_target_is_a_no_op_when_a_tab_exists(monkeypatch):
    calls: list[int] = []

    def _new_tab(*_a, **_k) -> bool:
        calls.append(1)
        return True

    monkeypatch.setattr(
        browser, "_cdp_get", lambda *a, **k: [{"type": "page", "url": "about:blank"}]
    )
    monkeypatch.setattr(browser, "_cdp_new_tab", _new_tab)
    browser._ensure_page_target(9222)
    assert not calls


def test_ensure_page_target_gives_up_instead_of_hanging(monkeypatch):
    # Tab creation refused → return at once and let connect_over_cdp raise the
    # real error, rather than masking it with one of our own.
    monkeypatch.setattr(browser, "_cdp_get", lambda *a, **k: [])
    monkeypatch.setattr(browser, "_cdp_new_tab", lambda *a, **k: False)
    browser._ensure_page_target(9222, timeout=30.0)  # must not sleep for 30 s
