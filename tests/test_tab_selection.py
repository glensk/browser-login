#!/usr/bin/env python3
"""Unit tests for tab selection, the zero-tab guard (tp#317) and the
origin-only no-match hint (tp#337).

Three failure modes are pinned here:

* ``eval --url SUBSTR`` used to fall back to an arbitrary tab when nothing
  matched — a SharePoint query then ran inside the Slack tab and returned
  Slack's HTML, which reads like an API error instead of a wrong-tab result.
  `_pick_page(..., require_match=True)` must return no page at all.
* A Chromium whose last tab was closed keeps running with zero page targets,
  and `connect_over_cdp` then fails for every consumer. `_ensure_page_target`
  creates exactly one blank tab first — and creates none when a tab exists.
* The `eval --url` no-match error used to list every open tab's URL path — a
  reset-token path, a magic-link token or a whole ``data:`` body went into the
  caller's log and the LLM transcript. `_tab_hint` renders origins only,
  fails closed on malformed URLs, and the message never points at `status`.

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

    def close(self) -> None:  # cmd_* call browser.close() in their finally
        pass


class _Playwright:
    def stop(self) -> None:
        pass


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


# --- the origin-only no-match hint (tp#337) ---------------------------------

_SECRETS = ("SECRET-IN-PATH", "HIDDEN", "secret-body", "user:pw", "99999")

# (url, expected hint) — plain tables, not pytest.mark.parametrize, so the
# module stays importable without pytest (the plan's verification scripts
# import it under `uv run`, whose venv has no pytest).
_HINT_TABLE = [
    (
        "https://example.test/reset/SECRET-IN-PATH?code=HIDDEN#frag",
        "https://example.test",
    ),
    ("https://user:pw@example.test:8443/x?y=z", "https://example.test:8443"),
    ("HTTPS://EXAMPLE.TEST/", "https://example.test"),
    ("http://[::1]:8080/p", "http://[::1]:8080"),
    ("chrome://newtab/", "chrome://newtab"),
    ("about:blank", "about:blank"),  # the "use `open`" signal, kept verbatim
    ("about:srcdoc", "about:…"),
    ("data:text/html,<b>secret-body</b>#frag", "data:…"),
    ("blob:https://example.test/0b1e-uuid", "blob:…"),
    ("file:///Users/x/reset-SECRET-IN-PATH.html", "file:…"),
    ("javascript:alert(document.cookie)", "javascript:…"),
    ("https:", "https:…"),
    ("", "(empty)"),
    ("http://[::1/x", "<unparseable url>"),  # malformed IPv6 → urlsplit raises
    ("http://h:99999/", "<unparseable url>"),  # .port raises: out of range
    ("http://h:abc/", "<unparseable url>"),  # .port raises: not an int
    ("https://exa\x00mple.test/x", "<unparseable url>"),  # control char in host
    ("ht\x00tps://h/x", "<unparseable url>"),  # control char breaks the scheme
    ("example.test/no-scheme", "<unparseable url>"),
]

_MALFORMED = [
    "http://[::1/LEAKMARK",  # malformed IPv6 literal
    "http://LEAKMARK:99999/",  # port out of range
    "http://LEAKMARK:abc/",  # port not an int
    "https://LEAK\x00MARK.test/x",  # control character in the host
    "LEAK\x00MARK://h/x",  # control character breaks the scheme
    "LEAKMARK.test/no-scheme",
]


def test_tab_hint_is_origin_only_and_fails_closed():
    for url, hint in _HINT_TABLE:
        assert browser._tab_hint(url) == hint, url


def test_tab_hint_leaks_no_byte_of_a_malformed_url():
    # Fail closed: the placeholder is a FIXED literal chosen without looking at
    # the input, so neither the marker, the offending port nor the control
    # character can reach the error line.
    for url in _MALFORMED:
        assert browser._tab_hint(url) == "<unparseable url>", url


def test_eval_no_match_names_open_tabs_by_origin_only(monkeypatch, capsys):
    br = _Browser(
        [
            "https://user:pw@example.test/reset/SECRET-IN-PATH?code=HIDDEN",
            "data:text/html,<b>secret-body</b>#frag",
            "blob:https://example.test/SECRET-IN-PATH",
            "http://h:99999/",
            "",
            "https://app.slack.com/client/T1/C1",
            "https://app.slack.com/client/T1/C2",
        ]
    )
    monkeypatch.setattr(browser, "_connect", lambda port: (_Playwright(), br))
    rc = browser.cmd_eval(9222, "1", "epflch.sharepoint.com")  # no traceback
    assert rc == 1
    out, err = capsys.readouterr()
    assert out == ""
    for secret in _SECRETS:
        assert secret not in err and secret not in out
    assert "status" not in err
    assert "No tab matching 'epflch.sharepoint.com' — nothing evaluated." in err
    assert err.rstrip("\n").endswith(
        "Open tabs: https://example.test, data:…, blob:…, <unparseable url>, "
        "(empty), https://app.slack.com ×2"
    )


def test_eval_no_match_dedups_before_capping(monkeypatch, capsys):
    # 12 tabs over 10 origins: a repeat inside the listed 8 (position 1) and a
    # repeat of an omitted origin (position 11 repeats position 9). The cap and
    # the "+N more" count are in ORIGINS, so a duplicate tab can neither push a
    # unique origin out of the list nor inflate the tail count (12-8 would be 4).
    origins = [f"https://o{i}.test" for i in range(10)]
    urls = [f"{o}/p/{n}?t=SECRET" for n, o in enumerate(origins)]
    urls.insert(1, f"{origins[0]}/dup?t=SECRET")
    urls.append(f"{origins[8]}/dup?t=SECRET")
    assert len(urls) == 12 and len({browser._tab_hint(u) for u in urls}) == 10
    monkeypatch.setattr(
        browser, "_connect", lambda port: (_Playwright(), _Browser(urls))
    )
    assert browser.cmd_eval(9222, "1", "nothing.test") == 1
    err = capsys.readouterr().err
    assert "SECRET" not in err and "/p/" not in err
    listed = err.split("Open tabs: ", 1)[1].rstrip("\n")
    assert listed == (
        "https://o0.test ×2, https://o1.test, https://o2.test, https://o3.test, "
        "https://o4.test, https://o5.test, https://o6.test, https://o7.test, "
        "… (+2 more origins)"
    )


def test_eval_matching_still_uses_the_full_url():
    # Only the PRINTED hint shrinks; a path substring still selects the tab.
    br = _Browser(["https://x.test/sites/foo/a", "https://x.test/other"])
    _ctx, page = browser._pick_page(br, "/sites/foo", require_match=True)
    assert page is not None and page.url.endswith("/a")
