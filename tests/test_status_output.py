"""Unit tests for the `status` tab listing (tp#365).

`browser.py status` used to print every tab's title and FULL URL verbatim.
Nearly every LLM session runs it first, so an in-flight OAuth authorize tab
(`state=`, `nonce=`, `redirect_uri=`), a magic-link tab (`/auth/magic/<token>`)
or a ``data:`` page landed its secret in the caller's log and the transcript.
Pinned here:

* the URL column is origin-only (`_tab_hint`, shared with the tp#337 `eval
  --url` no-match error) unless `-f/--full-urls` is given explicitly;
* the title column fails closed (`_tab_title`): Chrome titles a page without
  ``<title>`` with its own URL minus the scheme, so that default (raw or
  percent-decoded), a non-string, a blank, a non-printable (line-forging)
  title and an over-long one all render as a placeholder or a cut — with or
  without `--full-urls`;
* a non-string ``url`` never reaches `_tab_hint`;
* the header, the ``N tab(s):`` count, the lifecycle call and both exit codes
  are unchanged, and the default output never advertises the flag.

Run: python3 -m pytest tests/ -q     (from the repo root)
"""

from __future__ import annotations

# Tests reach into browser.py's private helpers on purpose (it is a script, not
# a package, so there is no public API).
# pylint: disable=protected-access,too-few-public-methods
# pylint: disable=missing-function-docstring,missing-class-docstring,import-error
# pylint: disable=unused-argument
import importlib.util
import sys
from pathlib import Path

import pytest

_BROWSER_PY = Path(__file__).resolve().parent.parent / "bin" / "browser.py"


def _load_browser_module():
    """Import bin/browser.py as a module (it has no module-level playwright import)."""
    spec = importlib.util.spec_from_file_location(
        "browser_status_under_test", _BROWSER_PY
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["browser_status_under_test"] = mod
    spec.loader.exec_module(mod)
    return mod


browser = _load_browser_module()

PORT = 9222

# --- fixture tabs -----------------------------------------------------------
# Every secret-bearing byte sequence is a LEAK-… marker so an assertion can
# sweep the whole stdout for it.

_KEYCLOAK = (
    "https://custos.datascience.ch/realms/sdsc/protocol/openid-connect/auth"
    "?scope=openid&state=LEAK-STATE&response_type=code&client_id=runai"
    "&redirect_uri=https%3A%2F%2Fapp.test%2Fcb&nonce=LEAK-NONCE"
)
_MAGIC = "https://mail.test/auth/magic/LEAK-MAGIC-TOKEN"
_DATA = "data:text/html,<b>LEAK-DATA-BODY</b>#LEAK-FRAG"
_USERINFO = "https://LEAK-USER:LEAK-PW@example.test/reset/LEAK-PATH?code=LEAK-CODE"
_IPV6 = "http://[::1]:8080/LEAK-V6-PATH"
_MALFORMED = "http://LEAK-MALFORMED:99999/"
# Chrome's untitled default: the URL minus its scheme, path + query included.
_UNTITLED_DEFAULT_URL = "https://cb.test/callback?token=LEAK-TITLE-TOKEN"
_UNTITLED_DEFAULT_TITLE = "cb.test/callback?token=LEAK-TITLE-TOKEN"
_ENCODED_URL = "https://cb.test/cb?next=%2Fhome%3Ft%3DLEAK-ENC-TOKEN"
_ENCODED_TITLE = "cb.test/cb?next=/home?t=LEAK-ENC-TOKEN"

_TARGETS: list[dict[str, object]] = [
    {"type": "page", "title": "Sign in to SDSC", "url": _KEYCLOAK},
    {"type": "page", "title": "Your magic link", "url": _MAGIC},
    {"type": "page", "title": "Probe", "url": _DATA},
    {"type": "page", "title": "New Tab", "url": "about:blank"},
    {"type": "page", "title": "Reset your password", "url": _USERINFO},
    {"type": "page", "title": "Local dev", "url": _IPV6},
    {"type": "page", "title": "Broken", "url": _MALFORMED},
    {"type": "page", "title": _UNTITLED_DEFAULT_TITLE, "url": _UNTITLED_DEFAULT_URL},
    {"type": "page", "title": _ENCODED_TITLE, "url": _ENCODED_URL},
    {
        "type": "page",
        "title": "Real\n   - FORGED  →  https://LEAK-FORGED",
        "url": "https://x.test/a",
    },
    {"type": "page", "title": 42, "url": "https://y.test/b"},
    {"type": "service_worker", "title": "sw", "url": "https://sw.test/LEAK-SW"},
]
_PAGE_COUNT = sum(1 for t in _TARGETS if t["type"] == "page")
_GENUINE_TITLES = [
    "Sign in to SDSC",
    "Your magic link",
    "Probe",
    "New Tab",
    "Reset your password",
    "Local dev",
    "Broken",
]
_RAW_URLS = [str(t["url"]) for t in _TARGETS if t["type"] == "page"]
_LEAKS = [
    "LEAK-",
    "state=",
    "nonce=",
    "redirect_uri=",
    "/auth/magic/",
    "/reset/",
    "/callback",
    "text/html",
    "99999",
    "FORGED",
    "?",
    "#",
]
_HEADER = f"✓ Up — Chrome/151.0 (headed) | CDP http://localhost:{PORT}"


def _stub_cdp(monkeypatch, targets: list[dict[str, object]] | None):
    """CDP up (version + targets) or down (targets=None)."""
    lifecycle_calls: list[int] = []

    def cdp_get(port, path, timeout=2.0):
        if targets is None:
            return None
        if path == "/json/version":
            return {"Browser": "Chrome/151.0"}
        if path == "/json/list":
            return targets
        raise AssertionError(path)

    monkeypatch.setattr(browser, "_cdp_get", cdp_get)
    monkeypatch.setattr(browser, "_browser_mode", lambda port: "headed")
    monkeypatch.setattr(browser, "_print_lifecycle", lifecycle_calls.append)
    return lifecycle_calls


def _tab_lines(out: str) -> list[str]:
    return [ln for ln in out.splitlines() if ln.startswith("   - ")]


# --- cmd_status ---------------------------------------------------------------


def test_status_default_prints_origins_only(monkeypatch, capsys):
    calls = _stub_cdp(monkeypatch, _TARGETS)
    assert browser.cmd_status(PORT) == 0
    out, err = capsys.readouterr()
    assert err == ""
    lines = out.splitlines()
    assert lines[0] == _HEADER
    assert lines[1] == f"  {_PAGE_COUNT} tab(s):"
    tabs = _tab_lines(out)
    assert len(tabs) == _PAGE_COUNT
    assert len(lines) == 2 + _PAGE_COUNT  # no trailer, no forged line
    for leak in _LEAKS:
        assert leak not in out, leak
    assert "full-urls" not in out and "-f" not in out
    for title in _GENUINE_TITLES:
        assert f"   - {title}  →  " in out, title
    assert [ln.rsplit("  →  ", 1)[1] for ln in tabs] == [
        "https://custos.datascience.ch",
        "https://mail.test",
        "data:…",
        "about:blank",
        "https://example.test",
        "http://[::1]:8080",
        "<unparseable url>",
        "https://cb.test",
        "https://cb.test",
        "https://x.test",
        "https://y.test",
    ]
    # untitled-default (raw + percent-decoded), multiline and non-string titles
    assert out.count("   - (untitled)  →  ") == 4
    assert calls == [PORT]


def test_status_full_urls_prints_raw_urls_but_titles_still_fail_closed(
    monkeypatch, capsys
):
    calls = _stub_cdp(monkeypatch, _TARGETS)
    assert browser.cmd_status(PORT, full_urls=True) == 0
    out = capsys.readouterr().out
    lines = out.splitlines()
    assert lines[0] == _HEADER
    assert lines[1] == f"  {_PAGE_COUNT} tab(s):"
    tabs = _tab_lines(out)
    assert len(tabs) == _PAGE_COUNT
    assert len(lines) == 2 + _PAGE_COUNT  # a multiline title still forges nothing
    assert [ln.rsplit("  →  ", 1)[1] for ln in tabs] == _RAW_URLS
    assert "LEAK-SW" not in out  # the service worker is not a page
    for title in _GENUINE_TITLES:
        assert f"   - {title}  →  " in out, title
    assert out.count("   - (untitled)  →  ") == 4
    assert "FORGED" not in out and "LEAK-TITLE-TOKEN  →" not in out
    assert calls == [PORT]


def test_status_with_zero_page_targets(monkeypatch, capsys):
    calls = _stub_cdp(
        monkeypatch, [{"type": "service_worker", "url": "https://sw.test/x"}]
    )
    assert browser.cmd_status(PORT) == 0
    out = capsys.readouterr().out
    assert out.splitlines() == [_HEADER, "  0 tab(s):"]
    assert calls == [PORT]


def test_status_when_cdp_is_down(monkeypatch, capsys):
    calls = _stub_cdp(monkeypatch, None)
    assert browser.cmd_status(PORT) == 1
    out = capsys.readouterr().out
    assert out.splitlines() == [
        f"✗ Shared browser is DOWN (no CDP on http://localhost:{PORT}). Run: browser.py up"
    ]
    assert _tab_lines(out) == []
    assert calls == [PORT]


# --- _tab_title ---------------------------------------------------------------


def test_tab_title_keeps_a_normal_title():
    assert browser._tab_title("Sign in to SDSC", _KEYCLOAK) == "Sign in to SDSC"
    assert browser._tab_title("Ünïcödé — ok ✓", "https://x.test/") == "Ünïcödé — ok ✓"


@pytest.mark.parametrize(
    "title,url",
    [
        (None, "https://x.test/a"),  # non-string
        (42, "https://x.test/a"),  # non-string
        ("", "https://x.test/a"),  # blank
        ("   ", "https://x.test/a"),  # blank
        (_UNTITLED_DEFAULT_TITLE, _UNTITLED_DEFAULT_URL),  # Chrome untitled default
        (_ENCODED_TITLE, _ENCODED_URL),  # …percent-decoded form
        ("x.test/a", "https://x.test/a"),  # substring of the URL at all
        ("Real\nFORGED line", "https://x.test/a"),  # newline forges a line
        ("tab\there", "https://x.test/a"),  # control character
        ("Real\n   - FORGED", None),  # url missing: still fails closed
    ],
)
def test_tab_title_fails_closed(title, url):
    assert browser._tab_title(title, url) == "(untitled)"


def test_tab_title_cuts_at_100_characters():
    assert browser._tab_title("t" * 100, "https://x.test/") == "t" * 100
    assert browser._tab_title("t" * 101, "https://x.test/") == "t" * 97 + "…"
    assert len(browser._tab_title("t" * 500, "https://x.test/")) == 98


# --- _tab_line ----------------------------------------------------------------


@pytest.mark.parametrize(
    "target,expected",
    [
        ({"title": "T"}, "   - T  →  (empty)"),
        ({"title": "T", "url": None}, "   - T  →  (empty)"),
        ({"title": "T", "url": ""}, "   - T  →  (empty)"),
        ({"title": "T", "url": 123}, "   - T  →  <unparseable url>"),
        ({"title": "T", "url": {}}, "   - T  →  <unparseable url>"),
        ({"title": "T", "url": ["https://LEAK"]}, "   - T  →  <unparseable url>"),
        ({}, "   - (untitled)  →  (empty)"),
    ],
)
def test_tab_line_never_raises_on_a_non_string_url(target, expected):
    assert browser._tab_line(target) == expected
    assert browser._tab_line(target, full_urls=True) == expected


def test_tab_line_default_vs_full_urls():
    target = {"title": "Your magic link", "url": _MAGIC}
    assert browser._tab_line(target) == "   - Your magic link  →  https://mail.test"
    assert (
        browser._tab_line(target, full_urls=True)
        == f"   - Your magic link  →  {_MAGIC}"
    )
    # the flag opts into raw URLs, not raw title bytes
    forged = {"title": "Real\n   - FORGED", "url": _MAGIC}
    assert browser._tab_line(forged, full_urls=True) == f"   - (untitled)  →  {_MAGIC}"


# --- argparse + dispatch ------------------------------------------------------


@pytest.mark.parametrize(
    "argv,expected",
    [
        (["browser.py", "status"], False),
        (["browser.py", "status", "-f"], True),
        (["browser.py", "status", "--full-urls"], True),
    ],
)
def test_status_parser_full_urls_flag(monkeypatch, argv, expected):
    monkeypatch.setattr(sys, "argv", argv)
    args = browser.parse_args()
    assert args.cmd == "status" and args.full_urls is expected


@pytest.mark.parametrize(
    "argv,expected",
    [
        (["browser.py", "status"], False),
        (["browser.py", "status", "-f"], True),
    ],
)
def test_main_dispatches_full_urls_to_cmd_status(monkeypatch, argv, expected):
    seen: list[tuple[int, bool]] = []

    def cmd_status(port, full_urls=False):
        seen.append((port, full_urls))
        return 42

    monkeypatch.setattr(sys, "argv", argv)
    monkeypatch.setattr(browser, "ensure_deps", lambda: None)
    monkeypatch.setattr(browser, "_set_purpose", lambda purpose: None)
    monkeypatch.setattr(browser, "cmd_status", cmd_status)
    assert browser.main() == 42
    assert seen == [(browser.DEFAULT_CDP_PORT, expected)]


def test_status_help_names_the_flag_unsafe(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["browser.py", "status", "-h"])
    with pytest.raises(SystemExit) as exc:
        browser.parse_args()
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "--full-urls" in out and "UNSAFE" in out and "origin only" in out
