"""Safari session import (tp#733): parser, site rules, browser.py and agent-login.py.

Hermetic: every cookie file is a synthetic one built here by a tiny encoder; the
real Safari jar is never read ($SAFARI_COOKIES points at tmp_path).
"""

from __future__ import annotations

# pylint: disable=protected-access,missing-function-docstring,import-error
# pylint: disable=wrong-import-position,too-few-public-methods,redefined-outer-name
# pylint: disable=unused-argument
import contextlib
import dataclasses
import importlib.util
import struct
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from broker import safari_cookies as sc  # noqa: E402


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod  # dataclasses resolve their module by name
    spec.loader.exec_module(mod)
    return mod


browser = _load("browser_safari_test", ROOT / "bin" / "browser.py")
al = _load("agent_login_safari_test", ROOT / "agent-login.py")

NOW = time.time()
FUTURE = NOW + 86400 * 200
SECRET = "S3CRET-session-value-never-printed"


# ---------------------------------------------------------------------------
# a tiny binarycookies encoder (the inverse of the parser, written from the spec)
# ---------------------------------------------------------------------------


def _record(c: dict) -> bytes:
    strings = [
        c["domain"].encode(),
        c["name"].encode(),
        c.get("path", "/").encode(),
        c.get("value", "v").encode(),
    ]
    offsets, off = [], 56
    for s in strings:
        offsets.append(off)
        off += len(s) + 1
    flags = (1 if c.get("secure") else 0) | (4 if c.get("http_only") else 0)
    head = struct.pack("<IIII", off, 0, flags, 0) + struct.pack("<4I", *offsets)
    head += b"\0" * 8
    head += struct.pack("<dd", c.get("expires", FUTURE) - sc.MAC_EPOCH, 0.0)
    assert len(head) == 56
    return head + b"".join(s + b"\0" for s in strings)


def _page(cookies: list[dict]) -> bytes:
    recs = [_record(c) for c in cookies]
    off = 8 + 4 * len(recs) + 4
    offsets = []
    for r in recs:
        offsets.append(off)
        off += len(r)
    head = b"\x00\x00\x01\x00" + struct.pack("<I", len(recs))
    head += struct.pack(f"<{len(recs)}I", *offsets) + b"\0" * 4
    return head + b"".join(recs)


def encode(*pages: list[dict]) -> bytes:
    blobs = [_page(p) for p in pages]
    out = b"cook" + struct.pack(">I", len(blobs))
    out += struct.pack(f">{len(blobs)}I", *(len(b) for b in blobs))
    return out + b"".join(blobs) + b"\0" * 8


JAR: list[list[dict]] = [
    [
        {
            "domain": ".www.anibis.ch",
            "name": "session",
            "value": SECRET,
            "secure": True,
            "http_only": True,
        },
        {"domain": "anibis.ch", "name": "cf_clearance", "value": "cf"},
        {"domain": ".anibis.ch", "name": "__cf_bm", "value": "bm"},
        {"domain": "auth.anibis.ch", "name": "_ga", "path": "/x"},
        {"domain": "evilanibis.ch", "name": "session", "value": "evil"},
    ],
    [
        {"domain": ".anibis.ch", "name": "old", "expires": NOW - 10},
        {"domain": ".tutti.ch", "name": "tsess", "value": "t"},
        {"domain": ".kleinanzeigen.de", "name": "_abck", "value": "akamai"},
    ],
]


@pytest.fixture
def jar(tmp_path: Path, monkeypatch) -> Path:
    path = tmp_path / "Cookies.binarycookies"
    path.write_bytes(encode(*JAR))
    monkeypatch.setenv("SAFARI_COOKIES", str(path))
    return path


# ---------------------------------------------------------------------------
# parser + site rules
# ---------------------------------------------------------------------------


def test_parse_roundtrip(jar) -> None:
    cookies = sc.read_binarycookies()
    assert sc.default_path() == jar
    assert len(cookies) == 8
    first = cookies[0]
    assert (first.domain, first.name, first.value, first.path) == (
        ".www.anibis.ch",
        "session",
        SECRET,
        "/",
    )
    assert first.secure and first.http_only
    assert abs(first.expires - FUTURE) < 1e-3
    assert SECRET not in repr(first)
    assert not cookies[1].secure and not cookies[1].http_only


@pytest.mark.parametrize(
    "blob",
    [
        b"",
        b"kooc\0\0\0\1",
        b"cook\0\0\0\5",  # five page sizes promised, none there
        encode(*JAR)[:-60],  # truncated inside a page
        b"cook\0\0\0\1\0\0\0\x08" + b"\xff" * 8,  # bad page header
    ],
)
def test_parse_malformed_raises_value_error(blob) -> None:
    with pytest.raises(ValueError):
        sc.parse_binarycookies(blob)


def test_parse_bad_string_offset() -> None:
    rec = bytearray(_record({"domain": "a.ch", "name": "n"}))
    struct.pack_into("<I", rec, 16, 10_000)
    page = b"\x00\x00\x01\x00" + struct.pack("<II", 1, 16) + b"\0" * 4 + bytes(rec)
    blob = b"cook" + struct.pack(">II", 1, len(page)) + page
    with pytest.raises(ValueError):
        sc.parse_binarycookies(blob)


def test_domain_matching() -> None:
    assert sc.domain_matches(".www.anibis.ch", "anibis.ch")
    assert sc.domain_matches("anibis.ch", "anibis.ch")
    assert sc.domain_matches("AUTH.Anibis.CH", "anibis.ch")
    assert not sc.domain_matches("evilanibis.ch", "anibis.ch")
    assert not sc.domain_matches("anibis.ch.evil.com", "anibis.ch")
    assert not sc.domain_matches("", "anibis.ch")


def test_deny_list_is_bot_management_only() -> None:
    rules = sc.SAFARI_SITES["anibis"]
    bot = "cf_clearance __cf_bm _abck ak_bmsc bm_sz bm_mi bm_sv __cfruid _cfuvid"
    for name in bot.split():
        assert sc.denied(name, rules), name
    for name in ("_ga", "session", "_gid", "cf_session"):
        assert not sc.denied(name, rules), name


def test_site_rules() -> None:
    assert {s: r.domains for s, r in sc.SAFARI_SITES.items()} == {
        "anibis": ("anibis.ch",),
        "tutti": ("tutti.ch",),
        "ricardo": ("ricardo.ch",),
        "kleinanzeigen": ("kleinanzeigen.de",),
    }
    assert [s for s, r in sc.SAFARI_SITES.items() if r.broker_fallback] == [
        "kleinanzeigen"
    ]


def test_site_cookies_filters_domain_deny_and_expiry(jar) -> None:
    picked = sc.site_cookies(sc.read_binarycookies(), "anibis", now=NOW)
    assert sorted(c.name for c in picked) == ["_ga", "session"]
    assert sc.site_cookies(sc.read_binarycookies(), "kleinanzeigen", now=NOW) == []
    n, latest = sc.session_summary("anibis", now=NOW)
    assert n == 2 and latest is not None and abs(latest - FUTURE) < 1e-3
    assert sc.session_summary("ricardo", now=NOW) == (0, None)


def test_to_playwright() -> None:
    c = sc.Cookie(".a.ch", "n", "v", "", FUTURE, True, False)
    assert c.to_playwright() == {
        "name": "n",
        "value": "v",
        "domain": ".a.ch",
        "path": "/",
        "expires": FUTURE,
        "secure": True,
        "httpOnly": False,
        "sameSite": "Lax",
    }


# ---------------------------------------------------------------------------
# browser.py import-safari / login
# ---------------------------------------------------------------------------


@pytest.fixture
def listed(monkeypatch):
    """A fake broker `sites` list (mutable per test)."""
    sites = {"anibis": {"site": "anibis", "check_url": "https://www.anibis.ch/me"}}
    monkeypatch.setattr(browser, "_broker_site", sites.get)
    return sites


def test_import_refused_when_not_listed(jar, listed, monkeypatch, capsys) -> None:
    del listed["anibis"]
    monkeypatch.setattr(
        browser._safari, "read_binarycookies", pytest.fail
    )  # consent first: Safari's jar is not even read
    assert browser.cmd_import_safari(9222, "anibis", dry_run=True) == 2
    assert browser.cmd_import_safari(9222, "anibis") == 2
    assert "not listed in Bitwarden agent-login" in capsys.readouterr().err


def test_import_refused_when_broker_down(jar, monkeypatch, capsys) -> None:
    def down(_site):
        raise browser.BrokerUnavailable("no login broker at /x")

    monkeypatch.setattr(browser, "_broker_site", down)
    assert browser.cmd_import_safari(9222, "anibis", dry_run=True) == 3
    assert "refusing the Safari import" in capsys.readouterr().err


def test_import_unknown_site(jar, listed, capsys) -> None:
    listed["geizhals"] = {"site": "geizhals"}
    assert browser.cmd_import_safari(9222, "geizhals", dry_run=True) == 2
    assert "no Safari import" in capsys.readouterr().err


def test_refused_broker_item_still_consents(jar, listed, capsys) -> None:
    listed["anibis"]["refused"] = True
    assert browser.cmd_import_safari(9222, "anibis", dry_run=True) == 0
    capsys.readouterr()


def test_dry_run_never_prints_values(jar, listed, capsys) -> None:
    assert browser.cmd_import_safari(9222, "Anibis", dry_run=True) == 0
    cap = capsys.readouterr()
    text = cap.out + cap.err
    assert "session" in text and "_ga" in text and ".www.anibis.ch" in text
    assert "secure,httponly" in text
    assert SECRET not in text
    for value in ("cf", "bm", "evil"):
        assert f" {value}\n" not in text
    assert "cf_clearance" not in text and "__cf_bm" not in text
    assert "evilanibis" not in text and "old" not in text
    assert "2 cookie(s) would be copied" in text


def test_dry_run_unreadable_jar(listed, monkeypatch, tmp_path, capsys) -> None:
    monkeypatch.setenv("SAFARI_COOKIES", str(tmp_path / "absent"))
    assert browser.cmd_import_safari(9222, "anibis", dry_run=True) == 2
    assert "Full Disk Access" in capsys.readouterr().err


class _Ctx:
    def __init__(self, cookies: list[dict]) -> None:
        self.jar = cookies
        self.cleared: list[tuple[str, str]] = []
        self.added: list[dict] = []

    def cookies(self) -> list[dict]:
        return list(self.jar)

    def clear_cookies(self, *, name: str, domain: str, path: str) -> None:
        assert path
        self.cleared.append((domain, name))

    def add_cookies(self, cookies: list[dict]) -> None:
        self.added.extend(cookies)


class _Browser:
    def __init__(self, ctx: _Ctx) -> None:
        self.contexts = [ctx]
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _Pw:
    def stop(self) -> None:
        pass


@pytest.fixture
def fake_chromium(monkeypatch):
    ctx = _Ctx(
        [
            {"domain": ".anibis.ch", "name": "session", "path": "/"},
            {"domain": "anibis.ch", "name": "cf_clearance", "path": "/"},
            {"domain": ".tutti.ch", "name": "tsess", "path": "/"},
            {"domain": "evilanibis.ch", "name": "x", "path": "/"},
        ]
    )
    leases: list[str] = []

    @contextlib.contextmanager
    def lease(purpose: str):
        leases.append(purpose)
        yield "owner"

    monkeypatch.setattr(browser, "_connect", lambda port: (_Pw(), _Browser(ctx)))
    monkeypatch.setattr(browser, "_interaction_lease", lease)
    monkeypatch.setattr(browser, "_record_login_event", lambda *a: None)
    return ctx, leases


def test_import_replaces_only_site_cookies(jar, listed, fake_chromium, monkeypatch):
    ctx, leases = fake_chromium
    checks = iter([0])
    monkeypatch.setattr(browser, "_broker_check_entry", lambda *a: next(checks))
    assert browser.cmd_import_safari(9222, "anibis") == 0
    assert leases == ["import-safari anibis"]
    assert ctx.cleared == [
        (".anibis.ch", "session")
    ]  # Chromium's own cf_clearance stays
    assert sorted(c["name"] for c in ctx.added) == ["_ga", "session"]
    assert all(c["domain"].endswith("anibis.ch") for c in ctx.added)


def test_import_not_logged_in_is_exit_2(jar, listed, fake_chromium, monkeypatch):
    monkeypatch.setattr(browser, "_broker_check_entry", lambda *a: 2)
    assert browser.cmd_import_safari(9222, "anibis") == 2


def test_login_prefers_safari(jar, listed, fake_chromium, monkeypatch, capsys):
    checks = iter([2, 0])
    monkeypatch.setattr(browser, "_broker_check_entry", lambda *a: next(checks))
    monkeypatch.setattr(browser, "_broker_login", pytest.fail)
    assert browser.cmd_login(9222, "anibis") == 0
    assert "route: Safari session" in capsys.readouterr().out


def test_login_falls_back_to_broker_for_kleinanzeigen(
    jar, listed, fake_chromium, monkeypatch, capsys
):
    listed["kleinanzeigen"] = {"site": "kleinanzeigen"}
    monkeypatch.setattr(browser, "_broker_check_entry", lambda *a: 2)
    calls: list[str] = []

    def broker_login(_port: int, site: str) -> int:
        calls.append(site)
        return 0

    monkeypatch.setattr(browser, "_broker_login", broker_login)
    assert browser.cmd_login(9222, "kleinanzeigen") == 0
    assert calls == ["kleinanzeigen"]
    assert "route: login broker" in capsys.readouterr().out


def test_login_no_fallback_for_anibis(jar, listed, fake_chromium, monkeypatch, capsys):
    monkeypatch.setattr(browser, "_broker_check_entry", lambda *a: 2)
    monkeypatch.setattr(browser, "_broker_login", pytest.fail)
    assert browser.cmd_login(9222, "anibis") == 2
    assert "open the site in Safari and log in" in capsys.readouterr().err


def test_login_refused_item_no_broker_fallback(jar, listed, fake_chromium, monkeypatch):
    listed["kleinanzeigen"] = {"site": "kleinanzeigen", "refused": True}
    monkeypatch.setattr(browser, "_broker_check_entry", lambda *a: 2)
    monkeypatch.setattr(browser, "_broker_login", pytest.fail)
    assert browser.cmd_login(9222, "kleinanzeigen") == 2


def test_import_safari_cli_parses(monkeypatch) -> None:
    monkeypatch.setattr(sys, "argv", ["browser.py", "import-safari", "-n", "anibis"])
    args = browser.parse_args()
    assert (args.cmd, args.site, args.dry_run) == ("import-safari", "anibis", True)


# ---------------------------------------------------------------------------
# agent-login.py
# ---------------------------------------------------------------------------

TARGETS = {t.site: t for t in al.TARGETS}


def test_agent_login_safari_flows() -> None:
    for site in ("anibis", "tutti", "ricardo", "kleinanzeigen"):
        assert TARGETS[site].flow == al.SAFARI_FLOW, site
    assert TARGETS["kleinanzeigen"].fallback == "two-step"
    assert al.STATUS["safari"][1] == "via your Safari session"


def test_agent_login_classify_safari() -> None:
    t = TARGETS["anibis"]
    assert al.classify(t, {"anibis": {"site": "anibis"}})[0] == "safari"
    refused = {"anibis": {"site": "anibis", "refused": True, "reason": "r"}}
    status, detail = al.classify(t, refused)
    assert status == "safari" and "refused: r" in detail
    assert al.classify(t, {})[0] == "missing"
    assert al.classify(t, {}, readable=False)[0] == "unchecked"


def test_agent_login_overview_safari_column(jar, monkeypatch) -> None:
    # the synthetic jar names anibis' login cookie "session"
    monkeypatch.setitem(
        sc.SAFARI_SITES,
        "anibis",
        dataclasses.replace(sc.SAFARI_SITES["anibis"], session_cookies=("session",)),
    )
    sites = [{"site": "anibis"}, {"site": "tutti"}, {"site": "ricardo"}]
    monkeypatch.setattr(
        al, "broker_state", lambda **_k: ("running, Bitwarden ok", sites)
    )
    rows = {r["site"]: r for r in al.overview()["rows"]}
    assert rows["anibis"]["safari"] is True
    assert rows["anibis"]["safari_expires"] == time.strftime(
        "%Y-%m-%d", time.localtime(FUTURE)
    )
    assert rows["ricardo"]["safari"] is False
    assert al.safari_cell(rows["anibis"]).startswith("Safari: until ")
    assert al.safari_cell(rows["ricardo"]) == "Safari: no session"
    assert al.safari_cell(rows["cscs"]) == ""
    assert "safari" not in rows["cscs"]


def test_agent_login_overview_unreadable_jar(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SAFARI_COOKIES", str(tmp_path / "absent"))
    monkeypatch.setattr(al, "broker_state", lambda **_k: ("not installed", []))
    rows = {r["site"]: r for r in al.overview()["rows"]}
    assert rows["anibis"]["safari"] is None
    assert al.safari_cell(rows["anibis"]) == "Safari: unreadable"


def _rows(*pairs: tuple[str, str]) -> dict:
    return {
        "broker": "running, Bitwarden readable",
        "broker_ok": True,
        "rows": [{"site": s, "status": st} for s, st in pairs],
    }


def test_check_all(monkeypatch, capsys) -> None:
    monkeypatch.setattr(al, "ensure_browser_up", lambda: True)
    monkeypatch.setattr(
        al,
        "overview",
        lambda: _rows(
            ("anibis", "safari"), ("tutti", "safari"), ("geizhals", "unknown")
        ),
    )
    seen = []

    def ensure(site):
        seen.append(site)
        return (site == "anibis", "x")

    mails: list[tuple[str, str]] = []

    def send(subject: str, body: str) -> bool:
        mails.append((subject, body))
        return True

    monkeypatch.setattr(al, "ensure_logged_in", ensure)
    monkeypatch.setattr(al, "send_mail", send)
    assert al.check_all(mail=False) == 1
    assert seen == ["anibis", "tutti"] and not mails
    assert al.check_all(mail=True) == 1
    assert len(mails) == 1
    subject, body = mails[0]
    assert "1 site(s)" in subject
    assert "tutti" in body and "anibis" not in body
    assert "./agent-login.py -t tutti" in body
    out = capsys.readouterr().out
    assert "✅ anibis" in out and "❌ tutti" in out


def test_check_all_all_good_sends_nothing(monkeypatch) -> None:
    monkeypatch.setattr(al, "ensure_browser_up", lambda: True)
    monkeypatch.setattr(al, "overview", lambda: _rows(("anibis", "safari")))
    monkeypatch.setattr(al, "ensure_logged_in", lambda site: (True, "logged in"))
    monkeypatch.setattr(al, "send_mail", pytest.fail)
    assert al.check_all(mail=True) == 0


def test_check_all_broker_down_fails(monkeypatch) -> None:
    monkeypatch.setattr(al, "ensure_browser_up", lambda: True)
    data = _rows()
    data["broker_ok"], data["broker"] = False, "not installed"
    monkeypatch.setattr(al, "overview", lambda: data)
    assert al.check_all() == 1


def test_plist() -> None:
    plist = al.launchagent_plist()
    assert "<string>com.albert.agent-login-check</string>" in plist
    assert "<key>Hour</key>\n        <integer>9</integer>" in plist
    assert "<key>Minute</key>\n        <integer>15</integer>" in plist
    assert "<string>-c</string>\n        <string>-m</string>" in plist
    assert str(Path(al.__file__).resolve()) in plist


def test_unattended_import_only_where_safe() -> None:
    """Ricardo (Cloudflare blocks automation) is never imported by the daily check;
    Kleinanzeigen is, since a copied refresh_token did not log Safari out."""
    assert sc.SAFARI_SITES["anibis"].auto and sc.SAFARI_SITES["tutti"].auto
    assert not sc.SAFARI_SITES["ricardo"].auto
    assert sc.SAFARI_SITES["kleinanzeigen"].auto
    assert sc.SAFARI_SITES["kleinanzeigen"].session_cookies == ("refresh_token",)
