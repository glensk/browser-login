"""Checks and logins use only tabs they own (tp#845).

Pinned with fakes only — a fake CDP endpoint (tests/fake_cdp.py) and a fake
Playwright attach; never a real Chrome, never the live browser (the one opt-in
test launches a DISPOSABLE headless browser on a free port and stops it):

* every check (logged-in anthropic/openai/slack/biopolwifi, `token`,
  `slack-session`) runs in `_owned_background_page` with the probe viewport,
  never in a tab it attached to and picked;
* every login drives its own fresh tab (never another tab: its context's
  `.pages` explodes), navigates it away from the blank marker only under the
  interaction lease (cscs, biopolwifi, switch, notion) and closes it even when
  the flow raises;
* a foreign guided login turns the checks, `token`, biopolwifi and `eval-fresh`
  into exit 75 BEFORE anything is created in the browser;
* the tab is created with exactly ``{url, background}`` (default context, so
  the profile's session is visible), on its marker URL;
* popups are closed leaves-first, unrelated tabs and iframe/worker targets are
  untouched, `page.close()` is never called;
* `login anthropic -e EMAIL` and `eval-fresh` keep their exit-code contracts;
* AST: `_match_page` only for `eval --url`; the URL pickers are gone;
  ``page.close()`` only in doctor's disposable probe;
* tp#863: `open` (also `-r` without a same-URL tab) never navigates a blank
  tab another client owns — it creates a new target and prints its id;
* tp#864: `logged-in switch`'s probe runs in a ledgered owned tab closed by id.

Run: uv run pytest -q tests/test_owned_tabs_tp845.py     (from the repo root)
"""

from __future__ import annotations

# Tests reach into browser.py's private helpers on purpose (it is a script).
# pylint: disable=protected-access,missing-function-docstring,import-error
# pylint: disable=redefined-outer-name,unused-argument,too-few-public-methods
# pylint: disable=missing-class-docstring,too-many-arguments
# pylint: disable=too-many-positional-arguments
# The cache fixture mirrors test_login_timeout's on purpose.
# pylint: disable=duplicate-code
import ast
import contextlib
import importlib.util
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from fake_cdp import FakeCdp
from playwright.sync_api import Error as PlaywrightError

_REPO = Path(__file__).resolve().parent.parent
_BROWSER_PY = _REPO / "bin" / "browser.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


browser = _load("browser_owned_tabs_test", _BROWSER_PY)

KEEP = "KEEP0001"
ME = "me@example.org"


# --- fixtures -------------------------------------------------------------------


@pytest.fixture
def fake() -> Iterator[FakeCdp]:
    srv = FakeCdp()
    srv.add(KEEP, "https://keep.example/", "keep")  # a page: no keep-alive needed
    yield srv
    srv.close()


@pytest.fixture
def cache(tmp_path, monkeypatch):
    """Every coordination file (and the journal) in tmp_path, for us and children."""
    monkeypatch.setenv("CLAUDE_BROWSER_CACHE_DIR", str(tmp_path))
    monkeypatch.setenv("CLAUDE_BROWSER_JOURNAL_FILE", str(tmp_path / "journal.jsonl"))
    monkeypatch.delenv("CLAUDE_BROWSER_LEASE_HELD", raising=False)
    monkeypatch.delenv(browser.MAINTENANCE_ENV, raising=False)
    for name, value in {
        "CACHE_DIR": tmp_path,
        "LIFECYCLE_FILE": tmp_path / ".browser-lifecycle.json",
        "CLIENTS_DIR": tmp_path / "clients",
        "REGISTRY_GATE": tmp_path / "clients" / ".registry.lock",
        "INTERACTION_LOCK": tmp_path / "interaction.lock",
        "MAINTENANCE_FILE": tmp_path / "maintenance.json",
        "MAINTENANCE_LOCK": tmp_path / ".maintenance.lock",
        "CSCS_TOKEN_CACHE": tmp_path / "portal_token",
    }.items():
        monkeypatch.setattr(browser, name, value)
    monkeypatch.setattr(browser, "DEADLINE_POLL_S", 0.02)
    monkeypatch.setattr(browser, "CLOSE_OWNED_CONFIRM_S", 0.3)
    monkeypatch.setattr(browser, "_record_login_event", lambda *a, **k: None)
    browser._ACTIVE_DEADLINE.clear()
    yield tmp_path
    browser._ACTIVE_DEADLINE.clear()


class Lease:
    """A fake interaction lease that remembers whether it is held."""

    def __init__(self) -> None:
        self.held = False
        self.taken = 0

    @contextlib.contextmanager
    def __call__(self, purpose: str, wait_s: float = 30.0) -> Iterator[str]:
        self.held = True
        self.taken += 1
        try:
            yield "nonce"
        finally:
            self.held = False


class _NoPages:
    """A browser context whose OTHER tabs must never be looked at."""

    @property
    def pages(self):
        raise AssertionError("a login looked at another tab (ctx.pages)")

    def cookies(self, *_a):
        return []


class OwnedPage:
    """The adopted owned page: records every navigation and the lease state."""

    def __init__(self, lease: Lease | None = None) -> None:
        self.lease = lease or Lease()
        self.url = "about:blank#owned-test"
        self.gotos: list[tuple[str, bool]] = []
        self.viewport: dict | None = None
        self.evaluate_answers: list[object] = []
        self.goto_error: Exception | None = None

    @property
    def context(self) -> _NoPages:
        return _NoPages()

    def goto(self, url, **_k):
        if self.goto_error is not None:
            raise self.goto_error
        self.gotos.append((url, self.lease.held))
        self.url = url

    def wait_for_timeout(self, _ms):
        return None

    def wait_for_load_state(self, *_a, **_k):
        return None

    def wait_for_selector(self, *_a, **_k):
        raise PlaywrightError("no such selector (fake)")

    def query_selector(self, *_a):
        return None

    def click(self, *_a, **_k):
        return None

    def evaluate(self, *_a, **_k):
        return self.evaluate_answers.pop(0) if self.evaluate_answers else True

    def set_viewport_size(self, size):
        self.viewport = size

    def bring_to_front(self):
        raise AssertionError("bring_to_front outside the headed lease")

    def close(self):
        raise AssertionError("page.close() must never close an owned tab")


class FakeBrowser:
    @property
    def contexts(self):
        raise AssertionError("attached browser's contexts used (a picked tab)")

    def new_context(self, *_a, **_k):
        raise AssertionError("new_context(): the session lives in the default one")

    def close(self) -> None:
        return None


class FakePw:
    def stop(self) -> None:
        return None


@pytest.fixture
def attach(monkeypatch):
    """A fake Playwright attach adopting `state["page"]` by target id."""
    state: dict[str, Any] = {"page": OwnedPage(), "adopted": []}

    def by_target(_browser, tid):
        state["adopted"].append(tid)
        return state["page"]

    monkeypatch.setattr(
        browser, "_connect", lambda port, purpose="": (FakePw(), FakeBrowser())
    )
    monkeypatch.setattr(browser, "_page_by_target", by_target)
    return state


def _ledgers(cache: Path) -> list[Path]:
    return (
        sorted((cache / "owned").glob("*.json")) if (cache / "owned").is_dir() else []
    )


def _write_foreign_record() -> None:
    rec = {
        "owner_nonce": "f" * 32,
        "pid": os.getpid(),
        "pid_start_time": browser._proc_lstart(os.getpid()),
        "site": "slack",
        "mode": "B",
        "state": "active",
        "owned_targets": [],
        "paused": [],
        "started": "2026-10-09T10:00:00+0200",
        "heartbeat": time.time(),
        "until": time.time() + 600,
    }
    browser.MAINTENANCE_FILE.parent.mkdir(parents=True, exist_ok=True)
    browser.MAINTENANCE_FILE.write_text(json.dumps(rec), encoding="utf-8")


# --- checks: always in the owned helper, with the probe viewport --------------------


def _stub_checks(monkeypatch) -> None:
    monkeypatch.setattr(browser, "_claude_logged_in", lambda page: True)
    monkeypatch.setattr(browser, "_chatgpt_logged_in", lambda page: True)
    monkeypatch.setattr(browser, "_slack_logged_in", lambda page: True)
    monkeypatch.setattr(browser, "_biopolwifi_logged_in", lambda page: True)
    monkeypatch.setattr(
        browser, "_slack_session_from_page", lambda ctx, page: {"token": "x"}
    )
    monkeypatch.setattr(browser, "_capture_and_cache_token", lambda ctx, page: 0)
    monkeypatch.setattr(browser, "_switch_page_verdict", lambda page: "logged-in")


CHECKS = {
    "anthropic": browser.cmd_anthropic_logged_in,
    "openai": browser.cmd_openai_logged_in,
    "slack": browser.cmd_slack_logged_in,
    "biopolwifi": browser.cmd_biopolwifi_logged_in,
    "token": browser.cmd_token,
    "slack-session": browser.cmd_slack_session,
    "switch": browser.cmd_switch_logged_in,  # tp#864
}


@pytest.mark.parametrize("name", sorted(CHECKS))
def test_checks_run_only_in_the_owned_helper_with_the_probe_viewport(
    cache, monkeypatch, name
):
    _stub_checks(monkeypatch)
    monkeypatch.setattr(browser, "_connect", lambda *a, **k: pytest.fail("attached"))
    seen: list[object] = []
    page = OwnedPage()

    @contextlib.contextmanager
    def owned(port, *, prepare=None):
        seen.append(prepare)
        if prepare is not None:
            prepare(page)
        yield page

    monkeypatch.setattr(browser, "_owned_background_page", owned)
    assert CHECKS[name](1) == 0
    assert seen == [browser._broker_probe_viewport]
    assert page.viewport == browser.BROKER_PROBE_VIEWPORT


# --- logins: own tab, lease before the first navigation, cleanup on raise ---------


def _login_stubs(monkeypatch, lease: Lease) -> None:
    monkeypatch.setattr(browser, "_interaction_lease", lease)
    monkeypatch.setattr(browser, "_capture_and_cache_token", lambda ctx, page: 0)
    monkeypatch.setattr(browser, "_switch_warm_or_via_broker", lambda port: False)
    monkeypatch.setattr(browser, "_notion_probe", lambda port: False)
    monkeypatch.setattr(browser, "_guided_login_allowed", lambda *a: True)
    monkeypatch.setattr(browser, "_switch_wait_for_login", lambda *a, **k: True)
    monkeypatch.setattr(browser, "_notion_wait_for_login", lambda *a, **k: True)


LEASED_NAV = {
    "cscs": (browser.cmd_cscs_login, browser.PORTAL_PROFILE_URL),
    "biopolwifi": (
        browser.cmd_biopolwifi_login,
        browser.BIOPOLWIFI_PORTAL_URL,
    ),
    "switch": (
        browser.cmd_switch_login,
        browser.SWITCH_ORIGIN + browser.SWITCH_LOGIN_PATH,
    ),
    "notion": (browser.cmd_notion_login, browser.NOTION_LOGIN_URL),
}


@pytest.mark.parametrize("name", sorted(LEASED_NAV))
def test_login_navigates_its_own_tab_only_under_the_lease(
    fake, cache, attach, monkeypatch, name
):
    lease = Lease()
    _login_stubs(monkeypatch, lease)
    page = OwnedPage(lease)
    attach["page"] = page
    cmd, first_url = LEASED_NAV[name]
    assert cmd(fake.port) == 0
    assert page.gotos and page.gotos[0] == (first_url, True)
    assert all(held for _url, held in page.gotos)
    tid = fake.created[0]
    assert tid in fake.closed and tid not in fake.targets  # closed again
    assert KEEP in fake.targets and not _ledgers(cache)


@pytest.mark.parametrize(
    ("name", "probe"),
    [
        ("anthropic", "_claude_logged_in"),
        ("openai", "_chatgpt_logged_in"),
        ("slack", "_slack_logged_in"),
    ],
)
def test_warm_probe_in_the_owned_tab_takes_no_lease(
    fake, cache, attach, monkeypatch, name, probe
):
    lease = Lease()
    _login_stubs(monkeypatch, lease)
    seen: list[object] = []

    def warm(page) -> bool:
        seen.append(page)
        return True

    monkeypatch.setattr(browser, probe, warm)
    page = OwnedPage(lease)
    attach["page"] = page
    assert getattr(browser, f"cmd_{name}_login")(fake.port) == 0
    assert seen == [page] and lease.taken == 0
    assert fake.created[0] in fake.closed


def test_anthropic_cold_path_navigates_under_the_lease(
    fake, cache, attach, monkeypatch
):
    lease = Lease()
    _login_stubs(monkeypatch, lease)
    monkeypatch.setattr(browser, "_claude_logged_in", lambda page: False)
    monkeypatch.setattr(browser, "ANTHROPIC_LOGIN_EMAIL", None)
    monkeypatch.setattr(browser, "_guided_login_allowed", lambda *a: False)
    page = OwnedPage(lease)
    attach["page"] = page
    assert browser.cmd_anthropic_login(fake.port) == browser.NEEDS_ALBERT_RC
    assert page.gotos == [(browser.CLAUDE_LOGIN_URL, True)]
    assert fake.created[0] in fake.closed


LOGINS = {
    "cscs": browser.cmd_cscs_login,
    "biopolwifi": browser.cmd_biopolwifi_login,
    "switch": browser.cmd_switch_login,
    "notion": browser.cmd_notion_login,
    "anthropic": browser.cmd_anthropic_login,
    "anthropic -e": lambda port: browser.cmd_anthropic_login(port, expect=ME),
    "openai": browser.cmd_openai_login,
    "slack": browser.cmd_slack_login,
}


@pytest.mark.parametrize("name", sorted(LOGINS))
def test_every_login_closes_its_tab_even_when_the_flow_raises(
    fake, cache, attach, monkeypatch, name
):
    lease = Lease()
    _login_stubs(monkeypatch, lease)

    def boom(*_a, **_k):
        raise RuntimeError("flow exploded")

    for probe in ("_claude_logged_in", "_chatgpt_logged_in", "_slack_logged_in"):
        monkeypatch.setattr(browser, probe, boom)
    monkeypatch.setattr(browser, "_claude_account", boom)
    page = OwnedPage(lease)
    page.goto_error = RuntimeError("flow exploded")
    attach["page"] = page
    with pytest.raises(RuntimeError, match="flow exploded"):
        LOGINS[name](fake.port)
    tid = fake.created[0]
    assert tid in fake.closed and tid not in fake.targets
    assert not _ledgers(cache) and not lease.held


# --- BUSY: a foreign guided login → 75 before anything is created ---------------------


BUSY = {
    **CHECKS,
    "eval-fresh": lambda port: browser.cmd_eval_fresh(port, "https://x.example/", "1"),
}


@pytest.mark.parametrize("name", sorted(BUSY))
def test_busy_exits_75_without_creating_a_target(fake, cache, monkeypatch, name):
    monkeypatch.setattr(browser, "_connect", lambda *a, **k: pytest.fail("attached"))
    _write_foreign_record()
    with pytest.raises(SystemExit) as exc:
        BUSY[name](fake.port)
    assert exc.value.code == browser.BUSY_RC == 75
    assert not fake.create_params and not fake.created
    assert not [m for m in fake.browser_log if m.get("method") == "Target.createTarget"]


# --- the created target ------------------------------------------------------------


@pytest.mark.parametrize("mode", ["headed", "headless"])
def test_created_target_payload_is_exactly_url_and_background(
    fake, cache, attach, monkeypatch, mode
):
    # Headless: its own invisible window, so neither the new tab nor the tab
    # that was active (a guided-login viewer's screencast) turns `hidden`.
    monkeypatch.setattr(browser, "_browser_mode", lambda _port: mode)
    seen: list[str] = []

    def fn(page):
        seen.append(page.url)
        return True

    assert browser._background_page_run(fake.port, "about:blank", None, fn) is True
    assert len(fake.create_params) == 1
    params = fake.create_params[0]
    want = {"url", "background"} | ({"newWindow"} if mode == "headless" else set())
    assert set(params) == want and params["background"] is True
    assert params.get("newWindow", True) is True
    assert params["url"].startswith(browser.OWNED_MARKER_PREFIX)
    assert seen == ["about:blank#owned-test"]  # `fn` got the adopted page


def test_popups_close_leaves_first_and_nothing_else(fake, cache, attach):
    def fn(page):
        tid = fake.created[0]
        fake.add("POPUP1", "https://idp.example/a", opener=tid)
        fake.add("POPUP2", "https://idp.example/b", opener="POPUP1")
        fake.add("FRAME1", "https://ads.example/", type="iframe", opener=tid)
        fake.add("WORKER", "https://x.example/sw.js", type="service_worker", opener=tid)
        fake.add("OTHER1", "https://other.example/")  # somebody else's tab
        return True

    assert browser._background_page_run(fake.port, "about:blank", None, fn) is True
    tid = fake.created[0]
    assert fake.closed == ["POPUP2", "POPUP1", tid]
    assert {"FRAME1", "WORKER", "OTHER1", KEEP} <= set(fake.targets)
    assert not _ledgers(cache)
    ops = [r for r in _journal(cache) if r.get("event") == "owned_tab"]
    assert ops and ops[-1]["confirmed"] is True


def _journal(cache: Path) -> list[dict]:
    path = cache / "journal.jsonl"
    if not path.exists():
        return []
    return [json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()]


def test_lost_create_reply_is_still_closed_by_its_marker(fake, cache, attach):
    fake.create_lose_reply = True
    real = browser._cdp_create_background_target
    browser_create = []

    def create(ws, url, budget_s=5.0):
        browser_create.append(url)
        return real(ws, url, 0.5)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(browser, "_cdp_create_background_target", create)
        assert (
            browser._background_page_run(fake.port, "about:blank", None, bool) is None
        )
    tid = fake.created[0]
    assert fake.targets.get(tid) is None and tid in fake.closed
    assert not _ledgers(cache) and not attach["adopted"]


# --- login -e EMAIL -------------------------------------------------------------------


@pytest.fixture
def expect_env(fake, cache, attach, monkeypatch):
    lease = Lease()
    _login_stubs(monkeypatch, lease)
    monkeypatch.setattr(browser, "EXPECT_ACCOUNT_POLL_S", 0.01)
    fills: list[str] = []

    def fill(page, email: str) -> bool:
        fills.append(email)
        return True

    monkeypatch.setattr(browser, "_claude_fill_email_and_continue", fill)
    page = OwnedPage(lease)
    attach["page"] = page
    return page, fills


def test_expect_account_match_is_0(fake, expect_env):
    page, fills = expect_env
    page.evaluate_answers = ["", "", ME.upper()]
    assert browser.cmd_anthropic_login(fake.port, expect=ME) == 0
    assert fills == [ME]
    assert page.gotos == [(browser.CLAUDE_LOGIN_URL, True)]
    assert fake.created[0] in fake.closed


def test_expect_account_mismatch_is_2_without_the_raw_email(fake, expect_env, capsys):
    page, fills = expect_env
    page.evaluate_answers = ["Some.One.Else@gmail.com"]
    assert browser.cmd_anthropic_login(fake.port, expect=ME) == 2
    err = capsys.readouterr().err
    assert "…@gmail.com" in err and "some.one.else" not in err.lower()
    assert not fills  # logged in already (as another account): nothing sent


def test_expect_account_times_out_with_1(fake, expect_env, monkeypatch):
    page, _fills = expect_env
    monkeypatch.setattr(browser, "EXPECT_ACCOUNT_WAIT_S", 0.05)
    page.evaluate_answers = [""] * 1000
    assert browser.cmd_anthropic_login(fake.port, expect=ME) == 1


def test_expect_account_needs_the_guided_lease(fake, cache, monkeypatch, capsys):
    monkeypatch.setattr(browser, "_connect", lambda *a, **k: pytest.fail("attached"))
    assert browser.cmd_anthropic_login(fake.port, expect=ME) == browser.NEEDS_ALBERT_RC
    assert not fake.create_params
    assert "needs Albert: agent-login.py -g anthropic" in capsys.readouterr().err


def test_expect_account_is_for_anthropic_only(fake, cache, monkeypatch, capsys):
    monkeypatch.setattr(browser, "_connect", lambda *a, **k: pytest.fail("attached"))
    assert browser.cmd_login(fake.port, "openai", expect=ME) == 2
    assert "anthropic only" in capsys.readouterr().err


def test_login_parser_has_expect_account_short_and_long(monkeypatch):
    for flag in ("-e", "--expect-account"):
        monkeypatch.setattr(sys, "argv", ["browser.py", "login", "anthropic", flag, ME])
        assert browser.parse_args().expect_account == ME


# --- eval-fresh ------------------------------------------------------------------------


class EvalPage(OwnedPage):
    def __init__(self, ready: str = "complete", result=42, error=None, block=None):
        super().__init__()
        self.ready, self.result, self.error, self.block = ready, result, error, block

    def evaluate(self, *args, **_k):
        expr = str(args[0]) if args else ""
        if "readyState" in expr:
            return self.ready
        if self.block is not None:
            self.block.wait(20)
        if self.error is not None:
            raise self.error
        return self.result


class Exits:
    """Stands in for `_hard_exit`: records the code and releases the stuck call."""

    def __init__(self) -> None:
        self.codes: list[int] = []
        self.released = threading.Event()

    def __call__(self, rc: int) -> None:
        self.codes.append(rc)
        self.released.set()


def test_eval_fresh_prints_the_json_result(fake, cache, attach, capsys):
    attach["page"] = EvalPage(result={"a": [1, "x"]})
    assert browser.cmd_eval_fresh(fake.port, "https://x.example/", "f()") == 0
    assert json.loads(capsys.readouterr().out) == {"a": [1, "x"]}
    assert fake.created[0] in fake.closed


def test_eval_fresh_not_ready_is_1(fake, cache, attach, monkeypatch, capsys):
    monkeypatch.setattr(browser, "EVAL_FRESH_READY_S", 0.2)
    monkeypatch.setattr(browser, "EVAL_FRESH_POLL_S", 0.01)
    attach["page"] = EvalPage(ready="loading")
    assert browser.cmd_eval_fresh(fake.port, "https://x.example/", "1") == 1
    assert "did not finish loading" in capsys.readouterr().err
    assert fake.created[0] in fake.closed


def test_eval_fresh_js_error_is_1(fake, cache, attach, capsys):
    err = PlaywrightError("ReferenceError: nope is not defined\n    at <anonymous>")
    attach["page"] = EvalPage(error=err)
    assert browser.cmd_eval_fresh(fake.port, "https://x.example/", "nope") == 1
    out = capsys.readouterr()
    assert "ReferenceError: nope is not defined" in out.err and out.out == ""
    assert fake.created[0] in fake.closed


def test_eval_fresh_deadline_is_124_and_closes_the_tab(
    fake, cache, attach, monkeypatch
):
    exits = Exits()
    monkeypatch.setattr(browser, "_hard_exit", exits)
    attach["page"] = EvalPage(block=exits.released)
    browser.cmd_eval_fresh(fake.port, "https://x.example/", "1", timeout_s=0.3)
    assert exits.codes == [browser.LOGIN_TIMEOUT_RC] == [124]
    tid = fake.created[0]
    assert tid in fake.closed and tid not in fake.targets


def test_eval_fresh_refuses_non_http_urls(fake, cache, capsys):
    for url in ("file:///etc/hosts", "javascript:1", "about:blank", "chrome://x"):
        assert browser.cmd_eval_fresh(fake.port, url, "1") == 2
    assert not fake.create_params


def test_eval_fresh_is_bounded_even_inside_a_guided_login(cache, monkeypatch):
    _write_foreign_record()
    monkeypatch.setenv(browser.MAINTENANCE_ENV, "f" * 32)  # we ARE the owner
    seen: list[object] = []

    def run(port, url, prepare, fn):
        seen.append(browser._active_deadline())
        return ("ok", 1)

    monkeypatch.setattr(browser, "_background_page_run", run)
    assert browser.cmd_eval_fresh(1, "https://x.example/", "1", timeout_s=5) == 0
    assert isinstance(seen[0], browser.LoginDeadline) and seen[0].timeout_s == 5


# --- tp#863: `open` never navigates a tab it did not create ------------------------------

FOREIGN = "FOREIGN1"  # another client's fresh `open -N` tab, not committed yet


class _ForeignBlankPage:
    """A blank tab some other client owns: navigating it is the bug."""

    url = "about:blank"

    def goto(self, *_a, **_k):
        raise AssertionError("open navigated a blank tab it does not own")


class _SameUrlPage:
    def __init__(self, url: str) -> None:
        self.url = url
        self.gotos: list[str] = []

    def goto(self, url, **_k):
        self.gotos.append(url)
        self.url = url

    def title(self) -> str:
        return "same"


class _Ctx:
    def __init__(self, pages: list[Any]) -> None:
        self.pages = pages


class _OpenBrowser:
    def __init__(self, pages: list[Any]) -> None:
        self.contexts = [_Ctx(pages)]

    def close(self) -> None:
        return None


def _assert_new_tab_only(fake: FakeCdp, url: str, out: str) -> None:
    creates = [m for m in fake.browser_log if m.get("method") == "Target.createTarget"]
    assert [m["params"] for m in creates] == [{"url": url, "background": True}]
    ids = [ln[7:] for ln in out.splitlines() if ln.startswith("target=")]
    assert ids == fake.created and FOREIGN not in ids
    assert fake.targets[FOREIGN].url == "about:blank"
    assert not fake.targets[FOREIGN].received  # no Page.navigate, nothing at all
    assert FOREIGN not in fake.closed


@pytest.mark.parametrize("new", [False, True], ids=["default", "-N"])
def test_open_never_navigates_a_foreign_blank_tab(
    fake, cache, monkeypatch, capsys, new
):
    fake.add(FOREIGN, "about:blank", "")
    monkeypatch.setattr(browser, "_connect", lambda *a, **k: pytest.fail("attached"))
    url = "https://app.example.com/x"
    assert browser.cmd_open(fake.port, url, new=new) == 0
    _assert_new_tab_only(fake, url, capsys.readouterr().out)


def test_open_reuse_without_a_match_opens_a_new_tab(fake, cache, monkeypatch, capsys):
    fake.add(FOREIGN, "about:blank", "")
    monkeypatch.setattr(
        browser,
        "_connect",
        lambda *a, **k: (FakePw(), _OpenBrowser([_ForeignBlankPage()])),
    )
    url = "https://app.example.com/x"
    assert browser.cmd_open(fake.port, url, reuse=True) == 0
    _assert_new_tab_only(fake, url, capsys.readouterr().out)


def test_open_reuse_navigates_the_same_url_tab(fake, cache, monkeypatch, capsys):
    same = _SameUrlPage("https://app.example.com/x?old=1")
    monkeypatch.setattr(
        browser,
        "_connect",
        lambda *a, **k: (FakePw(), _OpenBrowser([_ForeignBlankPage(), same])),
    )
    assert browser.cmd_open(fake.port, "https://app.example.com/x", reuse=True) == 0
    assert same.gotos == ["https://app.example.com/x"]
    assert not fake.created
    assert "✓ Reused tab:" in capsys.readouterr().out


# --- AST guards ---------------------------------------------------------------------------


def _tree() -> ast.Module:
    return ast.parse(_BROWSER_PY.read_text(encoding="utf-8"))


def test_match_page_is_called_only_by_eval_attached():
    callers = set()
    for fn in (n for n in ast.walk(_tree()) if isinstance(n, ast.FunctionDef)):
        for call in (c for c in ast.walk(fn) if isinstance(c, ast.Call)):
            if isinstance(call.func, ast.Name) and call.func.id == "_match_page":
                callers.add(fn.name)
    assert callers == {"_eval_attached"}


def test_the_url_pickers_are_gone_and_no_context_is_forged():
    src = _BROWSER_PY.read_text(encoding="utf-8")
    for name in ("_pick_page", "_pick_portal_page", "_close_stale_cscs_tabs"):
        assert not hasattr(browser, name), name
        assert name not in src, name
    assert "browserContextId" not in src
    new_pages = [
        c
        for c in ast.walk(_tree())
        if isinstance(c, ast.Call)
        and isinstance(c.func, ast.Attribute)
        and c.func.attr == "new_page"
    ]
    assert not new_pages  # every tab is a background one, created by id


# --- tp#864: `logged-in switch`'s probe tab is owned, ledgered, closed by id ------------


@pytest.mark.parametrize("verdict", ["logged-in", "login"])
def test_switch_probe_runs_in_a_ledgered_owned_tab(
    fake, cache, attach, monkeypatch, verdict
):
    ledgered: list[list[Path]] = []

    def judge(page) -> str:
        ledgered.append(_ledgers(cache))  # the tab is on the ledger meanwhile
        return str(verdict)

    monkeypatch.setattr(browser, "_switch_page_verdict", judge)
    got = browser._switch_probe(fake.port)
    tid = fake.created[0]
    assert got == (verdict, browser.SWITCH_ORIGIN + "/")
    assert attach["page"].gotos == [(browser.SWITCH_ORIGIN + "/", False)]
    assert attach["adopted"] == [tid] and len(ledgered[0]) == 1
    assert fake.closed == [tid] and not _ledgers(cache)  # by id; never page.close()
    assert fake.create_params[0]["url"].startswith(browser.OWNED_MARKER_PREFIX)


def test_switch_probe_failure_is_unknown_and_still_closes(fake, cache, attach):
    attach["page"].goto_error = PlaywrightError("net::ERR_TIMED_OUT (fake)")
    assert browser._switch_probe(fake.port) == ("unknown", "")
    assert fake.closed == fake.created and not _ledgers(cache)


def _close_calls_on_pages() -> set[str]:
    """Functions that call ``.close()`` on a Playwright page (``page``/``pg``)."""
    found = set()
    for fn in (n for n in ast.walk(_tree()) if isinstance(n, ast.FunctionDef)):
        for c in (c for c in ast.walk(fn) if isinstance(c, ast.Call)):
            f = c.func
            if (
                isinstance(f, ast.Attribute)
                and f.attr == "close"
                and isinstance(f.value, ast.Name)
                and f.value.id in {"page", "pg"}
            ):
                found.add(fn.name)
    return found


def test_page_close_only_in_doctors_disposable_probe():
    # tp#843/tp#864: owned tabs close by target id over raw CDP. The doctor's
    # disposable probe tab (not an owned check tab) is the one exception.
    assert _close_calls_on_pages() == {"_doctor_probe_cleanup"}


def test_switch_probe_uses_the_owned_helper():
    fn = next(
        n
        for n in ast.walk(_tree())
        if isinstance(n, ast.FunctionDef) and n.name == "_switch_probe"
    )
    called = {
        c.func.id
        for c in ast.walk(fn)
        if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)
    }
    assert "_background_page_run" in called
    assert not {"_connect", "_page_by_target"} & called
    assert not hasattr(browser, "_switch_close_target")


# --- opt-in: a real disposable headless browser ----------------------------------------------

E2E = pytest.mark.skipif(
    os.environ.get("LOGIN_BROKER_E2E") != "1", reason="set LOGIN_BROKER_E2E=1"
)


class _SeedSite(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        body = b"<!doctype html><title>seed</title><p>ok</p>"
        self.send_response(200)
        if self.path.startswith("/seed"):
            self.send_header("Set-Cookie", "sid=ok; Path=/")
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_a: object) -> None:
        return


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _cli(port: int, *argv: str) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if k != browser.MAINTENANCE_ENV}
    return subprocess.run(
        [sys.executable, str(_BROWSER_PY), "--cdp-port", str(port), *argv],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


@E2E
@pytest.mark.launches_chrome
def test_e2e_fresh_owned_tab_sees_the_profiles_session(cache):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _SeedSite)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    port = _free_port()
    up = _cli(port, "up")
    assert up.returncode == 0, up.stdout + up.stderr
    try:
        opened = _cli(port, "open", "-N", f"{base}/seed")
        tid = next(
            ln.split("=", 1)[1]
            for ln in opened.stdout.splitlines()
            if ln.startswith("target=")
        )
        seeded = _cli(port, "eval", "-T", tid, "localStorage.setItem('k', 'v') || 1")
        assert seeded.returncode == 0, seeded.stderr
        markers: list[str] = []

        def prepare(page) -> None:  # the marker URL round-trips in /json/list
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/json/list", timeout=5
            ) as r:
                markers.extend(
                    t["url"]
                    for t in json.loads(r.read())
                    if t["url"].startswith(browser.OWNED_MARKER_PREFIX)
                )

        got = browser._background_page_run(
            port,
            f"{base}/fresh",
            prepare,
            lambda page: page.evaluate(
                "() => [document.cookie, localStorage.getItem('k')]"
            ),
        )
        assert got == ["sid=ok", "v"]
        assert len(markers) == 1
        assert not any(
            t["url"].startswith(browser.OWNED_MARKER_PREFIX)
            for t in browser._page_targets(port)
        )
        assert not _ledgers(cache)
    finally:
        _cli(port, "down", "-f")
        srv.shutdown()
