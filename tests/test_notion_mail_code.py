"""tp#1633: the headless Notion e-mail-code login in the shared Chromium.

Hermetic: himalaya is a fake ``run``, the page a fake; nothing drives the
live browser, reads a real mailbox or opens a real sign-in. The EPFL test
imports ``sdsc/email/epfl_oauth.py`` by path (skipped when absent) and runs it
against a temp state dir with a dead store. No credential-shaped literals:
codes are generated per run.
"""

from __future__ import annotations

# pylint: disable=missing-function-docstring,import-error,wrong-import-position
# pylint: disable=protected-access,unused-argument,redefined-outer-name
import contextlib
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import agent_login_jobs as jobs  # noqa: E402
import agent_login_safari as s  # noqa: E402

EPFL_OAUTH = Path.home() / "obsidian/42-Git/sdsc/email/epfl_oauth.py"
_BROWSER_PY = Path(__file__).resolve().parent.parent / "bin" / "browser.py"


def _load_browser() -> Any:
    spec = importlib.util.spec_from_file_location("browser_nmc_test", _BROWSER_PY)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["browser_nmc_test"] = mod
    spec.loader.exec_module(mod)
    return mod


browser = _load_browser()


# ---------------------------------------------------------------------------
# B1: MailReader env, function-form fills
# ---------------------------------------------------------------------------


class _Recorder:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def run(self, argv: list[str], **kw: Any) -> subprocess.CompletedProcess:
        self.calls.append({"argv": argv, **kw})
        return subprocess.CompletedProcess(argv, 0, "[]", "")


def test_mail_reader_inherits_the_environment_by_default() -> None:
    rec = _Recorder()
    s.MailReader("himalaya-fake", account="epfl", run=rec.run).envelopes()
    assert rec.calls
    assert all("env" not in c for c in rec.calls)


def test_mail_reader_passes_the_notion_env_on_top_of_ours(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TP1633_MARKER", "kept")
    rec = _Recorder()
    reader = s.MailReader(
        "himalaya-fake", account="epfl", run=rec.run, env=s.NOTION_MAIL_ENV
    )
    reader.envelopes()
    assert rec.calls
    for call in rec.calls:
        assert call["env"]["SDSC_EMAIL_NO_AUTO_AUTH"] == "1"
        assert call["env"]["TP1633_MARKER"] == "kept"
        assert call["argv"][-2:] == ["-a", "epfl"]
    assert s.NOTION_MAIL_ENV == {"SDSC_EMAIL_NO_AUTO_AUTH": "1"}


def test_the_safari_fill_scripts_are_unchanged() -> None:
    """objection 6: safari.py evaluates these texts; they stay byte-identical."""
    assert (
        hashlib.sha256(s.EMAIL_FILL_JS.encode()).hexdigest()
        == "14e7fb9c52966e134eb38c50ba2eb2003a49b3bb97bc052da50bccfe7c3c6996"
    )
    assert (
        hashlib.sha256(s.CODE_FILL_JS.encode()).hexdigest()
        == "ae875b663e6b81b7eb8d7600e24e7cd52e3e81a9899e69249e96707e5d844b58"
    )


@pytest.mark.parametrize(
    ("iife", "fn"),
    [(s.EMAIL_FILL_JS, s.EMAIL_FILL_FN), (s.CODE_FILL_JS, s.CODE_FILL_FN)],
)
def test_the_function_forms_have_the_same_bodies(iife: str, fn: str) -> None:
    old, new = iife.splitlines(), fn.splitlines()
    assert old[1:3] == ["(() => {", "  const P = __PARAMS__;"]
    assert old[-1] == "})()"
    assert new[1] == "(P) => {"
    assert new[-1] == "}"
    assert old[3:-1] == new[2:-1]
    assert "__PARAMS__" not in fn


def _chromium_installed() -> bool:
    try:
        from chromium_page import (  # pylint: disable=import-outside-toplevel
            chromium_available,
        )
    except ImportError:
        return False
    return chromium_available()


CHROME = pytest.mark.skipif(
    not _chromium_installed(), reason="Playwright Chromium missing"
)

_LOGIN_FORM = """<form id="f" onsubmit="event.preventDefault(); window.sent += 1">
  <input type="email" name="email">
  <input name="code" inputmode="numeric">
  <button type="submit">Continue with login code</button>
</form><script>window.sent = 0</script>"""


@pytest.mark.launches_chrome
@CHROME
def test_the_function_forms_fill_through_the_evaluate_argument() -> None:
    from playwright.sync_api import (  # pylint: disable=import-outside-toplevel
        sync_playwright,
    )

    code = f"{int.from_bytes(os.urandom(3), 'big') % 900000 + 100000}"
    with sync_playwright() as pw:
        chrome = pw.chromium.launch(headless=True)
        try:
            page = chrome.new_page()
            page.set_content(_LOGIN_FORM)
            got = json.loads(
                page.evaluate(
                    s.EMAIL_FILL_FN,
                    {"field": s._USER_FIELD, "email": "me@example.org"},
                )
            )
            assert got == {"ok": True}
            got = json.loads(
                page.evaluate(
                    s.CODE_FILL_FN,
                    {
                        "otp": s._OTP_FIELD,
                        "code": code,
                        "submit": "Continue with login code",
                    },
                )
            )
            assert got == {"ok": True, "clicked": True}
            assert page.evaluate("window.sent") == 1
            assert page.evaluate("document.querySelector('[name=code]').value") == code
        finally:
            chrome.close()


# ---------------------------------------------------------------------------
# B1: SDSC_EMAIL_NO_AUTO_AUTH holds on the himalaya token commands
# ---------------------------------------------------------------------------


def _epfl(monkeypatch: pytest.MonkeyPatch, state: Path) -> Any:
    if not EPFL_OAUTH.is_file():
        pytest.skip("sdsc/email/epfl_oauth.py absent")
    monkeypatch.setenv("SDSC_EMAIL_STATE_DIR", str(state))
    monkeypatch.setenv("SDSC_EMAIL_NO_AUTO_AUTH", "1")
    for var in ("SDSC_EMAIL_SEED", "CREDENTIALS_DIRECTORY"):
        monkeypatch.delenv(var, raising=False)
    spec = importlib.util.spec_from_file_location("tp1633_epfl_oauth", EPFL_OAUTH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _dead_store(state: Path, *, refresh: bool) -> None:
    state.mkdir(mode=0o700, exist_ok=True)
    store: dict[str, str] = {
        "email": "me@example.org",
        "access_token": "",
        "expires_at": "1970-01-01T00:00:00+00:00",
    }
    if refresh:
        store["refresh_token"] = "dead-" + os.urandom(4).hex()
    path = state / "tokens.json"
    path.write_text(json.dumps(store), encoding="utf-8")
    path.chmod(0o600)


@pytest.mark.parametrize("command", ["cmd_token", "cmd_refresh_token"])
@pytest.mark.parametrize("refresh", [False, True])
def test_a_dead_epfl_grant_raises_instead_of_opening_a_browser(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, command: str, refresh: bool
) -> None:
    state = tmp_path / "state"
    mod = _epfl(monkeypatch, state)
    _dead_store(state, refresh=refresh)
    opened: list[object] = []
    posts: list[object] = []

    def _no_browser(*a: object, **_k: object) -> bool:
        opened.append(a)
        raise AssertionError("a browser sign-in was started")

    def _rejected(data: object) -> dict[str, str]:
        posts.append(data)
        return {"error": "invalid_grant"}

    monkeypatch.setattr(mod.webbrowser, "open", _no_browser)
    monkeypatch.setattr(mod, "_run_auth_flow", _no_browser)
    monkeypatch.setattr(mod, "_notify", _no_browser)
    monkeypatch.setattr(mod, "_post", _rejected)
    with pytest.raises(mod.EpflAuthError):
        getattr(mod, command)(None)
    assert not opened
    assert bool(posts) == refresh  # a refresh token is tried once, then stop
    assert not (state / "reauth_attempted").exists()


def test_the_variable_reaches_a_child_like_himalayas_cmd(tmp_path: Path) -> None:
    """himalaya runs ``python3 epfl_oauth.py token`` with its own environment:
    the variable set for himalaya (and nowhere else) stops the child."""
    if not EPFL_OAUTH.is_file():
        pytest.skip("sdsc/email/epfl_oauth.py absent")
    state = tmp_path / "state"
    _dead_store(state, refresh=False)
    child = tmp_path / "child.py"
    child.write_text(
        "import importlib.util, sys, webbrowser\n"
        "def _no(*a, **k):\n"
        "    raise SystemExit(99)\n"
        "webbrowser.open = _no\n"
        "spec = importlib.util.spec_from_file_location('m', sys.argv[1])\n"
        "m = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(m)\n"
        "m._run_auth_flow = _no\n"
        "m._notify = _no\n"
        "sys.argv = [sys.argv[1], 'token']\n"
        "sys.exit(m.main())\n",
        encoding="utf-8",
    )
    drop = ("SDSC_EMAIL_NO_AUTO_AUTH", "SDSC_EMAIL_SEED", "CREDENTIALS_DIRECTORY")
    env = {k: v for k, v in os.environ.items() if k not in drop}
    env["SDSC_EMAIL_STATE_DIR"] = str(state)
    res = subprocess.run(
        [sys.executable, "-I", str(child), str(EPFL_OAUTH)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env={**env, **s.NOTION_MAIL_ENV},
    )
    assert res.returncode == 1  # EpflAuthError, not 99 (a sign-in attempt)
    assert "auto-auth disabled" in res.stderr
    assert res.stdout == ""


# ---------------------------------------------------------------------------
# B2/B3 harness: a fake login tab, a fake himalaya, a fake clock
# ---------------------------------------------------------------------------

EMAIL = "me@example.org"
HIMALAYA = "/fake/bin/himalaya"
NOTION = s.RECIPES["notion"]


def _code() -> str:
    return f"{int.from_bytes(os.urandom(3), 'big') % 900000 + 100000}"


def _mail(msg_id: str, code: str, *, to: str = EMAIL) -> tuple[str, dict, str]:
    env = {
        "id": msg_id,
        "subject": "Your Notion login code",
        "from": {"addr": "notify@mail.notion.so"},
        "to": [{"addr": to}],
    }
    text = (
        "Authentication-Results: mx.example.org; dkim=pass header.d=mail.notion.so\n"
        f"\nYour login code is {code}\n"
    )
    return msg_id, env, text


class FakeMailbox:
    """himalaya as a ``subprocess.run``: INBOX + Archive answer, the rest is
    missing. ``after_trigger(n)`` gives the INBOX codes of the n-th list after
    the trigger click (1-based); ``dead`` fails every call."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.inbox: list[tuple[str, dict, str]] = []
        self.dead = False
        self.triggered = False
        self.polls = 0
        self.after_trigger: Any = None
        self.log: list[str] | None = None

    def trigger(self, code: str) -> None:
        self.triggered = True
        if self.after_trigger is None:
            self.after_trigger = lambda _n: [code]

    def __call__(self, argv: list[str], **kw: Any) -> subprocess.CompletedProcess:
        self.calls.append({"argv": list(argv), **kw})
        if self.log is not None:
            self.log.append("mail:" + " ".join(argv[1:3]))
        assert argv[0] == HIMALAYA
        if self.dead:
            return subprocess.CompletedProcess(argv, 1, "", "dead grant")
        verb = tuple(argv[1:3])
        if verb == ("envelope", "list"):
            folder = argv[argv.index("--folder") + 1]
            if folder == "Archive":
                return subprocess.CompletedProcess(argv, 0, "[]", "")
            if folder != "INBOX":
                return subprocess.CompletedProcess(argv, 1, "", "no folder")
            if self.triggered:
                self.polls += 1
                codes = self.after_trigger(self.polls)
                self.inbox = [_mail(f"n{i}-{c}", c) for i, c in enumerate(codes)]
            return subprocess.CompletedProcess(
                argv, 0, json.dumps([e for _i, e, _t in self.inbox]), ""
            )
        if verb == ("message", "read"):
            got = {i: t for i, _e, t in self.inbox}
            return subprocess.CompletedProcess(argv, 0, got.get(argv[3], ""), "")
        if verb == ("message", "move"):
            return subprocess.CompletedProcess(argv, 0, "", "")
        raise AssertionError(f"unexpected himalaya call {argv[1:3]}")


class FakePage:  # pylint: disable=too-many-instance-attributes
    """The owned login tab: ``stage`` blank / email / code / done; the
    detector answers from it, the fills and clicks are recorded."""

    def __init__(self, mailbox: FakeMailbox, log: list[str]) -> None:
        self.url = "about:blank#owned"
        self.stage = "blank"
        self.after_goto = "email"
        self.after_click = "code"
        self.after_submit = "done"
        self.extra: dict[str, bool] = {}
        self.mailbox = mailbox
        self.log = log
        self.code = _code()
        self.submitted: list[str] = []
        self.clicks = 0
        self.reads = 0

    def goto(self, url: str, **_kw: Any) -> None:
        self.log.append("goto")
        assert url == NOTION.start_url
        self.url = "https://app.notion.com/login"
        self.stage = self.after_goto

    def _flags(self) -> str:
        flags = {k: False for k in s.PAGE_FLAGS}
        flags["user"] = self.stage == "email"
        flags["code"] = self.stage == "code"
        flags["sentinel"] = self.stage == "done"
        flags.update(self.extra)
        steps = [{"when": flags["user"], "unless": False}]
        return json.dumps({**flags, "steps": steps})

    def evaluate(self, js: str, arg: Any = None) -> Any:
        if arg is None:
            assert js.startswith("() => ")
            self.reads += 1
            self.log.append("read")
            return self._flags()
        if js == s.EMAIL_FILL_FN:
            assert arg == {"field": NOTION.steps[0].email_field, "email": EMAIL}
            self.log.append("fill-email")
            return json.dumps({"ok": True})
        if js == browser.NOTION_BUTTON_FN:
            assert arg["label"] == "Continue"
            if not arg["click"]:
                self.log.append("find-button")
                return json.dumps({"ok": True})
            self.clicks += 1
            self.log.append("click")
            self.stage = self.after_click
            self.mailbox.trigger(self.code)
            return json.dumps({"ok": True})
        if js == s.CODE_FILL_FN:
            assert arg["submit"] == "Continue with login code"
            self.submitted.append(arg["code"])
            self.log.append("submit")
            self.stage = self.after_submit
            return json.dumps({"ok": True, "clicked": True})
        raise AssertionError("unexpected evaluate")


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def now(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.t += seconds


def _check(verdict: str, identity: str = "match") -> dict[str, Any]:
    server = {"valid": "valid", "invalid": "invalid"}.get(verdict, "indeterminate")
    return {
        "verdict": verdict,
        "proof": "server" if verdict != "indeterminate" else "",
        "server": server,
        "identity": identity,
        "cookie_days_left": None,
    }


class Rig:  # pylint: disable=too-many-instance-attributes
    """One `login notion -M` run against the fakes; `run()` returns
    (rc, result record)."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        self.tmp = tmp_path
        self.log: list[str] = []
        self.mailbox = FakeMailbox()
        self.page = FakePage(self.mailbox, self.log)
        self.clock = Clock()
        self.checks = [_check("invalid"), _check("valid")]
        self.check_calls = 0
        self.opened = 0
        self.leases: list[str] = []
        self.events: list[tuple[str, str]] = []
        self.result = tmp_path / "result.json"
        mp = monkeypatch
        mp.setattr(browser, "_nmc_sleep", self.clock.sleep)
        mp.setattr(browser, "_nmc_clock", self.clock.now)
        mp.setattr(browser, "_notion_check", self._notion_check)
        mp.setattr(browser, "_notion_expected_email", lambda: EMAIL)
        mp.setattr(browser, "_notion_wait_for_login", lambda *_a, **_k: True)
        mp.setattr(browser, "_owned_background_page", self._owned)
        mp.setattr(browser, "_interaction_lease", self._lease)
        mp.setattr(browser, "_record_login_event", self._event)
        mp.setattr(browser.shutil, "which", lambda name: HIMALAYA)
        mp.setattr(browser.subprocess, "run", self.mailbox)

    def _notion_check(self, port: int, expected: str = "") -> dict[str, Any]:
        assert expected == EMAIL
        self.log.append("check")
        got = self.checks[min(self.check_calls, len(self.checks) - 1)]
        self.check_calls += 1
        return got

    @contextlib.contextmanager
    def _owned(self, port: int, **_kw: Any) -> Iterator[FakePage]:
        self.opened += 1
        self.log.append("open")
        try:
            yield self.page
        finally:
            self.log.append("close")

    @contextlib.contextmanager
    def _lease(self, purpose: str, *_a: Any, **_k: Any) -> Iterator[str]:
        self.leases.append(purpose)
        self.log.append("lease")
        yield "nonce"

    def _event(self, site: str, mode: str) -> None:
        self.events.append((site, mode))

    @property
    def stamp(self) -> Path:
        return s_state_dir() / str(browser.NOTION_MAIL_CODE_FILE)

    def run(self) -> tuple[int, dict[str, Any]]:
        browser._result_begin("login", "notion", str(self.result))
        rc = browser._notion_mail_code_login(9)
        browser._result_write(rc)
        return rc, json.loads(self.result.read_text(encoding="utf-8"))


def s_state_dir() -> Path:
    return Path(browser._als.state_dir())


@pytest.fixture(autouse=True)
def _fresh_once() -> Iterator[None]:
    browser._NMC_ONCE.update(trigger=False, submit=False)
    browser._ACTIVE_DEADLINE.clear()
    yield
    browser._NMC_ONCE.update(trigger=False, submit=False)
    browser._ACTIVE_DEADLINE.clear()


@pytest.fixture
def rig(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Rig:
    return Rig(monkeypatch, tmp_path)


# ---------------------------------------------------------------------------
# B3: the time budget
# ---------------------------------------------------------------------------


def test_the_budget_fits_the_login_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(jobs.LOGIN_TIMEOUT_ENV, raising=False)
    budget = browser.NOTION_MAIL_CODE_BUDGET
    total = sum(budget.values())
    assert jobs.login_timeout_s() == browser.LOGIN_TIMEOUT_DEFAULT_S == 480.0
    assert browser.LOGIN_TIMEOUT_S == browser.LOGIN_TIMEOUT_DEFAULT_S
    assert total <= jobs.login_timeout_s()
    # agent-login's runner kills `browser.py login` only after the inner deadline
    assert jobs.browser_timeout("login") >= jobs.login_timeout_s() >= total
    # the caps the flow enforces are the ones the budget counts
    assert budget["baseline"] == browser.NOTION_MAIL_CODE_BASELINE_CAP_S == 45.0
    assert budget["archive"] == browser.NOTION_MAIL_CODE_ARCHIVE_CAP_S == 15.0
    assert budget["sidebar"] == browser.NOTION_MAIL_CODE_SIDEBAR_S == 45.0
    assert budget["last-poll"] == browser.NOTION_MAIL_CODE_LAST_POLL_S
    assert budget["code-wait"] == s.MAIL_WAIT_S == 180.0
    assert browser.NOTION_MAIL_CODE_PROOF_RESERVE_S == 120.0


def _wait_of(rig: Rig, monkeypatch: pytest.MonkeyPatch, left: float | None) -> Any:
    seen: list[float] = []

    def _code(*args: Any) -> int:
        seen.append(args[6])
        return 0

    monkeypatch.setattr(browser, "_deadline_left", lambda: left)
    monkeypatch.setattr(browser, "_nmc_code", _code)
    rc, rec = rig.run()
    return rc, rec, seen


@pytest.mark.parametrize(
    ("left", "wait"),
    [(None, 180.0), (400.0, 180.0), (300.0, 180.0), (250.0, 130.0), (131.0, 11.0)],
)
def test_the_code_wait_leaves_the_proof_reserve(
    rig: Rig, monkeypatch: pytest.MonkeyPatch, left: float | None, wait: float
) -> None:
    """code wait = min(MAIL_WAIT_S, deadline_left - 120)."""
    rc, _rec, seen = _wait_of(rig, monkeypatch, left)
    assert rc == 0
    assert seen == [wait]
    assert rig.page.clicks == 1


def test_no_time_for_the_code_wait_sends_nothing(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    rc, rec, seen = _wait_of(rig, monkeypatch, 125.0)
    assert (rc, rec["code"]) == (2, "timeout")
    assert not seen
    assert rig.page.clicks == 0
    assert not rig.stamp.exists()


def test_the_baseline_and_archive_reads_are_capped(rig: Rig) -> None:
    capped = browser._CappedRun(rig.mailbox)
    capped.cap(browser.NOTION_MAIL_CODE_BASELINE_CAP_S)
    rig.clock.t += 40.0
    capped([HIMALAYA, "envelope", "list", "--folder", "INBOX"], timeout=30)
    assert rig.mailbox.calls[-1]["timeout"] == pytest.approx(5.0)
    rig.clock.t += 6.0
    with pytest.raises(subprocess.TimeoutExpired):
        capped([HIMALAYA, "envelope", "list", "--folder", "INBOX"], timeout=30)
    capped.cap(None)
    capped([HIMALAYA, "envelope", "list", "--folder", "INBOX"], timeout=30)
    assert rig.mailbox.calls[-1]["timeout"] == 30
