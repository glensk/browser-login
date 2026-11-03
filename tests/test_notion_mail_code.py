"""tp#1633: the headless Notion e-mail-code login in the shared Chromium.

Hermetic: himalaya is a fake ``run``, the page a fake; nothing drives the
live browser, reads a real mailbox or opens a real sign-in. The EPFL test
imports ``sdsc/email/epfl_oauth.py`` by path (skipped when absent) and runs it
against a temp state dir with a dead store. No credential-shaped literals:
codes are generated per run.
"""

from __future__ import annotations

# pylint: disable=missing-function-docstring,import-error,wrong-import-position
# pylint: disable=protected-access,unused-argument
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import agent_login_safari as s  # noqa: E402

EPFL_OAUTH = Path.home() / "obsidian/42-Git/sdsc/email/epfl_oauth.py"


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
        browser = pw.chromium.launch(headless=True)
        try:
            page = browser.new_page()
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
            browser.close()


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
