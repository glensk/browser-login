"""`browser.py token` / `cscs-login`: the /api/me/ check after caching the token.

Regression for tp#491 D1: a network error (or a non-JSON answer) from the
portal check AFTER the token was cached escaped as a traceback, skipped the tab
cleanup, and the non-200 branch echoed the response body (which may hold the
token). Now every such case exits 1 with a fixed line, the cache file stays
written 0600, and the stale-tab cleanup plus browser/Playwright shutdown run.

Nothing here touches the network or a browser: `_connect`, the page, the token
scan and `requests.get` are all stand-ins; the token is a dummy.

Run: python3 -m pytest tests/test_token_verify.py -q     (from the repo root)
"""

from __future__ import annotations

# pylint: disable=protected-access,import-outside-toplevel,too-few-public-methods
# pylint: disable=missing-function-docstring,missing-class-docstring,import-error
# pylint: disable=redefined-outer-name,unused-argument
import contextlib
import importlib.util
import os
import sys
from pathlib import Path

import pytest
import requests

_BROWSER_PY = Path(__file__).resolve().parent.parent / "bin" / "browser.py"


def _load_browser_module():
    spec = importlib.util.spec_from_file_location("browser_token_verify", _BROWSER_PY)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["browser_token_verify"] = mod
    spec.loader.exec_module(mod)
    return mod


browser = _load_browser_module()

TOKEN = "d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0"  # dummy 40-hex, never real
SECRET_MSG = "DUMMY-SECRET-IN-EXCEPTION"
PORTAL = "https://portal.cscs.ch/profile/"
KEYCLOAK = "https://auth.cscs.ch/auth/realms/cscs/protocol/openid-connect/auth"


class _Resp:
    def __init__(self, status: int = 200, payload=None, exc: Exception | None = None):
        self.status_code = status
        self._payload = payload
        self._exc = exc
        # a hostile body: echoes the token plus terminal control characters
        self.text = f"\x1b[2J{TOKEN}\r\nbody-marker"

    def json(self):
        if self._exc is not None:
            raise self._exc
        return self._payload


class _Closer:
    def __init__(self, log: list, name: str):
        self._log, self._name = log, name

    def close(self):
        self._log.append(f"{self._name}.close")

    def stop(self):
        self._log.append(f"{self._name}.stop")


class _Page:
    def __init__(self, url: str):
        self.url = url

    def goto(self, url, **_kw):
        pass

    def wait_for_timeout(self, _ms):
        pass

    def bring_to_front(self):
        pass


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Wire a fake browser; returns (log, cache path, set_page, set_answer)."""
    log: list = []
    cache = tmp_path / "cscs-api" / "portal_token"
    monkeypatch.setattr(browser, "CSCS_TOKEN_CACHE", cache)
    monkeypatch.setattr(browser, "_scan_token", lambda ctx, page: TOKEN)
    monkeypatch.setattr(
        browser, "_connect", lambda port: (_Closer(log, "pw"), _Closer(log, "browser"))
    )
    monkeypatch.setattr(
        browser, "_interaction_lease", lambda *a, **k: contextlib.nullcontext()
    )

    def fake_close_stale(ctx, keep=None):
        log.append("close_stale")
        return 0

    monkeypatch.setattr(browser, "_close_stale_cscs_tabs", fake_close_stale)
    state: dict = {"page": _Page(PORTAL), "answer": _Resp(200, {"username": "u"})}
    monkeypatch.setattr(browser, "_pick_portal_page", lambda b: (None, state["page"]))

    def fake_get(*_a, **_k):
        ans: object = state["answer"]
        if isinstance(ans, Exception):
            raise ans  # pylint: disable=raising-non-exception  # (inference: _Resp|Exception)
        return ans

    monkeypatch.setattr(requests, "get", fake_get)
    old = os.umask(0o022)
    yield log, cache, state
    os.umask(old)


FAILURES = [
    requests.ConnectionError(SECRET_MSG),
    requests.Timeout(SECRET_MSG),
    _Resp(200, exc=ValueError(SECRET_MSG)),
    _Resp(200, exc=requests.JSONDecodeError(SECRET_MSG, "doc", 0)),
    _Resp(200, None),
    _Resp(200, ["u"]),
    _Resp(200, "u"),
    _Resp(200, 42),
    _Resp(401, {"detail": TOKEN}),
    _Resp(500, None),
]


def _assert_clean(capsys):
    out = capsys.readouterr()
    text = out.out + out.err
    assert TOKEN not in text
    assert "body-marker" not in text and "\x1b" not in text
    assert SECRET_MSG not in text
    return out


@pytest.mark.parametrize("cmd", ["token", "login"])
def test_verified_token_exits_0(env, capsys, cmd):
    log, cache, state = env
    state["answer"] = _Resp(200, {"username": "user\x1b[31m", "email": "u@x.ch"})
    rc = browser.cmd_token(9222) if cmd == "token" else browser.cmd_cscs_login(9222)
    assert rc == 0
    assert cache.read_text() == TOKEN
    assert cache.stat().st_mode & 0o777 == 0o600
    assert {"close_stale", "browser.close", "pw.stop"} <= set(log)
    out = _assert_clean(capsys)
    assert "Authenticated as: user[31m (u@x.ch)" in out.out


@pytest.mark.parametrize("answer", FAILURES)
@pytest.mark.parametrize("cmd", ["token", "login"])
def test_failed_verification_exits_1_and_still_cleans_up(env, capsys, cmd, answer):
    log, cache, state = env
    state["answer"] = answer
    rc = browser.cmd_token(9222) if cmd == "token" else browser.cmd_cscs_login(9222)
    assert rc == 1  # never 2: cscs-api.py maps 2 to "needs login"
    assert cache.read_text() == TOKEN
    assert cache.stat().st_mode & 0o777 == 0o600
    assert {"close_stale", "browser.close", "pw.stop"} <= set(log)
    out = _assert_clean(capsys)
    assert out.err.startswith("❌ ")


def test_keycloak_redirect_in_token_still_exits_2(env, capsys):
    log, cache, state = env
    state["page"] = _Page(KEYCLOAK)
    assert browser.cmd_token(9222) == 2
    assert not cache.exists()
    assert {"browser.close", "pw.stop"} <= set(log)
    assert "Not logged in" in capsys.readouterr().err
