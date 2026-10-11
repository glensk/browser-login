"""`browser.py token` / `cscs-login`: the portal token is VALIDATED before caching.

Regression for tp#491 D1 (a failed check escaped as a traceback, skipped the
tab cleanup and echoed the response body) and for WS2-cscs (the token was
cached BEFORE its check, so a dead token reached cscs-api.py): now every
candidate is checked against the portal's /api/users/me/ first and only a
validated one is cached; a rejected token exits 2 ("needs login"), anything
undecided exits 1; no line ever shows a token, a body or an exception text,
and the owned tab is always closed.

Nothing here touches the network or a browser: the owned tab, the page proof,
the candidate scan and `requests.get` are stand-ins; tokens are generated.

Run: python3 -m pytest tests/test_token_verify.py -q     (from the repo root)
"""

from __future__ import annotations

# pylint: disable=protected-access,import-outside-toplevel,too-few-public-methods
# pylint: disable=missing-function-docstring,missing-class-docstring,import-error
# pylint: disable=redefined-outer-name,unused-argument
import contextlib
import importlib.util
import os
import secrets
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

TOKEN = secrets.token_hex(20)  # generated: never a real one
SECRET_MSG = "DUMMY-SECRET-IN-EXCEPTION"
PORTAL = "https://portal.cscs.ch/profile/"


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


class _Page:
    def __init__(self, url: str):
        self.url = url

    def goto(self, url, **_kw):
        pass

    def wait_for_timeout(self, _ms):
        pass

    def set_viewport_size(self, _size):
        pass

    @property
    def context(self):
        return None


@pytest.fixture
def env(tmp_path, monkeypatch):
    """A fake owned tab; returns (log, cache path, state)."""
    log: list = []
    cache = tmp_path / "cscs-api" / "portal_token"
    monkeypatch.setattr(browser, "CSCS_TOKEN_CACHE", cache)
    state: dict = {
        "page": _Page(PORTAL),
        "proof": "valid",
        "tokens": [TOKEN],
        "answer": _Resp(200, {"username": "u"}),
    }
    monkeypatch.setattr(
        browser, "_token_candidates", lambda ctx, page: (list(state["tokens"]), None)
    )
    monkeypatch.setattr(browser, "_portal_auth_scheme", lambda method, *_a: ["Token"])
    monkeypatch.setattr(
        browser, "_broker_cscs_token_proof", lambda page, wait_s: state["proof"]
    )
    monkeypatch.setattr(
        browser, "_interaction_lease", lambda *a, **k: contextlib.nullcontext()
    )
    monkeypatch.setattr(browser, "_connect", pytest.fail)  # only the owned tab

    @contextlib.contextmanager
    def fake_owned(port, *, prepare=None):
        log.append("owned.open")
        if prepare is not None:
            prepare(state["page"])
        try:
            yield state["page"]
        finally:
            log.append("owned.close")

    monkeypatch.setattr(browser, "_owned_background_page", fake_owned)
    asked: list = []

    def fake_get(*_a, **k):
        asked.append(k.get("headers", {}).get("Authorization", ""))
        ans: object = state["answer"]
        if callable(ans):
            ans = ans(asked[-1])  # pylint: disable=not-callable  # (inference)
        if isinstance(ans, Exception):
            raise ans  # pylint: disable=raising-non-exception  # (inference: _Resp|Exception)
        return ans

    state["asked"] = asked
    monkeypatch.setattr(requests, "get", fake_get)
    old = os.umask(0o022)
    yield log, cache, state
    os.umask(old)


UNDECIDED = [
    requests.ConnectionError(SECRET_MSG),
    requests.Timeout(SECRET_MSG),
    _Resp(200, exc=ValueError(SECRET_MSG)),
    _Resp(200, exc=requests.JSONDecodeError(SECRET_MSG, "doc", 0)),
    _Resp(200, None),
    _Resp(200, ["u"]),
    _Resp(200, "u"),
    _Resp(200, 42),
    _Resp(200, {"email": "no identity"}),
    _Resp(500, None),
    _Resp(302, None),
]
REJECTED = [_Resp(401, {"detail": TOKEN}), _Resp(403, {"detail": TOKEN})]


def _assert_clean(capsys):
    out = capsys.readouterr()
    text = out.out + out.err
    assert TOKEN not in text
    assert "body-marker" not in text and "\x1b" not in text
    assert SECRET_MSG not in text
    return out


def _run(cmd: str) -> int:
    rc = browser.cmd_token(9222) if cmd == "token" else browser.cmd_cscs_login(9222)
    return int(rc)


@pytest.mark.parametrize("cmd", ["token", "login"])
def test_a_validated_token_is_cached(env, capsys, cmd):
    log, cache, state = env
    state["answer"] = _Resp(200, {"username": "user\x1b[31m", "email": "u@x.ch"})
    assert _run(cmd) == 0
    assert cache.read_text() == TOKEN
    assert cache.stat().st_mode & 0o777 == 0o600
    assert log == ["owned.open", "owned.close"]
    assert state["asked"] == [f"Token {TOKEN}"]
    out = _assert_clean(capsys)
    assert "Authenticated as: user[31m (u@x.ch)" in out.out


@pytest.mark.parametrize("answer", UNDECIDED)
@pytest.mark.parametrize("cmd", ["token", "login"])
def test_an_undecided_check_exits_1_and_caches_nothing(env, capsys, cmd, answer):
    log, cache, state = env
    cache.parent.mkdir(parents=True)
    cache.write_text("previous")
    state["answer"] = answer
    assert _run(cmd) == 1  # never 2: cscs-api.py maps 2 to "needs login"
    assert cache.read_text() == "previous"  # never overwritten unvalidated
    assert log == ["owned.open", "owned.close"]
    assert _assert_clean(capsys).err.startswith("❌ ")


@pytest.mark.parametrize("answer", REJECTED)
@pytest.mark.parametrize("cmd", ["token", "login"])
def test_a_rejected_token_exits_2_and_caches_nothing(env, capsys, cmd, answer):
    log, cache, state = env
    state["answer"] = answer
    assert _run(cmd) == 2  # the session is dead: cscs-api.py's "needs login"
    assert not cache.exists()
    assert log == ["owned.open", "owned.close"]
    _assert_clean(capsys)


def test_the_next_candidate_is_tried(env):
    _log, cache, state = env
    good = secrets.token_hex(20)
    state["tokens"] = [TOKEN, good]

    def answer(auth: str) -> _Resp:
        return _Resp(200, {"uuid": "x"}) if auth.endswith(good) else _Resp(401)

    state["answer"] = answer
    assert browser.cmd_token(9222) == 0
    assert cache.read_text() == good


def test_a_logged_out_portal_exits_2_before_any_scan(env, capsys):
    log, cache, state = env
    state["proof"] = "invalid"
    state["tokens"] = []  # never asked
    assert browser.cmd_token(9222) == 2
    assert not cache.exists() and not state["asked"]
    assert log == ["owned.open", "owned.close"]
    assert "Not logged in" in capsys.readouterr().err


def test_an_undecided_portal_exits_1(env, capsys):
    _log, cache, state = env
    state["proof"] = "indeterminate"
    assert browser.cmd_token(9222) == 1
    assert not cache.exists() and not state["asked"]
    assert "could not tell" in capsys.readouterr().err


def test_no_candidate_exits_1(env, capsys):
    _log, cache, state = env
    state["tokens"] = []
    assert browser.cmd_token(9222) == 1
    assert not cache.exists()


@pytest.mark.parametrize(
    "method, config, scheme",
    [
        ("local", None, ["Token"]),  # never asks the configuration
        ("passkey", None, ["Token"]),
        ("keycloak", {"WALDUR_CORE": {"OIDC_ACCESS_TOKEN_ENABLED": True}}, ["Bearer"]),
        ("keycloak", {"WALDUR_CORE": {"OIDC_ACCESS_TOKEN_ENABLED": False}}, ["Token"]),
        (None, {"WALDUR_CORE": {}}, ["Token"]),
        # the configuration cannot be read: both are tried (debate C8)
        ("keycloak", requests.ConnectionError("x"), ["Token", "Bearer"]),
        ("keycloak", ["not", "a", "dict"], ["Token", "Bearer"]),
    ],
)
def test_the_scheme_follows_the_portal_configuration(
    monkeypatch, method, config, scheme
):
    asked: list = []

    def get(url, **_k):
        asked.append(url)
        if isinstance(config, Exception):
            raise config
        return _Resp(200, config)

    monkeypatch.setattr(requests, "get", get)
    assert browser._portal_auth_scheme(method) == scheme
    assert (not asked) == (method in ("local", "passkey"))


def test_an_unknown_scheme_rejects_only_when_every_scheme_does(env):
    _log, cache, state = env
    state["tokens"] = [TOKEN]

    def answer(auth: str) -> _Resp:
        return _Resp(200, {"uuid": "x"}) if auth.startswith("Bearer ") else _Resp(401)

    state["answer"] = answer
    browser_scheme = browser._portal_auth_scheme
    try:
        browser._portal_auth_scheme = lambda method, *_a: ["Token", "Bearer"]
        assert browser.cmd_token(9222) == 0
    finally:
        browser._portal_auth_scheme = browser_scheme
    assert cache.read_text() == TOKEN
    assert state["asked"] == [f"Token {TOKEN}", f"Bearer {TOKEN}"]
