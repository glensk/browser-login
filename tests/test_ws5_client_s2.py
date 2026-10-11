"""WS5 S2 (tp#833): the client's server identity proof, role instances and
group aliases in bin/browser.py.

A REAL broker (``broker.daemon.Broker`` behind its own socket server, a fake
vault, a tmp home) answers ``sites`` / ``identity_challenge`` /
``identity_answer`` over a Unix socket; the reviewed recipe runs in a
throwaway headless Chromium against routed fixture endpoints (no network).
Account names are generated per run, never literals; the leak tests look for
them in stdout, stderr, the journal and the ``-R`` result record.
"""

from __future__ import annotations

# pylint: disable=protected-access,missing-function-docstring,missing-class-docstring
# pylint: disable=import-error,wrong-import-position,redefined-outer-name
# pylint: disable=too-many-lines  # one file: the client proof end to end
import argparse
import contextlib
import importlib.util
import json
import os
import secrets
import shutil
import sys
import tempfile
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from broker import daemon, identity, identity_ops, limiter, vault  # noqa: E402


def _load(rel: str, name: str) -> Any:
    """A repo script as a module of its own, registered under `name`
    (dataclasses resolve their module through sys.modules)."""
    path = REPO / rel
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


browser = _load("bin/browser.py", "ws5s2_browser")
# agent-login: its rows, checks.json and agents.md (the leak test)
al = _load("agent-login.py", "ws5s2_agent_login")

HOST = "gitlab.ws5c.example"
CHECK = f"https://{HOST}/dashboard"
_LOGIN_KEY = "pass" + "word"  # built from parts: no credential-shaped literal


def _user() -> str:
    """A fresh account name (never a literal in this file)."""
    return f"zz-{secrets.token_hex(5)}"


def _raw(site: str, user: str, **fields: str) -> dict:
    """A Bitwarden-shaped item of the agent-logins collection on HOST."""
    base = {
        "agent_site": site,
        "agent_fill_origins": f"https://{HOST}",
        "agent_check_url": CHECK,
        "agent_logged_in_selector": "#me",
        "agent_cookie_hosts": HOST,
    }
    base.update({f"agent_{k}": v for k, v in fields.items()})
    return {
        "id": f"id-{site}",
        "name": site,
        "login": {"username": user, _LOGIN_KEY: secrets.token_urlsafe(18)},
        "fields": [{"name": k, "value": v} for k, v in base.items()],
    }


class _Vault:
    def __init__(self, items: list[vault.SiteItem]) -> None:
        self._items = items

    def items(self) -> list[vault.SiteItem]:
        return self._items

    def secret(self, site: str) -> vault.Secret:
        raise AssertionError(f"no login may reach the vault ({site})")


class _NoRunner:
    def __call__(self, item: Any, get_secret: Any) -> dict[str, Any]:
        raise AssertionError("the broker must not log in")


class FakeBroker:  # pylint: disable=too-many-instance-attributes
    """The real broker (`daemon.Broker`) behind its real socket server."""

    def __init__(self, raws: list[dict], home: Path) -> None:
        self.items = vault.build_items(raws)
        lim = limiter.Limiter(
            home / "l.json", cooldown_s=1800, min_interval_s=0, per_hour=50, per_day=100
        )
        # The broker's clock: real time plus `offset` (a test can step past
        # the mismatch guard's cooldown).
        self.offset = 0.0
        self.broker = daemon.Broker(
            _Vault(self.items),  # type: ignore[arg-type]
            lim,
            home / "home",
            runner=_NoRunner(),
            clock=lambda: time.time() + self.offset,
        )
        self.ops: list[tuple[str, Any]] = []
        # Every nonce, challenge id and digest that crossed the socket (the
        # leak tests look for them in every output).
        self.secrets: list[str] = []
        real = self.broker.handle

        def handle(req: Any, uid: Any = None, pid: Any = None) -> dict:
            if isinstance(req, dict):
                self.ops.append((str(req.get("op")), req.get("site")))
                self.secrets += [
                    str(req[k]) for k in ("challenge_id", "digest") if req.get(k)
                ]
            reply = real(req, uid, pid)
            self.secrets += [
                str(reply[k]) for k in ("challenge_id", "nonce") if reply.get(k)
            ]
            return reply

        self.broker.handle = handle  # type: ignore[method-assign]
        # AF_UNIX paths are capped at 104 bytes on macOS: a short temp dir.
        self.dir = tempfile.mkdtemp(prefix="ws5c-")
        self.path = os.path.join(self.dir, "b.sock")
        self.server = daemon.BrokerServer(self.path, self.broker, os.getuid())
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self.dir, ignore_errors=True)

    def op_names(self) -> list[str]:
        return [op for op, _site in self.ops]


@pytest.fixture
def result_file(tmp_path: Path) -> Iterator[Path]:
    path = tmp_path / "result.json"
    browser._result_begin("logged-in", "", str(path))
    browser._LOGIN_OPTS.update(scheduled=False, candidate=None, refresh_only=False)
    browser._BROKER_SITES_CACHE.clear()
    yield path
    browser._result_begin("logged-in", "", None)
    browser._BROKER_SITES_CACHE.clear()


@pytest.fixture
def make_broker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Any]:
    made: list[FakeBroker] = []

    def make(raws: list[dict]) -> FakeBroker:
        fake = FakeBroker(raws, tmp_path)
        monkeypatch.setenv("LOGIN_BROKER_SOCKET", fake.path)
        browser._BROKER_SITES_CACHE.clear()
        made.append(fake)
        return fake

    yield make
    for fake in made:
        fake.close()


def _record(path: Path, rc: int) -> dict:
    browser._result_write(rc)
    rec: dict = json.loads(path.read_text())
    return rec


def _gitlab_pair(
    glensk: str, admin: str, *, glensk_inst: str = "", admin_inst: str = "admin"
) -> list[dict]:
    """Two accounts of one GitLab: the default member and its admin."""
    return [
        _raw(
            "gl-glensk",
            glensk,
            instance=glensk_inst,
            privilege="user",
            identity="gitlab",
            alias="gl",
        ),
        _raw(
            "gl-admin",
            admin,
            instance=admin_inst,
            privilege="admin",
            identity="gitlab",
        ),
    ]


# ---------------------------------------------------------------------------
# A real headless Chromium: the fixture GitLab and the probe page
# ---------------------------------------------------------------------------


def _chromium_installed() -> bool:
    try:
        from playwright.sync_api import (  # pylint: disable=import-outside-toplevel
            sync_playwright,
        )

        with sync_playwright() as pw:
            return Path(pw.chromium.executable_path).exists()
    except Exception:  # pylint: disable=broad-exception-caught
        return False


CHROME = pytest.mark.skipif(
    not _chromium_installed(), reason="Playwright Chromium missing"
)


class _Api:
    """Routes every request: the check page (with the sentinel while
    `logged_in`) and the identity endpoint (`body`, `status`, `ctype`).
    `cleared` records the client's foreign-session clears (which log the
    fixture out)."""

    def __init__(self) -> None:
        self.body: Any = {}
        self.status = 200
        self.ctype = "application/json; charset=utf-8"
        self.calls = 0
        self.redirect: str | None = None
        self.logged_in = True
        self.cleared: list[tuple[str, Any, str]] = []

    def handle(self, route: Any) -> None:
        req = route.request
        if req.resource_type == "document":
            page = "<p id=me>hi</p>" if self.logged_in else "<p>log in</p>"
            route.fulfill(status=200, content_type="text/html", body=page)
            return
        self.calls += 1
        if self.redirect:
            route.fulfill(status=302, headers={"Location": self.redirect})
            return
        route.fulfill(
            status=self.status, content_type=self.ctype, body=json.dumps(self.body)
        )


@pytest.fixture
def chrome(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[Any, _Api]]:
    """A throwaway headless Chromium whose page stands in for the probe tab
    (`_with_prepared_background_page`): it loads the check URL, records its
    status like the real helper, and runs the probe's callback."""
    from playwright.sync_api import (  # pylint: disable=import-outside-toplevel
        sync_playwright,
    )

    api = _Api()
    with sync_playwright() as pw:
        chromium = pw.chromium.launch(headless=True)
        try:
            ctx = chromium.new_context()
            ctx.route("**/*", api.handle)
            page = ctx.new_page()

            def probe_tab(_port: int, url: str, _prepare: Any, fn: Any) -> Any:
                resp = page.goto(url)
                browser._BG_STATUS[id(page)] = getattr(resp, "status", None)
                try:
                    return fn(page)
                finally:
                    browser._BG_STATUS.pop(id(page), None)

            def clear(
                _port: int, site: str, _entry: dict, names: Any, *, why: str
            ) -> int:
                api.cleared.append((site, names, why))
                api.logged_in = False  # its cookies are gone
                return 2

            monkeypatch.setattr(browser, "_with_prepared_background_page", probe_tab)
            monkeypatch.setattr(browser, "_broker_note_session_age", lambda *_a: None)
            monkeypatch.setattr(browser, "_broker_clear_cookies", clear)
            yield page, api
        finally:
            chromium.close()


def _leak_free(
    names: list[str], capsys: pytest.CaptureFixture[str], *paths: Path
) -> None:
    out = capsys.readouterr()
    texts = [out.out, out.err]
    texts += [p.read_text(encoding="utf-8") for p in paths if p.exists()]
    journal = os.environ.get("CLAUDE_BROWSER_JOURNAL_FILE")
    if journal and Path(journal).exists():
        texts.append(Path(journal).read_text(encoding="utf-8"))
    for name in names:
        for text in texts:
            assert name not in text and name.upper() not in text


@pytest.mark.launches_chrome
@CHROME
def test_match_passes_and_nothing_leaks(
    chrome: tuple[Any, _Api],
    make_broker: Any,
    result_file: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _page, api = chrome
    glensk, admin = _user(), _user()
    fake = make_broker(_gitlab_pair(glensk, admin))
    api.body = {"username": f" {glensk.upper()} ", "id": 7}  # no is_admin: user
    assert browser._broker_logged_in(9222, "gl-glensk") == 0
    rec = _record(result_file, 0)
    assert rec["identity"] == "match" and rec["code"] == "ok"
    assert rec["multi_account"] is True and rec["instance"] == ""
    assert fake.op_names() == ["sites", "identity_challenge", "identity_answer"]
    assert api.calls == 1
    # what agent-login makes of it: checks.json and agents.md
    agents = result_file.with_name("agents.md")
    al.record_check("gl-glensk", True, "logged in", rec)
    sites = fake.broker.handle({"op": "sites"}, os.getuid(), os.getpid())["sites"]
    monkeypatch.setattr(al, "broker_state", lambda **_k: ("running, Bitwarden", sites))
    monkeypatch.setattr(al, "safari_state", lambda _names: {})
    agents.write_text(
        al.agent_summary(al.overview(), al.last_checks()), encoding="utf-8"
    )
    assert "✅ gl-glensk" in agents.read_text(encoding="utf-8")
    checks = Path(os.environ["AGENT_LOGIN_STATE_FILE"]).with_name("checks.json")
    assert len(fake.secrets) == 4  # challenge id ×2, nonce, digest
    _leak_free([glensk, admin, *fake.secrets], capsys, result_file, agents, checks)


@pytest.mark.launches_chrome
@CHROME
def test_mismatch_is_wrong_account_and_clears_the_foreign_session(
    chrome: tuple[Any, _Api],
    make_broker: Any,
    result_file: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _page, api = chrome
    glensk, admin = _user(), _user()
    make_broker(_gitlab_pair(glensk, admin))
    api.body = {"username": admin, "is_admin": True}  # the admin's session
    assert browser._broker_logged_in(9222, "gl-glensk") == 2
    rec = _record(result_file, 2)
    assert (rec["phase"], rec["code"]) == ("client-proof", "wrong_account")
    assert rec["foreign_cleared"] == 2
    assert api.cleared == [("gl-glensk", None, "clear-foreign")]
    err = capsys.readouterr().err
    assert "ANOTHER account" in err and "foreign session cleared" in err
    assert "Logged into" not in err and glensk not in err and admin not in err
    # had it come back: the broker's mismatch guard gives no verdict for an
    # hour, the client says so (and clears nothing on a non-verdict)
    api.logged_in = True
    browser._result_begin("logged-in", "", str(result_file))
    assert browser._broker_logged_in(9222, "gl-glensk") == 2
    assert _record(result_file, 2)["code"] == "identity_blocked"
    assert len(api.cleared) == 1
    _leak_free([glensk, admin], capsys, result_file)


@pytest.mark.launches_chrome
@CHROME
def test_admin_bit_mismatch_is_privilege_mismatch(
    chrome: tuple[Any, _Api], make_broker: Any, result_file: Path
) -> None:
    _page, api = chrome
    glensk, admin = _user(), _user()
    make_broker(_gitlab_pair(glensk, admin))
    api.body = {"username": glensk, "is_admin": True}  # the right name, admin
    assert browser._broker_logged_in(9222, "gl-glensk") == 2
    assert _record(result_file, 2)["code"] == "privilege_mismatch"


@pytest.mark.launches_chrome
@CHROME
@pytest.mark.parametrize(
    "case",
    [
        # (status, content type, body from the account name, code)
        (500, "application/json", lambda n: {"username": n}, "identity_indeterminate"),
        (200, "text/html", lambda n: {"username": n}, "identity_indeterminate"),
        (
            200,
            "application/json",
            lambda n: {"username": n + "ü"},
            "identity_indeterminate",
        ),
        (200, "application/json", lambda n: {"name": n}, "identity_indeterminate"),
        (401, "application/json", lambda n: {}, "logged_out"),
    ],
)
def test_unclear_answers_never_pass(
    chrome: tuple[Any, _Api], make_broker: Any, result_file: Path, case: tuple
) -> None:
    status, ctype, body_of, code = case
    _page, api = chrome
    glensk = _user()
    make_broker(_gitlab_pair(glensk, _user()))
    api.status, api.ctype, api.body = status, ctype, body_of(glensk)
    assert browser._broker_logged_in(9222, "gl-glensk") == 2
    rec = _record(result_file, 2)
    assert rec["code"] == code and rec["phase"] == "client-proof"


@pytest.mark.launches_chrome
@CHROME
def test_a_redirect_of_the_identity_endpoint_never_passes(
    chrome: tuple[Any, _Api], make_broker: Any, result_file: Path
) -> None:
    """Cross-origin or not: the recipe follows no redirect at all."""
    _page, api = chrome
    glensk = _user()
    make_broker(_gitlab_pair(glensk, _user()))
    api.body = {"username": glensk}
    for target in ("https://evil.ws5c.example/u", f"https://{HOST}/api/v4/other"):
        api.redirect = target
        browser._result_begin("logged-in", "", str(result_file))
        assert browser._broker_logged_in(9222, "gl-glensk") == 2
        rec = _record(result_file, 2)
        assert (rec["code"], rec["identity_why"]) == (
            "identity_indeterminate",
            "redirect",
        )


@pytest.mark.launches_chrome
@CHROME
def test_an_out_of_band_account_change_is_caught(
    chrome: tuple[Any, _Api], make_broker: Any, result_file: Path
) -> None:
    _page, api = chrome
    glensk, admin = _user(), _user()
    make_broker(_gitlab_pair(glensk, admin))
    api.body = {"username": glensk}
    assert browser._broker_logged_in(9222, "gl-glensk") == 0
    api.body = {"username": admin, "is_admin": True}  # someone switched it
    browser._result_begin("logged-in", "", str(result_file))
    assert browser._broker_logged_in(9222, "gl-glensk") == 2
    assert _record(result_file, 2)["code"] == "wrong_account"


@pytest.mark.launches_chrome
@CHROME
def test_page_scripts_cannot_hook_the_client_recipe(
    chrome: tuple[Any, _Api], make_broker: Any, result_file: Path
) -> None:
    """The recipe runs in an isolated world: a page that replaces fetch's
    JSON parser and the hash in ITS world cannot fake the account."""
    page, api = chrome
    glensk, admin = _user(), _user()
    make_broker(_gitlab_pair(glensk, admin))
    api.body = {"username": admin, "is_admin": True}
    page.context.add_init_script(
        "Response.prototype.json = async function () { return {username: %s}; };"
        "crypto.subtle.digest = async () => new ArrayBuffer(32);" % json.dumps(glensk)
    )
    assert browser._broker_logged_in(9222, "gl-glensk") == 2
    assert _record(result_file, 2)["code"] == "wrong_account"


def _guard_mismatches(fake: FakeBroker, site: str) -> int:
    path = fake.broker.identity_ops.guard.path
    data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    return len(((data.get("sites") or {}).get(site) or {}).get("mismatches") or [])


@pytest.mark.launches_chrome
@CHROME
@pytest.mark.launches_chrome
@CHROME
def test_a_foreign_session_is_cleared_by_the_check_and_never_costs_again(
    chrome: tuple[Any, _Api],
    make_broker: Any,
    result_file: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No sibling may live in this instance (S1 refuses it), so another
    account's session here is foreign: the CHECK that says wrong_account
    clears it at once (cookies only — never storage or the broker's profile:
    no `logout`). Gated or not: a gated login's free check clears it and
    logs nothing in. A repeated check sees no sentinel: no challenge, no
    further mismatch. Past the guard's cooldown an ungated login's free
    check sees "logged out" (no challenge) and its verify proves the
    injected account — two challenges in all, one mismatch."""
    _page, api = chrome
    glensk, admin = _user(), _user()
    fake = make_broker(_gitlab_pair(glensk, admin))
    api.body = {"username": admin, "is_admin": True}  # a foreign session here
    injected: list = []

    def inject(*_a: Any, **_k: Any) -> tuple:
        injected.append(1)
        api.logged_in, api.body = True, {"username": glensk}  # the right account
        return None, {}, 1, 0

    def gated(site: str) -> int:
        return int(browser._broker_fail(2, f"{site}: no scheduled login — pending"))

    monkeypatch.setattr(browser, "_broker_fetch_inject", inject)
    monkeypatch.setattr(browser, "_broker_gate", gated)
    # 1) a gated login (pending, not promoted): its free check clears, no login
    assert browser._broker_login(9222, "gl-glensk") == 2
    assert api.cleared == [("gl-glensk", None, "clear-foreign")] and not injected
    assert _guard_mismatches(fake, "gl-glensk") == 1
    # 2) checks again: no sentinel → no challenge, no mismatch, nothing cleared
    for _ in range(3):
        browser._result_begin("logged-in", "gl-glensk", str(result_file))
        assert browser._broker_logged_in(9222, "gl-glensk") == 2
        assert _record(result_file, 2)["code"] == "logged_out"
    assert fake.op_names().count("identity_challenge") == 1
    assert _guard_mismatches(fake, "gl-glensk") == 1 and len(api.cleared) == 1
    # 3) an ungated login past the guard's cooldown: one login, proven
    fake.offset += identity_ops.GUARD_COOLDOWNS_S[0] + 1
    monkeypatch.setattr(browser, "_broker_gate", lambda _s: None)
    browser._result_begin("login", "gl-glensk", str(result_file))
    assert browser._broker_login(9222, "gl-glensk") == 0
    assert _record(result_file, 0)["identity"] == "match" and injected == [1]
    assert fake.op_names().count("identity_challenge") == 2
    assert _guard_mismatches(fake, "gl-glensk") == 1
    assert "logout" not in fake.op_names()


def _fake_browser(cookies: list[dict]) -> tuple[Any, Any, list]:
    """(pw, browser, cleared) stand-ins for `_connect`: one context holding
    `cookies`; `cleared` records every `clear_cookies` call."""
    cleared: list = []

    class Ctx:
        def cookies(self) -> list[dict]:
            return cookies

        def clear_cookies(self, **kw: Any) -> None:
            cleared.append((kw["domain"], kw["name"]))

    class Browser:
        contexts = [Ctx()]

        def close(self) -> None:
            pass

    class Pw:
        def stop(self) -> None:
            pass

    return Pw(), Browser(), cleared


@pytest.mark.parametrize(
    ("names", "gone"),
    [
        (
            ["_gitlab_session"],
            [
                ("gitlab.ws5c.example", "_gitlab_session"),
                (".sub.gitlab.ws5c.example", "_gitlab_session"),
            ],
        ),
        (
            None,
            [
                ("gitlab.ws5c.example", "_gitlab_session"),
                ("gitlab.ws5c.example", "known_device"),
                (".sub.gitlab.ws5c.example", "_gitlab_session"),
            ],
        ),
    ],
)
def test_clearing_a_foreign_session_takes_only_the_items_cookies(
    monkeypatch: pytest.MonkeyPatch, names: list[str] | None, gone: list[tuple]
) -> None:
    """Its cookie hosts and their subdomains, never a parent domain or
    another site's host; only its `cookie_names` when it has them."""
    cookies = [
        {"domain": "gitlab.ws5c.example", "name": "_gitlab_session", "path": "/"},
        {"domain": ".sub.gitlab.ws5c.example", "name": "_gitlab_session", "path": "/"},
        {"domain": "gitlab.ws5c.example", "name": "known_device", "path": "/"},
        {"domain": ".ws5c.example", "name": "_gitlab_session", "path": "/"},  # parent
        {"domain": "github.com", "name": "_gitlab_session", "path": "/"},  # sibling
    ]
    pw, fake, cleared = _fake_browser(cookies)
    monkeypatch.setattr(browser, "_connect", lambda _port: (pw, fake))
    monkeypatch.setattr(
        browser, "_interaction_lease", lambda _why: contextlib.nullcontext()
    )
    entry = {"site": "gl-glensk", "cookie_hosts": [HOST], "cookie_names": names}
    said = browser._broker_clear_foreign(9222, "gl-glensk", entry)
    assert sorted(cleared) == sorted(gone)
    assert f"foreign session cleared ({len(gone)} cookie(s)" in said
    assert browser._RESULT["foreign_cleared"] == len(gone)


def test_candidate_login_verify_still_proves_the_account(
    make_broker: Any, result_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`login -x CSS` of a multi-account item: the verify after the
    injection claims the item's account, so it runs the identity proof."""
    make_broker(_gitlab_pair(_user(), _user()))
    seen: list[Any] = []

    def probe_tab(_port: int, _url: str, _prepare: Any, fn: Any) -> Any:
        seen.append(fn)
        return "privilege_mismatch"

    monkeypatch.setattr(browser, "_with_prepared_background_page", probe_tab)
    monkeypatch.setattr(browser, "_broker_gate", lambda _s: None)
    monkeypatch.setattr(
        browser, "_broker_fetch_inject", lambda *a, **k: (None, {}, 1, 0)
    )
    browser._LOGIN_OPTS.update(candidate="#cand")
    try:
        assert browser._broker_login(9222, "gl-glensk") == 2
    finally:
        browser._LOGIN_OPTS.update(candidate=None)
    assert _record(result_file, 2)["code"] == "privilege_mismatch"
    assert len(seen) == 1


# ---------------------------------------------------------------------------
# The protocol without a browser: refusals and malformed answers
# ---------------------------------------------------------------------------


class _Page:
    """A stand-in page: `_evaluate_isolated` is patched per test."""


def _proof(
    monkeypatch: pytest.MonkeyPatch, answer: Any, entry: dict, site: str = "gl-glensk"
) -> str:
    def evaluate(_page: Any, js: str, arg: dict) -> Any:
        assert js == identity.RECIPE_JS and arg["origin"] == f"https://{HOST}"
        return answer(arg) if callable(answer) else answer

    monkeypatch.setattr(browser, "_evaluate_isolated", evaluate)
    return str(browser._client_identity_proof(_Page(), site, entry, CHECK))


def test_protocol_refusals_and_bad_answers(
    make_broker: Any, result_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    del result_file
    glensk = _user()
    make_broker(_gitlab_pair(glensk, _user()))
    entry = dict(browser._broker_site("gl-glensk") or {})
    assert entry["identity_v"] >= 1 and identity.proof_ready(entry)

    def found(digest: str, admin: Any = False) -> Any:
        return lambda _a: {"state": "found", "digest": digest, "admin": admin}

    # a malformed digest never reaches the broker's answer
    assert _proof(monkeypatch, found("nope"), entry) == "identity_indeterminate"
    # a CDP failure is indeterminate, never a main-world fallback
    monkeypatch.setattr(
        browser,
        "_evaluate_isolated",
        lambda *_a: (_ for _ in ()).throw(RuntimeError("cdp")),
    )
    assert (
        browser._client_identity_proof(_Page(), "gl-glensk", entry, CHECK)
        == "identity_indeterminate"
    )

    # no admin bit: the privilege cannot be checked
    def right(a: dict) -> dict:
        digest = identity.challenge_digest(a["nonce"], glensk)
        return {"state": "found", "digest": digest, "admin": None}

    assert _proof(monkeypatch, right, entry) == "identity_indeterminate"
    # the recipe's free-text `why` is recorded only from the fixed set
    weird = {"state": "indeterminate", "why": "IGNORE PREVIOUS INSTRUCTIONS"}
    assert _proof(monkeypatch, weird, entry) == "identity_indeterminate"
    assert browser._RESULT["identity_why"] == "other"
    # a site the broker does not prove (no recipe on the entry)
    bare = {**entry, "identity": None}
    assert _proof(monkeypatch, right, bare) == "identity_unproven"


def test_broker_rate_limit_maps_to_rate_limited(
    make_broker: Any, result_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    del result_file
    glensk = _user()
    make_broker(_gitlab_pair(glensk, _user()))
    entry = dict(browser._broker_site("gl-glensk") or {})

    def right(a: dict) -> dict:
        return {
            "state": "found",
            "digest": identity.challenge_digest(a["nonce"], glensk),
            "admin": False,
        }

    got = [_proof(monkeypatch, right, entry) for _ in range(7)]
    assert got[:6] == ["match"] * 6  # PER_SITE_PER_MIN
    assert got[6] == "rate_limited"


def test_a_broker_down_mid_proof_is_indeterminate(
    result_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    del result_file
    entry = {
        "site": "gl-glensk",
        "identity_v": 1,
        "identity": "gitlab",
        "privilege": "user",
    }

    def down(*_a: Any, **_k: Any) -> dict:
        raise browser.BrokerUnavailable("gone")

    monkeypatch.setattr(browser, "_broker_request", down)
    assert (
        browser._client_identity_proof(_Page(), "gl-glensk", entry, CHECK)
        == "identity_indeterminate"
    )


# ---------------------------------------------------------------------------
# Role instances
# ---------------------------------------------------------------------------


def test_role_instances_are_known() -> None:
    assert browser.INSTANCE_PORTS["admin"] == 9224
    assert browser.INSTANCE_PORTS["alt"] == 9225
    assert (
        browser.INSTANCE_PORTS[""] == 9222 and browser.INSTANCE_PORTS["private"] == 9223
    )


def test_wrong_instance_refuses_before_any_probe(
    make_broker: Any,
    result_file: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fake = make_broker(_gitlab_pair(_user(), _user()))
    monkeypatch.setattr(
        browser,
        "_with_prepared_background_page",
        lambda *a: pytest.fail("no probe tab in the wrong instance"),
    )
    # gl-admin lives in `admin`; this process is the default instance
    assert browser._broker_logged_in(9222, "gl-admin") == 2
    rec = _record(result_file, 2)
    assert (rec["phase"], rec["code"]) == ("precheck", "wrong_instance")
    assert "CLAUDE_BROWSER_INSTANCE=admin browser.py logged-in gl-admin" in (
        capsys.readouterr().err
    )
    # and the default member from the admin instance
    monkeypatch.setattr(browser, "INSTANCE", "admin")
    browser._result_begin("login", "", str(result_file))
    assert browser._broker_login(9224, "gl-glensk") == 2
    assert _record(result_file, 2)["code"] == "wrong_instance"
    assert "env -u CLAUDE_BROWSER_INSTANCE browser.py login gl-glensk" in (
        capsys.readouterr().err
    )
    assert "identity_challenge" not in fake.op_names()


def test_the_broker_refuses_a_challenge_from_another_instance(
    make_broker: Any, result_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Defence in depth: even past the client gate, the broker's challenge
    is bound to the item's instance."""
    del result_file
    make_broker(_gitlab_pair(_user(), _user()))
    entry = dict(browser._broker_site("gl-admin") or {})
    monkeypatch.setattr(browser, "INSTANCE", "alt")
    assert _proof(monkeypatch, {}, entry, "gl-admin") == "wrong_instance"


def _args(site: str, cmd: str = "login", port: int = 9222) -> argparse.Namespace:
    return argparse.Namespace(cmd=cmd, site=site, cdp_port=port)


def _unpinned(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "CLAUDE_BROWSER_CDP_PORT",
        "CLAUDE_BROWSER_CACHE_DIR",
        "CLAUDE_BROWSER_MAINTENANCE",
        browser.INSTANCE_ROUTED_ENV,
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(browser, "INSTANCE", "")


def test_an_unpinned_run_follows_the_item_into_its_instance(
    make_broker: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_broker(_gitlab_pair(_user(), _user(), glensk_inst=""))
    _unpinned(monkeypatch)
    assert browser._instance_route(_args("gl-admin")) == "admin"
    assert browser._instance_route(_args("gl-admin", "logged-in")) == "admin"
    assert browser._instance_route(_args("gl-glensk")) is None  # already here
    assert browser._instance_route(_args("gl", "logged-in")) is None  # alias → glensk
    assert browser._instance_route(_args("gl-admin", "logout")) is None
    assert browser._instance_route(_args("anthropic")) is None  # static
    seen: dict = {}

    def execve(exe: str, argv: list[str], env: dict) -> None:
        seen.update(exe=exe, argv=argv, env=env)
        raise SystemExit(0)

    monkeypatch.setattr(os, "execve", execve)
    monkeypatch.setattr(sys, "argv", ["browser.py", "login", "gl-admin"])
    with pytest.raises(SystemExit):
        browser._reexec_in_instance("admin")
    assert seen["env"]["CLAUDE_BROWSER_INSTANCE"] == "admin"
    assert seen["env"][browser.INSTANCE_ROUTED_ENV] == "1"
    assert seen["argv"][-2:] == ["login", "gl-admin"]


@pytest.mark.parametrize(
    ("env", "port"),
    [
        ({"CLAUDE_BROWSER_CDP_PORT": "9500"}, 9222),
        ({"CLAUDE_BROWSER_CACHE_DIR": "/nonexistent"}, 9222),
        ({"CLAUDE_BROWSER_INSTANCE_ROUTED": "1"}, 9222),
        ({}, 9500),  # --cdp-port
    ],
)
def test_a_pinned_run_is_never_rerouted(
    make_broker: Any, monkeypatch: pytest.MonkeyPatch, env: dict, port: int
) -> None:
    make_broker(_gitlab_pair(_user(), _user()))
    _unpinned(monkeypatch)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    assert browser._instance_route(_args("gl-admin", port=port)) is None
    monkeypatch.delenv("CLAUDE_BROWSER_CDP_PORT", raising=False)
    monkeypatch.setattr(browser, "INSTANCE", "alt")  # an explicit instance
    assert browser._instance_route(_args("gl-admin")) is None


# ---------------------------------------------------------------------------
# Aliases
# ---------------------------------------------------------------------------


def test_alias_resolves_to_its_default_member(
    make_broker: Any, result_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    del result_file
    make_broker(_gitlab_pair(_user(), _user()))
    site = browser._resolve_site("gl")
    assert site.name == "gl-glensk"
    assert "gl = gl-glensk" in capsys.readouterr().err
    assert browser._broker_canonical_site("gl") == "gl-glensk"
    assert browser._broker_canonical_site("gl-admin") == "gl-admin"
    assert browser._RESULT["alias"] == "gl"


def test_static_names_and_site_ids_win_over_an_alias(
    monkeypatch: pytest.MonkeyPatch, result_file: Path
) -> None:
    """Order: static names, broker site ids, aliases (S1 refuses such
    aliases; the client never lets one shadow anything either)."""
    del result_file
    sites = [
        {"site": "gl-glensk", "alias": "cscs", "refused": False},
        {"site": "gl-admin", "alias": "gl-test", "refused": False},
        {"site": "gl-test", "refused": False},
        {"site": "a1", "alias": "twice", "refused": False},
        {"site": "a2", "alias": "twice", "refused": False},
        {"site": "r1", "alias": "gone", "refused": True},
    ]
    monkeypatch.setattr(browser, "_broker_sites", lambda: sites)
    assert browser._resolve_site("cscs").name == "cscs"  # static
    assert browser._broker_canonical_site("gl-test") == "gl-test"  # a site id
    assert browser._broker_alias_target("twice") is None  # ambiguous
    assert browser._broker_alias_target("gone") is None  # refused
    with pytest.raises(SystemExit) as exc:
        browser._resolve_site("twice")
    assert exc.value.code == 2


def test_a_pre_ws5_broker_keeps_a_multi_account_item_closed(
    monkeypatch: pytest.MonkeyPatch, result_file: Path
) -> None:
    """New client, old broker (no identity_v, no identity fields): closed."""
    sites = [
        {"site": s, "cookie_hosts": [HOST], "check_url": CHECK, "sentinel": True}
        for s in ("gl-glensk", "gl-admin")
    ]
    monkeypatch.setattr(browser, "_broker_sites", lambda: sites)
    monkeypatch.setattr(
        browser,
        "_with_prepared_background_page",
        lambda *a: pytest.fail("no probe for an unprovable item"),
    )
    assert browser._broker_logged_in(9222, "gl-glensk") == 2
    assert _record(result_file, 2)["code"] == "identity_unproven"


# ---------------------------------------------------------------------------
# Review round 1: an explicit port pins the run; other commands' instances
# ---------------------------------------------------------------------------


def test_an_explicit_cdp_port_is_pinned(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["browser.py", "--cdp-port", "9222", "login", "x"])
    args = browser.parse_args()
    assert args.cdp_port_given is True and args.cdp_port == 9222
    _unpinned(monkeypatch)
    assert browser._instance_pinned(args)
    monkeypatch.setattr(sys, "argv", ["browser.py", "login", "x"])
    args = browser.parse_args()
    assert args.cdp_port_given is False
    assert args.cdp_port == browser.DEFAULT_CDP_PORT


@pytest.mark.parametrize(
    "case",
    [
        ("logged-in", None),
        ("login", None),
        # a disposable cache dir does not exempt a KNOWN instance's port
        ("login", "cache"),
    ],
)
def test_the_admin_item_on_the_default_port_is_refused(
    make_broker: Any,
    result_file: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    case: tuple,
) -> None:
    """`[CLAUDE_BROWSER_CACHE_DIR=x] CLAUDE_BROWSER_INSTANCE=admin browser.py
    --cdp-port 9222 login gl-admin` (a guided login's `_self_run` child, or by
    hand): the instance NAME matches, the PORT is the default browser's —
    wrong_instance, no challenge, nothing injected there. Runs under the
    conftest test guard (CLAUDE_BROWSER_TEST_NO_LAUNCH=1): no exemption."""
    cmd, cache = case
    fake = make_broker(_gitlab_pair(_user(), _user()))
    assert os.environ.get("CLAUDE_BROWSER_TEST_NO_LAUNCH") == "1"
    if cache:
        monkeypatch.setenv("CLAUDE_BROWSER_CACHE_DIR", str(result_file.parent))
    monkeypatch.setattr(browser, "INSTANCE", "admin")
    monkeypatch.setattr(
        browser, "_with_prepared_background_page", lambda *a: pytest.fail("no probe")
    )
    monkeypatch.setattr(
        browser, "_broker_fetch_inject", lambda *a, **k: pytest.fail("no inject")
    )
    browser._result_begin(cmd, "gl-admin", str(result_file))
    run = browser._broker_logged_in if cmd == "logged-in" else browser._broker_login
    assert run(9222, "gl-admin") == 2
    rec = _record(result_file, 2)
    assert (rec["phase"], rec["code"]) == ("precheck", "wrong_instance")
    assert f"CLAUDE_BROWSER_INSTANCE=admin browser.py {cmd} gl-admin" in (
        capsys.readouterr().err
    )
    assert "identity_challenge" not in fake.op_names()
    admin = browser._broker_site("gl-admin")
    assert browser._instance_gate("gl-admin", admin, 9224) is None  # its own port
    assert browser._instance_gate("gl-admin", admin, 41234) is None  # disposable


def test_a_sentinel_question_claims_no_account_but_keeps_the_instance(
    make_broker: Any,
    result_file: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    make_broker(_gitlab_pair(_user(), _user()))
    noted: list = []
    monkeypatch.setattr(browser, "_broker_note_session_age", lambda *a: noted.append(a))
    monkeypatch.setattr(browser, "_with_prepared_background_page", lambda *a: "valid")
    glensk = browser._broker_site("gl-glensk")
    assert browser._broker_check_entry(9222, "gl-glensk", glensk, sentinel="#x") == 0
    out = capsys.readouterr().out
    assert "sentinel present on gl-glensk" in out and "Logged into" not in out
    assert not noted
    admin = browser._broker_site("gl-admin")
    assert browser._broker_check_entry(9222, "gl-admin", admin, sentinel="#x") == 2
    assert _record(result_file, 2)["code"] == "wrong_instance"


def test_a_safari_import_keeps_the_identity_verdict(
    result_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    entry = {"site": "anibis", "check_url": "https://anibis.example/x"}
    monkeypatch.setattr(browser, "_safari_gated_entry", lambda _s, _p: (entry, 0))
    monkeypatch.setattr(browser, "_safari_site_cookies", lambda _s: ([object()], 0))
    monkeypatch.setattr(browser._safari, "has_session", lambda _s, _c: True)
    monkeypatch.setattr(browser, "_safari_inject", lambda *_a: 1)

    def check(*_a: Any, **_k: Any) -> int:
        browser._result_fail("client-proof", "wrong_account")
        return 2

    monkeypatch.setattr(browser, "_broker_check_entry", check)
    assert browser._import_safari(9222, "anibis", dry_run=False) == 2
    assert _record(result_file, 2)["code"] == "wrong_account"


def test_logout_and_guided_login_respect_the_instance(
    make_broker: Any,
    result_file: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """`logout gl-admin` from the default browser would delete a SIBLING's
    cookies there and drop the admin's broker profile; `assisted-login`
    would log the admin into the default browser. Both refuse first."""
    del result_file
    fake = make_broker(_gitlab_pair(_user(), _user()))
    monkeypatch.setattr(
        browser, "_broker_clear_cookies", lambda *a, **k: pytest.fail("no clear")
    )
    assert browser.cmd_broker_logout(9222, "gl-admin") == 2
    assert "logout" not in fake.op_names()
    assert "browser.py logout gl-admin" in capsys.readouterr().err
    monkeypatch.setattr(browser, "_is_up", lambda _p: pytest.fail("no browser start"))
    req = browser.GuidedRequest("gl-admin")
    assert browser._assisted_precheck(None, 9222, req) == 2
    assert "browser.py assisted-login gl-admin" in capsys.readouterr().err


def test_a_guided_login_never_runs_ungated(
    make_broker: Any,
    result_file: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A non-static site whose instance cannot be confirmed — an alias, an
    unlisted name, a broker that does not answer — is refused, exit 2."""
    del result_file
    make_broker(_gitlab_pair(_user(), _user()))
    monkeypatch.setattr(browser, "_is_up", lambda _p: pytest.fail("no browser start"))
    alias = browser.GuidedRequest("gl")
    assert browser._assisted_precheck(None, 9222, alias) == 2
    assert "is an alias" in capsys.readouterr().err
    unlisted = browser.GuidedRequest("nowhere")
    assert browser._assisted_precheck(None, 9222, unlisted) == 2
    assert "not listed by the login broker" in capsys.readouterr().err
    browser._BROKER_SITES_CACHE.clear()
    monkeypatch.setenv("LOGIN_BROKER_SOCKET", "/nonexistent/broker.sock")
    down = browser.GuidedRequest("gl-glensk")
    assert browser._assisted_precheck(None, 9222, down) == 2
    assert "cannot confirm its browser instance" in capsys.readouterr().err
