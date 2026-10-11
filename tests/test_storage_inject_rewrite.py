"""Storage injection survives an app that rewrites its own session keys.

Live evidence (2026-10-11, navidrome-albert): the broker logged in and
exported 8 localStorage keys, the client reported "wrote 0 of 8 storage
key(s)" and rolled the injection back. Root cause: the read-back proof of
`_broker_write_storage` compared every key's value with the bundle AFTER the
page had loaded, i.e. after the app had run. Navidrome's server answers every
API call with a fresh JWT (`X-ND-Authorization`, `JWTRefresher`) and its UI
stores it under ``token`` at once — so the read-back saw a different (valid)
token and called the write failed. Every app that renews a stored token on
boot (Home Assistant's ``hassTokens``, Jellyfin's ``jellyfin_credentials``,
Kavita's ``kavita-user``, Audiobookshelf) hits the same wall; the CSCS expiry
was special-cased (``VOLATILE_STORAGE_KEYS``) instead of fixing the rule.

The proof is now two-part: the init script records at document start, before
any app code, that every key read back equal (the write landed), and after
load every key must still be PRESENT (the app did not throw the session
away). Whether the session is valid stays the client proof's job.

The fixture SPAs below are served through Playwright routes in a throwaway
headless Chromium — never the shared browser, no real site. Values are
generated per test.
"""

from __future__ import annotations

# pylint: disable=protected-access,missing-function-docstring,missing-class-docstring
# pylint: disable=import-error,wrong-import-position,redefined-outer-name
# pylint: disable=duplicate-code
import contextlib
import importlib.util
import json
import secrets
import sys
import urllib.parse
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


browser = _load("browser_storage_rewrite_test", REPO / "bin" / "browser.py")


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

MUSIC = "https://music.fixture.test"
ELSEWHERE = "https://idp.fixture.test"
PORTAL = browser.CSCS_PORTAL_ORIGIN
EXPIRES_KEY = browser.BROKER_CSCS_EXPIRES_KEY
TOKEN_KEY = browser.BROKER_CSCS_TOKEN_KEY
# Navidrome's eight keys (dashes included), as the sites list names them.
ND_KEYS = (
    "token",
    "userId",
    "username",
    "name",
    "role",
    "subsonic-salt",
    "subsonic-token",
    "is-authenticated",
)

# A Navidrome-like SPA: a valid session renews its token at once (sync, like a
# boot call) and again after an API round trip; a rejected one is thrown away
# entirely (Navidrome's removeItems on 401).
_ND_APP_JS = """(async () => {
  const keys = __KEYS__;
  const tok = localStorage.getItem('token');
  if (!tok || localStorage.getItem('is-authenticated') !== 'true') return;
  const r = await fetch('/api/keepalive', {headers: {'X-ND-Authorization': tok}});
  if (r.status === 401) { for (const k of keys) localStorage.removeItem(k); return; }
  localStorage.setItem('token', r.headers.get('X-ND-Authorization'));
  document.getElementById('app').textContent = 'music ' + localStorage.getItem('name');
})();
if (localStorage.getItem('is-authenticated') === 'true' && __ROTATE_SYNC__)
  localStorage.setItem('token', 'renewed-' + Math.random().toString(36).slice(2));
"""


@dataclass
class Music:
    """Server state of the fixture music app."""

    tokens: set[str] = field(default_factory=set)
    rotate_sync: bool = True
    root_redirect: str = "/app/"  # Navidrome: `/` -> /app/
    renewed: list[str] = field(default_factory=list)

    def issue(self) -> str:
        token = "jwt-" + secrets.token_urlsafe(16)
        self.tokens.add(token)
        return token

    def handle(self, route: Any) -> None:
        url = urllib.parse.urlsplit(route.request.url)
        origin = f"{url.scheme}://{url.netloc}"
        if origin == ELSEWHERE:
            _html(route, "<html><body>idp</body></html>")
        elif url.path == "/":
            # Navidrome answers `/` with a 302 to /app/; a fulfilled 3xx is not
            # followed through routes, so the fixture redirects in-page (the
            # init script then runs on both documents — the harder case).
            _html(route, f"<script>location.replace('{self.root_redirect}')</script>")
        elif url.path == "/api/keepalive":
            sent = route.request.headers.get("x-nd-authorization", "")
            if sent not in self.tokens:
                route.fulfill(status=401, body="")
                return
            fresh = self.issue()
            self.renewed.append(fresh)
            route.fulfill(
                status=200,
                body="{}",
                content_type="application/json",
                headers={
                    "X-ND-Authorization": fresh,
                    "Access-Control-Expose-Headers": "X-ND-Authorization",
                },
            )
        else:
            app = _ND_APP_JS.replace("__KEYS__", json.dumps(list(ND_KEYS))).replace(
                "__ROTATE_SYNC__", "true" if self.rotate_sync else "false"
            )
            _html(
                route,
                f"<html><body><div id=app>loading</div><script>{app}</script>"
                "</body></html>",
            )


# A CSCS-portal-like page: /profile/ rewrites the recorded expiry (the app's
# own, ``VOLATILE_STORAGE_KEYS``) and keeps the token; `/` must never load.
_PORTAL_APP_JS = """
if (location.pathname === '/') location.replace('__ELSEWHERE__/');
else if (localStorage.getItem('__TOKEN__'))
  localStorage.setItem('__EXPIRES__', new Date(Date.now() + 3600e3).toISOString());
"""


def _portal_handle(route: Any) -> None:
    url = urllib.parse.urlsplit(route.request.url)
    if f"{url.scheme}://{url.netloc}" == ELSEWHERE:
        _html(route, "<html><body>idp</body></html>")
        return
    app = (
        _PORTAL_APP_JS.replace("__ELSEWHERE__", ELSEWHERE)
        .replace("__TOKEN__", TOKEN_KEY)
        .replace("__EXPIRES__", EXPIRES_KEY)
    )
    _html(route, f"<html><body><script>{app}</script></body></html>")


def _html(route: Any, body: str) -> None:
    route.fulfill(
        status=200,
        body=body,
        content_type="text/html",
        headers={"cache-control": "no-store"},
    )


def _under(origin: str) -> Any:
    """A route matcher for every URL of `origin` (`/` included — the glob
    ``origin/**`` misses the bare root)."""
    return lambda url: url.startswith(origin + "/")


@pytest.fixture
def music() -> Music:
    return Music()


@contextlib.contextmanager
def _client(
    music: Music, monkeypatch: pytest.MonkeyPatch
) -> Iterator[tuple[Any, list[str]]]:
    """`_with_prepared_background_page` on a routed throwaway context, the way
    `_background_page_run` drives it: prepare on the blank tab, goto
    (domcontentloaded), wait for ``load`` — the app has run — then `fn`.
    Yields (the context, the URLs loaded)."""
    from playwright.sync_api import (  # pylint: disable=import-outside-toplevel
        Error as PlaywrightError,
    )
    from playwright.sync_api import (  # pylint: disable=import-outside-toplevel
        sync_playwright,
    )

    loaded: list[str] = []
    with sync_playwright() as pw:
        chrome = pw.chromium.launch(headless=True)
        try:
            ctx = chrome.new_context()
            ctx.route(_under(MUSIC), music.handle)
            ctx.route(_under(ELSEWHERE), music.handle)
            ctx.route(_under(PORTAL), _portal_handle)

            def run(_port: int, url: str, prepare: Any, fn: Any) -> Any:
                page = ctx.new_page()
                try:
                    if prepare is not None:
                        prepare(page)
                    loaded.append(url)
                    page.goto(url, wait_until="domcontentloaded")
                    with contextlib.suppress(PlaywrightError):
                        page.wait_for_load_state("load", timeout=10_000)
                    with contextlib.suppress(PlaywrightError):
                        page.wait_for_load_state("networkidle", timeout=3_000)
                    return fn(page)
                except Exception:  # pylint: disable=broad-exception-caught
                    return None  # the real runner's contract
                finally:
                    browser._BG_NOCACHE.pop(id(page), None)
                    page.close()

            monkeypatch.setattr(browser, "_with_prepared_background_page", run)
            yield ctx, loaded
        finally:
            chrome.close()


def _storage(ctx: Any, origin: str, keys: list[str]) -> dict[str, str | None]:
    """The origin's values for `keys`, read on a page where no app runs."""
    page = ctx.new_page()
    try:
        page.route(_under(origin), lambda r: _html(r, "<html></html>"))
        page.goto(origin + "/static-probe")
        return dict(
            page.evaluate("ks => ks.map(k => [k, localStorage.getItem(k)])", keys)
        )
    finally:
        page.close()


def _nd_bundle(music: Music, origin: str = MUSIC) -> dict[str, Any]:
    kv = {
        "token": music.issue(),
        "userId": "u-" + secrets.token_hex(4),
        "username": "fixture-user",
        "name": "Fixture User",
        "role": "regular",
        "subsonic-salt": secrets.token_hex(3),
        "subsonic-token": secrets.token_hex(16),
        "is-authenticated": "true",
    }
    return {"storage": {origin: kv}, "storage_keys": {origin: list(kv)}}


# ---------------------------------------------------------------------------
# generic (non-CSCS) site
# ---------------------------------------------------------------------------


@pytest.mark.launches_chrome
@CHROME
@pytest.mark.parametrize("rotate_sync", [True, False])
def test_an_app_that_renews_its_token_still_counts_as_written(
    music: Music, monkeypatch: pytest.MonkeyPatch, rotate_sync: bool
) -> None:
    """The navidrome-albert regression: 8 keys, the app renews `token` on
    boot (sync) or after its first API call — all 8 are written."""
    music.rotate_sync = rotate_sync
    bundle = _nd_bundle(music)
    kv = bundle["storage"][MUSIC]
    with _client(music, monkeypatch) as (ctx, loaded):
        touched: list[str] = []
        n = browser._broker_write_storage(0, bundle, touched)
        assert n == len(ND_KEYS) == browser._broker_bundle_keys(bundle)
        assert touched == [MUSIC] and loaded == [MUSIC + "/"]
        after = _storage(ctx, MUSIC, list(ND_KEYS))
    assert all(after[k] is not None for k in ND_KEYS)
    assert after["token"] != kv["token"]  # the app really renewed it
    assert {k: after[k] for k in ND_KEYS if k != "token"} == {
        k: v for k, v in kv.items() if k != "token"
    }


@pytest.mark.launches_chrome
@CHROME
def test_an_app_that_throws_the_session_away_is_not_written(
    music: Music, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Still fail-closed: a rejected token (401 -> the app removes every
    key) is no write, and no value reaches the output."""
    music.rotate_sync = False
    bundle = _nd_bundle(music)
    music.tokens.clear()  # revoked between export and injection
    with _client(music, monkeypatch):
        assert browser._broker_write_storage(0, bundle) == 0
    out = capsys.readouterr()
    for value in bundle["storage"][MUSIC].values():
        if len(value) > 8:
            assert value not in out.out + out.err


@pytest.mark.launches_chrome
@CHROME
def test_a_static_app_keeps_every_value_dashed_and_json_keys_included(
    music: Music, monkeypatch: pytest.MonkeyPatch
) -> None:
    other = "https://books.fixture.test"
    kv_json = {
        "kavita-user": json.dumps({"token": "t-" + secrets.token_hex(8), "a": [1]}),
        "_deviceId2": secrets.token_hex(6),
    }
    bundle = _nd_bundle(music)
    bundle["storage"][MUSIC]["is-authenticated"] = "false"  # app stays inert
    bundle["storage"][other] = kv_json
    with _client(music, monkeypatch) as (ctx, _loaded):
        ctx.route(_under(other), lambda r: _html(r, "<html>static</html>"))
        assert browser._broker_write_storage(0, bundle) == len(ND_KEYS) + 2
        assert _storage(ctx, other, list(kv_json)) == kv_json
        assert _storage(ctx, MUSIC, list(ND_KEYS)) == bundle["storage"][MUSIC]


@pytest.mark.launches_chrome
@CHROME
def test_a_redirect_off_the_origin_writes_nothing(
    music: Music, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The app sends the tab to another origin: no proof there (0 written),
    nothing leaks to that origin, and the bundle's origin is reported as
    touched (its first document may have been written) for the rollback."""
    music.root_redirect = ELSEWHERE + "/login"
    bundle = _nd_bundle(music)
    with _client(music, monkeypatch) as (ctx, _loaded):
        touched: list[str] = []
        assert browser._broker_write_storage(0, bundle, touched) == 0
        assert touched == [MUSIC]
        assert _storage(ctx, ELSEWHERE, ["token"]) == {"token": None}


# ---------------------------------------------------------------------------
# CSCS (/profile/, the app-owned expiry)
# ---------------------------------------------------------------------------


@pytest.mark.launches_chrome
@CHROME
def test_cscs_writes_all_keys_on_profile(
    music: Music, monkeypatch: pytest.MonkeyPatch
) -> None:
    kv = {
        TOKEN_KEY: secrets.token_hex(20),
        "waldur/auth/method": "keycloak",
        EXPIRES_KEY: "2000-01-01T00:00:00+00:00",  # stale: the app rewrites it
    }
    bundle = {"storage": {PORTAL: kv}, "storage_keys": {PORTAL: list(kv)}}
    with _client(music, monkeypatch) as (ctx, loaded):
        assert browser._broker_write_storage(0, bundle) == 3
        assert loaded == [PORTAL + "/profile/"]
        after = _storage(ctx, PORTAL, list(kv))
    assert after[TOKEN_KEY] == kv[TOKEN_KEY]
    assert after[EXPIRES_KEY] not in (None, kv[EXPIRES_KEY])


# ---------------------------------------------------------------------------
# the proof scripts themselves (no browser)
# ---------------------------------------------------------------------------


def test_the_init_script_records_its_own_read_back() -> None:
    src = browser._broker_storage_init_script(MUSIC, {"a-b": "1"})
    assert browser.BROKER_STORAGE_PROOF_VAR in src
    assert json.dumps(MUSIC) in src and json.dumps({"a-b": "1"}) in src
    assert "__ORIGIN__" not in src and "__KV__" not in src
