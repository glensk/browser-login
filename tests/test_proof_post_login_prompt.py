"""A post-login prompt on the CHECK page is answered by the proof (tp#1472).

Live evidence (2026-10-31, infomaniak): the broker's login passed the
password and the OTP step and reached ``manager.infomaniak.com/…/ng/home``;
the proof then reloaded the check page and the manager redirected it to
``…/ng/security-check`` — "Verification of your back-up email address" with
"Confirm" and "Verify later". No sentinel there, so the proof said
``not-logged-in`` and the login counted as a post-submit failure.

``recipes.check_proof_reason`` now answers a known post-login prompt on the
check page (``page_state.POST_LOGIN_PROMPTS``: "Verify later", never
"Confirm") and proves the check page again, at most
``MAX_POST_LOGIN_PROMPTS`` times. The fixture reproduces the redirect.

Drives a disposable headless Chromium (never browser.py's shared one); skipped
when Playwright's Chromium is missing.
"""

from __future__ import annotations

# pylint: disable=missing-function-docstring,missing-class-docstring,import-error
# pylint: disable=wrong-import-position,invalid-name
import contextlib
import http.server
import sys
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from broker import recipes, vault  # noqa: E402

SENTINEL = "wc-user-panel"

_HOME = (
    "<html><head><title>Admin console</title></head><body>"
    "<wc-user-panel>Albert</wc-user-panel><h1>Home</h1></body></html>"
)
_PROMPT = (
    "<html><head><title>Administration console</title></head><body>"
    "<h2>Verification of your back-up email address</h2>"
    "<p>Please confirm or update your backup email address</p>"
    "<input type=email name=email value='backup@example.org'>"
    "<button id=confirm onclick=\"location.href='/confirm'\">Confirm</button>"
    "<a href='/later'>Verify later</a></body></html>"
)


class _Manager(http.server.BaseHTTPRequestHandler):
    """``/home`` redirects to ``/security-check`` until the prompt was
    postponed (``/later``) — or always, with ``sticky``."""

    sticky = False
    postponed = False
    prompt_origin = ""  # where /home sends the prompt ("" = this server)
    hits: list[str] = []

    def log_message(self, *args: Any) -> None:
        return

    def _send(self, code: int, body: str = "", location: str = "") -> None:
        self.send_response(code)
        if location:
            self.send_header("Location", location)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self) -> None:  # noqa: N802
        cls = type(self)
        cls.hits.append(self.path)
        if self.path.startswith("/home"):
            if cls.postponed and not cls.sticky:
                self._send(200, _HOME)
            else:
                self._send(302, location=cls.prompt_origin + "/security-check")
        elif self.path.startswith("/security-check"):
            self._send(200, _PROMPT)
        elif self.path.startswith("/later"):
            cls.postponed = True
            self._send(302, location="/home")
        elif self.path.startswith("/confirm"):
            self._send(200, "<html><body>confirmed</body></html>")
        else:
            self._send(404, "nope")


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


@contextlib.contextmanager
def _servers(*, sticky: bool, n: int = 1) -> Iterator[list[str]]:
    _Manager.sticky, _Manager.postponed, _Manager.hits = sticky, False, []
    _Manager.prompt_origin = ""
    srvs = [
        http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Manager) for _ in range(n)
    ]
    for srv in srvs:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield [f"http://127.0.0.1:{srv.server_port}" for srv in srvs]
    finally:
        for srv in srvs:
            srv.shutdown()
            srv.server_close()


@contextlib.contextmanager
def _page() -> Iterator[Any]:
    from playwright.sync_api import (  # pylint: disable=import-outside-toplevel
        sync_playwright,
    )

    with sync_playwright() as pw:
        b = pw.chromium.launch(headless=True)
        try:
            yield b.new_page()
        finally:
            b.close()


def _item(origin: str) -> vault.SiteItem:
    fields = {
        "agent_site": "managerfix",
        "agent_fill_origins": "http://127.0.0.1:9",  # the login origin
        "agent_check_url": origin + "/home",
        "agent_logged_in_selector": SENTINEL,
    }
    return vault.site_item_from_json(
        {
            "name": "manager fixture",
            "fields": [{"name": k, "value": v} for k, v in fields.items()],
        },
        dev=True,  # the fixture serves http on 127.0.0.1
    )


@pytest.mark.launches_chrome
@CHROME
def test_backup_email_prompt_is_postponed_and_the_check_page_proven() -> None:
    with _servers(sticky=False) as (origin,), _page() as page:
        item = _item(origin)
        assert not item.refused, item.refused
        assert recipes.check_proof_reason(page, item, dev=True, wait_s=2) == (
            recipes.VALID,
            "",
        )
    assert "/later" in _Manager.hits
    assert "/confirm" not in _Manager.hits  # never vouches for the address


@pytest.mark.launches_chrome
@CHROME
def test_a_prompt_that_keeps_coming_back_is_answered_a_bounded_number_of_times() -> (
    None
):
    with _servers(sticky=True) as (origin,), _page() as page:
        item = _item(origin)
        assert not item.refused, item.refused
        assert recipes.check_proof_reason(page, item, dev=True, wait_s=1) == (
            recipes.INVALID,
            "not-logged-in",
        )
    assert _Manager.hits.count("/later") == recipes.MAX_POST_LOGIN_PROMPTS
    assert "/confirm" not in _Manager.hits


@pytest.mark.launches_chrome
@CHROME
def test_no_click_off_the_proof_origins() -> None:
    # the check page redirects to the prompt on ANOTHER origin, off the item's
    # proof origins: the prompt is not the site's to answer
    with _servers(sticky=False, n=2) as (origin, other), _page() as page:
        _Manager.prompt_origin = other
        item = _item(origin)
        assert not item.refused, item.refused
        answer, reason = recipes.check_proof_reason(page, item, dev=True, wait_s=1)
        assert (answer, reason) != (recipes.VALID, "")
    assert "/later" not in _Manager.hits
