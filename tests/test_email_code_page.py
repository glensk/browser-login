"""A code page whose code came by e-mail is named as such (tp#1127).

Namecheap's "Device Verification" e-mails a code; the broker reported it as
"otp required but the item has no TOTP seed", which sent the reader looking for
a missing seed. ``recipes.email_code_page`` tells the two apart, answered in the
page as a boolean.
"""

from __future__ import annotations

import secrets
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from broker import recipes, vault  # noqa: E402  # pylint: disable=wrong-import-position

NAMECHEAP = (
    "<nav>Domains Hosting Email Account</nav><h3>Device Verification</h3>"
    "<p><b>UPDATE</b> We sent a verification code to the <b>email address</b>"
    " listed below for your <b>account fixture</b>. It may take a few minutes"
    " to arrive.</p><label>Verification Code<input id=otp></label>"
)
TOTP = (
    "<nav>Domains Hosting Email Account</nav>"
    "<p>Enter the 6-digit code from your authenticator app.</p>"
    "<input id=otp><footer>Questions? Contact us by email.</footer>"
)
INBOX = "<p>Check your inbox for the code we just sent.</p><input id=otp>"


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


@pytest.fixture(scope="module", name="page")
def _page() -> Iterator[Any]:
    from playwright.sync_api import (  # pylint: disable=import-outside-toplevel
        sync_playwright,
    )

    with sync_playwright() as pw:
        chrome = pw.chromium.launch(headless=True)
        try:
            yield chrome.new_page()
        finally:
            chrome.close()


@pytest.mark.launches_chrome
@CHROME
@pytest.mark.parametrize(
    ("html", "emailed"), [(NAMECHEAP, True), (INBOX, True), (TOTP, False)]
)
def test_an_emailed_code_is_told_from_an_authenticator(
    page: Any, html: str, emailed: bool
) -> None:
    page.set_content(html)
    assert recipes.email_code_page(page) is emailed


@pytest.mark.launches_chrome
@CHROME
def test_no_seed_on_an_email_code_page_says_so(page: Any) -> None:
    page.set_content(NAMECHEAP)
    secret = vault.Secret(username="u", password=secrets.token_hex(4))
    with pytest.raises(recipes.NeedsHuman, match="e-mailed a verification code"):
        recipes._fill_otp(  # pylint: disable=protected-access
            page, None, secret, ["https://www.namecheap.com"], dev=False
        )


def test_an_unreadable_page_is_not_an_email_code_page() -> None:
    class _Broken:
        def evaluate(self, *_a: Any) -> Any:
            raise RuntimeError("detached")

    assert recipes.email_code_page(_Broken()) is False
