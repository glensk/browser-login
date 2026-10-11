"""The logged-in proof of a hash-route SPA (Portainer ``#!/home``, Jellyfin
``/web/#/home``) on a real Chromium.

Live evidence (2026-10-11, portainer-ds218): the broker's login succeeded, but
the proof that followed on the same page did ``goto(check_url)`` where the
check URL differed from the page's URL only after ``#``. Chromium does a
same-document navigation then, Playwright's ``goto`` answers None (no
Response, status unknown) and the strict proof called it ``indeterminate``
before it looked at the sentinel. ``recipes.load_document`` loads the check
page as a fresh document (via ``about:blank``) instead.

Drives a disposable headless Chromium (never browser.py's shared one); skipped
when Playwright's Chromium is missing.
"""

from __future__ import annotations

# pylint: disable=missing-function-docstring,import-error,wrong-import-position
import contextlib
import functools
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

SENTINEL = "a[href='#!/home']"

# A tiny ui-router-like app: `#!/home` shows the sentinel when the token is
# set, every other route (or no token) the login form.
_INDEX = """<!doctype html><html><head><title>hash fixture</title></head>
<body><div id=root></div><script>
function render() {
  const root = document.getElementById('root');
  const token = localStorage.getItem('token');
  if (location.hash === '#!/home' && token) {
    root.innerHTML = '<nav><a href="#!/home">Home</a></nav><h1>Environments</h1>';
  } else {
    root.innerHTML = '<form><input type=text name=u><input type=password name=p>'
      + '<button type=submit>Login</button></form>';
  }
}
window.addEventListener('hashchange', render);
render();
</script></body></html>"""


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
def _server(root: Path) -> Iterator[str]:
    (root / "index.html").write_text(_INDEX, encoding="utf-8")
    handler = functools.partial(
        http.server.SimpleHTTPRequestHandler, directory=str(root)
    )
    setattr(handler, "log_message", lambda *_a: None)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{srv.server_port}"
    finally:
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
        "agent_site": "hashfix",
        "agent_fill_origins": origin,
        "agent_login_url": origin + "/#!/auth",
        "agent_check_url": origin + "/#!/home",
        "agent_logged_in_selector": SENTINEL,
    }
    return vault.site_item_from_json(
        {
            "name": "hash fixture",
            "fields": [{"name": k, "value": v} for k, v in fields.items()],
        },
        dev=True,  # the fixture serves http on 127.0.0.1
    )


@pytest.mark.launches_chrome
@CHROME
def test_hash_route_check_page_is_proven_after_a_login(tmp_path: Path) -> None:
    with _server(tmp_path) as origin, _page() as page:
        item = _item(origin)
        assert not item.refused, item.refused
        assert page.goto(item.login_url, wait_until="domcontentloaded").status == 200
        page.evaluate("localStorage.setItem('token', 'x')")  # "logged in"
        # Chromium: a goto that changes only the fragment has no Response —
        # the status the strict proof needs is unknown
        assert page.goto(item.check_url, wait_until="domcontentloaded") is None
        page.evaluate("location.hash = '#!/auth'")  # where a login ends
        assert recipes.check_proof_reason(page, item, dev=True, wait_s=3) == (
            recipes.VALID,
            "",
        )
        # logged out: the fresh load answers 200 and the sentinel is absent
        page.evaluate("localStorage.removeItem('token'); location.hash = '#!/auth'")
        assert recipes.check_proof_reason(page, item, dev=True, wait_s=1) == (
            recipes.INVALID,
            "not-logged-in",
        )
