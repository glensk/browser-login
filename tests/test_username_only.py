"""Username-only logins (``agent_login_mode=username-only``): Mullvad.

Mullvad's login (``https://mullvad.net/en/account/login``, read 2026-10-11) is
ONE field, ``<input type=password name=account_number inputmode=numeric>``,
plus a "Show" toggle (``type=button``) and a ``Log in`` submit button; the
account number is the whole credential. The vault item keeps it as its
USERNAME and has no password, so the broker failed at phase ``vault`` ("the
item has no password") with a hint about collection permissions only.

Tested here:

* the vault field ``agent_login_mode`` (``password`` default, ``username-only``),
  its refusals, and the secret it yields (the username carried as the secret);
* the new ``no_password`` / ``no_username`` errors and their fixed texts;
* the secret ops never expose a username-only login item;
* diagnostics mask the account number, also when the page shows it in groups,
  and no failure screenshot is ever taken of such a login;
* the real runner against a Mullvad-like fixture (real headless Chromium): the
  account number alone is typed and submitted with every submit-safety rule
  (fail-closed buttons, tripwire, submit marker), proven by the sentinel;
* nothing changes for password items.

Account numbers are generated at run time.
"""
# pylint: disable=too-many-lines,duplicate-code

from __future__ import annotations

# pylint: disable=protected-access,missing-function-docstring,missing-class-docstring
# pylint: disable=import-error,wrong-import-position,too-few-public-methods
import email.parser
import email.policy
import functools
import http.server
import json
import secrets
import sys
import threading
import urllib.parse
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from broker import daemon, limiter, page_state, phases, recipes, vault  # noqa: E402


def _account() -> str:
    """A random 16-digit account number (never a real one)."""
    return "".join(secrets.choice("0123456789") for _ in range(16))


def _grouped(number: str) -> str:
    return " ".join(number[i : i + 4] for i in range(0, len(number), 4))


ACCOUNT = _account()
SITE = "mullfix"
SENTINEL = 'a[href$="/account/devices"]'
PASSWORD = secrets.token_urlsafe(18)


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


def _raw(
    site: str = "mullvad",
    *,
    username: str | None = ACCOUNT,
    password: str | None = None,
    **fields: str,
) -> dict[str, Any]:
    base = {
        "agent_site": site,
        "agent_fill_origins": "https://mullvad.net",
        "agent_check_url": "https://mullvad.net/en/account",
        "agent_login_url": "https://mullvad.net/en/account/login",
        "agent_logged_in_selector": SENTINEL,
        "agent_login_mode": "username-only",
    }
    login: dict[str, Any] = {}
    if username is not None:
        login["username"] = username
    if password is not None:
        login["password"] = password
    merged = {**base, **fields}
    return {
        "id": f"id-{site}",
        "name": site,
        "login": login,
        "fields": [{"name": k, "value": v} for k, v in merged.items() if v != ""],
    }


# ---------------------------------------------------------------------------
# A. the vault field and the secret it yields
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "want"),
    [
        ("", "password"),
        ("password", "password"),
        ("username-only", "username-only"),
        ("  Username-Only ", "username-only"),
    ],
)
def test_login_mode_values(raw: str, want: str) -> None:
    assert vault.login_mode(raw) == (want, "")


@pytest.mark.parametrize("raw", ["username", "account", "usernameonly", "true"])
def test_a_bad_login_mode_is_refused(raw: str) -> None:
    item = vault.site_item_from_json(_raw(agent_login_mode=raw))
    assert item.refused and "agent_login_mode" in item.refused


def test_username_only_item() -> None:
    item = vault.site_item_from_json(_raw())
    assert item.refused is None
    assert item.login_mode == "username-only"
    assert item.public()["username_only"] is True
    assert ACCOUNT not in json.dumps(item.public())


def test_username_only_without_a_username_says_no_username(tmp_path: Path) -> None:
    """Not refused at parse time: the login reaches the fresh secret read and
    answers the typed `no_username` (phase vault), not a generic refusal."""
    assert vault.site_item_from_json(_raw(username="")).refused is None
    brk = _broker(tmp_path, _raw(username=""))
    resp = brk._login_request("mullvad", {})
    assert resp["ok"] is False and resp["error"] == "no_username"
    assert resp["phase"] == "vault" and resp["submitted"] is False


def test_username_only_needs_the_generic_recipe() -> None:
    raw = _raw("cscs", agent_fill_origins="https://auth.cscs.ch")
    item = vault.site_item_from_json(raw)
    assert item.refused and "generic login recipe" in item.refused


def test_the_secret_is_the_username_carried_as_the_credential() -> None:
    secret = vault.secret_from_json(_raw(password=PASSWORD))
    assert secret.mode == vault.USERNAME_ONLY
    assert secret.password == ACCOUNT  # the credential every masking path knows
    assert secret.username == ""  # never typed or shown as a user name
    assert ACCOUNT not in repr(secret) and PASSWORD not in repr(secret)
    assert secret.identity == ACCOUNT  # WHICH account: the number itself
    plain = vault.Secret(username="someone@example.org", password=PASSWORD)
    assert plain.identity == "someone@example.org"


def test_a_username_only_secret_without_a_username_fails() -> None:
    with pytest.raises(vault.MissingSecret) as exc:
        vault.secret_from_json(_raw(username="   "))
    assert exc.value.code == "no_username"


def test_no_password_names_username_only_and_the_permission() -> None:
    raw = _raw(agent_login_mode="", password="")
    with pytest.raises(vault.MissingSecret) as exc:
        vault.secret_from_json(raw)
    assert exc.value.code == "no_password"
    text = str(exc.value)
    assert "agent_login_mode=username-only" in text
    assert "'Can view'" in text and "except passwords" in text
    assert ACCOUNT not in text


def test_default_items_are_unchanged() -> None:
    raw = _raw(agent_login_mode="", username="someone@example.org", password=PASSWORD)
    item = vault.site_item_from_json(raw)
    assert item.refused is None and item.login_mode == "password"
    assert item.public()["username_only"] is False
    secret = vault.secret_from_json(raw)
    assert secret.mode == "password"
    assert (secret.username, secret.password) == ("someone@example.org", PASSWORD)


def test_new_codes_have_fixed_text_and_phase() -> None:
    for code in ("no_password", "no_username"):
        assert code in phases.CODE_TEXT
        assert phases.phase_for_error(code) == "vault"
    assert "username-only" in phases.text("vault", "no_password")


class _Runner:
    """Asks for the secret like the real runner, never opens a page."""

    def __call__(
        self, _item: vault.SiteItem, get_secret: Any
    ) -> dict[str, Any]:  # pragma: no cover - raises
        get_secret()
        raise AssertionError("the secret read must fail")


def _broker(tmp_path: Path, *items: dict[str, Any]) -> daemon.Broker:
    path = tmp_path / "vault.json"
    path.write_text(json.dumps(list(items)))
    return daemon.Broker(
        vault.FixtureVault(path, dev=True),
        limiter.Limiter(tmp_path / "limiter.json", 0, 100, 100),
        tmp_path / "home",
        runner=_Runner(),
        clock=lambda: 10.0,
    )


def test_a_login_without_a_password_says_why(tmp_path: Path) -> None:
    brk = _broker(tmp_path, _raw(agent_login_mode="", password=""))
    resp = brk._login_request("mullvad", {})
    assert resp["ok"] is False and resp["error"] == "no_password"
    assert resp["phase"] == "vault" and resp["submitted"] is False
    assert "agent_login_mode=username-only" in resp["detail"]


def test_the_fingerprint_op_is_removed_for_a_username_only_item(
    tmp_path: Path,
) -> None:
    """tp#965 S1: no length, no hash — the op answers `removed`."""
    brk = _broker(tmp_path, _raw())
    fp = brk.handle({"op": "fingerprint", "site": "mullvad"})
    assert fp["ok"] is False and fp["error"] == "removed"
    assert "password_check" not in fp and "len=" not in json.dumps(fp)
    assert ACCOUNT not in json.dumps(fp)


# ---------------------------------------------------------------------------
# B. the secret ops never expose a username-only login item
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("mode", "refused"),
    [
        ("username-only", vault.USERNAME_ONLY_SECRET),
        ("USERNAME-ONLY", vault.USERNAME_ONLY_SECRET),
        ("maybe", "cannot tell"),  # malformed: fail closed
        ("password", None),
        ("", None),
    ],
)
def test_secret_ops_refuse_a_username_only_item(mode: str, refused: str | None) -> None:
    raw = {
        "id": "id-x",
        "name": "mullvad copy",
        "login": {"username": ACCOUNT, "password": PASSWORD},
        "fields": [
            {"name": "agent_secret_fields", "value": "username"},
            *([{"name": "agent_login_mode", "value": mode}] if mode else []),
        ],
    }
    item, values = vault.secret_item_from_json(raw, 1)
    if refused:
        assert values is None and refused in (item.refused or "")
        assert ACCOUNT not in json.dumps(item.public())
    else:
        assert item.refused is None and values is not None


def test_secret_values_of_a_username_only_copy_are_unreachable(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    copy = _raw(password=PASSWORD, agent_secret_fields="username")
    path.write_text(json.dumps({"logins": [], "secrets": [copy]}))
    fv = vault.FixtureVault(path, dev=True)
    listed = fv.secret_items()
    assert [it.refused for it in listed] == [vault.USERNAME_ONLY_SECRET]
    with pytest.raises(vault.VaultError):
        fv.secret_values(listed[0].secret_id)


# ---------------------------------------------------------------------------
# C. masking
# ---------------------------------------------------------------------------


def test_redaction_masks_a_grouped_account_number() -> None:
    secret = vault.Secret(username="", password=ACCOUNT, mode=vault.USERNAME_ONLY)
    for shown in (ACCOUNT, _grouped(ACCOUNT), "-".join(_grouped(ACCOUNT).split())):
        text = page_state._redact(f"Account {shown} not found", secret)
        assert text == "Account *** not found", text


class _DiagPage:
    """A failure page that shows the account number at the 200-char cut and
    in its URL path."""

    def __init__(self, number: str) -> None:
        self.number = number
        self.url = f"https://mullvad.net/en/account/{number}/devices?x=1"

    def title(self) -> str:
        return "x" * 110 + self.number

    def evaluate(self, _js: str, raw: int = 0) -> dict[str, Any]:
        text = "y" * 190 + f"Account {_grouped(self.number)} not found"
        return {
            "messages": [text[:raw]],
            "buttons": [f"Use {self.number}"[:raw]],
            "inputs": ["password:account_number"],
            "frames": [],
        }

    def query_selector_all(self, _sel: str) -> list[Any]:
        return []

    frames: list[Any] = []


class _EchoPage:
    """A failure page echoing an e-mail-like username-only credential in its
    (percent-encoded) URL path, an input name and an iframe host."""

    def __init__(self, cred: str) -> None:
        self.cred = cred
        self.url = "https://example.org/u/" + urllib.parse.quote(cred) + "/x"

    def title(self) -> str:
        return "t"

    def evaluate(self, _js: str, _raw: int = 0) -> dict[str, Any]:
        return {
            "messages": [],
            "buttons": [],
            "inputs": [f"text:{self.cred}"],
            "frames": [f"{self.cred}.example.org"],
        }

    def query_selector_all(self, _sel: str) -> list[Any]:
        return []

    frames: list[Any] = []


def test_every_diagnostic_string_is_masked() -> None:
    cred = "acct-" + secrets.token_hex(6) + "@example.org"
    secret = vault.Secret(username="", password=cred, mode=vault.USERNAME_ONLY)
    diag = page_state.diagnose(_EchoPage(cred), secret)
    flat = json.dumps(diag)
    assert cred not in flat and urllib.parse.quote(cred) not in flat
    assert diag["url"] == "https://example.org/u/***/x"
    assert diag["inputs"] == ["text:***"] and diag["frames"] == ["***.example.org"]


class _StretchPage(_EchoPage):
    """The account number stretched by separators past the page-side cut."""

    def evaluate(self, _js: str, raw: int = 0) -> dict[str, Any]:
        stretched = "-".join(self.cred) + "-" * 2000
        return {
            "messages": [stretched[:raw], "short"],
            "buttons": [],
            "inputs": [],
            "frames": [],
        }


def test_a_text_cut_page_side_is_withheld() -> None:
    """No secret-length rule can cover unbounded separators: any string the
    page side had to cut is withheld whole."""
    secret = vault.Secret(username="", password=ACCOUNT, mode=vault.USERNAME_ONLY)
    diag = page_state.diagnose(_StretchPage(ACCOUNT), secret)
    assert diag["messages"] == ["<withheld>", "short"]
    assert ACCOUNT[:4] not in json.dumps(diag)


def test_the_url_never_carries_user_info() -> None:
    cred = "acct@example.org"
    secret = vault.Secret(username="", password=cred, mode=vault.USERNAME_ONLY)
    page = _EchoPage(cred)
    page.url = "https://acct%40example.org:pw@example.test:8443/login?x=1"
    diag = page_state.diagnose(page, secret)
    assert diag["url"] == "https://example.test:8443/login"


def test_the_longer_secret_is_masked_first() -> None:
    """A password inside the username must not leave the username's rest."""
    user = "alice1234@example.org"
    secret = vault.Secret(username=user, password=user[0:9])
    assert page_state._redact(f"User {user}", secret) == "User ***"


def test_diagnostics_mask_before_they_cut() -> None:
    """A secret cut at a length limit would leave its prefix unmasked: the
    page side returns long texts, the broker masks, THEN cuts."""
    secret = vault.Secret(username="", password=ACCOUNT, mode=vault.USERNAME_ONLY)
    diag = page_state.diagnose(_DiagPage(ACCOUNT), secret)
    flat = json.dumps(diag)
    for k in range(5, len(ACCOUNT) + 1):  # no 5+ digit run of it anywhere
        assert ACCOUNT[:k] not in flat and ACCOUNT[-k:] not in flat
    assert diag["url"] == "https://mullvad.net/en/account/***/devices"
    assert len(diag["messages"][0]) <= page_state.DIAG_LIMITS["messages"]


def _trip(attempt: recipes.AttemptController) -> recipes.SubmitTripwire:
    ctx = SimpleNamespace(service_workers=[])
    trip = recipes.SubmitTripwire(
        SimpleNamespace(context=ctx),
        ["https://mullvad.net"],
        dev=False,
        attempt=attempt,
    )
    trip.secret_keys.add("account_number")
    trip.protect.add("account_number")
    trip._secret = vault.Secret(username="", password=ACCOUNT, mode=vault.USERNAME_ONLY)
    trip.arm()
    return trip


class _Req:
    method = "POST"
    url = "https://mullvad.net/en/account/login"
    headers = {"content-type": "application/x-www-form-urlencoded"}
    redirected_from = None

    def __init__(self, value: str = ACCOUNT) -> None:
        self.post_data_buffer = f"account_number={value}".encode()

    @staticmethod
    def is_navigation_request() -> bool:
        return True


class _Route:
    def __init__(self, log: list[str], value: str = ACCOUNT) -> None:
        self.request = _Req(value)
        self.log = log

    def abort(self, _code: str) -> None:
        self.log.append("abort")

    def continue_(self) -> None:
        self.log.append("continue")


def test_a_self_submit_is_marked_before_it_leaves() -> None:
    log: list[str] = []

    class _Attempt(recipes.AttemptController):
        def mark_submitted(self) -> None:
            log.append("mark")
            super().mark_submitted()

    attempt = _Attempt()
    trip = _trip(attempt)
    trip._handle(_Route(log))
    assert log == ["mark", "continue"] and trip.secret_sent
    trip._handle(_Route(log))  # marked once, however often it goes
    assert log == ["mark", "continue", "continue"]
    only = vault.Secret(username="", password=ACCOUNT, mode=vault.USERNAME_ONLY)
    assert recipes._sent_by_itself(trip, only)  # never submitted a second time
    plain = vault.Secret(username="u", password=PASSWORD)
    assert not recipes._sent_by_itself(trip, plain)


@pytest.mark.parametrize("value", ["", ACCOUNT[:8], _grouped(ACCOUNT)[:-1]])
def test_a_partial_or_empty_value_is_not_the_submit(value: str) -> None:
    """An on-input check request with an empty or partial number is not the
    secret leaving: no marker, and the explicit submit still happens."""
    log: list[str] = []
    attempt = recipes.AttemptController()
    trip = _trip(attempt)
    trip._handle(_Route(log, value))
    assert log == ["continue"] and not trip.secret_sent and not attempt.submitted
    only = vault.Secret(username="", password=ACCOUNT, mode=vault.USERNAME_ONLY)
    assert not recipes._sent_by_itself(trip, only)


def test_a_grouped_complete_number_is_the_submit() -> None:
    log: list[str] = []
    attempt = recipes.AttemptController()
    trip = _trip(attempt)
    trip._handle(_Route(log, urllib.parse.quote(_grouped(ACCOUNT))))
    assert trip.secret_sent and attempt.submitted


def test_no_marker_no_request() -> None:
    class _Broken(recipes.AttemptController):
        def mark_submitted(self) -> None:
            raise OSError("limiter state not writable")

    log: list[str] = []
    trip = _trip(_Broken())
    trip._handle(_Route(log))
    assert log == ["abort"] and not trip.secret_sent
    assert trip.never_sent  # provably stopped in the browser
    with pytest.raises(recipes.LoginFailed, match="marker"):
        trip.check()


def test_holds_accepts_a_regrouped_account_number_only() -> None:
    only = vault.Secret(username="", password=ACCOUNT, mode=vault.USERNAME_ONLY)
    assert recipes._holds(_grouped(ACCOUNT), only)
    assert not recipes._holds(ACCOUNT[:-1], only)
    spaced = "".join(["ab ", "cd-ef"])  # an exact value with a space
    plain = vault.Secret(username="u", password=spaced)
    assert recipes._holds("ab cd-ef", plain)
    assert not recipes._holds("abcdef", plain)  # a password is exact


# ---------------------------------------------------------------------------
# D. the real runner against a Mullvad-like fixture (headless Chromium)
# ---------------------------------------------------------------------------

_MULLVAD_FIELD = (
    '<input type="password" name="account_number" '
    'placeholder="Enter your account number" inputmode="numeric">'
)
# a text field that regroups what is typed ("1234 5678 …"), as some sites do
_TEXT_FIELD = (
    '<input type="text" name="accountNumber" id="accountNumber" '
    'placeholder="Account number" inputmode="numeric" '
    "oninput=\"const d=this.value.replace(/\\D/g,'');"
    "this.value=d.replace(/(\\d{4})(?=\\d)/g,'$1 ');\">"
)
# a field that submits its form by itself once the number is complete
_SELF_SUBMIT_FIELD = (
    '<input type="password" name="account_number" inputmode="numeric" '
    "oninput=\"if (this.value.replace(/\\D/g,'').length === 16) "
    'this.form.requestSubmit();">'
)
_PASSWORD_FORM = (
    '<input type="text" name="username" autocomplete="username">'
    '<input type="password" name="password">'
)
_FORGOT = '<button type="submit" name="action" value="forgot">Forgot?</button>'
# a second control of the login form, outside the <form> tag (form=…)
_FORM_ATTR = '<input type="text" name="username" form="loginform">'
# another form on the page whose e-mail field is a username candidate too
_NEWSLETTER = (
    '<form method="post" action="/newsletter">'
    '<input type="email" name="email" placeholder="Newsletter"></form>'
)
# SvelteKit's `use:enhance`: no native submit; the form data goes by fetch
# (multipart) to `?/login`, the JSON answer says where to go
_ENHANCE_JS = """<script>
document.getElementById('loginform').addEventListener('submit', async ev => {
  ev.preventDefault();
  const r = await fetch('/en/account/login?/login', {method: 'POST',
      body: new FormData(ev.target), headers: {'x-sveltekit-action': 'true'}});
  const j = await r.json();
  if (j.type === 'redirect') location.href = j.location;
  else document.getElementById('err').textContent = j.error;
});
</script>"""

_LOGIN_HTML = """<!doctype html><html><head><title>Log in | Mullfix</title></head>
<body><header><button type=submit aria-label="Menu toggle">Menu</button></header>
<form id="loginform" method="POST" aria-label="Log in">
  <div class="input-icon-wrapper">{fields}
    <button class="icon-button" type="button" aria-label="Show">o</button></div>
  <div id="err" role="alert" class="error">{flash}</div>{before}
  <button type="submit" class="link lg">Log in</button>
</form>{outside}
<form method="post" class="lang"><ul>
  <li><button type="submit" formaction="/en/setlocale/de?page=/en/account/login">Deutsch</button></li>
</ul></form>{script}</body></html>"""

_ACCOUNT_HTML = """<!doctype html><html><body>
<nav><a href="/en/account/devices">Devices</a></nav>
<p>Account number: {grouped}</p></body></html>"""

# variant -> (fields, before the login button, after the form, script)
_VARIANTS = {
    "mullvad": (_MULLVAD_FIELD, "", "", ""),
    "text": (_TEXT_FIELD, "", "", ""),
    "forgot": (_MULLVAD_FIELD, _FORGOT, "", ""),
    "password": (_PASSWORD_FORM, "", "", ""),
    "formattr": (_MULLVAD_FIELD, "", _FORM_ATTR, ""),
    "newsletter": (_TEXT_FIELD, "", _NEWSLETTER, ""),
    "selfsubmit": (_SELF_SUBMIT_FIELD, "", "", ""),
    "enhanced": (_MULLVAD_FIELD, "", "", _ENHANCE_JS),
}


@dataclass
class _App:
    """Server-side state of the fixture."""

    variant: str = "mullvad"  # a key of _VARIANTS
    posts: list[dict[str, str]] = field(default_factory=list)
    logins: int = 0
    sessions: set[str] = field(default_factory=set)


class _Server(http.server.ThreadingHTTPServer):
    app: _App


def _form_body(ctype: str, data: bytes) -> dict[str, str]:
    """An urlencoded or multipart form body as a dict."""
    if ctype.startswith("multipart/form-data"):
        msg = email.parser.BytesParser(policy=email.policy.HTTP).parsebytes(
            b"Content-Type: " + ctype.encode() + b"\r\n\r\n" + data
        )
        out: dict[str, str] = {}
        for part in msg.iter_parts():
            name = part.get_param("name", header="content-disposition")
            if name:
                out[str(name)] = part.get_content()
        return out
    return dict(urllib.parse.parse_qsl(data.decode(), keep_blank_values=True))


class _Handler(http.server.BaseHTTPRequestHandler):
    server: _Server

    def log_message(self, *args: Any) -> None:
        return

    def _send(
        self,
        code: int,
        body: str,
        cookies: list[str] | None = None,
        ctype: str = "text/html; charset=utf-8",
    ) -> None:
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for ck in cookies or []:
            self.send_header("Set-Cookie", ck)
        self.end_headers()
        self.wfile.write(data)

    def _redirect(self, where: str, cookies: list[str] | None = None) -> None:
        self.send_response(303)
        self.send_header("Location", where)
        self.send_header("Content-Length", "0")
        for ck in cookies or []:
            self.send_header("Set-Cookie", ck)
        self.end_headers()

    def _logged_in(self) -> bool:
        raw = self.headers.get("Cookie") or ""
        jar = dict(p.strip().partition("=")[::2] for p in raw.split(";") if p.strip())
        return jar.get("session") in self.server.app.sessions

    def _login_page(self, flash: str = "") -> None:
        fields, before, outside, script = _VARIANTS[self.server.app.variant]
        page = (
            _LOGIN_HTML.replace("{fields}", fields)
            .replace("{before}", before)
            .replace("{outside}", outside)
            .replace("{script}", script)
            .replace("{flash}", flash)
        )
        self._send(200, page)

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/en/account/login":
            self._login_page()
        elif path.startswith("/en/account"):
            if self._logged_in():
                self._send(200, _ACCOUNT_HTML.replace("{grouped}", _grouped(ACCOUNT)))
            else:
                self._redirect("/en/account/login")
        else:
            self._send(200, "<!doctype html><html><body>home</body></html>")

    def do_POST(self) -> None:  # noqa: N802
        app = self.server.app
        n = int(self.headers.get("Content-Length") or 0)
        body = _form_body(self.headers.get("Content-Type") or "", self.rfile.read(n))
        app.posts.append(body)
        if self.path.split("?", 1)[0] != "/en/account/login":
            self._send(404, "no")
            return
        enhanced = self.headers.get("x-sveltekit-action") == "true"
        typed = body.get("account_number", body.get("accountNumber", ""))
        number = typed.replace(" ", "")
        if number == ACCOUNT and "action" not in body:
            app.logins += 1
            token = secrets.token_hex(16)
            app.sessions.add(token)
            cookie = [f"session={token}; Path=/; HttpOnly"]
            if enhanced:
                answer = {"type": "redirect", "status": 303, "location": "/en/account"}
                self._send(200, json.dumps(answer), cookie, "application/json")
            else:
                self._redirect("/en/account", cookie)
            return
        # the site echoes what was typed, grouped
        error = f"Account {_grouped(number)} not found"
        if enhanced:
            answer = {"type": "failure", "error": error}
            self._send(200, json.dumps(answer), None, "application/json")
        else:
            self._login_page(error)


@pytest.fixture(name="site")
def _site() -> Iterator[tuple[_App, str]]:
    httpd = _Server(("127.0.0.1", 0), _Handler)
    httpd.app = _App()
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield httpd.app, f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()


@dataclass
class _Rig:
    brk: daemon.Broker
    home: Path

    def login(self) -> dict[str, Any]:
        return self.brk._login_request(SITE, {})

    def attempts(self) -> list[Any]:
        path = self.home / "limiter.json"
        if not path.exists():
            return []
        entry = json.loads(path.read_text()).get("sites", {}).get(SITE) or {}
        return list(entry.get("attempts") or [])


def _rig(tmp_path: Path, origin: str, *, account: str = ACCOUNT) -> _Rig:
    raw = _raw(
        SITE,
        username=account,
        agent_fill_origins=origin,
        agent_check_url=origin + "/en/account",
        agent_login_url=origin + "/en/account/login",
    )
    fixture = tmp_path / "items.json"
    fixture.write_text(json.dumps([raw]))
    home = tmp_path / "home"
    brk = daemon.Broker(
        vault.FixtureVault(fixture, dev=True),
        limiter.Limiter(home / "limiter.json", 0, 100, 100),
        home,
        runner=daemon.PlaywrightRunner(home, dev=True),
    )
    return _Rig(brk, home)


@pytest.fixture(name="fast")
def _fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(daemon, "PROFILE_PROOF_WAIT_S", 2.5)
    monkeypatch.setattr(
        daemon,
        "recipe_for",
        lambda site: functools.partial(recipes.generic_login, settle_s=4.0),
    )


@pytest.fixture(name="marks")
def _marks(monkeypatch: pytest.MonkeyPatch, site: tuple[_App, str]) -> list[int]:
    """How many POSTs the server had seen each time the submit marker was set."""
    app, _origin = site
    seen: list[int] = []
    real = daemon._LimiterAttempt.mark_submitted

    def mark(self: Any) -> None:
        seen.append(len(app.posts))
        real(self)

    monkeypatch.setattr(daemon._LimiterAttempt, "mark_submitted", mark)
    return seen


def _leaks(resp: dict[str, Any], account: str) -> bool:
    dumped = json.dumps(resp)
    return account in dumped or _grouped(account) in dumped


@pytest.mark.launches_chrome
@CHROME
@pytest.mark.usefixtures("fast")
@pytest.mark.parametrize(
    "variant",
    ["mullvad", "text", "forgot", "newsletter", "selfsubmit", "enhanced"],
)
def test_username_only_login_is_typed_submitted_and_proven(
    tmp_path: Path, site: tuple[_App, str], marks: list[int], variant: str
) -> None:
    """Mullvad's masked field, a regrouping text field, a form whose default
    button is a secondary one, a page with a second (newsletter) form, a field
    that submits itself, and SvelteKit's fetch-enhanced form: the account
    number alone is typed, submitted ONCE (never "Forgot?"), the marker set
    before anything reached the site, and the sentinel proves the login."""
    app, origin = site
    app.variant = variant
    rig = _rig(tmp_path, origin)
    resp = rig.login()
    assert resp.get("ok"), resp
    assert resp["fresh_auth"] is True and resp["bundle"]["via"] == "login"
    assert len(app.posts) == 1 and app.logins == 1
    post = app.posts[0]
    typed = post.get("account_number", post.get("accountNumber", ""))
    assert typed.replace(" ", "") == ACCOUNT
    assert set(post) <= {"account_number", "accountNumber"}  # nothing else typed
    assert marks == [0]  # the marker once, right before the submit
    assert rig.attempts()[-1][1] == "ok"
    assert [c["name"] for c in resp["bundle"]["cookies"]] == ["session"]
    assert not _leaks(resp, ACCOUNT)


@pytest.mark.launches_chrome
@CHROME
@pytest.mark.usefixtures("fast")
def test_a_wrong_account_fails_post_submit_masked_without_a_screenshot(
    tmp_path: Path, site: tuple[_App, str], marks: list[int]
) -> None:
    app, origin = site
    wrong = _account()
    rig = _rig(tmp_path, origin, account=wrong)
    stale = rig.home / f"last-failure-{SITE}.png"
    stale.parent.mkdir(parents=True, exist_ok=True)
    stale.write_bytes(b"an older run's picture")
    resp = rig.login()
    assert resp["ok"] is False and resp["phase"] == "submit"
    assert resp["submitted"] is True and marks == [0]
    assert "account number" in resp["detail"]
    assert len(app.posts) == 1
    diag = resp["diag"]
    # the page echoed the typed number in groups: masked, never shown
    assert any("***" in m for m in diag["messages"]), diag["messages"]
    assert not _leaks(resp, wrong)
    assert "password_check" not in diag  # tp#965 S1: no length either
    assert "screenshot" not in diag and diag["screenshot_withheld"]
    assert not stale.exists()  # no picture of this site is left behind
    assert rig.attempts()[-1][1] == "unknown"


@pytest.mark.launches_chrome
@CHROME
@pytest.mark.usefixtures("fast")
@pytest.mark.parametrize("variant", ["password", "formattr"])
def test_a_password_form_is_never_typed_into(
    tmp_path: Path, site: tuple[_App, str], marks: list[int], variant: str
) -> None:
    """A username-only item on a username + password form — also one whose
    second field sits outside the <form> tag (form=…): nothing typed, nothing
    submitted, the attempt is not_submitted (no cooldown)."""
    app, origin = site
    app.variant = variant
    rig = _rig(tmp_path, origin)
    resp = rig.login()
    assert resp["ok"] is False and resp["phase"] == "recipe"
    assert resp["submitted"] is False and "nothing typed" in resp["detail"]
    assert app.posts == [] and marks == []
    assert rig.attempts()[-1][1] == "failed"  # not_submitted
    assert not _leaks(resp, ACCOUNT)
