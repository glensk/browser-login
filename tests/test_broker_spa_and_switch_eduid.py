"""tp#821: broker storage write that beats a SPA redirect, the CSCS token probe,
and the SWITCH Cloud login chained onto the broker's edu-ID session.

Hermetic by default (fake pages, stubbed broker / lease / CDP). The real-browser
test (`-m browser`, opt-in via LOGIN_BROKER_E2E=1) serves a fake CSCS portal over
local HTTPS and points a throwaway headless Chromium at it with
``--host-resolver-rules``; it never touches the shared browser or a real site.

Run: uv run --no-sync pytest tests/test_broker_spa_and_switch_eduid.py
"""

from __future__ import annotations

# pylint: disable=protected-access,import-outside-toplevel,too-few-public-methods
# pylint: disable=missing-function-docstring,missing-class-docstring,import-error
# pylint: disable=redefined-outer-name,unused-argument
import contextlib
import http.server
import importlib.util
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

import pytest

_BROWSER_PY = Path(__file__).resolve().parent.parent / "bin" / "browser.py"


def _load_browser_module():
    spec = importlib.util.spec_from_file_location("browser_tp821_test", _BROWSER_PY)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["browser_tp821_test"] = mod
    spec.loader.exec_module(mod)
    return mod


browser = _load_browser_module()

PORTAL = "https://portal.cscs.ch"
KEYCLOAK = "https://auth.cscs.ch/auth/realms/cscs/protocol/openid-connect/auth"


def _token() -> str:
    """A HomePort-shaped token (40 hex), fresh per test — never a real one."""
    return secrets.token_hex(20)


# ---------------------------------------------------------------------------
# A. storage write: init script before navigation, read-back as the proof
# ---------------------------------------------------------------------------


class _FakeSpa:
    """A tab on a SPA that redirects to Keycloak after load unless its token is
    in localStorage at document start. Runs the init script's effect by
    reading the JSON literals the client embedded (the guard included)."""

    def __init__(self, origin: str) -> None:
        self.origin = origin
        self.url = "about:blank"
        self.scripts: list[str] = []
        self.storage: dict[str, str] = {}
        self.goto_urls: list[str] = []

    def add_init_script(self, script: str) -> None:
        self.scripts.append(script)

    def goto(self, url: str, **_kw) -> None:
        self.goto_urls.append(url)
        target = browser._url_origin(url)
        for script in self.scripts:  # document start: the init scripts run
            m = re.search(r"const origin = (\".*?\"); const kv = (\{.*?\});", script)
            assert m, "init script lost its JSON literals"
            if json.loads(m.group(1)) == target:  # the location.origin guard
                self.storage.update(json.loads(m.group(2)))
        has = any(re.search(r"\b[0-9a-f]{40}\b", v) for v in self.storage.values())
        self.url = url if has else KEYCLOAK  # the SPA's post-load redirect

    def evaluate(self, js: str, arg=None):
        assert js == browser._BROKER_STORAGE_CHECK_JS
        return all(self.storage.get(k) == v for k, v in arg.items())


def _prepared(page: _FakeSpa, calls: list):
    def fake(port, url, prepare, fn):
        calls.append(url)
        prepare(page)
        page.goto(url)
        return fn(page)

    return fake


def test_storage_write_lands_before_the_redirect(monkeypatch, capsys):
    tok = _token()
    page = _FakeSpa(PORTAL)
    calls: list = []
    monkeypatch.setattr(
        browser, "_with_prepared_background_page", _prepared(page, calls)
    )
    bundle = {"storage": {PORTAL: {"homeport": tok}}}
    assert browser._broker_write_storage(9222, bundle) == 1
    assert calls == [PORTAL + "/"] and page.url == PORTAL + "/"
    assert page.storage == {"homeport": tok}
    out = capsys.readouterr()
    assert tok not in out.out + out.err


def test_storage_write_refuses_without_proof(monkeypatch, capsys):
    """Wrong origin in the script / redirected anyway: nothing counted, no value printed."""
    tok = _token()
    page = _FakeSpa(PORTAL)

    def fake(port, url, prepare, fn):
        page.goto(url)  # prepare skipped: the old post-load write race
        return fn(page)

    monkeypatch.setattr(browser, "_with_prepared_background_page", fake)
    assert browser._broker_write_storage(9222, {"storage": {PORTAL: {"k": tok}}}) == 0
    err = capsys.readouterr().err
    assert "could not write 1 localStorage key(s) on https://portal.cscs.ch" in err
    assert tok not in err


def test_storage_write_skips_non_https_and_mismatched_origins(monkeypatch):
    called: list = []

    def fake(*args) -> bool:
        called.append(args)
        return True

    monkeypatch.setattr(browser, "_with_prepared_background_page", fake)
    bundle = {
        "storage": {
            "http://portal.cscs.ch": {"k": "v"},
            "https://portal.cscs.ch/x": {"k": "v"},
            PORTAL: "not a dict",
        }
    }
    assert browser._broker_write_storage(9222, bundle) == 0
    assert not called


def test_init_script_guards_the_origin():
    script = browser._broker_storage_init_script(PORTAL, {"a": 'x"y'})
    assert "location.origin !== origin" in script
    assert json.dumps(PORTAL) in script and json.dumps({"a": 'x"y'}) in script


# ---------------------------------------------------------------------------
# A. the cscs probe polls for the token
# ---------------------------------------------------------------------------


class _SpaProbePage:
    """URL/token sequence advanced by each wait (500 ms per poll)."""

    def __init__(self, urls: list[str], tokens: list[bool]) -> None:
        self._urls, self._tokens = urls, tokens
        self.url = urls[0]
        self.waits = 0

    def evaluate(self, _js: str) -> bool:
        return self._tokens.pop(0) if self._tokens else False

    def wait_for_timeout(self, _ms: float) -> None:
        self.waits += 1
        if len(self._urls) > 1:
            self._urls.pop(0)
        self.url = self._urls[0]

    def wait_for_selector(self, _sel: str, **_kw) -> object:
        return object()  # the DOM sentinel shows


# WS1a: CSCS needs a DOM sentinel too (next to its token) and a known status.
CSCS_ENTRY = {
    "site": "cscs",
    "check_url": PORTAL + "/profile/",
    "logged_in_selector": "#me",
}


def _probe(page) -> str:
    browser._BG_STATUS[id(page)] = 200
    try:
        return str(browser._broker_probe(page, CSCS_ENTRY))
    finally:
        browser._BG_STATUS.pop(id(page), None)


def test_cscs_probe_waits_for_the_token():
    late = _SpaProbePage([PORTAL + "/profile/"] * 4, [False, False, True])
    assert _probe(late) == browser.PROOF_VALID
    assert late.waits == 2  # polled, no fixed 1 s sleep first


def test_cscs_probe_on_portal_without_token_is_not_logged_in():
    """Regression: the old probe said "logged in" 1 s after load on the portal;
    the SPA moves a token-less session to Keycloak after that second."""
    redirect_after_1s = _SpaProbePage(
        [PORTAL + "/profile/", PORTAL + "/profile/", KEYCLOAK], []
    )
    assert _probe(redirect_after_1s) == browser.PROOF_INVALID


def test_cscs_probe_gives_up_after_the_wait(monkeypatch):
    monkeypatch.setattr(browser, "CSCS_PROBE_WAIT_S", 0.2)
    never = _SpaProbePage([PORTAL + "/profile/"], [])
    assert _probe(never) == browser.PROOF_INVALID


def test_cscs_without_a_dom_sentinel_keeps_its_token_proof():
    """C2: until WS2-cscs, CSCS without a DOM sentinel keeps the old token rule
    (also without a known status), recorded as the weak proof (proof_v 0)."""
    page = _SpaProbePage([PORTAL + "/profile/"], [True])
    assert browser._broker_probe(page, {"site": "cscs"}) == browser.PROOF_VALID
    assert browser._RESULT["proof_v"] == 0
    gone = _SpaProbePage([PORTAL + "/profile/", KEYCLOAK], [])
    assert browser._broker_probe(gone, {"site": "cscs"}) == browser.PROOF_INVALID


# ---------------------------------------------------------------------------
# B. SWITCH Cloud: broker edu-ID session, then the SSO click in the background
# ---------------------------------------------------------------------------


class _SwitchPage:
    """A background portal tab whose SSO click ends in `outcome`:
    ``logged-in``, ``eduid-login`` (the edu-ID login form) or ``login``."""

    def __init__(self, outcome: str) -> None:
        self.url = browser.SWITCH_ORIGIN + browser.SWITCH_LOGIN_PATH
        self.outcome = outcome
        self.clicks: list[str] = []

    def click(self, selector: str, **_kw) -> None:
        self.clicks.append(selector)
        if self.outcome == "eduid-login":
            self.url = IDP_URL
        elif self.outcome == "logged-in":
            self.url = browser.SWITCH_ORIGIN + "/"

    def query_selector(self, selector: str):
        if selector == browser.SWITCH_IDP_LOGIN_INPUT_SELECTOR:
            return object() if self.outcome == "eduid-login" else None
        raise AssertionError(f"unexpected selector {selector!r}")


IDP_URL = "https://login.eduid.ch/idp/profile/oidc/authorize?execution=e1s1"
LOGIN_URL = browser.SWITCH_ORIGIN + browser.SWITCH_LOGIN_PATH
_REAL_GUIDED = browser._guided_login_allowed
_REAL_BROKER_LOGIN = browser._broker_login


@pytest.fixture
def switch_env(monkeypatch):
    """Everything around `cmd_switch_login` stubbed; returns the call log.

    ``state["clicks"]`` lists the outcome of each background SSO click in turn
    (the broker-free click first, then the one after the broker's login)."""
    log: dict = {
        "broker": [],
        "bg": [],
        "pages": [],
        "events": [],
        "headed": 0,
        "hints": [],
        "waits": [],
    }
    entry: object = {"site": "eduid", "refused": False}
    state: dict = {
        "entry": entry,
        "broker_rc": 0,
        "clicks": ["eduid-login", "logged-in"],
        "headed": False,
        "probe": "login",
    }

    def broker_site(site):
        assert site == "eduid"
        if state["entry"] == "down":
            raise browser.BrokerUnavailable("no login broker")
        return state["entry"]

    def broker_login(port, site):
        log["broker"].append(site)
        return state["broker_rc"]

    def bg(port, url, fn):
        log["bg"].append(url)
        page = _SwitchPage(state["clicks"][len(log["pages"])])
        log["pages"].append(page)
        return fn(page)

    def headed(port, site, label, hint=""):
        assert site == "switch" and label
        log["headed"] += 1
        log["hints"].append(hint)
        return state["headed"]

    def wait(page, timeout_s, **kw):
        log["waits"].append(kw.get("idp_give_up_s"))
        return browser._switch_page_verdict(page) == "logged-in"

    monkeypatch.setattr(browser, "_BROKER_REFUSALS", {})
    monkeypatch.setattr(browser, "_switch_probe", lambda port: (state["probe"], ""))
    monkeypatch.setattr(browser, "_broker_site", broker_site)
    monkeypatch.setattr(browser, "_broker_login", broker_login)
    monkeypatch.setattr(browser, "_with_background_page", bg)
    monkeypatch.setattr(
        browser,
        "_switch_page_verdict",
        lambda page: "logged-in" if page.outcome == "logged-in" else "login",
    )
    monkeypatch.setattr(browser, "_switch_wait_for_login", wait)
    monkeypatch.setattr(
        browser, "_interaction_lease", lambda purpose: contextlib.nullcontext("n")
    )
    monkeypatch.setattr(browser, "_guided_login_allowed", headed)
    monkeypatch.setattr(
        browser, "_record_login_event", lambda s, m: log["events"].append((s, m))
    )
    return log, state


def test_switch_login_chains_broker_eduid_and_background_click(switch_env, capsys):
    log, _state = switch_env
    assert browser.cmd_switch_login(9222) == 0
    assert log["broker"] == ["eduid"]
    assert log["bg"] == [LOGIN_URL, LOGIN_URL]
    assert [p.clicks for p in log["pages"]] == [
        [browser.SWITCH_SIGN_IN_BUTTON_SELECTOR]
    ] * 2
    assert log["events"] == [("switch", "broker-sso")]
    assert log["headed"] == 0  # no window needed: works headless
    out, err = capsys.readouterr()
    assert "✅ Logged into Switch Cloud Portal (broker" in out
    assert "landed on the edu-ID login form" in err


def test_switch_login_falls_back_when_the_click_does_not_log_in(switch_env, capsys):
    log, state = switch_env
    state["clicks"] = ["eduid-login", "login"]  # broker's session did not carry it
    # no guided login: the window flow is refused with "needs Albert"
    assert browser.cmd_switch_login(9222) == browser.NEEDS_ALBERT_RC
    assert log["broker"] == ["eduid"] and len(log["bg"]) == 2
    assert log["headed"] == 1 and not log["events"]
    assert log["hints"] == [""]
    assert "falling back to the window flow" in capsys.readouterr().err


def test_switch_login_falls_back_when_the_broker_login_fails(switch_env, capsys):
    log, state = switch_env
    state["broker_rc"] = 4
    assert browser.cmd_switch_login(9222) == browser.NEEDS_ALBERT_RC
    assert log["broker"] == ["eduid"] and len(log["bg"]) == 1
    assert log["headed"] == 1
    assert "broker login eduid failed (exit 4)" in capsys.readouterr().err


@pytest.mark.parametrize(
    "entry",
    [
        None,
        {"site": "eduid", "refused": True, "reason": "x"},
        "down",  # BrokerUnavailable
    ],
    ids=["not-listed", "refused", "broker-down"],
)
def test_switch_login_without_broker_eduid_is_the_window_flow(switch_env, entry):
    log, state = switch_env
    state["entry"] = entry
    assert browser.cmd_switch_login(9222) == browser.NEEDS_ALBERT_RC
    assert not log["broker"] and len(log["bg"]) == 1  # only the broker-free click
    assert log["headed"] == 1


# --- tp#866: the broker-free click first, then the broker, then the gate ---------


@pytest.mark.parametrize("broker", ["failing", "down"])
def test_switch_background_click_alone_logs_in_without_the_broker(
    switch_env, capsys, broker
):
    """(1) A live edu-ID session in the profile: the click alone logs in —
    exit 0, the broker is never asked, no guided gate."""
    log, state = switch_env
    state["clicks"] = ["logged-in"]
    state["broker_rc"] = 2
    if broker == "down":
        state["entry"] = "down"
    assert browser.cmd_switch_login(9222) == 0
    assert not log["broker"] and log["bg"] == [LOGIN_URL]
    assert log["events"] == [("switch", "sso-background")]
    assert log["headed"] == 0
    # the broker-free click gives up early on the edu-ID login form
    assert log["waits"] == [browser.SWITCH_IDP_FORM_SETTLE_S]
    assert "live edu-ID session + SSO click" in capsys.readouterr().out


def test_switch_click_on_the_eduid_form_tries_the_broker_next(switch_env, capsys):
    """(2) The broker-free click lands on edu-ID's login form → the broker path
    runs next (its click waits the full time: no early give-up there)."""
    log, _state = switch_env
    assert browser.cmd_switch_login(9222) == 0
    assert log["broker"] == ["eduid"]
    assert log["pages"][0].url == IDP_URL
    assert log["waits"] == [browser.SWITCH_IDP_FORM_SETTLE_S, None]
    assert log["events"] == [("switch", "broker-sso")]
    err = capsys.readouterr().err
    assert "SSO click without the broker landed on the edu-ID login form" in err


def test_switch_warm_session_clicks_nothing(switch_env, capsys):
    """(4) Warm portal session: no click, no broker, no gate, no login event."""
    log, state = switch_env
    state["probe"] = "logged-in"
    assert browser.cmd_switch_login(9222) == 0
    assert not log["bg"] and not log["broker"] and not log["events"]
    assert log["headed"] == 0
    assert "Already logged into Switch Cloud Portal" in capsys.readouterr().out


class _FakeBrowser:
    def close(self) -> None:
        return None


class _FakePw:
    def stop(self) -> None:
        return None


def _refusing_broker(monkeypatch, error: str, detail: str) -> list[str]:
    """The REAL `_broker_login` and guided gate against a broker that refuses
    every login with `error`; returns the requests it saw."""
    requests: list[str] = []

    def request(op, **kw):
        requests.append(f"{op}:{kw.get('site')}")
        return {"ok": False, "error": error, "detail": detail}

    monkeypatch.setattr(browser, "_broker_login", _REAL_BROKER_LOGIN)
    monkeypatch.setattr(browser, "_broker_logged_in", lambda port, site: 2)
    monkeypatch.setattr(browser, "_connect", lambda port: (_FakePw(), _FakeBrowser()))
    monkeypatch.setattr(browser, "_broker_request", request)
    monkeypatch.setattr(browser, "_guided_login_allowed", _REAL_GUIDED)
    monkeypatch.setattr(browser, "_headed_lease_held", lambda: False)
    return requests


def test_switch_both_fail_names_the_broker_cooldown(switch_env, monkeypatch, capsys):
    """(3) Click on the edu-ID form AND the broker rate-limited → exit 4, and
    the needs-Albert line names the broker's cooldown (its structured
    ``rate_limited`` code; the detail verbatim)."""
    log, state = switch_env
    state["clicks"] = ["eduid-login"]
    detail = "cooldown after a failed login: retry in 1487s"
    requests = _refusing_broker(monkeypatch, "rate_limited", detail)
    assert browser.cmd_switch_login(9222) == browser.NEEDS_ALBERT_RC
    assert requests == ["login:eduid"] and len(log["bg"]) == 1
    assert not log["events"]
    err = capsys.readouterr().err
    assert "rate limited by the broker" in err
    assert (
        "needs Albert: agent-login.py -g switch (or wait: the broker rate-limits "
        f"eduid — {detail})"
    ) in err


def test_switch_both_fail_without_rate_limit_has_no_wait_hint(
    switch_env, monkeypatch, capsys
):
    _log, state = switch_env
    state["clicks"] = ["eduid-login"]
    _refusing_broker(monkeypatch, "login_failed", "")
    assert browser.cmd_switch_login(9222) == browser.NEEDS_ALBERT_RC
    err = capsys.readouterr().err
    assert "needs Albert: agent-login.py -g switch\n" in err
    assert "or wait" not in err


# --- the early give-up of the wait itself ----------------------------------------


class _IdpWaitPage:
    """A tab that shows `urls` in turn (one per poll), with the edu-ID login
    form only where `forms` says so."""

    def __init__(self, urls: list[str], forms: list[bool]) -> None:
        self._urls, self._forms, self.polls = urls, forms, 0

    @property
    def url(self) -> str:
        return self._urls[min(self.polls, len(self._urls) - 1)]

    def query_selector(self, selector: str):
        if selector == browser.SWITCH_SIGN_IN_FORM_SELECTOR:
            return None
        return object() if self._forms[min(self.polls, len(self._forms) - 1)] else None

    def wait_for_timeout(self, _ms: float) -> None:
        self.polls += 1
        time.sleep(0.01)


def test_wait_gives_up_once_the_eduid_form_settles():
    page = _IdpWaitPage([IDP_URL], [True])
    t0 = time.monotonic()
    assert not browser._switch_wait_for_login(
        page, timeout_s=10, poll_s=0.01, idp_give_up_s=0.05
    )
    assert time.monotonic() - t0 < 2
    assert browser._switch_on_idp_login_form(page)


def test_wait_rides_out_a_pass_through_the_idp():
    """A live IdP session redirects THROUGH login.eduid.ch, rendering no form."""
    page = _IdpWaitPage([IDP_URL] * 3 + [browser.SWITCH_ORIGIN + "/projects"], [False])
    assert browser._switch_wait_for_login(
        page, timeout_s=10, poll_s=0.01, idp_give_up_s=0.0
    )


def test_wait_without_give_up_ignores_the_eduid_form():
    page = _IdpWaitPage([IDP_URL], [True])
    t0 = time.monotonic()
    assert not browser._switch_wait_for_login(page, timeout_s=0.3, poll_s=0.01)
    assert time.monotonic() - t0 >= 0.3


def test_the_eduid_form_check_needs_the_idp_host():
    page = _IdpWaitPage([LOGIN_URL], [True])
    assert not browser._switch_on_idp_login_form(page)


# ---------------------------------------------------------------------------
# A, real browser: fake CSCS portal over local HTTPS (opt-in)
# ---------------------------------------------------------------------------

_SPA_JS = (
    "const has = () => { const re=/\\b[0-9a-f]{40}\\b/;"
    " for (let i=0;i<localStorage.length;i++)"
    " { const v=localStorage.getItem(localStorage.key(i));"
    " if (v && re.test(v)) return true; } return false; };"
    "window.addEventListener('load', () => {"
    " if (has()) { document.getElementById('app').textContent='portal'; return; }"
    " setTimeout(() => location.replace('" + KEYCLOAK + "'), __DELAY__); });"
)


class _PortalApp(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        return

    def do_GET(self):  # noqa: N802
        if self.path.startswith("/auth/"):  # "Keycloak" (auth.cscs.ch)
            body = "<html><body><form><input type=password></form></body></html>"
        else:
            # /slow/: redirect 1 s after load; /slower/: 3 s (the old probe's
            # "on the portal 1 s after load" called that logged in)
            delays = {"/slow/": "1000", "/slower/": "3000"}
            delay = next((d for p, d in delays.items() if self.path.startswith(p)), "0")
            body = (
                "<html><body><div id=app>loading</div><script>"
                + _SPA_JS.replace("__DELAY__", delay)
                + "</script></body></html>"
            )
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@contextlib.contextmanager
def _fake_portal_browser():
    """(cdp port) of a throwaway headless Chromium whose portal.cscs.ch and
    auth.cscs.ch resolve to a local HTTPS fake; everything torn down after."""
    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("openssl not found (needed for the local HTTPS fake)")
    from playwright.sync_api import sync_playwright

    with sync_playwright() as pw:
        exe = pw.chromium.executable_path
    tmp = Path(tempfile.mkdtemp(prefix="tp821-"))
    proc = None
    httpd = None
    try:
        key, cert = tmp / "k.pem", tmp / "c.pem"
        subprocess.run(
            [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-keyout", str(key), "-out", str(cert), "-subj", "/CN=portal.cscs.ch"],
            check=True,
            capture_output=True,
        )  # fmt: skip
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _PortalApp)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(str(cert), str(key))
        httpd.socket = tls.wrap_socket(httpd.socket, server_side=True)
        hp = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        cdp = _free_port()
        rules = f"MAP portal.cscs.ch 127.0.0.1:{hp},MAP auth.cscs.ch 127.0.0.1:{hp}"
        proc = subprocess.Popen(  # pylint: disable=consider-using-with
            [exe, "--headless=new", f"--remote-debugging-port={cdp}",
             f"--user-data-dir={tmp / 'profile'}", "--no-first-run",
             "--no-default-browser-check", "--ignore-certificate-errors",
             f"--host-resolver-rules={rules}", "about:blank"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )  # fmt: skip
        deadline = time.monotonic() + 20
        while True:
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{cdp}/json/version", timeout=1
                ):
                    break
            except OSError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.2)
        yield cdp
    finally:
        if proc is not None:
            proc.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=10)
        if httpd is not None:
            httpd.shutdown()
        shutil.rmtree(tmp, ignore_errors=True)


@pytest.mark.browser
@pytest.mark.skipif(
    os.environ.get("LOGIN_BROKER_E2E") != "1", reason="set LOGIN_BROKER_E2E=1"
)
def test_e2e_storage_write_beats_the_spa_redirect(monkeypatch, capsys):
    # The throwaway browser is not the shared one: no registry, no lifecycle.
    monkeypatch.setattr(browser, "_is_up", lambda port: True)
    monkeypatch.setattr(browser, "_ensure_page_target", lambda port, **_k: None)
    monkeypatch.setattr(browser, "_registry_register", lambda *a, **k: lambda: None)
    entry = {"site": "cscs", "check_url": PORTAL + "/", "logged_in_selector": None}
    checks = [
        {**entry, "check_url": PORTAL + path} for path in ("/", "/slow/", "/slower/")
    ]
    tok = _token()
    with _fake_portal_browser() as port:
        # no token: redirected right after load / after 1 s / 3 s -> NOT logged in
        for check in checks:
            assert browser._broker_check_entry(port, "cscs", check) == 2, check
        bundle = {"storage": {PORTAL: {"homeport-token": tok}}}
        assert browser._broker_write_storage(port, bundle) == 1
        for check in checks:
            assert browser._broker_check_entry(port, "cscs", check) == 0, check
    out = capsys.readouterr()
    assert tok not in out.out + out.err
