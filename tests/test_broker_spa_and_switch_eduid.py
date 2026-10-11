"""tp#821: broker storage write that beats a SPA redirect, the CSCS token probe,
and the SWITCH Cloud login chained onto the broker's edu-ID session.

Hermetic (fake pages, stubbed broker / lease / CDP). The CSCS portal in a real
headless Chromium (server proof, write on /profile/, read-back) is tested in
tests/test_ws2_cscs.py against a routed fixture portal.

Run: uv run --no-sync pytest tests/test_broker_spa_and_switch_eduid.py
"""

from __future__ import annotations

# pylint: disable=protected-access,import-outside-toplevel,too-few-public-methods
# pylint: disable=missing-function-docstring,missing-class-docstring,import-error
# pylint: disable=redefined-outer-name,unused-argument
import contextlib
import importlib.util
import json
import re
import secrets
import sys
import time
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
    assert calls == [PORTAL + "/profile/"] and page.url == PORTAL + "/profile/"
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
# A. the cscs probe asks the portal's API (WS2-cscs; real Chromium: test_ws2_cscs)
# ---------------------------------------------------------------------------


class _ShownEl:
    """A visible element."""

    def is_visible(self) -> bool:
        return True


class _SpaProbePage:
    """URL sequence advanced by each wait (500 ms per poll); the in-page
    server check (``recipes.cscs_token_state``) answers from `states`."""

    def __init__(self, urls: list[str], states: list[str]) -> None:
        self._urls, self._states = urls, states
        self.url = urls[0]
        self.waits = 0

    def evaluate(self, _js: str, _arg=None) -> dict:
        return {"state": self._states.pop(0) if self._states else "none"}

    def wait_for_timeout(self, _ms: float) -> None:
        self.waits += 1
        if len(self._urls) > 1:
            self._urls.pop(0)
        self.url = self._urls[0]

    def query_selector_all(self, _sel: str) -> list[_ShownEl]:
        return [_ShownEl()]  # the DOM sentinel shows


# An item MAY add a DOM sentinel; the server proof decides first.
CSCS_ENTRY = {
    "site": "cscs",
    "check_url": PORTAL + "/profile/",
    "logged_in_selector": "#me",
}


def _probe(page, entry=None) -> str:
    browser._BG_STATUS[id(page)] = 200
    try:
        return str(browser._broker_probe(page, entry or CSCS_ENTRY))
    finally:
        browser._BG_STATUS.pop(id(page), None)


def test_cscs_probe_waits_for_the_server_answer():
    late = _SpaProbePage([PORTAL + "/profile/"] * 4, ["none", "error", "valid"])
    assert _probe(late) == browser.PROOF_VALID
    assert late.waits == 2  # polled, no fixed 1 s sleep first


def test_cscs_probe_on_portal_with_a_dead_token_is_not_logged_in():
    """Regression (WS2-cscs): the old probe said "logged in" for any 40-hex
    value on the portal — an expired token too."""
    assert _probe(_SpaProbePage([PORTAL + "/profile/"], ["invalid"])) == "invalid"
    moved = _SpaProbePage([PORTAL + "/profile/", KEYCLOAK], ["none"])
    assert _probe(moved) == browser.PROOF_INVALID


def test_cscs_probe_api_trouble_is_undecided():
    down = _SpaProbePage([PORTAL + "/profile/"], ["indeterminate"])
    assert _probe(down) == browser.PROOF_UNDECIDED


def test_cscs_probe_gives_up_after_the_wait(monkeypatch):
    monkeypatch.setattr(browser, "CSCS_PROBE_WAIT_S", 0.2)
    never = _SpaProbePage([PORTAL + "/profile/"], [])
    assert _probe(never) == browser.PROOF_INVALID


def test_cscs_without_a_dom_sentinel_is_the_strict_server_proof():
    """WS2-cscs: the server proof is strict on its own (proof_v 1), and like
    every strict proof it needs a known status."""
    entry = {"site": "cscs", "check_url": PORTAL + "/profile/"}
    page = _SpaProbePage([PORTAL + "/profile/"], ["valid"])
    assert _probe(page, entry) == browser.PROOF_VALID
    assert browser._RESULT["proof_v"] == browser.PROOF_V
    no_status = _SpaProbePage([PORTAL + "/profile/"], ["valid"])
    assert browser._broker_probe(no_status, entry) == browser.PROOF_UNDECIDED


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
