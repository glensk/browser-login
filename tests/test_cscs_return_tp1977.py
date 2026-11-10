"""CSCS: the portal's Keycloak return endpoint refuses the answer (tp#1977).

After a submit Keycloak accepted, ``https://portal.cscs.ch/api-auth/keycloak/
complete/`` intermittently answers a JSON 400 ("keycloak error: Invalid auth
state.") instead of redirecting on to the portal app; the recipe then waited
out its settle time there and ended "did not reach the CSCS portal", which
quarantined the item. Now ``cscs_login`` makes ONE more trip to the portal's
start URL (fresh OIDC state, Keycloak's new session answers without a form)
and never types or submits anything a second time.

Hermetic: no Chromium, no network, no live CSCS login.

Run: uv run --no-sync pytest tests/test_cscs_return_tp1977.py
"""

from __future__ import annotations

# pylint: disable=protected-access,missing-function-docstring,import-error
# pylint: disable=wrong-import-position
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from broker import recipes, vault  # noqa: E402

AUTH = "https://auth.cscs.ch"
KC_POST = AUTH + "/auth/realms/cscs/login-actions/authenticate"
START = "https://portal.cscs.ch/profile/"
RETURN = "https://portal.cscs.ch/api-auth/keycloak/complete/?state=s&code=c"
PORTAL = "https://portal.cscs.ch/profile/"


class _Page:
    """A fake page: the submit lands on `after_submit`, whose document is
    JSON when `json` is set; every ``goto`` is recorded."""

    def __init__(self, after_submit: str, *, json: bool) -> None:
        self.url = START
        self.after_submit = after_submit
        self.json = json
        self.gotos: list[str] = []
        self.waits = 0

    def goto(self, url: str, **_k: Any) -> None:
        self.gotos.append(url)
        self.url = url

    def wait_for_timeout(self, _ms: float) -> None:
        self.waits += 1

    def evaluate(self, js: str, _arg: Any = None) -> Any:
        if js == recipes._CSCS_RETURN_ERROR_JS:
            return self.json and recipes.cscs_on_return(self.url)
        if js == recipes._KC_PAGE_HINT_JS:
            return {"path": urlpath(self.url), "fields": []}
        return ""


def urlpath(url: str) -> str:
    return "/" + url.split("://", 1)[1].split("/", 1)[1].split("?", 1)[0]


class _Rig:  # pylint: disable=too-few-public-methods
    """The recipe's collaborators, counted: password fills and submits."""

    def __init__(self) -> None:
        self.fills = 0
        self.submits = 0
        self.rejoin_looks = 0


def _rig(monkeypatch: pytest.MonkeyPatch, page: _Page, rejoin: Any) -> tuple[_Rig, Any]:
    """Wire ``cscs_login`` to `page`; `rejoin` is what the form wait after
    the fresh start does (returns a value or raises)."""
    rig = _Rig()

    def fill(_p: Any, field: Any, *_a: Any, **_k: Any) -> Any:
        rig.fills += 1
        return field

    def submit(*_a: Any, **_k: Any) -> bool:
        rig.submits += 1
        page.url = page.after_submit
        return True

    def form_or_portal(_p: Any, _timeout_s: float) -> Any:
        rig.rejoin_looks += 1
        if isinstance(rejoin, BaseException):
            raise rejoin
        if rejoin is None:
            page.url = PORTAL
        return rejoin

    monkeypatch.setattr(recipes, "cscs_item_problem", lambda *_a, **_k: "")
    monkeypatch.setattr(recipes, "cscs_start_url", lambda *_a, **_k: START)
    monkeypatch.setattr(recipes, "_cscs_password_field", lambda *_a, **_k: object())
    monkeypatch.setattr(recipes, "_fill_password", fill)
    monkeypatch.setattr(recipes, "_guard", lambda *_a, **_k: None)
    monkeypatch.setattr(recipes, "click_keycloak_submit", submit)
    monkeypatch.setattr(recipes, "_cscs_form_or_portal", form_or_portal)
    monkeypatch.setattr(recipes, "_otp_target", lambda *_a, **_k: None)
    monkeypatch.setattr(
        recipes,
        "ChallengeWatch",
        lambda: SimpleNamespace(clear=lambda _p: True, final=lambda _p: None),
    )
    item = SimpleNamespace(fill_origins=[AUTH], otp_label=None)
    return rig, item


def _secret() -> vault.Secret:
    return vault.Secret("someone", "not-a-real-password", None)


def _login(page: _Page, item: Any, settle_s: float = 30.0) -> None:
    recipes.cscs_login(page, item, _secret(), settle_s=settle_s)


def test_a_refused_return_rejoins_the_portal_once_without_typing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    page = _Page(RETURN, json=True)
    rig, item = _rig(monkeypatch, page, None)
    _login(page, item)
    assert page.gotos == [START, START]  # the login's start, then ONE rejoin
    assert (rig.fills, rig.submits, rig.rejoin_looks) == (1, 1, 1)
    assert page.url == PORTAL
    assert page.waits <= 2  # the JSON error ends the settle wait at once


def test_a_rejoin_that_asks_for_the_password_again_types_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    page = _Page(RETURN, json=True)
    form = recipes.KeycloakForm(object(), object())
    rig, item = _rig(monkeypatch, page, form)
    with pytest.raises(recipes.LoginFailed, match="not typed twice") as err:
        _login(page, item)
    assert err.value.submitted
    assert "CSCS portal" in err.value.detail
    assert page.gotos == [START, START]
    assert (rig.fills, rig.submits, rig.rejoin_looks) == (1, 1, 1)


def test_a_rejoin_that_finds_nothing_is_a_submitted_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    page = _Page(RETURN, json=True)
    nothing = recipes.LoginFailed("Keycloak login form not found (on /x)")
    rig, item = _rig(monkeypatch, page, nothing)
    with pytest.raises(recipes.LoginFailed, match="CSCS portal") as err:
        _login(page, item)
    assert err.value.submitted and "form not found" in err.value.detail
    assert (rig.submits, rig.rejoin_looks) == (1, 1)


def test_a_challenge_on_the_rejoin_needs_a_human_after_the_submit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    page = _Page(RETURN, json=True)
    challenge = recipes.NeedsHuman("bot challenge", challenge={"kind": "x"})
    _rig_, item = _rig(monkeypatch, page, challenge)
    with pytest.raises(recipes.NeedsHuman) as err:
        _login(page, item)
    assert err.value.submitted and err.value.challenge == {"kind": "x"}
    assert _rig_.submits == 1


def test_a_return_page_that_never_moves_rejoins_after_the_settle_wait(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    page = _Page(RETURN, json=False)  # no JSON answer: only the deadline ends it
    rig, item = _rig(monkeypatch, page, None)
    _login(page, item, settle_s=0.2)
    assert page.gotos == [START, START]
    assert (rig.submits, rig.rejoin_looks) == (1, 1)


def test_a_failure_elsewhere_keeps_the_old_error_and_no_rejoin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    page = _Page(KC_POST, json=True)  # still on Keycloak: nothing to rejoin
    rig, item = _rig(monkeypatch, page, None)
    with pytest.raises(recipes.LoginFailed, match="CSCS portal") as err:
        _login(page, item, settle_s=0.2)
    assert err.value.submitted and "(on /auth/realms/cscs" in err.value.detail
    assert page.gotos == [START]
    assert rig.rejoin_looks == 0


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://portal.cscs.ch/api-auth/keycloak/complete/", True),
        ("https://portal.cscs.ch/api-auth/keycloak/complete?state=s", True),
        ("https://portal.cscs.ch:443/api-auth/keycloak/complete/?code=c", True),
        ("http://portal.cscs.ch/api-auth/keycloak/complete/", False),
        ("https://portal.cscs.ch.evil.example/api-auth/keycloak/complete/", False),
        ("https://auth.cscs.ch/api-auth/keycloak/complete/", False),
        ("https://portal.cscs.ch:8443/api-auth/keycloak/complete/", False),
        ("https://portal.cscs.ch/api-auth/keycloak/init/", False),
        ("https://portal.cscs.ch/profile/", False),
        ("not a url", False),
    ],
)
def test_the_return_endpoint_is_matched_exactly(url: str, expected: bool) -> None:
    assert recipes.cscs_on_return(url) is expected
    assert not (recipes.cscs_on_return(url) and recipes.cscs_on_portal(url))


def test_the_json_check_is_value_free() -> None:
    js = recipes._CSCS_RETURN_ERROR_JS
    assert "contentType" in js and "innerText" not in js and "textContent" not in js


def test_an_unreadable_return_page_is_not_a_failure() -> None:
    def boom(_js: str) -> Any:
        raise RuntimeError("navigating")

    page = SimpleNamespace(url=RETURN, evaluate=boom)
    assert recipes._cscs_return_failed(page) is False
