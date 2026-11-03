"""One-time codes split into one-digit boxes (CSCS Keycloak, tp#1675).

CSCS's Keycloak theme (2026-11-03) asks for the TOTP in six one-character
boxes under "One-Time Code"; ``OTP_SELECTOR`` misses them and a ``fill`` into
the first box keeps one digit. Here: the pure group judge
(``otp_detect.split_otp_group_like``) on descriptor dicts, and the recipe's
target and wiring (``recipes._otp_target``, ``_settle``, ``cscs_login``) on a
scripted fake page (``_SplitOtpPage``).

Hermetic: no Chromium, no network.

Run: uv run --no-sync pytest tests/test_split_otp.py
"""

from __future__ import annotations

# pylint: disable=protected-access,missing-function-docstring,import-error
# pylint: disable=wrong-import-position
import base64
import os
import re
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from broker import login_form, otp_detect, recipes, vault  # noqa: E402

SEED = base64.b32encode(os.urandom(20)).decode()  # test-only, never a real seed
ORIGIN = "https://auth.cscs.ch"
URL = ORIGIN + "/auth/realms/cscs/login-actions/authenticate"

# ---------------------------------------------------------------------------
# A. split_otp_group_like on descriptor groups (what SPLIT_OTP_DESCRIBE_JS returns)
# ---------------------------------------------------------------------------

CSCS_CONTEXT = (
    "Two-Factor Authentication\nEnter the code from your authenticator app\n"
    "One-Time Code\nThe code will refresh automatically\nVerify Code"
)


def _box(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "type": "text",
        "name": "",
        "id": "",
        "autocomplete": "",
        "inputmode": "",
        "pattern": "",
        "maxlength": 1,
        "placeholder": "",
        "aria_label": "",
        "title": "",
        "labels": "",
        "context": "",
        "username": False,
        "in_form": True,
    }
    base.update(kw)
    return base


def _group(
    n: int = 6,
    context: str = CSCS_CONTEXT,
    first: dict[str, Any] | None = None,
    **kw: Any,
) -> dict[str, Any]:
    members = [_box(**kw) for _ in range(n)]
    if first is not None:
        members[0].update(first)
    return {
        "members": members,
        "indexes": list(range(n)),
        "total": n,
        "in_form": True,
        "context": context,
        "hidden_code": False,
    }


@pytest.mark.parametrize(
    "group",
    [
        _group(),  # the CSCS shape: no attributes, "One-Time Code" around
        _group(context="", first={"autocomplete": "one-time-code"}),
        _group(4),
        _group(8),
        _group(context="Enter your code", inputmode="numeric"),
    ],
    ids=["cscs", "autocomplete-first", "four", "eight", "numeric-code"],
)
def test_a_split_code_group_is_accepted(group: dict[str, Any]) -> None:
    assert otp_detect.split_otp_group_like(group)


def _with(group: dict[str, Any], i: int, **kw: Any) -> dict[str, Any]:
    group["members"][i].update(kw)
    return group


@pytest.mark.parametrize(
    "group",
    [
        _group(3),
        _group(9),
        _with(_group(), 2, maxlength=2),
        _with(_group(), 0, username=True),
        _group(context="Enter the SMS code we sent you"),
        _group(context="One-time backup code"),
        _group(context="Your initials"),  # 6 one-letter boxes, no code words
        _group(context="Enter your code"),  # a code word, but not numeric
        _group(context="", type="tel"),  # numeric, but no OTP or code word
        _with(_group(), 1, type="password"),
        _with(_group(), 3, maxlength=-1),
        {"members": "nope"},
        {},
    ],
    ids=[
        "three",
        "nine",
        "maxlength-2",
        "username",
        "sms",
        "backup",
        "initials",
        "code-not-numeric",
        "numeric-no-word",
        "password",
        "no-maxlength",
        "bad-members",
        "empty",
    ],
)
def test_a_group_that_is_no_split_code_is_rejected(group: dict[str, Any]) -> None:
    assert not otp_detect.split_otp_group_like(group)


def test_a_single_six_digit_field_is_no_split_group() -> None:
    field = _box(type="tel", maxlength=6, inputmode="numeric", context=CSCS_CONTEXT)
    group = {"members": [field], "context": CSCS_CONTEXT}
    assert not otp_detect.split_otp_group_like(group)
    assert otp_detect.otp_field_like(field)  # the single-field judge keeps it


def test_the_describe_script_is_value_free() -> None:
    js = otp_detect.SPLIT_OTP_DESCRIBE_JS
    assert not re.search(r"\.value\b", js)  # never a field's value
    assert otp_detect.OTP_DESCRIBE_JS in js
    assert "maxLength !== 1" in js


# ---------------------------------------------------------------------------
# B. a scripted split-code page
# ---------------------------------------------------------------------------


class _Prop:
    def __init__(self, value: Any) -> None:
        self.value = value

    def as_element(self) -> Any:
        return None if isinstance(self.value, str) else self.value

    def json_value(self) -> Any:
        return self.value


class _Handle:
    def __init__(self, props: dict[str, Any]) -> None:
        self.props = props

    def get_properties(self) -> dict[str, _Prop]:
        return {k: _Prop(v) for k, v in self.props.items()}


class _Element:
    """What every fake element answers: its frame, its form's action, its
    form's submit buttons."""

    def __init__(self, page: _SplitOtpPage, *, in_form: bool) -> None:
        self.page = page
        self.in_form = in_form
        self.attached = True
        self.frame_url = URL

    def live(self) -> None:
        if not self.attached:
            raise RuntimeError("Element is not attached to the DOM")

    def is_visible(self) -> bool:
        return self.attached

    def is_editable(self) -> bool:
        return True

    def owner_frame(self) -> Any:
        self.live()
        return SimpleNamespace(url=self.frame_url)

    def get_attribute(self, _name: str) -> Any:
        return None

    def evaluate(self, js: str, *args: Any) -> Any:
        self.live()
        if js == login_form.FORM_ACTION_JS:
            return {"form": self.in_form, "action": None}
        if js == "(a, b) => a === b":
            return args[0] is self
        return self.page.element_script(self, js)

    def evaluate_handle(self, js: str) -> _Handle:
        assert js == login_form.SUBMIT_BUTTONS_JS
        return _Handle({"0": self.page.button} if self.in_form else {})


class _Box(_Element):
    def __init__(self, page: _SplitOtpPage, i: int, *, in_form: bool) -> None:
        super().__init__(page, in_form=in_form)
        self.i = i
        self.value = ""
        self.fills: list[str] = []
        self.focuses = 0

    def focus(self) -> None:
        self.live()
        self.focuses += 1
        self.page.focused = self.i

    def click(self, **_kw: Any) -> None:
        self.focus()

    def fill(self, value: str) -> None:
        self.live()
        self.fills.append(value)
        if value == "" or self.page.takes_fill:
            self.value = value
            self.page.after_input(self.i)

    def press(self, key: str) -> None:
        self.page.enters.append(key)


class _Button(_Element):
    def is_enabled(self) -> bool:
        after = self.page.button_enabled_after_ms
        filled = self.page.filled_at
        return (
            after is not None
            and filled is not None
            and self.page.clock >= filled + after / 1000
        )

    def evaluate(self, js: str, *args: Any) -> Any:
        if js == login_form.BUTTON_DESCRIBE_JS:
            return {
                "name": "login",
                "id": "kc-login",
                "cls": "",
                "text": "Verify Code",
                "aria": "",
                "value": "",
                "formaction": "",
                "post_value": "",
                "disabled": not self.is_enabled(),
                "visible": True,
            }
        return super().evaluate(js, *args)

    def click(self, **_kw: Any) -> None:
        self.page.clicks.append(self.page.clock)


class _Keyboard:
    def __init__(self, page: _SplitOtpPage) -> None:
        self.page = page

    def press(self, key: str) -> None:
        page = self.page
        page.keys.append(key)
        page.clock += page.key_delay_ms / 1000
        if not page.takes_keys or page.focused is None:
            return
        i = page.focused
        if page.auto_advance == "off_by_one":
            i = min(i + 1, len(page.boxes) - 1)
        page.boxes[i].value = key
        if page.auto_advance != "none":
            page.focused = i + 1
        page.after_input(i)


class _SplitOtpPage:  # pylint: disable=too-many-instance-attributes
    """A split one-time-code page: `n` boxes (each records focus, key
    presses and fills), a hidden code input kept in sync by `hidden_sync`
    (``ok|wrong|empty|none``), a "Verify Code" button enabled
    `button_enabled_after_ms` after the last box filled (None: never), a
    page that submits itself after the last digit, and an injected clock
    (``wait_for_timeout`` and each key advance it)."""

    def __init__(  # pylint: disable=too-many-arguments
        self,
        n: int = 6,
        *,
        takes_keys: bool = True,
        takes_fill: bool = True,
        auto_advance: str = "ok",
        hidden_sync: str = "ok",
        self_submit_after_last: bool = False,
        in_form: bool = True,
        button_enabled_after_ms: float | None = 0,
        clock: float = 1_800_000_000.0,  # a step start (30 s steps)
        key_delay_ms: float = 0,
        password: bool = False,
    ) -> None:
        self.url = URL
        self.takes_keys = takes_keys
        self.takes_fill = takes_fill
        self.auto_advance = auto_advance
        self.hidden_sync = hidden_sync
        self.self_submit_after_last = self_submit_after_last
        self.in_form = in_form
        self.button_enabled_after_ms = button_enabled_after_ms
        self.clock = clock
        self.key_delay_ms = key_delay_ms
        self.password = _Element(self, in_form=True) if password else None
        self.single: Any = None  # an OTP_SELECTOR field
        self.boxes = [_Box(self, i, in_form=in_form) for i in range(n)]
        self.hidden = _Element(self, in_form=True)
        self.button = _Button(self, in_form=in_form)
        self.keyboard = _Keyboard(self)
        self.focused: int | None = None
        self.filled_at: float | None = None
        self.keys: list[str] = []
        self.enters: list[str] = []
        self.clicks: list[float] = []
        self.checks = 0
        self.events = 0
        self.waits: list[float] = []

    def now(self) -> float:
        return self.clock

    def goto(self, *_a: Any, **_k: Any) -> None:
        return None

    def wait_for_timeout(self, ms: float) -> None:
        self.waits.append(ms)
        self.clock += ms / 1000

    def after_input(self, i: int) -> None:
        if all(b.value for b in self.boxes):
            if self.filled_at is None:
                self.filled_at = self.clock
            if self.self_submit_after_last and i == len(self.boxes) - 1:
                self.url = URL + "?execution=done"
                for b in self.boxes:
                    b.attached = False

    def hidden_value(self) -> str | None:
        joined = "".join(b.value for b in self.boxes)
        return {
            "ok": joined,
            "wrong": ("1" if joined[:1] != "1" else "2") + joined[1:],
            "empty": "",
        }.get(self.hidden_sync)

    def groups(self) -> list[dict[str, Any]]:
        if len(self.boxes) < 2:
            return []
        group = _group(len(self.boxes), inputmode="numeric", in_form=self.in_form)
        group["in_form"] = self.in_form
        group["hidden_code"] = self.hidden_sync != "none"
        return [group]

    def check(self, boxes: list[Any], code: str) -> dict[str, Any]:
        self.checks += 1
        vals = [b.value if b.attached else None for b in boxes]
        hidden = self.hidden_value()
        state = "none"
        if hidden is not None:
            state = (
                "empty" if hidden == "" else "match" if hidden == code else "mismatch"
            )
        return {
            "boxes_ok": all(v == (code[i : i + 1]) for i, v in enumerate(vals)),
            "blank": all(v == "" for v in vals),
            "hidden": state,
        }

    def scope(self) -> dict[str, Any]:
        if self.in_form:
            return {"kind": "form", "anchor": self.boxes[0], "button": "null"}
        if self.hidden_sync != "none":
            return {"kind": "hidden-form", "anchor": self.hidden, "button": "null"}
        return {"kind": "button", "anchor": "null", "button": self.button}

    def element_script(self, element: Any, js: str) -> Any:
        if js == getattr(recipes, "_SPLIT_OTP_EVENTS_JS", None):
            self.events += 1
            return None
        raise AssertionError(f"unexpected element script on {element}: {js[:40]}")

    def evaluate(self, js: str, arg: Any = None) -> Any:
        if js == otp_detect.SPLIT_OTP_DESCRIBE_JS:
            return self.groups()
        if js == getattr(recipes, "SPLIT_OTP_CHECK_JS", None):
            boxes, code = arg
            return self.check(boxes, code)
        if js == recipes._KC_PAGE_HINT_JS:
            return {
                "path": "/auth/realms/cscs/login-actions/authenticate",
                "fields": ["text#otp-0/1"] * len(self.boxes),
            }
        if "selectedCredentialId" in js:
            return "single"
        return ""

    def evaluate_handle(self, js: str, _arg: Any = None) -> _Handle:
        assert js == getattr(recipes, "SPLIT_OTP_SCOPE_JS", None)
        return _Handle(self.scope())

    def query_selector_all(self, sel: str) -> list[Any]:
        if sel == "input":
            return list(self.boxes)
        if sel == recipes.PASSWORD_SELECTOR:
            return [self.password] if self.password is not None else []
        if sel == recipes.OTP_SELECTOR:
            return [self.single] if self.single is not None else []
        return []


class _SingleField(_Element):
    """A classic Keycloak ``#otp`` field on a page that posts once filled."""

    def __init__(self, page: _SplitOtpPage) -> None:
        super().__init__(page, in_form=True)
        self.fills: list[str] = []

    def fill(self, value: str) -> None:
        self.fills.append(value)
        self.page.url = URL + "?execution=done"
        self.attached = False


def _secret() -> vault.Secret:
    return vault.Secret(
        "someone", "pw-" + base64.b32encode(os.urandom(5)).decode(), SEED
    )


def test_a_single_otp_field_keeps_the_old_path() -> None:
    page = _SplitOtpPage(0)
    page.single = _SingleField(page)
    assert recipes._fill_otp(page, page.single, _secret(), [ORIGIN], dev=False)
    assert len(page.single.fills) == 1 and page.single.fills[0].isdigit()
    assert not page.keys and not page.clicks and not page.enters


def test_a_password_field_next_to_six_boxes_is_no_split_target() -> None:
    page = _SplitOtpPage(password=True)
    assert recipes._otp_target(page, generic=True) is None
    target = recipes._otp_target(page, generic=False)  # cscs has no such guard
    assert target is not None and target.boxes == tuple(page.boxes)


def test_a_box_that_is_the_credential_field_drops_the_target() -> None:
    page = _SplitOtpPage()
    assert recipes._settle_otp_target(page, page.boxes[2]) is None
    other = _Box(page, 9, in_form=True)  # an account field elsewhere
    target = recipes._settle_otp_target(page, other)
    assert target is not None and target.split and len(target.boxes) == 6
    assert target.hidden_code


def test_a_page_without_evaluate_falls_back_to_otp_field(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    field = object()
    monkeypatch.setattr(recipes, "_otp_field", lambda _page: field)
    page = SimpleNamespace(url=URL, wait_for_timeout=lambda _ms: None)
    target = recipes._otp_target(page, generic=True)
    assert target is not None and target.boxes == (field,) and not target.split


@pytest.mark.parametrize("result", ["", None, {"members": []}, [["x"]]])
def test_an_unreadable_describe_is_no_group(result: Any) -> None:
    page = _SplitOtpPage()
    page.groups = lambda: result  # type: ignore[method-assign]
    assert recipes._split_otp_group(page) is None


def test_a_page_that_changed_between_the_reads_is_no_group() -> None:
    page = _SplitOtpPage()
    groups = page.groups()
    page.groups = lambda: groups  # type: ignore[method-assign]
    page.boxes.append(_Box(page, 6, in_form=True))  # one more input now
    assert recipes._split_otp_group(page) is None


def _cscs_run(
    monkeypatch: pytest.MonkeyPatch, page: _SplitOtpPage
) -> list[tuple[Any, bool]]:
    calls: list[tuple[Any, bool]] = []

    def fill(_page: Any, target: Any, *_a: Any, generic: bool, **_k: Any) -> bool:
        calls.append((target, generic))
        page.url = "https://portal.cscs.ch/"
        return True

    class _Watch:
        def clear(self, _page: Any) -> bool:
            return True

        def final(self, _page: Any) -> None:
            return None

    monkeypatch.setattr(recipes, "cscs_item_problem", lambda *_a, **_k: "")
    monkeypatch.setattr(recipes, "cscs_start_url", lambda *_a, **_k: URL)
    monkeypatch.setattr(recipes, "_cscs_password_field", lambda *_a, **_k: object())
    monkeypatch.setattr(recipes, "_fill_password", lambda _p, field, *_a, **_k: field)
    monkeypatch.setattr(recipes, "_guard", lambda *_a, **_k: None)
    monkeypatch.setattr(recipes, "click_keycloak_submit", lambda *_a, **_k: True)
    monkeypatch.setattr(recipes, "ChallengeWatch", _Watch)
    monkeypatch.setattr(recipes, "_fill_otp", fill)
    item = SimpleNamespace(fill_origins=[ORIGIN], otp_label=None)
    recipes.cscs_login(page, item, _secret(), settle_s=2.0)  # type: ignore[arg-type]
    return calls


def test_cscs_waits_for_a_split_otp_step(monkeypatch: pytest.MonkeyPatch) -> None:
    page = _SplitOtpPage()
    calls = _cscs_run(monkeypatch, page)
    assert len(calls) == 1
    target, generic = calls[0]
    assert generic is False and target.boxes == tuple(page.boxes)


def test_kc_page_hint_marks_one_char_and_formless_fields() -> None:
    js = recipes._KC_PAGE_HINT_JS
    assert "e.maxLength === 1 ? '/1'" in js and "e.form ? '' : '!f'" in js
    page = SimpleNamespace(
        evaluate=lambda _js: {
            "path": "/auth/realms/cscs/login-actions/authenticate",
            "fields": ["text#otp-0/1!f", "tel#a-very-long-identifier-of-32-chars/1!f"],
        }
    )
    hint = recipes._kc_page_hint(page)
    assert "text#otp-0/1!f" in hint and "a-very-long-identifier-of-32-chars/1!f" in hint


def test_cscs_names_the_page_when_the_portal_never_came(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    page = _SplitOtpPage(0)  # no OTP step at all: the loop runs out
    monkeypatch.setattr(recipes, "cscs_item_problem", lambda *_a, **_k: "")
    monkeypatch.setattr(recipes, "cscs_start_url", lambda *_a, **_k: URL)
    monkeypatch.setattr(recipes, "_cscs_password_field", lambda *_a, **_k: object())
    monkeypatch.setattr(recipes, "_fill_password", lambda _p, field, *_a, **_k: field)
    monkeypatch.setattr(recipes, "_guard", lambda *_a, **_k: None)
    monkeypatch.setattr(recipes, "click_keycloak_submit", lambda *_a, **_k: True)
    monkeypatch.setattr(
        recipes,
        "ChallengeWatch",
        lambda: SimpleNamespace(clear=lambda _p: True, final=lambda _p: None),
    )
    item = SimpleNamespace(fill_origins=[ORIGIN], otp_label=None)
    with pytest.raises(recipes.LoginFailed, match="CSCS portal") as err:
        recipes.cscs_login(page, item, _secret(), settle_s=0.3)  # type: ignore[arg-type]
    assert err.value.submitted and "(on /auth/realms/cscs" in err.value.detail
