"""One-time codes split into one-digit boxes (CSCS Keycloak, tp#1675).

CSCS's Keycloak theme (2026-11-03) asks for the TOTP in six one-character
boxes under "One-Time Code"; ``OTP_SELECTOR`` misses them and a ``fill`` into
the first box keeps one digit. Here: the pure group judge
(``otp_detect.split_otp_group_like``) on descriptor dicts.

Hermetic: no Chromium, no network.

Run: uv run --no-sync pytest tests/test_split_otp.py
"""

from __future__ import annotations

# pylint: disable=protected-access,missing-function-docstring,import-error
# pylint: disable=wrong-import-position
import re
import sys
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from broker import otp_detect  # noqa: E402

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
