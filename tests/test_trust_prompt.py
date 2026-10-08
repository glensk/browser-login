"""Post-login "Trust this browser?" prompt (tp#835, Zoho): the detector in
``broker.page_state`` finds only the confirming button of a known prompt."""

from __future__ import annotations

# pylint: disable=missing-function-docstring,missing-class-docstring,import-error
# pylint: disable=wrong-import-position,too-few-public-methods
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from broker.page_state import trust_prompt_button  # noqa: E402


class FakeButton:
    def __init__(self, label: str, *, visible: bool = True, value: str = "") -> None:
        self.label = label
        self.visible = visible
        self.value = value

    def inner_text(self) -> str:
        return self.label

    def get_attribute(self, name: str) -> str | None:
        return self.value if name == "value" else None

    def is_visible(self) -> bool:
        return self.visible


class FakePage:
    def __init__(self, text: str, buttons: list[Any]) -> None:
        self.text = text
        self.buttons = buttons

    def inner_text(self, selector: str, timeout: float = 0) -> str:
        assert selector == "body" and timeout
        return self.text

    def query_selector_all(self, _selector: str) -> list[Any]:
        return self.buttons


ZOHO = (
    "Trust this browser?\nWe won't ask you to verify your account with "
    "Two-Factor Authentication on this browser for the next 180 days."
)


def test_zoho_prompt_picks_trust_not_not_now() -> None:
    trust = FakeButton("Trust")
    page = FakePage(ZOHO, [FakeButton("Not now"), trust])
    assert trust_prompt_button(page) is trust


def test_no_prompt_text_means_no_click() -> None:
    page = FakePage(
        "Sign in to Zoho\nPassword", [FakeButton("Trust"), FakeButton("Yes")]
    )
    assert trust_prompt_button(page) is None


def test_prompt_without_a_confirming_button_or_hidden_one() -> None:
    assert trust_prompt_button(FakePage(ZOHO, [FakeButton("Not now")])) is None
    assert (
        trust_prompt_button(FakePage(ZOHO, [FakeButton("Trust", visible=False)]))
        is None
    )


def test_stay_signed_in_input_button() -> None:
    yes = FakeButton("", value="Yes")
    page = FakePage("Stay signed in?\nDo this to reduce sign-in prompts.", [yes])
    assert trust_prompt_button(page) is yes
