"""The rule for an item's ``agent_storage_keys`` (WS3) — one leaf module.

`broker/vault.py` refuses an item whose field breaks it; `broker/onboarding.py`
judges a ``sites`` view with the same function, so the broker and the
onboarding review never disagree. Imports only `broker.origins`.

The field is a JSON object ``{origin: [key, ...]}``: at most
``MAX_STORAGE_ORIGINS`` origins, each parsing to EXACTLY one origin
(`origins.parse_fill_origins`; dev mode keeps ``http://127.0.0.1:<port>``),
no two normalising to the same origin, each with 1..``MAX_STORAGE_KEYS``
distinct keys, every key a string of 1..``MAX_STORAGE_KEY_LEN`` characters
without whitespace or control characters. The reasons are fixed strings —
never a key, an origin or a value.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

from broker.origins import parse_fill_origins

MAX_STORAGE_ORIGINS = 8
MAX_STORAGE_KEYS = 16
MAX_STORAGE_KEY_LEN = 128
_KEY_BAD = re.compile(r"[\s\x00-\x1f\x7f-\x9f]")


# One early return per rule.
def _keys_problem(keys: object) -> str:  # pylint: disable=too-many-return-statements
    """Why one origin's key list breaks the rule ('' = fine)."""
    if not isinstance(keys, list):
        return "expected {origin: [keys]}"
    if not keys:
        return "an origin without keys"
    if len(keys) > MAX_STORAGE_KEYS:
        return f"more than {MAX_STORAGE_KEYS} keys on one origin"
    if not all(isinstance(k, str) for k in keys):
        return "a key is not a string"
    if any(not k or len(k) > MAX_STORAGE_KEY_LEN or _KEY_BAD.search(k) for k in keys):
        return (
            f"a key is empty, longer than {MAX_STORAGE_KEY_LEN} characters or holds "
            "whitespace / control characters"
        )
    if len(set(keys)) != len(keys):
        return "a key is listed twice"
    return ""


# One early return per rule, in the order a reader checks them.
def parse_storage_keys(  # pylint: disable=too-many-return-statements
    value: object, *, dev: bool = False
) -> tuple[dict[str, list[str]] | None, str]:
    """(``{normalised origin: keys}``, '') of a parsed ``agent_storage_keys``
    value, or (None, why it is refused — a fixed string)."""
    if not isinstance(value, Mapping):
        return None, "not an object"
    if len(value) > MAX_STORAGE_ORIGINS:
        return None, f"more than {MAX_STORAGE_ORIGINS} origins"
    out: dict[str, list[str]] = {}
    for origin, keys in value.items():
        if not isinstance(origin, str):
            return None, "an origin is not a string"
        try:
            parsed = parse_fill_origins(origin, dev=dev)
        except ValueError:
            return None, "an origin is not an https://host[:port] origin"
        if len(parsed) != 1:
            return None, "expected exactly one origin per entry"
        if parsed[0] in out:
            return None, "two origins normalise to one"
        problem = _keys_problem(keys)
        if problem:
            return None, problem
        out[parsed[0]] = list(keys)
    return out, ""


def storage_keys_problem(value: object, *, dev: bool = False) -> str:
    """'' when `value` passes `parse_storage_keys`, else why not."""
    return parse_storage_keys(value, dev=dev)[1]
