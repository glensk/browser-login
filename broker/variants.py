"""Variant policy: the byte patterns a secret value may show up as in output.

Vendored, pure-stdlib copy of the shared policy in mydotfiles'
``bin/secret_patterns.py`` (``secret_variants`` / ``VARIANT_POLICY_VERSION``,
tp#818). It is vendored, not imported, because the root-owned install must
never import from a user-writable path; ``tests/test_masker.py`` keeps the two
copies equal (bump ``VARIANT_POLICY_VERSION`` together with the shared copy).

Variants of a value (UTF-8, surrogates escaped), in this order:

* raw;
* base64 with and without padding, URL-safe base64 with and without padding;
* hex lower and upper case;
* percent-encoding (``urllib.parse.quote(value, safe="")``);
* extended (default): the JSON-string-escaped form (``ensure_ascii`` False,
  then True; quotes stripped) and the POSIX shell single-quoted form
  (``'…'``, every ``'`` as ``'"'"'``).

Every candidate is filtered on its own: empty, whitespace-only or shorter than
``VARIANT_MIN_BYTES`` -> dropped and COUNTED (shown by ``secret-run -v``),
never silently; duplicates are removed keeping the first (not counted);
candidates beyond ``VARIANT_CAP`` are counted as dropped. Nothing is derived
from a ``.strip()``-ed value: padding whitespace is part of the secret.
``raw_only`` (a short value an item explicitly allows) keeps only the raw form,
down to ``RAW_ONLY_MIN_BYTES``.
"""

from __future__ import annotations

import base64
import binascii
import json
import urllib.parse
from dataclasses import dataclass

VARIANT_POLICY_VERSION = 2
VARIANT_CAP = 16
VARIANT_MIN_BYTES = 8
RAW_ONLY_MIN_BYTES = 6


@dataclass(frozen=True)
class VariantSet:
    """The patterns of one value and how many candidate variants were dropped."""

    patterns: tuple[bytes, ...]
    dropped: int


def shell_single_quote(value: str) -> str:
    """POSIX ``'…'`` quoting: every ``'`` becomes ``'"'"'``."""
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _kept(candidate: bytes, min_bytes: int) -> bool:
    """False for an empty, whitespace-only or too-short candidate."""
    if len(candidate) < min_bytes:
        return False
    return bool(candidate.decode("utf-8", "surrogateescape").strip())


def secret_variants(
    value: str, *, extended: bool = True, raw_only: bool = False
) -> tuple[list[bytes], int]:
    """``(variants, dropped)`` of `value` — the shared-policy entry point."""
    raw = value.encode("utf-8", "surrogateescape")
    if raw_only:
        if _kept(raw, RAW_ONLY_MIN_BYTES):
            return [raw], 0
        return [], 1
    b64 = base64.b64encode(raw)
    url = base64.urlsafe_b64encode(raw)
    hexed = binascii.hexlify(raw)
    candidates = [
        raw,
        b64,
        b64.rstrip(b"="),
        url,
        url.rstrip(b"="),
        hexed,
        hexed.upper(),
        urllib.parse.quote(value, safe="", errors="surrogateescape").encode(
            "ascii", "replace"
        ),
    ]
    if extended:
        candidates += [
            json.dumps(value, ensure_ascii=False)[1:-1].encode(
                "utf-8", "surrogateescape"
            ),
            json.dumps(value, ensure_ascii=True)[1:-1].encode("ascii"),
            shell_single_quote(value).encode("utf-8", "surrogateescape"),
        ]
    kept: list[bytes] = []
    seen: set[bytes] = set()
    dropped = 0
    for candidate in candidates:
        if not _kept(candidate, VARIANT_MIN_BYTES):
            dropped += 1
            continue
        if candidate in seen:
            continue
        if len(kept) >= VARIANT_CAP:
            dropped += 1
            continue
        seen.add(candidate)
        kept.append(candidate)
    return kept, dropped


def variant_set(
    value: str, *, extended: bool = True, raw_only: bool = False
) -> VariantSet:
    """``secret_variants`` as a ``VariantSet``."""
    patterns, dropped = secret_variants(value, extended=extended, raw_only=raw_only)
    return VariantSet(tuple(patterns), dropped)
