"""The variant policy (broker/variants.py) and the streaming masker
(broker/masker.py): property tests against a whole-buffer oracle.

Run: uv run --no-sync pytest tests/test_masker.py
"""

from __future__ import annotations

# pylint: disable=missing-function-docstring,import-error,wrong-import-position
import base64
import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from broker import masker, variants  # noqa: E402

STAR = b"*"


def _pats(value: str) -> list[bytes]:
    return list(variants.variant_set(value).patterns)


SECRET_ALPHABET = st.characters(codec="utf-8", exclude_characters="*")


def oracle(patterns: list[bytes], data: bytes, *, pty: bool = False) -> bytes:
    """Whole-buffer reference: union of every occurrence, plus the EOF suffix
    that is a prefix of a pattern; merged spans -> one ``***``."""
    pats = {p for p in patterns if p}
    if pty:
        pats |= {p.replace(b"\n", b"\r\n") for p in pats if b"\n" in p}
    covered = [False] * len(data)
    for pat in pats:
        start = data.find(pat)
        while start != -1:
            for i in range(start, start + len(pat)):
                covered[i] = True
            start = data.find(pat, start + 1)
    for k in range(min(len(data), max((len(p) for p in pats), default=0)), 0, -1):
        if any(p.startswith(data[-k:]) for p in pats):
            for i in range(len(data) - k, len(data)):
                covered[i] = True
            break
    out = bytearray()
    i = 0
    while i < len(data):
        if covered[i]:
            out += b"***"
            while i < len(data) and covered[i]:
                i += 1
        else:
            out.append(data[i])
            i += 1
    return bytes(out)


def stream(patterns: list[bytes], data: bytes, cuts: list[int], **kw) -> bytes:
    m = masker.Masker(patterns, **kw)
    out = bytearray()
    pos = 0
    for cut in sorted(set(c % (len(data) + 1) for c in cuts)) + [len(data)]:
        out += m.feed(data[pos:cut])
        pos = cut
    out += m.flush()
    return bytes(out)


@st.composite
def stream_case(draw):
    secrets_ = draw(
        st.lists(
            st.text(SECRET_ALPHABET, min_size=8, max_size=24), min_size=1, max_size=4
        )
    )
    if draw(st.booleans()) and len(secrets_[0]) > 3:  # shared prefixes / overlaps
        secrets_.append(
            secrets_[0][:3] + draw(st.text(SECRET_ALPHABET, min_size=3, max_size=8))
        )
    patterns = [p for s in secrets_ for p in _pats(s)]
    pieces = draw(
        st.lists(
            st.one_of(
                st.binary(max_size=20).map(lambda b: b.replace(STAR, b"")),
                st.sampled_from(patterns),
                st.sampled_from(patterns).map(lambda p: p[: max(1, len(p) // 2)]),
                st.just(b"\r\n"),
                st.text(max_size=10).map(lambda t: t.encode().replace(STAR, b"")),
            ),
            max_size=12,
        )
    )
    data = b"".join(pieces)
    cuts = draw(st.lists(st.integers(min_value=0, max_value=10_000), max_size=10))
    return patterns, data, cuts


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(stream_case())
def test_streaming_equals_oracle_and_leaks_nothing(case):
    patterns, data, cuts = case
    got = stream(patterns, data, cuts)
    assert got == oracle(patterns, data)
    for pat in patterns:
        assert pat not in got
    # one-byte chunks are the worst case for the hold-back
    assert stream(patterns, data, list(range(len(data)))) == got


@settings(max_examples=150, deadline=None)
@given(stream_case())
def test_pty_mode_matches_crlf_forms(case):
    patterns, data, cuts = case
    translated = data.replace(b"\n", b"\r\n")
    got = stream(patterns, translated, cuts, pty=True)
    assert got == oracle(patterns, translated, pty=True)
    for pat in patterns:
        assert pat.replace(b"\n", b"\r\n") not in got


@settings(max_examples=150, deadline=None)
@given(
    st.lists(st.text(SECRET_ALPHABET, min_size=8, max_size=20), min_size=1, max_size=3),
    st.binary(max_size=200),
    st.lists(st.integers(min_value=0, max_value=300), max_size=8),
)
def test_text_without_pattern_bytes_is_identical(secrets_, noise, cuts):
    patterns = [p for s in secrets_ for p in _pats(s)]
    used = set(b"".join(patterns))
    clean = bytes(b for b in noise if b not in used)
    assert stream(patterns, clean, cuts) == clean


@settings(max_examples=100, deadline=None)
@given(
    st.text(SECRET_ALPHABET, min_size=8, max_size=20),
    st.binary(max_size=40),
    st.binary(max_size=40),
    st.lists(st.integers(min_value=0, max_value=200), max_size=6),
)
def test_value_split_across_streams_is_masked_per_stream(value, pre, post, cuts):
    """Each stream has its own masker: a value printed whole on stdout and
    whole on stderr is masked on both; neither stream leaks it."""
    patterns = _pats(value)
    raw = value.encode()
    out = stream(patterns, pre.replace(STAR, b"") + raw, cuts)
    err = stream(patterns, raw + post.replace(STAR, b""), cuts)
    assert raw not in out and raw not in err


def test_eof_fragment_is_masked():
    pats = [b"supersecret1"]
    assert masker.mask_all(pats, b"log: super") == b"log: ***"
    assert masker.mask_all(pats, b"log: s") == b"log: ***"
    assert masker.mask_all(pats, b"log: x") == b"log: x"


def test_overlaps_merge_into_one_mask():
    pats = [b"abcdefgh", b"efghijkl"]
    assert masker.mask_all(pats, b"<abcdefghijkl>") == b"<***>"
    assert masker.mask_all(pats, b"<abcdefghabcdefgh>") == b"<***>"
    m = masker.Masker(pats)
    out = m.feed(b"x abcdefgh y efghijkl z") + m.flush()
    assert out == b"x *** y *** z" and m.masked == 2


def test_unicode_and_binary_noise():
    value = "pässwört-ünicode-🔑"
    pats = _pats(value)
    data = b"\x00\xff" + value.encode() + b"\xfe\n" + base64.b64encode(value.encode())
    got = masker.mask_all(pats, data)
    assert got == b"\x00\xff***\xfe\n***"


def test_no_patterns_passes_through():
    m = masker.Masker([])
    assert m.feed(b"abc") == b"abc" and m.flush() == b""


# ---------------------------------------------------------------------------
# variants
# ---------------------------------------------------------------------------


def test_variant_policy_forms():
    value = 'it\'s a $ecret, "quoted"\\'
    raw = value.encode()
    got = _pats(value)
    assert got[0] == raw
    assert base64.b64encode(raw) in got and base64.b64encode(raw).rstrip(b"=") in got
    assert base64.urlsafe_b64encode(raw) in got
    assert raw.hex().encode() in got and raw.hex().upper().encode() in got
    assert json.dumps(value)[1:-1].encode() in got
    assert variants.shell_single_quote(value).encode() in got
    assert variants.shell_single_quote("a'b") == "'a'\"'\"'b'"
    assert len(got) <= variants.VARIANT_CAP


def test_short_candidates_are_dropped_and_counted():
    patterns, dropped = variants.secret_variants("abcdef")  # 6 bytes
    assert b"abcdef" not in patterns and dropped >= 1
    assert all(len(p) >= variants.VARIANT_MIN_BYTES for p in patterns)
    eight, _ = variants.secret_variants("abcdefgh")
    assert eight[0] == b"abcdefgh"


def test_raw_only_short_values():
    vs = variants.variant_set("Ab3$xY7", raw_only=True)
    assert vs.patterns == (b"Ab3$xY7",) and vs.dropped == 0
    assert not variants.variant_set("Ab3$x", raw_only=True).patterns
    assert not variants.variant_set("       ", raw_only=True).patterns


@settings(max_examples=200, deadline=None)
@given(
    st.text(st.sampled_from(" \t\n\r"), min_size=0, max_size=4),
    st.text(min_size=0, max_size=12),
    st.text(st.sampled_from(" \t\n\r"), min_size=0, max_size=4),
)
def test_whitespace_never_yields_short_or_empty_patterns(lead, core, trail):
    value = lead + core + trail
    vs = variants.variant_set(value)
    for i, pat in enumerate(vs.patterns):
        assert pat.strip(), (value, pat)
        assert len(pat) >= variants.VARIANT_MIN_BYTES, (i, pat)


# ---------------------------------------------------------------------------
# parity with the shared policy in mydotfiles (tp#818 M1)
# ---------------------------------------------------------------------------

SHARED = Path(
    os.environ.get(
        "SECRET_PATTERNS_PY",
        str(Path.home() / "obsidian/42-Git/home/mydotfiles/bin/secret_patterns.py"),
    )
)
CORPUS = [
    "correct-horse-battery",
    'it\'s a $ecret, "quoted"\\',
    "pässwört-ünicode-🔑",
    "  padded value  ",
    "line1\nline2",
    "abcdef",
    "x" * 64,
    "tab\there",
]


def _shared_module():
    if not SHARED.is_file():
        pytest.skip(f"shared policy not reachable ({SHARED} missing)")
    spec = importlib.util.spec_from_file_location("shared_secret_patterns", SHARED)
    if spec is None or spec.loader is None:
        pytest.skip(f"cannot load {SHARED}")
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        pytest.skip(f"cannot import {SHARED}: {exc}")
    if not hasattr(mod, "secret_variants"):
        pytest.skip(f"{SHARED} has no secret_variants yet (tp#818 M1 not landed)")
    return mod


def test_parity_with_shared_policy():
    shared = _shared_module()
    if hasattr(shared, "VARIANT_POLICY_VERSION"):
        assert shared.VARIANT_POLICY_VERSION == variants.VARIANT_POLICY_VERSION
    for value in CORPUS:
        for kw in ({}, {"extended": False}, {"raw_only": True}):
            assert variants.secret_variants(value, **kw) == shared.secret_variants(
                value, **kw
            ), (value, kw)
