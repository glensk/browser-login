#!/usr/bin/env python3
"""RFC 6238 conformance for the daemon's stdlib TOTP generator.

The CSCS login daemon runs under a service account with no third-party packages,
so it cannot use `pyotp`. These are the published RFC 6238 test vectors: if this
drifts, the daemon submits wrong one-time codes and walks the account into a
Keycloak lockout, which is exactly the failure that must never ship.

Run: python3 -m pytest tests/ -q     (from the repo root)
"""

from __future__ import annotations

# pylint: disable=protected-access,import-error,missing-function-docstring
import importlib.util
import sys
from pathlib import Path

import pytest

_FLOW = Path(__file__).resolve().parent.parent / "daemon" / "cscs_login_flow.py"


def _load():
    spec = importlib.util.spec_from_file_location("cscs_login_flow_under_test", _FLOW)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["cscs_login_flow_under_test"] = mod
    spec.loader.exec_module(mod)
    return mod


flow = _load()

# RFC 6238 Appendix B uses the ASCII seed "12345678901234567890" (SHA-1).
# Base32 of that seed, and the published 8-digit codes truncated to the 6 digits
# Keycloak asks for.
RFC_SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
RFC_VECTORS = [
    (59, "287082"),
    (1111111109, "081804"),
    (1111111111, "050471"),
    (1234567890, "005924"),
    (2000000000, "279037"),
]


@pytest.mark.parametrize("at,expected", RFC_VECTORS)
def test_rfc6238_vectors(at, expected):
    assert flow.totp_now(RFC_SEED, at=at) == expected


def test_accepts_lowercase_and_spaced_seed():
    spaced = "gezd gnbv gy3t qojq gezd gnbv gy3t qojq"
    assert flow.totp_now(spaced, at=59) == "287082"


def test_accepts_otpauth_uri():
    uri = f"otpauth://totp/CSCS:aglensk?secret={RFC_SEED}&issuer=CSCS"
    assert flow.totp_now(uri, at=59) == "287082"


def test_unpadded_seed_is_padded_not_rejected():
    # Real seeds are not always a multiple of 8 base32 chars; a naive
    # b32decode raises on those, which would break every login.
    assert len(flow.totp_now("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQABCDEFG", at=59)) == 6


def test_rejects_non_base32_seed():
    with pytest.raises(flow.LoginError):
        flow.totp_now("not!valid!base32", at=59)


def test_otpauth_uri_without_secret_is_rejected():
    with pytest.raises(flow.LoginError):
        flow.totp_now("otpauth://totp/CSCS:aglensk?issuer=CSCS", at=59)


def test_auth_rejected_is_a_login_error():
    # The daemon's lockout guard keys on this distinction.
    assert issubclass(flow.AuthRejected, flow.LoginError)
