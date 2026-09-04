#!/usr/bin/env python3
"""Credential-side helpers for the CSCS login daemon. Stdlib only.

Why stdlib only: this runs under a dedicated service account whose whole runtime
lives in a root-only-writable directory. Every third-party import is one more
file an attacker holding the user's uid might influence, and one more supply
chain to trust. ``hmac`` + ``urllib`` cover what is needed here.

**A browserless Keycloak flow was attempted and does not work** (measured
2026-09-04, tp#144). The HTTP flow drives cleanly through Kerberos-SPNEGO,
username/password and the OTP step — all three accepted — and reaches the
portal's OIDC callback, which then answers:

    {"detail":"keycloak error: Invalid auth state."}

The portal validates a `state` it registers server-side when its SPA starts the
login. That registration is not a cookie (tested), is not among the 285
endpoints in the API root, and has no server-side initiation URL
(`/api-auth/keycloak/{login,start,begin,authorize}/` all 404). Driving it would
mean reverse-engineering an undocumented, changeable mechanism, so the daemon
performs the login in a private headless browser owned by the service account
with no CDP listener instead. What survives here is what that daemon still
needs: the one-time code, and the post-condition that a token really works.

Python 3.9 compatible (`from __future__ import annotations`).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import struct
import time
import urllib.error
import urllib.parse
import urllib.request

PORTAL_HOST = "portal.cscs.ch"
HEX40 = re.compile(r"\b[0-9a-f]{40}\b")
MAX_BODY = 4 * 1024 * 1024
USER_AGENT = "cscs-logind/1 (+browser-login)"


class LoginError(RuntimeError):
    """A login attempt failed. The message never contains a credential."""


class AuthRejected(LoginError):
    """Keycloak positively rejected the credentials (vs a transport failure).

    Separated because the caller must treat these differently: a definite
    rejection trips the lockout guard, a transport error does not.
    """


def totp_now(seed: str, *, at: float | None = None) -> str:
    """RFC 6238 6-digit TOTP from a base32 seed (or an ``otpauth://`` URI).

    Implemented here rather than via ``pyotp`` to keep the service account's
    runtime free of third-party code.
    """
    s = seed.strip()
    if s.lower().startswith("otpauth://"):
        query = urllib.parse.urlparse(s).query
        params = urllib.parse.parse_qs(query)
        secret_list = params.get("secret")
        if not secret_list:
            raise LoginError("otpauth URI carries no secret")
        s = secret_list[0]
    s = s.replace(" ", "").upper()
    s += "=" * (-len(s) % 8)
    try:
        key = base64.b32decode(s, casefold=True)
    except (ValueError, TypeError) as exc:
        raise LoginError("TOTP seed is not valid base32") from exc
    counter = int((time.time() if at is None else at) // 30)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{code % 1_000_000:06d}"


def verify_token(token: str, *, timeout: float = 30.0) -> str | None:
    """Return the username this token authenticates as, or ``None``.

    The daemon's post-condition: it never hands back a token it has not seen
    work. ``ProxyHandler({})`` is deliberate — ambient ``http_proxy``/``ALL_PROXY``
    must not steer this check through anything else.
    """
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(f"https://{PORTAL_HOST}/api/users/me/")
    req.add_header("Authorization", f"Token {token}")
    req.add_header("User-Agent", USER_AGENT)
    try:
        with opener.open(req, timeout=timeout) as resp:
            data = json.loads(resp.read(MAX_BODY))
    except (urllib.error.URLError, ValueError):
        return None
    username = data.get("username") if isinstance(data, dict) else None
    return str(username) if username else None
