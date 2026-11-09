"""Vaultwarden's account revision date: the cheap "has the vault changed?" check.

tp#1963: a full vault read is unlock + sync + list + lock of the ``bw`` CLI
(~25-30 s). Vaultwarden bumps an account's revision date on every change the
account can see (its own items, an organisation item it reaches, a collection
or membership change); Bitwarden's own clients skip a sync while it is
unchanged. ``RevisionProbe`` asks for it directly: an OAuth
``client_credentials`` token from the broker account's API key (cached in
memory until shortly before it expires), then ``GET
/api/accounts/revision-date``. The probe registers as its OWN device (a
stable id derived from the client id), so it never touches the session of the
``bw`` CLI.

Any problem (network, TLS, HTTP status, an unexpected body) answers None:
the caller then reads the vault in full, exactly as before. The token and
the client secret never reach an exception, a log line or a return value.
"""

from __future__ import annotations

import json
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Callable
from typing import Any

REVISION_TIMEOUT_S = 10.0
# A cached token is dropped this long before the server says it expires.
TOKEN_MARGIN_S = 60.0
MAX_RESPONSE_BYTES = 64 * 1024
DEVICE_NAME = "login-broker revision check"
# Bitwarden's DeviceType ``MacOsCLI``.
DEVICE_TYPE = "24"
USER_AGENT = "login-broker-revision/1"

# (request, timeout_s) -> (HTTP status, body bytes); raises OSError on a
# transport failure. Tests inject a fake.
Transport = Callable[[urllib.request.Request, float], tuple[int, bytes]]


class _Unavailable(Exception):
    """The revision cannot be read; `code` is a fixed, secret-free reason."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _stderr(line: str) -> None:
    print(line, file=sys.stderr, flush=True)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is an error: the token request is never re-sent anywhere."""

    def redirect_request(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def _ssl_context() -> ssl.SSLContext:
    try:
        import certifi  # pylint: disable=import-outside-toplevel

        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:  # pragma: no cover - certifi ships with requests
        return ssl.create_default_context()


def https_transport(req: urllib.request.Request, timeout_s: float) -> tuple[int, bytes]:
    """The real transport: no proxy, no redirect, certifi's roots."""
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _NoRedirect(),
        urllib.request.HTTPSHandler(context=_ssl_context()),
    )
    try:
        with opener.open(req, timeout=timeout_s) as resp:
            return int(resp.status), resp.read(MAX_RESPONSE_BYTES)
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        exc.close()
        return status, b""


def device_id(server_url: str, client_id: str) -> str:
    """The probe's stable Vaultwarden device id (no secret goes into it)."""
    return str(
        uuid.uuid5(
            uuid.NAMESPACE_URL, f"login-broker-revision:{server_url}:{client_id}"
        )
    )


class RevisionProbe:
    """Answers the account revision date (a string) or None; thread-safe."""

    def __init__(
        self,
        *,
        transport: Transport = https_transport,
        clock: Callable[[], float] = time.monotonic,
        timeout_s: float = REVISION_TIMEOUT_S,
        log: Callable[[str], None] = _stderr,
    ) -> None:
        self.transport = transport
        self.clock = clock
        self.timeout_s = timeout_s
        self.log = log
        self._lock = threading.Lock()
        # ((server_url, client_id), token, expires_at by `clock`)
        self._token: tuple[tuple[str, str], str, float] | None = None
        # The last answer's reason code ("" = read); a change is logged once.
        self.problem = ""

    def revision(
        self, server_url: str, client_id: str, client_secret: str
    ) -> str | None:
        """The revision date as Vaultwarden returns it (milliseconds since the
        epoch, as a string), or None when it cannot be read."""
        with self._lock:
            value: str | None = None
            try:
                value = self._revision(server_url, client_id, client_secret)
                problem = ""
            except _Unavailable as exc:
                problem = exc.code
            except Exception as exc:  # pylint: disable=broad-exception-caught  # any failure = full read
                # the class name only: a message could quote a request
                problem = f"error:{type(exc).__name__}"
            if problem:
                self._token = None
            if problem != self.problem:
                self.problem = problem
                self.log(
                    f"vault revision check unavailable ({problem}): full vault reads"
                    if problem
                    else "vault revision check available again"
                )
            return value

    def forget(self) -> None:
        """Drop the cached token."""
        with self._lock:
            self._token = None

    def _revision(self, server_url: str, client_id: str, client_secret: str) -> str:
        if not server_url.startswith("https://"):
            raise _Unavailable("not_https")
        base = server_url.rstrip("/")
        key = (base, client_id)
        cached = self._token
        if cached is not None and cached[0] == key and self.clock() < cached[2]:
            status, body = self._get_revision(base, cached[1])
            if status != 401:
                return _parse_revision(status, body)
            self._token = None
        token = self._new_token(base, client_id, client_secret)
        status, body = self._get_revision(base, token)
        return _parse_revision(status, body)

    def _new_token(self, base: str, client_id: str, client_secret: str) -> str:
        form = urllib.parse.urlencode(
            {
                "grant_type": "client_credentials",
                "scope": "api",
                "client_id": client_id,
                "client_secret": client_secret,
                "deviceIdentifier": device_id(base, client_id),
                "deviceName": DEVICE_NAME,
                "deviceType": DEVICE_TYPE,
            }
        ).encode()
        req = urllib.request.Request(
            f"{base}/identity/connect/token",
            data=form,
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
            },
        )
        status, body = self.transport(req, self.timeout_s)
        if status != 200:
            raise _Unavailable(f"token_http_{status}")
        try:
            data = json.loads(body)
        except ValueError as exc:
            raise _Unavailable("token_bad_body") from exc
        token = data.get("access_token") if isinstance(data, dict) else None
        if not isinstance(token, str) or not token:
            raise _Unavailable("token_bad_body")
        expires = data.get("expires_in")
        if isinstance(expires, int) and not isinstance(expires, bool) and expires > 0:
            ttl = float(expires) - TOKEN_MARGIN_S
            if ttl > 0:
                self._token = ((base, client_id), token, self.clock() + ttl)
        return token

    def _get_revision(self, base: str, token: str) -> tuple[int, bytes]:
        req = urllib.request.Request(
            f"{base}/api/accounts/revision-date",
            method="GET",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
            },
        )
        return self.transport(req, self.timeout_s)


def _parse_revision(status: int, body: bytes) -> str:
    """A non-negative integer body (Vaultwarden: epoch ms) as a string."""
    if status != 200:
        raise _Unavailable(f"revision_http_{status}")
    try:
        value = json.loads(body)
    except ValueError as exc:
        raise _Unavailable("revision_bad_body") from exc
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise _Unavailable("revision_bad_body")
    return str(value)
