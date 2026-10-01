"""Exact-origin checks: where the broker may type a secret.

Every comparison is scheme + host + port equality on parsed URLs — never a
substring or suffix test (``https://auth.cscs.ch.evil.example`` and
``https://evil.example/?auth.cscs.ch`` both fail). Plain ``http`` is accepted
only for ``127.0.0.1`` and only in dev mode (the hermetic end-to-end test).
"""

from __future__ import annotations

import re
import urllib.parse

DEV_HOST = "127.0.0.1"
_HOST_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$"
)
_DEFAULT_PORTS = {"https": 443, "http": 80}


# One early return per rejection reason reads as the checklist it is.
def _origin_of(url: str, *, dev: bool) -> str | None:  # pylint: disable=too-many-return-statements
    """Normalised ``scheme://host[:port]`` of `url`, or None when not acceptable.

    Not acceptable: unparseable, userinfo present, a scheme other than https
    (http only for 127.0.0.1 with `dev`), or a host that is not a plain
    lowercase DNS name / the dev loopback address.
    """
    try:
        parts = urllib.parse.urlsplit(url.strip())
        host = parts.hostname
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if not host or parts.username is not None or parts.password is not None:
        return None
    if "@" in parts.netloc:
        return None
    host = host.lower()
    if scheme == "https":
        if not _HOST_RE.match(host):
            return None
    elif scheme == "http":
        if not (dev and host == DEV_HOST):
            return None
    else:
        return None
    if port is None or port == _DEFAULT_PORTS[scheme]:
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def parse_fill_origins(field: str, *, dev: bool = False) -> list[str]:
    """Parse an ``agent_fill_origins`` field into normalised origins.

    Entries are comma- or newline-separated; each must be exactly
    ``https://host[:port]`` (a bare trailing ``/`` is tolerated) with no path,
    query, fragment or userinfo. Raises ``ValueError`` on anything else or when
    the field holds no origin at all. With `dev`, ``http://127.0.0.1:<port>`` is
    accepted too.
    """
    out: list[str] = []
    for raw in re.split(r"[,\n]", field or ""):
        entry = raw.strip()
        if not entry:
            continue
        try:
            parts = urllib.parse.urlsplit(entry)
        except ValueError as exc:
            raise ValueError(f"unparseable origin: {entry!r}") from exc
        if parts.path not in ("", "/") or parts.query or parts.fragment:
            raise ValueError(f"origin must not carry a path/query/fragment: {entry!r}")
        if entry.endswith("?") or entry.endswith("#"):
            raise ValueError(f"origin must not carry a path/query/fragment: {entry!r}")
        origin = _origin_of(entry, dev=dev)
        if origin is None:
            raise ValueError(f"not an https://host[:port] origin: {entry!r}")
        if origin not in out:
            out.append(origin)
    if not out:
        raise ValueError("no origin given")
    return out


def url_origin(url: str, *, dev: bool = False) -> str | None:
    """Normalised ``scheme://host[:port]`` of `url`, or None when not acceptable
    (non-https, ``chrome-error://``, userinfo, odd host; http only in dev)."""
    return _origin_of(url, dev=dev)


def origin_allowed(url: str, allowed: list[str], *, dev: bool = False) -> bool:
    """True iff `url`'s origin equals one of `allowed` exactly (scheme, host, port)."""
    origin = _origin_of(url, dev=dev)
    return origin is not None and origin in allowed


def form_action_allowed(
    page_url: str, action: str | None, allowed: list[str], *, dev: bool = False
) -> bool:
    """True iff the form `action` (resolved against `page_url`) is on an allowed origin.

    An absent or empty action submits to the page itself.
    """
    target = urllib.parse.urljoin(page_url, action) if action else page_url
    return origin_allowed(target, allowed, dev=dev)
