"""Read Safari's cookie jar and pick ONE whitelisted site's session cookies.

Albert logs into some sites in Safari (Bitwarden autofill, passes the Cloudflare
"are you human" box); those sessions last for months. ``browser.py import-safari``
copies such a session into the shared Chromium so agents can reuse it — only for
the sites in ``SAFARI_SITES``, and never the bot-management cookies, which are
bound to Safari's user agent and IP.

Stdlib only. A cookie's value is never part of its ``repr``; callers that print
must print names, domains and expiry only.

Format (``Cookies.binarycookies``): magic ``cook``, big-endian page count and page
sizes; each page: header ``00 00 01 00``, little-endian cookie count and offsets;
each cookie: flags at 8 (1 = secure, 4 = httpOnly), offsets of url/name/path/value
at 16..32, expiry as Mac absolute time (double at 40, seconds since 2001-01-01).
"""

from __future__ import annotations

import fnmatch
import os
import struct
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_PATH = (
    "~/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies"
)
MAC_EPOCH = 978307200  # 2001-01-01T00:00:00Z as a unix timestamp
_PAGE_HEADER = b"\x00\x00\x01\x00"
_COOKIE_MIN = 56  # fixed part of a cookie record: up to and incl. the creation date

# Bot-management cookies (Cloudflare, Akamai): bound to Safari's user agent / IP,
# so copying them into Chromium would only make the site distrust the session.
# Analytics / ad cookies are harmless and stay in.
BOT_COOKIE_DENY: tuple[str, ...] = (
    "cf_clearance",
    "__cf_bm",
    "__cfruid",
    "_cfuvid",
    "_abck",
    "ak_bmsc",
    "bm_sz",
    "bm_mi",
    "bm_sv",
)


@dataclass(frozen=True)
class SafariSite:
    """Which cookies of Safari's jar belong to a site, and which never travel."""

    domains: tuple[str, ...]  # registrable domains; their subdomains match too
    deny: tuple[str, ...] = BOT_COOKIE_DENY  # fnmatch patterns on the cookie name
    broker_fallback: bool = False  # the login broker can log in when Safari can't
    # Names of the cookies that ARE the login (their presence/expiry is what the
    # overview reports); empty = any allowed cookie counts.
    session_cookies: tuple[str, ...] = ()
    # Imported by the unattended daily check. False where an import is not safe
    # or cannot work unattended (see SAFARI_SITES).
    auto: bool = True


SAFARI_SITES: dict[str, SafariSite] = {
    "anibis": SafariSite(("anibis.ch",), session_cookies=("mp_session_id",)),
    "tutti": SafariSite(("tutti.ch",), session_cookies=("mp_session_id",)),
    # Cloudflare challenges the automated browser on every Ricardo page, so a
    # copied session cannot be used there: agents work in Albert's Safari instead.
    "ricardo": SafariSite(("ricardo.ch",), session_cookies=("appSession",), auto=False),
    # Kleinanzeigen keeps an Auth0 refresh_token; using it from a second browser may
    # rotate it and log Safari out. Manual imports only until that is tested.
    "kleinanzeigen": SafariSite(
        ("kleinanzeigen.de",),
        broker_fallback=True,
        session_cookies=("refresh_token",),
        auto=False,
    ),
}


@dataclass(frozen=True)
class Cookie:
    """One cookie from Safari's jar (``value`` is never in the repr)."""

    domain: str
    name: str
    value: str = field(repr=False)
    path: str
    expires: float  # unix time
    secure: bool
    http_only: bool

    def to_playwright(self) -> dict:
        """The dict Playwright's ``BrowserContext.add_cookies`` takes."""
        return {
            "name": self.name,
            "value": self.value,
            "domain": self.domain,
            "path": self.path or "/",
            "expires": self.expires,
            "secure": self.secure,
            "httpOnly": self.http_only,
            "sameSite": "Lax",
        }


def default_path() -> Path:
    """Safari's cookie file: ``$SAFARI_COOKIES`` or the sandbox container path."""
    return Path(os.path.expanduser(os.environ.get("SAFARI_COOKIES") or DEFAULT_PATH))


def _cstring(rec: bytes, off: int) -> str:
    """The NUL-terminated string at `off` inside one cookie record."""
    if not 0 <= off < len(rec):
        raise ValueError(f"string offset {off} outside the cookie record")
    end = rec.find(b"\0", off)
    if end < 0:
        raise ValueError("unterminated string in a cookie record")
    return rec[off:end].decode("latin-1")


def _parse_cookie(rec: bytes) -> Cookie:
    """One cookie record (bounds already checked by the caller)."""
    flags = struct.unpack_from("<I", rec, 8)[0]
    url_o, name_o, path_o, value_o = struct.unpack_from("<4I", rec, 16)
    expiry = struct.unpack_from("<d", rec, 40)[0]
    return Cookie(
        domain=_cstring(rec, url_o),
        name=_cstring(rec, name_o),
        value=_cstring(rec, value_o),
        path=_cstring(rec, path_o),
        expires=expiry + MAC_EPOCH,
        secure=bool(flags & 1),
        http_only=bool(flags & 4),
    )


def _parse_page(page: bytes) -> list[Cookie]:
    if len(page) < 8 or page[:4] != _PAGE_HEADER:
        raise ValueError("bad page header")
    count = struct.unpack_from("<I", page, 4)[0]
    if 8 + 4 * count > len(page):
        raise ValueError("truncated page (cookie offsets)")
    out = []
    for off in struct.unpack_from(f"<{count}I", page, 8):
        if off + 4 > len(page):
            raise ValueError("cookie offset outside its page")
        size = struct.unpack_from("<I", page, off)[0]
        if size < _COOKIE_MIN or off + size > len(page):
            raise ValueError("truncated cookie record")
        out.append(_parse_cookie(page[off : off + size]))
    return out


def parse_binarycookies(data: bytes) -> list[Cookie]:
    """Every cookie in a ``Cookies.binarycookies`` blob; ValueError when malformed."""
    if len(data) < 8 or data[:4] != b"cook":
        raise ValueError("not a Safari binarycookies file (bad magic)")
    try:
        n_pages = struct.unpack_from(">I", data, 4)[0]
        if 8 + 4 * n_pages > len(data):
            raise ValueError("truncated header (page sizes)")
        sizes = struct.unpack_from(f">{n_pages}I", data, 8)
        off = 8 + 4 * n_pages
        cookies: list[Cookie] = []
        for size in sizes:
            if off + size > len(data):
                raise ValueError("truncated page")
            cookies.extend(_parse_page(data[off : off + size]))
            off += size
    except struct.error as exc:
        raise ValueError(f"malformed binarycookies file: {exc}") from None
    return cookies


def read_binarycookies(path: str | os.PathLike[str] | None = None) -> list[Cookie]:
    """Parse Safari's cookie file (default: ``default_path()``).

    OSError when unreadable (Safari's container needs Full Disk Access for the
    calling terminal), ValueError when malformed.
    """
    return parse_binarycookies(Path(path or default_path()).read_bytes())


def domain_matches(domain: str, registrable: str) -> bool:
    """True if cookie `domain` is `registrable` or one of its subdomains."""
    d = domain.strip().lstrip(".").lower()
    r = registrable.strip().lstrip(".").lower()
    return bool(d and r) and (d == r or d.endswith("." + r))


def denied(name: str, rules: SafariSite) -> bool:
    """True if `name` is a bot-management cookie that must not travel."""
    return any(fnmatch.fnmatchcase(name, pat) for pat in rules.deny)


def site_cookies(
    cookies: Iterable[Cookie], site: str, *, now: float | None = None
) -> list[Cookie]:
    """`site`'s cookies from `cookies`: in its domains, not denied, not expired."""
    rules = SAFARI_SITES[site]
    at = time.time() if now is None else now
    return [
        c
        for c in cookies
        if any(domain_matches(c.domain, r) for r in rules.domains)
        and not denied(c.name, rules)
        and c.expires > at
    ]


def session_summary(
    site: str, path: str | os.PathLike[str] | None = None, *, now: float | None = None
) -> tuple[int, float | None]:
    """(number of usable cookies Safari holds for `site`, latest expiry or None).

    Reads names and expiry only; raises OSError / ValueError like
    ``read_binarycookies``.
    """
    picked = site_cookies(read_binarycookies(path), site, now=now)
    return len(picked), max((c.expires for c in picked), default=None)
