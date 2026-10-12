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
import hashlib
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
# Analytics / ad cookies are harmless and stay in. Akamai Bot Manager names its
# cookies `bm_*` (bm_sz, bm_mi, bm_sv, bm_s, bm_so, bm_lso, …): one pattern for
# every site — an application cookie of a Safari site that starts with `bm_`
# would stay behind too (none known; add a site-specific `deny` if one shows up).
BOT_COOKIE_DENY: tuple[str, ...] = (
    "cf_clearance",
    "__cf_bm",
    "__cfruid",
    "_cfuvid",
    "_abck",
    "ak_bmsc",
    "bm_*",
    # Akamai's crypto challenge (sec_cpt) and its behavioral session cookies
    # (sbsd, sbsd_o, sbsd_ss): bound to the browser that solved them, too.
    "sec_cpt",
    "sbsd*",
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
    # Handled by the unattended daily check at all. False where even a check
    # makes no sense (see SAFARI_SITES).
    auto: bool = True
    # The daily check may IMPORT when its free check fails. False: it only
    # checks, the import runs by hand (`agent-login.py -t SITE`) — for a site
    # whose copied session's durability is unproven (an import replaces the
    # shared browser's cookies, possibly a newer rotated token, with Safari's).
    import_unattended: bool = True
    # The import also deletes the shared Chromium's OWN bot-management cookies
    # (the `deny` ones) in the site's domains, so the bot manager scores the
    # imported session afresh. For sites where Chromium's cookies carry a failed
    # verdict (Akamai `_abck` with validation flag -1 after rejected logins);
    # by default Chromium's own bot cookies stay.
    drop_bot_cookies: bool = False


SAFARI_SITES: dict[str, SafariSite] = {
    "anibis": SafariSite(("anibis.ch",), session_cookies=("mp_session_id",)),
    "tutti": SafariSite(("tutti.ch",), session_cookies=("mp_session_id",)),
    # Cloudflare challenges the automated browser on every Ricardo page, so a
    # copied session cannot be used there: agents work in Albert's Safari instead.
    "ricardo": SafariSite(("ricardo.ch",), session_cookies=("appSession",), auto=False),
    # Kleinanzeigen keeps an Auth0 refresh_token; tested: Chromium using a copy did
    # not log Safari out, so it is imported unattended like anibis/tutti.
    "kleinanzeigen": SafariSite(
        ("kleinanzeigen.de",),
        broker_fallback=True,
        session_cookies=("refresh_token",),
    ),
    # Galaxus (Akamai Bot Manager + reCAPTCHA) answers the headless broker's
    # password with "credentials wrong": the broker never submits there
    # (vault.NO_SUBMIT_SITES). The shop's `.at` (180 days, refreshes the 30-min
    # access token `.atinfo`) lives on www.galaxus.ch; the IdP session
    # (`.AspNetCore.Identity.Application`, `DeviceCookie_*`, `Tenant`) on
    # id.digitecgalaxus.ch. Chromium's own Akamai cookies hold the verdict of
    # the rejected broker logins, so they are dropped on import. Whether a
    # copied `.at` survives its refresh (rotation) and the IdP cookie's 30-day
    # expiry is unproven: the daily check only checks; imports run by hand.
    "galaxus": SafariSite(
        ("galaxus.ch", "digitecgalaxus.ch"),
        session_cookies=(".at",),
        drop_bot_cookies=True,
        import_unattended=False,
    ),
    # galaxus.de is a SEPARATE account (WS2): the shop on www.galaxus.de, its
    # IdP on id.galaxus.eu. Same Akamai/reCAPTCHA wall as galaxus.ch, so the
    # broker never submits (vault.NO_SUBMIT_SITES) and Chromium's own bot
    # cookies go on import. The session reaches Safari through an agent's
    # Safari login (`agent-login.py -L galaxus-de`, WS1b); imports run only
    # when explicitly asked (`-L`, `-t`), never from the daily check.
    "galaxus-de": SafariSite(
        ("galaxus.de", "galaxus.eu"),
        session_cookies=(".at",),
        drop_bot_cookies=True,
        import_unattended=False,
    ),
}

# browser.py BUILT-IN sites (not broker items) whose session an agent may copy
# from Safari with the explicit `browser.py import-safari SITE` (WS1b; Albert,
# 2026-10-11: agents log these in through his Safari). Consent is this table,
# not a vault item; the import's check is the built-in site's own `logged-in`.
# `login`/`logged-in` of these sites keep their own flows — only the explicit
# import knows them, so they are never imported unattended.
SAFARI_BUILTIN: dict[str, SafariSite] = {
    "notion": SafariSite(
        ("notion.so", "notion.com"),
        session_cookies=("token_v2",),
        import_unattended=False,
    ),
    "slack": SafariSite(
        ("slack.com",), session_cookies=("d",), import_unattended=False
    ),
    # next-auth splits a large session token into `.0`, `.1`, …
    "openai": SafariSite(
        ("chatgpt.com", "openai.com"),
        session_cookies=("__Secure-next-auth.session-token*",),
        import_unattended=False,
    ),
}


def rule(site: str) -> SafariSite:
    """`site`'s import rules (``SAFARI_SITES``, else ``SAFARI_BUILTIN``);
    KeyError for a site with neither."""
    found = SAFARI_SITES.get(site) or SAFARI_BUILTIN.get(site)
    if found is None:
        raise KeyError(site)
    return found


def importable_site(site: str) -> bool:
    """May `import-safari SITE` run at all (a broker-listed Safari site or a
    built-in one)?"""
    return site in SAFARI_SITES or site in SAFARI_BUILTIN


def is_session_cookie(name: str, site: str) -> bool:
    """True if cookie `name` is one of `site`'s session cookies (fnmatch
    patterns; a site that names none counts every allowed cookie)."""
    pats = rule(site).session_cookies
    return not pats or any(fnmatch.fnmatchcase(name, p) for p in pats)


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


def in_site(domain: str, site: str) -> bool:
    """True if cookie `domain` belongs to one of `site`'s domains."""
    return any(domain_matches(domain, r) for r in rule(site).domains)


def importable(domain: str, name: str, site: str) -> bool:
    """True if a cookie may be copied INTO the shared browser for `site`:
    in its domains and not a bot-management cookie."""
    return in_site(domain, site) and not denied(name, rule(site))


def replaced_on_import(domain: str, name: str, site: str) -> bool:
    """True if the shared browser's OWN cookie is deleted by an import of
    `site`: every cookie in its domains, except the bot-management ones —
    which go too for a site with ``drop_bot_cookies``."""
    rules = rule(site)
    return in_site(domain, site) and (rules.drop_bot_cookies or not denied(name, rules))


def has_session(site: str, cookies: Iterable[Cookie]) -> bool:
    """True if `cookies` (already filtered by `site_cookies`) hold at least one
    of `site`'s ``session_cookies`` (fnmatch patterns) — the login itself (any
    cookie counts for a site that names none). Without it an import must
    change NOTHING: a logged-out Safari never wipes the shared browser's good
    session."""
    return any(is_session_cookie(c.name, site) for c in cookies)


def session_fingerprint(site: str, cookies: Iterable[Cookie]) -> str:
    """One sha256 over `site`'s session cookies in `cookies` (domain, name,
    path, flags, expiry AND value): two reads that differ tell that Safari
    wrote a new session — a rotated value with the same expiry included.
    In memory only: never persist or print it (it digests secrets)."""
    rows = sorted(
        (c.domain, c.name, c.path, c.secure, c.http_only, round(c.expires), c.value)
        for c in cookies
        if is_session_cookie(c.name, site)
    )
    h = hashlib.sha256()
    for row in rows:
        h.update(repr(row).encode("utf-8", "surrogatepass"))
        h.update(b"\0")
    return h.hexdigest()


def site_cookies(
    cookies: Iterable[Cookie], site: str, *, now: float | None = None
) -> list[Cookie]:
    """`site`'s cookies from `cookies`: in its domains, not denied, not expired."""
    at = time.time() if now is None else now
    return [c for c in cookies if importable(c.domain, c.name, site) and c.expires > at]


def session_summary(
    site: str, path: str | os.PathLike[str] | None = None, *, now: float | None = None
) -> tuple[int, float | None]:
    """(number of usable cookies Safari holds for `site`, latest expiry or None).

    Reads names and expiry only; raises OSError / ValueError like
    ``read_binarycookies``.
    """
    picked = site_cookies(read_binarycookies(path), site, now=now)
    return len(picked), max((c.expires for c in picked), default=None)
