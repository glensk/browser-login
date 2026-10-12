"""Account identity of broker items that share one cookie scope (WS5, tp#833).

The shared Chromium has ONE cookie jar and ONE localStorage per origin. Two
broker items whose cookie scope overlaps log into the same site, and the
second login overwrites the first one's session: a DOM sentinel then proves
"someone is logged in", never WHICH account. Such items are *multi-account*:
a logged-in check may not pass for them without a server identity proof.

``scope_conflicts`` decides it from what the broker ADVERTISES in its ``sites``
view only — cookie hosts, fill origins, storage origins and an explicit
``same_account_as`` declaration — never from a username or a password. Two
items with identical scopes may well be the same account, but that cannot be
known without reading values, so they conflict unless BOTH declare each other
the same account (the broker refuses a one-sided declaration, WS5 S1).

Over-inclusion only costs a refusal, never a wrong account: hosts match at the
host level (parent domains included, cookie names ignored), and every listed
item takes part, refused ones included (their cookies may still be in the
browser). Since S4c a cookie scope may carry a path (``CookieScope``: Keycloak
keeps each realm's session cookies under ``/realms/<realm>/``): two scopes
overlap only when their domains are related AND their paths overlap (RFC 6265
path-match). Fill and storage origins stay host-wide: origin state cannot be
split by path.

WS5 S1 adds what the broker and the client share for the server identity
proof: the item-field vocabularies (instances, privileges, the static site
names an alias may not take), the name normalisation (identical in Python
and in ``RECIPE_JS``), the challenge digest ``sha256(nonce || name)``, the
account tag, and the reviewed recipes (``IDENTITIES``: one fixed same-origin
endpoint each, run in a page by the one generic ``RECIPE_JS``).

Pure: no I/O, no imports beyond the standard library. Imported by
``bin/browser.py`` (the client guard), ``agent-login.py`` (rows, agents.md)
and the broker (``vault``, ``identity_ops``, ``daemon``).
"""

# too-many-lines: the one shared module of the identity protocol (the in-page
# RECIPE_JS and the reviewed recipe table are long, and must stay in ONE
# place for the broker and the client).
# pylint: disable=too-many-lines

from __future__ import annotations

import hashlib
import hmac
import json
import re
import unicodedata
import urllib.parse
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

# The browser instance an item lives in (WS5 S2): "" = the shared 9222 browser.
DEFAULT_INSTANCE = ""


def _norm_host(value: object) -> str:
    """A host from a bare host or an ``https://…`` origin, lower-case, no
    leading dot, no port; '' when there is none."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    if "://" in raw:
        try:
            raw = urllib.parse.urlsplit(raw).hostname or ""
        except ValueError:
            return ""
    else:
        raw = raw.split("/", 1)[0].split(":", 1)[0]
    return raw.strip().lstrip(".").rstrip(".").lower()


def _https_origin(value: object) -> str:
    """``https://host[:port]`` of a URL or an origin (lower-case, the default
    port dropped); '' for anything that is not https."""
    try:
        parts = urllib.parse.urlsplit(str(value or ""))
        host, port = parts.hostname, parts.port
    except ValueError:
        return ""
    if parts.scheme != "https" or not host:
        return ""
    return f"https://{host.lower()}" + ("" if port in (None, 443) else f":{port}")


def _list(value: object) -> list[str]:
    """A field that holds one string or a list of strings, as a list."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if isinstance(v, str)]
    return []


def str_list(value: object) -> list[str]:
    """A ``sites`` field that holds one string or a list of strings, as a
    list of strings (anything else: [])."""
    return _list(value)


def scope_hosts(entry: Mapping[str, object]) -> frozenset[str]:
    """Every host an item's session lives on or is typed into: its cookie
    hosts, and the hosts of its fill and storage origins."""
    hosts = {_norm_host(h) for h in _list(entry.get("cookie_hosts"))}
    for key in ("fill_origins", "storage_origins"):
        hosts |= {_norm_host(o) for o in _list(entry.get(key))}
    hosts.discard("")
    return frozenset(hosts)


def domains_related(a: str, b: str) -> bool:
    """`a` equals, or is a parent or a subdomain of, `b` (cookie domain
    matching in both directions)."""
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def hosts_overlap(a: Iterable[str], b: Iterable[str]) -> bool:
    """Any host of `a` equals, or is a parent or a subdomain of, a host of
    `b` (cookie domain matching in both directions: ``docker.com`` covers
    ``app.docker.com``)."""
    bs = list(b)
    return any(domains_related(x, y) for x in a for y in bs)


# ---------------------------------------------------------------------------
# WS5 S4c: cookie scopes with a path (Keycloak scopes its session cookies to
# /realms/<realm>/: two realms on one host are two cookie scopes)
# ---------------------------------------------------------------------------
# The `sites` view's (and the bundle's) cookie-scope protocol version: an
# entry with ``scope_v`` >= 1 carries ``cookie_scopes`` ([{host, path}]). A
# reader that does not know it (an old client) uses ``cookie_hosts``, which
# the broker keeps as the scopes' hosts: host-wide, so over-inclusive — more
# conflicts, a wider clear — never a narrower scope (fail closed).
SCOPE_V = 1
MAX_COOKIE_SCOPES = 16
_SCOPE_HOST = re.compile(
    r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)
# A cookie path: printable ASCII without whitespace, the characters that
# end a path or a cookie attribute, and `%` (no percent-encoding at all:
# `%2e%2e` would be a dot segment the checks below cannot see — the paths
# are vault-authored, so they stay plain).
_SCOPE_PATH = re.compile(r"^/[!$&'()*+\-./0-9:=@A-Z\[\]^_`a-z{|}~]{0,255}$")


def _scope_path(path: str) -> str:
    """The canonical form of a scope path: '/' stays, any other path loses
    its trailing slashes (``/realms/sdsc/`` → ``/realms/sdsc``) — so the
    RFC 6265 path-match below covers the exact path without its slash too."""
    trimmed = path.rstrip("/")
    return trimmed or "/"


def path_match(request_path: str, cookie_path: str) -> bool:
    """RFC 6265 §5.1.4: `request_path` path-matches `cookie_path` — equal,
    or `cookie_path` is a prefix ending in '/', or a prefix followed by '/'
    in `request_path` (``/realms/sdscx`` does not match ``/realms/sdsc``)."""
    if request_path == cookie_path:
        return True
    if not request_path.startswith(cookie_path):
        return False
    return cookie_path.endswith("/") or request_path[len(cookie_path)] == "/"


def paths_overlap(a: str, b: str) -> bool:
    """Two cookie paths (canonical or not) share a request path: one
    path-matches the other (``/`` overlaps everything; sibling realms
    ``/realms/a`` and ``/realms/b`` do not)."""
    pa, pb = _scope_path(a or "/"), _scope_path(b or "/")
    return path_match(pa, pb) or path_match(pb, pa)


@dataclass(frozen=True, order=True)
class CookieScope:
    """Where one item's cookies live: a host (its subdomains included, as
    for every cookie host) and a path (RFC 6265 path-match; ``/`` = the
    whole host). The ONE implementation behind every scope decision: the
    multi-account and in-instance conflicts (`overlaps`), and every cookie
    operation — the broker's export, fresh-login wipe and reset, the
    client's replace, rollback, logout and foreign clear (`holds`,
    `reaches`). A host-only scope (path ``/``) decides exactly as the
    host lists did before."""

    host: str
    path: str = "/"

    def __post_init__(self) -> None:
        object.__setattr__(self, "host", _norm_host(self.host))
        object.__setattr__(self, "path", _scope_path(str(self.path or "/")))

    def holds(self, domain: object, path: object = "/") -> bool:
        """A cookie of `domain` and `path` LIES IN this scope: its domain is
        the host or a subdomain of it (never a parent), and its path is the
        scope path (with or without its trailing slash) or below it."""
        d = _norm_host(domain)
        if (
            not self.host
            or not d
            or not (d == self.host or d.endswith("." + self.host))
        ):
            return False
        if self.path == "/":
            return True
        return path_match(str(path or "/"), self.path)

    def clears(self, domain: object, path: object = "/") -> bool:
        """A DELETE in the shared browser takes this cookie: one the scope
        `holds`, or one on the host or a subdomain (never a parent domain)
        whose path is an ANCESTOR of the scope path — ``/`` and
        ``/realms/`` of a ``/realms/sdsc/`` scope: such a cookie is sent to
        the realm and may carry a foreign session's state into it. Never a
        sibling path (``/realms/master/``). Safe for the sibling realm: an
        item of it can never share the instance — the fill origin (the
        Keycloak host) keeps the two in conflict (O11). Export and
        injection stay exact (`holds`)."""
        if self.holds(domain, path):
            return True
        d = _norm_host(domain)
        if (
            not self.host
            or not d
            or not (d == self.host or d.endswith("." + self.host))
        ):
            return False
        return path_match(self.path, _scope_path(str(path or "/")))

    def reaches(self, domain: object, path: object = "/") -> bool:
        """A cookie of `domain` and `path` lies in this scope OR is sent
        into it: the domains are related either way (a parent domain's
        cookie reaches the host) and the paths overlap (a ``/`` cookie
        reaches every path)."""
        d = _norm_host(domain)
        if not self.host or not d or not domains_related(d, self.host):
            return False
        return self.path == "/" or paths_overlap(str(path or "/"), self.path)

    def overlaps(self, other: CookieScope) -> bool:
        """Joint overlap: related domains AND overlapping paths."""
        if not self.host or not other.host:
            return False
        return domains_related(self.host, other.host) and paths_overlap(
            self.path, other.path
        )

    def view(self) -> dict[str, str]:
        """``{host, path}`` for the `sites` view and the bundle."""
        return {"host": self.host, "path": self.path}


def scope_problem(raw: object) -> str:
    """Why one ``{host, path}`` object is not a valid cookie scope ('' =
    it is): exactly the keys host (a plain lower-case DNS name or IPv4,
    no scheme, port or path) and optionally path (absolute, printable
    ASCII, no ``//``, no ``.``/``..`` segment, ≤ 256 characters)."""
    if not isinstance(raw, Mapping):
        return "each scope is an object {host, path}"
    if not set(raw) <= {"host", "path"} or "host" not in raw:
        return "each scope has exactly the keys host and path"
    host, path = raw.get("host"), raw.get("path", "/")
    if not isinstance(host, str) or not _SCOPE_HOST.match(host.strip().lower()):
        return "bad host (a plain host name, no scheme, port or path)"
    if not isinstance(path, str) or not _SCOPE_PATH.match(path):
        return "bad path (absolute, plain printable ASCII, no %, ≤ 256 characters)"
    segments = path.split("/")[1:]
    if "//" in path or any(seg in (".", "..") for seg in segments):
        return "bad path (no // and no . or .. segment)"
    return ""


def parse_cookie_scopes(raw: object) -> tuple[tuple[CookieScope, ...], str]:
    """(scopes, '') from the vault field ``agent_cookie_scopes`` (a JSON
    list of ``{host, path}``, as text or already parsed), or ((), why not).
    Duplicates fold; at most ``MAX_COOKIE_SCOPES``."""
    value = raw
    if isinstance(raw, str):
        try:
            value = json.loads(raw)
        except ValueError:
            return (), "not JSON"
    if not isinstance(value, list) or not value:
        return (), "a non-empty JSON list of {host, path}"
    if len(value) > MAX_COOKIE_SCOPES:
        return (), f"at most {MAX_COOKIE_SCOPES} scopes"
    out: list[CookieScope] = []
    for one in value:
        problem = scope_problem(one)
        if problem:
            return (), problem
        scope = CookieScope(str(one["host"]), str(one.get("path", "/")))
        if scope not in out:
            out.append(scope)
    return tuple(out), ""


def _versioned(entry: Mapping[str, object]) -> bool:
    version = entry.get("scope_v")
    return not isinstance(version, bool) and isinstance(version, int) and version >= 1


def entry_cookie_scopes(entry: Mapping[str, object]) -> tuple[CookieScope, ...]:
    """The cookie scopes of a ``sites`` entry or a session bundle: its
    ``cookie_scopes`` when it speaks ``scope_v`` >= 1 AND they are valid AND
    name exactly its ``cookie_hosts``; otherwise its ``cookie_hosts`` at
    path ``/`` (a pre-S4c broker or a malformed entry: host-wide, the
    over-inclusive reading — fail closed)."""
    hosts = tuple(
        CookieScope(h) for h in dict.fromkeys(_list(entry.get("cookie_hosts"))) if h
    )
    hosts = tuple(s for s in hosts if s.host)
    if not _versioned(entry):
        return hosts
    scopes, problem = parse_cookie_scopes(entry.get("cookie_scopes"))
    if problem or {s.host for s in scopes} != {s.host for s in hosts}:
        return hosts
    return scopes


def item_scopes(entry: Mapping[str, object]) -> frozenset[CookieScope]:
    """Every scope an item's session lives in or is typed into: its cookie
    scopes (`entry_cookie_scopes`), and its fill and storage origins'
    hosts at path ``/`` — origin-scoped state (localStorage, a login form)
    cannot be split by path, so an origin overlap stays a conflict."""
    scopes = set(entry_cookie_scopes(entry))
    for key in ("fill_origins", "storage_origins"):
        scopes |= {CookieScope(o) for o in _list(entry.get(key))}
    return frozenset(s for s in scopes if s.host)


def scopes_overlap(a: Iterable[CookieScope], b: Iterable[CookieScope]) -> bool:
    """Any scope of `a` overlaps (domain AND path) a scope of `b`."""
    bs = list(b)
    return any(x.overlaps(y) for x in a for y in bs)


def scopes_hold(
    scopes: Iterable[CookieScope], domain: object, path: object = "/"
) -> bool:
    """A cookie of `domain` / `path` lies in one of `scopes`
    (`CookieScope.holds`)."""
    return any(s.holds(domain, path) for s in scopes)


def scopes_clear(
    scopes: Iterable[CookieScope], domain: object, path: object = "/"
) -> bool:
    """A delete in the shared browser takes this cookie
    (`CookieScope.clears`: held, or an ancestor path of a scope)."""
    return any(s.clears(domain, path) for s in scopes)


def scopes_reach(
    scopes: Iterable[CookieScope], domain: object, path: object = "/"
) -> bool:
    """A cookie of `domain` / `path` lies in or is sent into one of `scopes`
    (`CookieScope.reaches`)."""
    return any(s.reaches(domain, path) for s in scopes)


def instance_of(entry: Mapping[str, object]) -> str:
    """The browser instance an item is advertised for (absent = the shared one)."""
    inst = entry.get("instance")
    return inst if isinstance(inst, str) else DEFAULT_INSTANCE


def _same_account(a: Mapping[str, object], b: Mapping[str, object]) -> bool:
    """`a` and `b` are DECLARED the same account — by both of them."""
    sa, sb = str(a.get("site") or ""), str(b.get("site") or "")
    return sb in _list(a.get("same_account_as")) and sa in _list(
        b.get("same_account_as")
    )


def scope_conflicts(
    sites: Iterable[Mapping[str, object]],
) -> dict[str, tuple[str, ...]]:
    """``{site: (sibling ids, sorted)}`` for every item whose scope overlaps
    an item that is not declared the same account — in ANY instance (an item
    is multi-account wherever its siblings live). Items without a conflict
    are absent."""
    items = [
        (str(e.get("site")), e, item_scopes(e))
        for e in sites
        if isinstance(e, Mapping) and isinstance(e.get("site"), str) and e.get("site")
    ]
    out: dict[str, set[str]] = {}
    for i, (sa, ea, ha) in enumerate(items):
        for sb, eb, hb in items[i + 1 :]:
            if sa == sb or not ha or not hb:
                continue
            if scopes_overlap(ha, hb) and not _same_account(ea, eb):
                out.setdefault(sa, set()).add(sb)
                out.setdefault(sb, set()).add(sa)
    return {site: tuple(sorted(sib)) for site, sib in sorted(out.items())}


def conflict_groups(sites: Iterable[Mapping[str, object]]) -> list[tuple[str, ...]]:
    """The connected groups of `scope_conflicts` (each sorted, groups sorted)."""
    return connected_groups(scope_conflicts(sites))


def connected_groups(
    graph: Mapping[str, Iterable[str]],
) -> list[tuple[str, ...]]:
    """The connected groups of an undirected `graph` ``{node: neighbours}``
    (each sorted, groups sorted)."""
    seen: set[str] = set()
    groups = []
    for start in graph:
        if start in seen:
            continue
        stack, group = [start], set()
        while stack:
            node = stack.pop()
            if node in group:
                continue
            group.add(node)
            stack.extend(graph.get(node, ()))
        seen |= group
        groups.append(tuple(sorted(group)))
    return sorted(groups)


# ---------------------------------------------------------------------------
# WS5 S1: item fields, normalisation, the challenge digest, identity recipes
# ---------------------------------------------------------------------------
# Shared by the broker (field validation, the challenge ops, its own proof in
# its own page) and the client (S2: the same recipe in the shared browser's
# probe page). A username never leaves the broker or the page: the page
# hashes ``nonce || normalised value`` and only that digest crosses CDP and
# the broker socket.

# The `sites` view's identity protocol version: fields `instance`,
# `privilege`, `identity`, `alias`, `same_account_as`, `multi_account`, and
# the ops `identity_challenge` / `identity_answer` (whether two items are one
# account is the root-only `install.sh -S`, never a socket op).
IDENTITY_V = 1
# Browser instances an item may live in besides the shared one ("" = 9222).
# Their CDP ports are browser.py's `INSTANCE_PORTS` (S2): admin 9224, alt 9225.
ROLE_INSTANCES = ("admin", "alt")
# Their CDP ports (browser.py builds its INSTANCE_PORTS from this; agents.md
# names them).
ROLE_INSTANCE_PORTS = {"admin": 9224, "alt": 9225}
INSTANCES = (DEFAULT_INSTANCE, *ROLE_INSTANCES)
# `agent_privilege`: what the account may do on the site. The recipe's admin
# bit must say "admin" for `admin` and "not admin" for the others.
PRIVILEGES = ("admin", "user", "readonly")

# browser.py's static site registry (`_sites()`: names and aliases). An
# `agent_alias` never equals one of them: static names resolve first, so such
# an alias would be dead, or read as the static site. The broker release does
# not ship browser.py, hence this copy; tests/test_ws5_broker.py keeps it
# equal to the registry.
STATIC_SITE_NAMES = frozenset(
    {
        "cscs",
        "portal",
        "cscs.ch",
        "anthropic",
        "claude",
        "claude.ai",
        "claude-ai",
        "openai",
        "chatgpt",
        "chatgpt.com",
        "oai",
        "slack",
        "slack.com",
        "app.slack.com",
        "notion",
        "notion.so",
        "app.notion.com",
        "notion.com",
        "biopolwifi",
        "biopol",
        "cloudpath",
        "edificom",
        "switch",
        "switch-cloud",
        "cloud.switch.ch",
        "scp",
    }
)

# The verdicts of one identity proof (the broker's own; the client's in S2).
MATCH = "match"
WRONG_ACCOUNT = "wrong_account"
PRIVILEGE_MISMATCH = "privilege_mismatch"
LOGGED_OUT = "logged_out"
INDETERMINATE = "indeterminate"

# The ASCII whitespace JavaScript's String.prototype.trim removes (Python's
# str.strip() would also drop \x1c-\x1f: both sides must agree).
_TRIM = " \t\n\r\x0b\x0c"
NONCE_BYTES = 32
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def normalize_identity(value: object) -> str | None:
    """The comparable form of an account name, identical in Python and in
    ``RECIPE_JS``: NFKC, then anything non-ASCII → None (indeterminate),
    then ASCII lower-case, then trimmed; empty → None."""
    if not isinstance(value, str):
        return None
    text = unicodedata.normalize("NFKC", value)
    if not text.isascii():
        return None
    text = text.lower().strip(_TRIM)
    return text or None


def is_digest(value: object) -> bool:
    """A lower-case hex SHA-256 digest (64 characters)."""
    return isinstance(value, str) and _HEX64.match(value) is not None


def challenge_digest(nonce_hex: str, normalized: str) -> str:
    """``sha256(nonce || value)`` in hex: the nonce's 32 raw bytes, then the
    normalised (ASCII) value. ValueError on a malformed nonce or a value that
    is not normalised."""
    if not is_digest(nonce_hex):
        raise ValueError("nonce must be 32 bytes, lower-case hex")
    if normalize_identity(normalized) != normalized:
        raise ValueError("value is not normalised")
    return hashlib.sha256(
        bytes.fromhex(nonce_hex) + normalized.encode("ascii")
    ).hexdigest()


def account_tag(key: bytes, username: object) -> str | None:
    """HMAC-SHA256 of the normalised username under the broker's tag key: a
    sanity check of a DECLARED same-account pair, never authorization (the
    same name in two realms is two accounts). None when the name does not
    normalise or the key is short (callers read None as "not equal")."""
    norm = normalize_identity(username)
    if norm is None or len(key) < NONCE_BYTES:
        return None
    return hmac.new(key, norm.encode("ascii"), hashlib.sha256).hexdigest()


def admin_verdict(admin: object, privilege: str) -> str:
    """The recipe's admin bit against the item's `agent_privilege`: MATCH,
    PRIVILEGE_MISMATCH, or INDETERMINATE (no bit, unknown privilege)."""
    if not isinstance(admin, bool) or privilege not in PRIVILEGES:
        return INDETERMINATE
    return MATCH if admin == (privilege == "admin") else PRIVILEGE_MISMATCH


# One return per verdict, in the order they are decided.
def local_verdict(  # pylint: disable=too-many-return-statements
    answer: object, nonce_hex: str, username: object, privilege: str
) -> str:
    """The broker's OWN proof: the recipe's answer (run in the broker's page
    with `nonce_hex`) against the vault username, compared in-process.

    found + equal digest + matching admin bit → MATCH; another digest →
    WRONG_ACCOUNT; a wrong admin bit → PRIVILEGE_MISMATCH; 401/403 →
    LOGGED_OUT; anything else (no answer, an unknown state, a malformed
    digest, a name that does not normalise, no admin bit) → INDETERMINATE."""
    if not isinstance(answer, Mapping):
        return INDETERMINATE
    state = answer.get("state")
    if state == LOGGED_OUT:
        return LOGGED_OUT
    digest = answer.get("digest")
    if state != "found" or not is_digest(digest):
        return INDETERMINATE
    norm = normalize_identity(username)
    if norm is None:
        return INDETERMINATE
    try:
        expected = challenge_digest(nonce_hex, norm)
    except ValueError:
        return INDETERMINATE
    if not hmac.compare_digest(str(digest), expected):
        return WRONG_ACCOUNT
    return admin_verdict(answer.get("admin"), privilege)


@dataclass(frozen=True)
class IdentityRecipe:  # pylint: disable=too-many-instance-attributes  # one reviewed spec
    """One reviewed server identity source: ONE fixed same-origin endpoint,
    ONE identity field, one admin bit. Nothing of it comes from the vault:
    an item only names a recipe (`agent_identity`)."""

    name: str
    # The endpoint on the check page's origin; with `base_segments`, prefixed
    # by the check URL's first path segment when it is one of them.
    path: str
    id_field: tuple[str, ...]
    # "cookie" (the session cookie), "bearer-local-storage" (`token_key` of
    # the origin's localStorage), "jwt-local-storage" (the same, a JWT whose
    # `path_claim` names the endpoint's last path segment) or "syno-token"
    # (DSM's in-page SynoToken).
    auth: str = "cookie"
    token_key: str = ""
    # The request header a localStorage token travels in: `auth_header:
    # <auth_scheme><token>`.
    auth_header: str = "Authorization"
    auth_scheme: str = "Bearer "
    # jwt-local-storage: the JWT payload claim appended to `path` (which ends
    # in "/") as ONE path segment of safe characters, and the response field
    # that must equal it (the record is the token's own user, never another
    # one an admin token may read).
    path_claim: str = ""
    claim_field: tuple[str, ...] | None = None
    base_segments: tuple[str, ...] = ()
    admin_field: tuple[str, ...] | None = None
    admin_true: tuple[object, ...] = (True,)
    admin_false: tuple[object, ...] = (False,)
    # GitLab exposes `is_admin` only to admins: absent means "not admin".
    absent_admin_is_false: bool = False
    # DSM: `success` must be true; an error code in `logged_out_codes` is
    # logged out, any other error indeterminate.
    ok_field: tuple[str, ...] | None = None
    error_code_field: tuple[str, ...] | None = None
    logged_out_codes: tuple[int, ...] = ()
    # authentik: this field must be present and null (non-null = an admin
    # impersonating the user → indeterminate).
    must_be_null: tuple[str, ...] | None = None
    # Verified against the live site (status + key names, never values).
    live_confirmed: bool = False
    # The forms of a vault username this recipe's identity field can be
    # compared with (`identity_form`): a vault holding another form can never
    # match, so the item is refused at validation instead of failing later.
    forms: tuple[str, ...] = ("username",)
    # --- WS5 S4c: who may use the recipe (enforced by the broker's
    # validation, its own proof and the challenge gate, and by the client's
    # proof): only these site ids ("" = any) and only on this exact https
    # origin ("" = the check URL's).
    allowed_sites: tuple[str, ...] = ()
    origin: str = ""
    # "token-endpoint" (Run:ai): `path` is a same-origin POST of the fixed
    # JSON `token_body`; the response's `token_field` holds a JWT whose
    # claims are the identity source (`id_field` is a claim path), pinned
    # by `claim_pins` (claim == value), `issuer` (the `iss` claim, exactly)
    # and an `exp` in the future.
    token_body: tuple[tuple[str, str], ...] = ()
    token_field: tuple[str, ...] | None = None
    claim_pins: tuple[tuple[str, str], ...] = ()
    issuer: str = ""
    # The admin bit from a fixed same-origin GET with the token as bearer:
    # a status in `admin_probe_true` = admin, in `admin_probe_false` = not;
    # anything else = no admin bit (indeterminate).
    admin_probe: str = ""
    admin_probe_true: tuple[int, ...] = (200,)
    admin_probe_false: tuple[int, ...] = (403,)
    # The probe's "not admin" answer counts from a JSON content type, or —
    # whatever the content type — from a body (at most 64 KiB) that is
    # exactly the site's error object: these two keys, the first a number,
    # the second a string, nothing else (Run:ai answers its 403 as
    # text/plain with {"code": …, "message": …}). () = JSON content type only.
    admin_probe_error_shape: tuple[str, ...] = ()
    # The admin bit's "admin" answer was seen live. While False an item
    # with `agent_privilege admin` may not use the recipe (it stays
    # unproven); a `user` / `readonly` item may (its "not admin" side is
    # confirmed).
    admin_true_confirmed: bool = True
    # localStorage keys the page keeps its OWN claim of the account in
    # (forgeable, seen stale: Run:ai B1): an item using the recipe may not
    # list them in `agent_storage_keys` — never exported, never injected.
    identity_storage_keys: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        problem = recipe_problem(self)
        if problem:
            raise ValueError(f"identity recipe {self.name or '?'}: {problem}")


# How a recipe authenticates its request (`IdentityRecipe.auth`).
AUTHS = (
    "cookie",
    "bearer-local-storage",
    "jwt-local-storage",
    "syno-token",
    "token-endpoint",
)
# The ones that read a token from the origin's localStorage: a foreign
# session of such a site lives there, not (only) in cookies.
LOCAL_STORAGE_AUTHS = frozenset({"bearer-local-storage", "jwt-local-storage"})
_RECIPE_NAME = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
_HEADER_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,63}$")
# Headers a recipe may not send its token in: the fetch spec's forbidden
# ones (names and prefixes), and the recipe's own Accept.
_RESERVED_HEADER_PREFIXES = ("proxy-", "sec-", "access-control-request-")
_RESERVED_HEADERS = frozenset(
    {
        "accept",
        "accept-charset",
        "access-control-request-headers",
        "access-control-request-method",
        "access-control-request-private-network",
        "accept-encoding",
        "connection",
        "content-length",
        "content-type",
        "cookie",
        "cookie2",
        "date",
        "dnt",
        "expect",
        "host",
        "keep-alive",
        "origin",
        "referer",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "via",
    }
)
_AUTH_SCHEME = re.compile(r"^(?:[A-Za-z]{1,16} )?$")
_CLAIM_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,31}$")
_FIELD_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


# One return per rule of the reviewed spec, in the order they are checked.
def recipe_problem(  # pylint: disable=too-many-return-statements,too-many-branches
    recipe: IdentityRecipe,
) -> str:
    """Why `recipe` is not a well-formed reviewed spec ('' = it is): a
    known auth, ONE fixed same-origin path, field paths of plain keys, a
    token key and a settable header where the token is read from
    localStorage, and a JWT claim only as the last path segment of a
    jwt-local-storage recipe that also checks the record's own id
    against it."""
    if not _RECIPE_NAME.match(recipe.name):
        return "bad name"
    if recipe.auth not in AUTHS:
        return f"bad auth {recipe.auth!r}"
    if not recipe.path.startswith("/") or recipe.path.startswith("//"):
        return "path must be an absolute path on the check origin"
    if "\\" in recipe.path or "#" in recipe.path:
        return "bad path"
    if not recipe.id_field:
        return "no identity field"
    for field_path in (recipe.id_field, recipe.admin_field, recipe.claim_field):
        if field_path is not None and not all(
            isinstance(k, str) and _FIELD_KEY.match(k) for k in field_path
        ):
            return "bad field path"
    if recipe.auth in LOCAL_STORAGE_AUTHS:
        if not recipe.token_key:
            return f"{recipe.auth} needs token_key"
        header = recipe.auth_header.lower()
        if (
            not _HEADER_NAME.match(recipe.auth_header)
            or header in _RESERVED_HEADERS
            or header.startswith(_RESERVED_HEADER_PREFIXES)
        ):
            return f"bad auth_header {recipe.auth_header!r}"
        if not _AUTH_SCHEME.match(recipe.auth_scheme):
            return "bad auth_scheme"
    if recipe.path_claim or recipe.claim_field:
        if recipe.auth != "jwt-local-storage":
            return "path_claim needs jwt-local-storage"
        if not _CLAIM_NAME.match(recipe.path_claim):
            return "bad path_claim"
        if not recipe.claim_field:
            return "path_claim needs claim_field (the record's own id)"
        if not recipe.path.endswith("/") or "?" in recipe.path:
            return "path_claim needs a path ending in '/'"
        if recipe.base_segments:
            return "path_claim takes no base_segments"
    elif recipe.auth == "jwt-local-storage":
        return "jwt-local-storage needs path_claim"
    return _token_recipe_problem(recipe) or _scope_rule_problem(recipe)


_SITE_SLUG = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_PIN_VALUE = re.compile(r"^[!-~]{1,128}$")
_ISSUER = re.compile(r"^https://[a-z0-9.-]+(?::[0-9]{1,5})?/[!-\"$-/0-9:;=@-~]{0,200}$")


def _fixed_path_problem(path: str) -> str:
    """'' for an absolute same-origin path without a fragment."""
    if not path.startswith("/") or path.startswith("//"):
        return "must be an absolute path on the check origin"
    if "\\" in path or "#" in path or any(c.isspace() for c in path):
        return "bad path"
    return ""


def _scope_rule_problem(recipe: IdentityRecipe) -> str:
    """WS5 S4c: `allowed_sites` are site ids, `origin` an exact https
    origin, `identity_storage_keys` plain names."""
    if not all(
        isinstance(s, str) and _SITE_SLUG.match(s) for s in recipe.allowed_sites
    ):
        return "bad allowed_sites"
    if recipe.origin and _https_origin(recipe.origin) != recipe.origin:
        return "origin must be an exact https origin"
    if not all(isinstance(k, str) and k for k in recipe.identity_storage_keys):
        return "bad identity_storage_keys"
    return ""


# One return per rule of the token-endpoint spec, in the order they are checked.
def _token_recipe_problem(  # pylint: disable=too-many-return-statements,too-many-branches
    recipe: IdentityRecipe,
) -> str:
    """The token-endpoint rules: a fixed JSON body of plain keys and
    printable values, the token's response field, claim pins, an issuer
    path suffix, a fixed admin probe with disjoint status sets, and a
    recipe pinned to its sites AND its origin (a fixed source). Any other
    auth carries none of these fields."""
    token_fields = (
        recipe.token_body,
        recipe.token_field,
        recipe.claim_pins,
        recipe.issuer,
        recipe.admin_probe,
        recipe.admin_probe_error_shape,
    )
    if recipe.auth != "token-endpoint":
        return "token fields need auth token-endpoint" if any(token_fields) else ""
    if not recipe.token_body or not all(
        isinstance(k, str)
        and _FIELD_KEY.match(k)
        and isinstance(v, str)
        and _PIN_VALUE.match(v)
        for k, v in recipe.token_body
    ):
        return "token-endpoint needs a token_body of plain keys and values"
    if not recipe.token_field or not all(
        isinstance(k, str) and _FIELD_KEY.match(k) for k in recipe.token_field
    ):
        return "token-endpoint needs a token_field"
    if not all(
        isinstance(k, str)
        and _CLAIM_NAME.match(k)
        and isinstance(v, str)
        and _PIN_VALUE.match(v)
        for k, v in recipe.claim_pins
    ):
        return "bad claim_pins"
    if not _ISSUER.match(recipe.issuer):
        return "token-endpoint needs an issuer (an https URL, no query)"
    if recipe.admin_field is not None:
        return "token-endpoint takes its admin bit from admin_probe"
    problem = _fixed_path_problem(recipe.admin_probe)
    if problem:
        return f"admin_probe {problem}"
    statuses = (*recipe.admin_probe_true, *recipe.admin_probe_false)
    if (
        not recipe.admin_probe_true
        or not recipe.admin_probe_false
        or not all(
            isinstance(c, int) and not isinstance(c, bool) and 100 <= c <= 599
            for c in statuses
        )
        or set(recipe.admin_probe_true) & set(recipe.admin_probe_false)
    ):
        return "admin_probe statuses must be disjoint HTTP codes"
    shape = recipe.admin_probe_error_shape
    if shape and (
        len(shape) != 2
        or not all(isinstance(k, str) and _FIELD_KEY.match(k) for k in shape)
        or shape[0] == shape[1]
    ):
        return "admin_probe_error_shape must be two distinct plain keys"
    if recipe.base_segments or "?" in recipe.path:
        return "token-endpoint takes one fixed path"
    if not recipe.allowed_sites or not recipe.origin:
        return "token-endpoint needs allowed_sites and an origin (a fixed source)"
    return ""


# Reviewed recipes only.
IDENTITIES: dict[str, IdentityRecipe] = {
    # live 2026-10-11: 200, keys username / email / is_admin (as an admin)
    # It compares the GitLab `username` only. A vault holding the e-mail is
    # refused at validation (fail closed) rather than compared with `email`:
    # one reviewed field per recipe, and an e-mail is not unique across
    # GitLab's secondary addresses the way the username is.
    "gitlab": IdentityRecipe(
        name="gitlab",
        path="/api/v4/user",
        id_field=("username",),
        admin_field=("is_admin",),
        absent_admin_is_false=True,
        live_confirmed=True,
        forms=("username",),
    ),
    # live 2026-10-11: 200 with the bearer token of localStorage `token`
    "audiobookshelf": IdentityRecipe(
        name="audiobookshelf",
        path="/api/me",
        base_segments=("audiobookshelf",),
        id_field=("username",),
        auth="bearer-local-storage",
        token_key="token",
        admin_field=("type",),
        admin_true=("root", "admin"),
        admin_false=("user", "guest"),
        live_confirmed=True,
    ),
    # live 2026-10-11: Navidrome keeps its session in localStorage `token`, a
    # JWT whose payload claims are exp, iat, iss, sub and uid (uid = the
    # localStorage `userId`). GET /api/user/<uid> with `x-nd-authorization:
    # Bearer <token>` (no cookie needed) answers 200 application/json with
    # id, userName, name, email, isAdmin (a boolean), lastLoginAt,
    # lastAccessAt, createdAt, updatedAt, scrobbleFilter, libraries; without
    # the header 401 JSON {"error": …}. The web app lives under /app/, the API
    # at the origin root. The record must be the token's own user (`id` ==
    # uid): an admin token can read other users.
    "navidrome": IdentityRecipe(
        name="navidrome",
        path="/api/user/",
        id_field=("userName",),
        auth="jwt-local-storage",
        token_key="token",
        auth_header="x-nd-authorization",
        auth_scheme="Bearer ",
        path_claim="uid",
        claim_field=("id",),
        admin_field=("isAdmin",),
        live_confirmed=True,
        forms=("username",),
    ),
    # DSM Web API (logged out it answers success:false, code 119). This
    # answer has no admin bit: an item using it stays indeterminate until S4
    # confirms one (fail closed).
    "dsm": IdentityRecipe(
        name="dsm",
        path="/webapi/entry.cgi?api=SYNO.Core.NormalUser&method=get&version=1",
        id_field=("data", "username"),
        auth="syno-token",
        ok_field=("success",),
        error_code_field=("error", "code"),
        logged_out_codes=(106, 107, 119),
    ),
    # authentik API docs (UserSelf): `user.username`, `user.is_superuser`;
    # `original` (impersonation) must be null.
    "authentik": IdentityRecipe(
        name="authentik",
        path="/api/v3/core/users/me/",
        id_field=("user", "username"),
        admin_field=("user", "is_superuser"),
        must_be_null=("original",),
    ),
    # Run:ai (S4c B1, live 2026-10-11 as runai-test3, value-free): the SPA
    # keeps its bearer in page memory only; it renews it with ITS OWN
    # same-origin `POST /api/v1/token` (JSON grantType refresh_token,
    # clientID runai-admin-ui; the HttpOnly `refresh-token` cookie, path
    # /api/v1/token, authenticates it) → 200 {accessToken, idToken}. The
    # access token is a JWT of Run:ai's Keycloak (`iss` path
    # /auth/realms/sdsc, `azp` runai-admin-ui) whose `preferred_username`
    # (= `email` = `sub`) is the vault username, an e-mail address. Its
    # Keycloak lives on app1.run.ai, which serves EVERY Run:ai tenant: the
    # items' cookie scope there is the realm path /auth/realms/sdsc/ only.
    #
    # Why the claims count as a SERVER proof without a JWKS check: the
    # recipe fetches the token itself, from the fixed same-origin endpoint,
    # in a CDP isolated world (the page cannot hook that world's fetch,
    # JSON, atob or Date), with no redirect allowed — the claims are what
    # Run:ai's server said about the session cookie it was sent, exactly
    # like gitlab's /api/v4/user record. Nothing of the page (a token in
    # memory, localStorage `logged-in-user-email`: seen stale in B1) is
    # read. The pins (azp, the exact issuer, a future exp) reject a token
    # minted for another client, realm or host, or an old one.
    #
    # Side effect: the POST is a refresh, the same request the SPA sends
    # every few minutes — the server may rotate the `refresh-token` cookie
    # (the browser stores the new one). Each check runs the recipe once.
    #
    # The admin bit: `GET /api/v1/authorization/access-rules?subjectType=user`
    # with the access token as bearer → 403 for a non-admin (test3, live
    # 2026-10-12: `content-type: text/plain; charset=utf-8`, the body Run:ai's
    # JSON error object {"code": number, "message": string} — the same on
    # /api/v1/users and /api/v1/authorization/roles), hence
    # `admin_probe_error_shape`. 200 (application/json, a JSON body) is
    # expected for an admin but NOT yet seen (`admin_true_confirmed` False:
    # an `agent_privilege admin` item stays unproven until the main session
    # confirms it with runai-admin). An HTML 200/403 — an SPA fallback, a WAF
    # page — is no bit.
    "runai": IdentityRecipe(
        name="runai",
        path="/api/v1/token",
        auth="token-endpoint",
        token_body=(("grantType", "refresh_token"), ("clientID", "runai-admin-ui")),
        token_field=("accessToken",),
        id_field=("preferred_username",),
        claim_pins=(("azp", "runai-admin-ui"),),
        issuer="https://app1.run.ai/auth/realms/sdsc",
        admin_probe="/api/v1/authorization/access-rules?subjectType=user",
        admin_probe_true=(200,),
        admin_probe_false=(403,),
        admin_probe_error_shape=("code", "message"),
        admin_true_confirmed=False,
        allowed_sites=("runai-admin", "runai-test3"),
        origin="https://sdsc.run.ai",
        identity_storage_keys=("logged-in-user-email",),
        live_confirmed=True,
        forms=("email",),
    ),
}


_EMAIL_FORM = re.compile(r"^[^@\s]+@[^@\s]+$")


def identity_form(value: object) -> str | None:
    """``email`` (one ``@`` between non-empty parts) or ``username`` for a
    vault username that normalises; None when it does not (empty,
    non-ASCII)."""
    norm = normalize_identity(value)
    if norm is None:
        return None
    return "email" if _EMAIL_FORM.match(norm) else "username"


def usable_recipe(name: object) -> IdentityRecipe | None:
    """The recipe an item may use: reviewed, live-confirmed, WITH an admin
    bit (the privilege check needs one: a response field or an admin
    probe). None for anything else — dsm and authentik until S4 confirms
    them live; their items stay unproven. Whether ONE item may use it is
    `item_recipe`."""
    recipe = IDENTITIES.get(name) if isinstance(name, str) else None
    if recipe is None or not recipe.live_confirmed:
        return None
    if recipe.admin_field is None and not recipe.admin_probe:
        return None
    return recipe


def recipe_config_problem(name: object, *, site: object, check_url: object) -> str:
    """Why the item `site` (its check URL) is not configured for recipe
    `name` ('' = it is): not usable at all, another site than the recipe's
    `allowed_sites`, or a check page off the recipe's `origin`. The vault
    refuses such an item."""
    recipe = usable_recipe(name)
    if recipe is None:
        return f"agent_identity {name} is not live-confirmed with an admin bit yet"
    if recipe.allowed_sites and site not in recipe.allowed_sites:
        return (
            f"the {recipe.name} identity proof is reviewed for "
            + ", ".join(recipe.allowed_sites)
            + " only"
        )
    if recipe.origin and _https_origin(check_url) != recipe.origin:
        return f"the {recipe.name} identity proof runs on {recipe.origin} only"
    return ""


def recipe_refusal(
    name: object, *, site: object, check_url: object, privilege: object
) -> str:
    """Why the item `site` (its check URL, its `agent_privilege`) may not
    use recipe `name` ('' = it may): `recipe_config_problem`, or an admin
    item while the recipe's "admin" answer is unconfirmed — a valid item
    that stays unproven (``identity_unproven``) until the flag flips. One
    rule for the broker's own proof, its login precheck and challenge gate,
    and the client's proof."""
    problem = recipe_config_problem(name, site=site, check_url=check_url)
    if problem:
        return problem
    recipe = IDENTITIES[str(name)]
    if privilege == "admin" and not recipe.admin_true_confirmed:
        return (
            f"the {recipe.name} identity proof's admin answer is not live-confirmed yet"
        )
    return ""


def item_recipe(
    name: object, *, site: object, check_url: object, privilege: object
) -> IdentityRecipe | None:
    """The recipe the item may use (`recipe_refusal` is ''), else None."""
    if recipe_refusal(name, site=site, check_url=check_url, privilege=privilege):
        return None
    return usable_recipe(name)


def recipe_hosts(entry: Mapping[str, object]) -> frozenset[str]:
    """Hosts of the reviewed recipe a ``sites`` entry declares
    (``agent_identity``): its pinned ``issuer`` (token-endpoint) and its
    ``origin`` — Run:ai's Keycloak on app1.run.ai issues the token its SSO
    login passes through. Only a recipe of the reviewed table whose site and
    origin pins the entry meets; never a host from the vault. The onboarding
    review counts them as the item's own for its cookie hosts."""
    name = entry.get("identity")
    recipe = IDENTITIES.get(name) if isinstance(name, str) else None
    if recipe is None:
        return frozenset()
    if recipe.allowed_sites and entry.get("site") not in recipe.allowed_sites:
        return frozenset()
    check = entry.get("check_url") or entry.get("login_url")
    if recipe.origin and _https_origin(check) != recipe.origin:
        return frozenset()
    hosts = {_norm_host(recipe.issuer), _norm_host(recipe.origin)}
    return frozenset(h for h in hosts if h)


def entry_recipe(entry: Mapping[str, object]) -> IdentityRecipe | None:
    """`item_recipe` of a ``sites`` entry (its check URL, else its login
    URL — where the check looks)."""
    return item_recipe(
        entry.get("identity"),
        site=entry.get("site"),
        check_url=entry.get("check_url") or entry.get("login_url"),
        privilege=entry.get("privilege"),
    )


def proof_ready(entry: Mapping[str, object]) -> bool:
    """A ``sites`` entry the CLIENT can prove the account of (S2): not
    refused, a broker that speaks the identity protocol (``identity_v`` >= 1),
    a usable recipe and a known privilege. A multi-account entry that is not
    proof-ready stays ``identity_unproven`` (fail closed: a rolled-back
    broker, an item without its WS5 fields)."""
    version = entry.get("identity_v")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        return False
    if entry.get("refused"):
        return False
    return entry_recipe(entry) is not None and entry.get("privilege") in PRIVILEGES


FETCH_MS = 8000
TOTAL_MS = 12000
# The most of an admin probe's error body the recipe reads (bytes).
PROBE_BODY_MAX = 65536

# The ONE in-page function every recipe runs; its spec comes from
# `recipe_args` (the reviewed table), never from the page or the vault. It
# fetches the fixed path on the page's own origin (no redirect at all, status
# 200, JSON), reads the identity field and the admin bit, normalises, hashes
# and returns only {state: found|logged_out|indeterminate, digest, admin,
# why?, status?}: the raw value never leaves the page.
RECIPE_JS = r"""async (a) => {
  const out = (state, extra) => Object.assign({state: state}, extra || {});
  const get = (obj, path) => {
    let v = obj;
    for (const k of path) {
      if (v === null || typeof v !== 'object' || Array.isArray(v)
          || !Object.prototype.hasOwnProperty.call(v, k)) return undefined;
      v = v[k];
    }
    return v;
  };
  const norm = (s) => {
    if (typeof s !== 'string') return null;
    let t = s.normalize('NFKC');
    if (!/^[\x00-\x7f]*$/.test(t)) return null;
    t = t.toLowerCase().replace(/^[ \t\n\r\v\f]+|[ \t\n\r\v\f]+$/g, '');
    return t ? t : null;
  };
  // A JWT's payload claims (base64url; no signature check: the server
  // validates the token); null for anything that is not one.
  const jwt = (t) => {
    const parts = t.split('.');
    if (parts.length !== 3 || !parts.every(p => /^[A-Za-z0-9_-]+$/.test(p))) return null;
    try {
      let b = parts[1].replace(/-/g, '+').replace(/_/g, '/');
      while (b.length % 4) b += '=';
      const v = JSON.parse(atob(b));
      return v !== null && typeof v === 'object' && !Array.isArray(v) ? v : null;
    } catch (e) { return null; }
  };
  // sha256(nonce || id) in hex: the only form a name ever leaves the page in.
  const digestOf = async (id) => {
    const data = new Uint8Array(32 + id.length);
    for (let i = 0; i < 32; i++) data[i] = parseInt(a.nonce.substr(2 * i, 2), 16);
    for (let i = 0; i < id.length; i++) data[32 + i] = id.charCodeAt(i);
    const d = new Uint8Array(await crypto.subtle.digest('SHA-256', data));
    return Array.from(d, x => x.toString(16).padStart(2, '0')).join('');
  };
  // One same-origin request: {r} or {err} (a redirect of any kind, another
  // final URL, a network error or the time limit is indeterminate).
  const call = async (origin, path, init) => {
    const url = new URL(path, origin);
    if (url.origin !== origin) return {err: out('indeterminate', {why: 'origin'})};
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), a.fetch_ms);
    let r;
    try {
      r = await fetch(url.href, Object.assign({credentials: 'same-origin',
        cache: 'no-store', redirect: 'manual', signal: ctl.signal}, init));
    } catch (e) {
      return {err: out('indeterminate',
        {why: e && e.name === 'AbortError' ? 'timeout' : 'network'})};
    } finally { clearTimeout(timer); }
    if (r.type === 'opaqueredirect') return {err: out('indeterminate', {why: 'redirect'})};
    let final = null;
    try { final = new URL(r.url); } catch (e) { final = null; }
    if (r.redirected || !final || final.origin !== origin
        || final.pathname !== url.pathname || final.search !== url.search)
      return {err: out('indeterminate', {why: 'redirect', status: r.status})};
    return {r: r};
  };
  // At most `max` bytes of a response body as UTF-8 text; null when it is
  // longer, unreadable or not UTF-8.
  const readCapped = async (r, max) => {
    if (!r.body) return '';
    const reader = r.body.getReader();
    const chunks = [];
    let n = 0;
    try {
      for (;;) {
        const step = await reader.read();
        if (step.done) break;
        n += step.value.length;
        if (n > max) {
          try { await reader.cancel(); } catch (e) { /* gone already */ }
          return null;
        }
        chunks.push(step.value);
      }
    } catch (e) { return null; }
    const buf = new Uint8Array(n);
    let off = 0;
    for (const c of chunks) { buf.set(c, off); off += c.length; }
    try { return new TextDecoder('utf-8', {fatal: true}).decode(buf); }
    catch (e) { return null; }
  };
  const jsonType = (r) =>
    /^application\/json\s*(;|$)/.test((r.headers.get('content-type') || '').toLowerCase());
  // The admin bit of the probe's answer (null = none). A status in
  // admin_probe_true: a JSON content type AND a JSON body. In
  // admin_probe_false: a JSON content type, or — whatever the content type
  // (Run:ai's 403 is text/plain) — a body (capped) that is exactly the
  // recipe's error object. An HTML 200/403 (an SPA fallback, a WAF page)
  // says nothing about the account's rights.
  const probeBit = async (r) => {
    if (a.admin_probe_true.indexOf(r.status) >= 0) {
      if (!jsonType(r)) return null;
      try { await r.json(); } catch (e) { return null; }
      return true;
    }
    if (a.admin_probe_false.indexOf(r.status) < 0) return null;
    if (jsonType(r)) return false;
    const shape = a.admin_probe_error_shape;
    if (!Array.isArray(shape) || shape.length !== 2) return null;
    const text = await readCapped(r, a.probe_body_max);
    if (text === null) return null;
    let v;
    try { v = JSON.parse(text); } catch (e) { return null; }
    if (v === null || typeof v !== 'object' || Array.isArray(v)) return null;
    const keys = Object.keys(v);
    if (keys.length !== 2 || keys.indexOf(shape[0]) < 0 || keys.indexOf(shape[1]) < 0)
      return null;
    if (typeof v[shape[0]] !== 'number' || !Number.isFinite(v[shape[0]])
        || typeof v[shape[1]] !== 'string') return null;
    return false;
  };
  // token-endpoint (Run:ai): POST the fixed body, read the JWT the server
  // returns, pin its claims, read the identity claim; the admin bit from
  // a fixed GET with that token as bearer. The token never leaves here.
  const tokenWork = async (origin) => {
    const tok = await call(origin, a.path, {method: 'POST',
      headers: {Accept: 'application/json', 'Content-Type': 'application/json'},
      body: JSON.stringify(a.token_body)});
    if (tok.err) return tok.err;
    const r = tok.r;
    if (r.status === 401 || r.status === 403) return out('logged_out', {status: r.status});
    if (r.status !== 200) return out('indeterminate', {why: 'status', status: r.status});
    const ct = (r.headers.get('content-type') || '').toLowerCase();
    if (!/^application\/json\s*(;|$)/.test(ct))
      return out('indeterminate', {why: 'content-type', status: r.status});
    let body;
    try { body = await r.json(); } catch (e) { return out('indeterminate', {why: 'body'}); }
    if (body === null || typeof body !== 'object' || Array.isArray(body))
      return out('indeterminate', {why: 'schema'});
    const t = get(body, a.token_field);
    if (typeof t !== 'string' || !t) return out('indeterminate', {why: 'token'});
    const claims = jwt(t);
    if (claims === null) return out('indeterminate', {why: 'token'});
    for (const pin of a.claim_pins)
      if (get(claims, [pin[0]]) !== pin[1]) return out('indeterminate', {why: 'claim'});
    if (get(claims, ['iss']) !== a.issuer) return out('indeterminate', {why: 'claim'});
    const exp = get(claims, ['exp']);
    if (typeof exp !== 'number' || !isFinite(exp) || exp * 1000 <= Date.now())
      return out('indeterminate', {why: 'expired'});
    const id = norm(get(claims, a.id_field));
    if (id === null) return out('indeterminate', {why: 'identity'});
    const probe = await call(origin, a.admin_probe, {method: 'GET',
      headers: {Accept: 'application/json', Authorization: 'Bearer ' + t}});
    const admin = probe.err ? null : await probeBit(probe.r);
    return out('found', {digest: await digestOf(id), admin: admin});
  };
  const work = async () => {
    const origin = location.origin;
    if (!origin || origin === 'null' || origin !== a.origin)
      return out('indeterminate', {why: 'origin'});
    if (!/^[0-9a-f]{64}$/.test(a.nonce)) return out('indeterminate', {why: 'nonce'});
    if (!window.crypto || !crypto.subtle) return out('indeterminate', {why: 'crypto'});
    if (a.auth === 'token-endpoint') return await tokenWork(origin);
    const headers = {Accept: 'application/json'};
    let path = a.path, claim = null;
    if (a.auth === 'bearer-local-storage' || a.auth === 'jwt-local-storage') {
      let t = null;
      try { t = localStorage.getItem(a.token_key); } catch (e) { t = null; }
      if (typeof t !== 'string' || !t) return out('logged_out', {why: 'no token'});
      if (a.auth === 'jwt-local-storage') {
        const claims = jwt(t);
        if (claims === null) return out('indeterminate', {why: 'token'});
        claim = get(claims, [a.path_claim]);
        if (typeof claim !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(claim))
          return out('indeterminate', {why: 'claim'});
        path = a.path + claim;
      }
      headers[a.auth_header] = a.auth_scheme + t;
    } else if (a.auth === 'syno-token') {
      let t = null;
      try { t = window.SYNO.SDS.Session.SynoToken; } catch (e) { t = null; }
      if (typeof t !== 'string' || !t) return out('indeterminate', {why: 'no token'});
      headers['X-SYNO-TOKEN'] = t;
    } else if (a.auth !== 'cookie') {
      return out('indeterminate', {why: 'auth'});
    }
    const url = new URL(path, origin);
    if (url.origin !== origin) return out('indeterminate', {why: 'origin'});
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), a.fetch_ms);
    let r;
    try {
      r = await fetch(url.href, {headers: headers, credentials: 'same-origin',
        cache: 'no-store', redirect: 'manual', signal: ctl.signal});
    } catch (e) {
      return out('indeterminate', {why: e && e.name === 'AbortError' ? 'timeout' : 'network'});
    } finally { clearTimeout(timer); }
    if (r.type === 'opaqueredirect') return out('indeterminate', {why: 'redirect'});
    let final = null;
    try { final = new URL(r.url); } catch (e) { final = null; }
    if (r.redirected || !final || final.origin !== origin || final.pathname !== url.pathname)
      return out('indeterminate', {why: 'redirect', status: r.status});
    if (r.status === 401 || r.status === 403) return out('logged_out', {status: r.status});
    if (r.status !== 200) return out('indeterminate', {why: 'status', status: r.status});
    const ct = (r.headers.get('content-type') || '').toLowerCase();
    if (!/^application\/json\s*(;|$)/.test(ct))
      return out('indeterminate', {why: 'content-type', status: r.status});
    let body;
    try { body = await r.json(); } catch (e) { return out('indeterminate', {why: 'body'}); }
    if (body === null || typeof body !== 'object' || Array.isArray(body))
      return out('indeterminate', {why: 'schema'});
    if (a.ok_field && get(body, a.ok_field) !== true) {
      const code = a.error_code_field ? get(body, a.error_code_field) : undefined;
      if (typeof code === 'number' && a.logged_out_codes.indexOf(code) >= 0)
        return out('logged_out', {why: 'api'});
      return out('indeterminate', {why: 'schema'});
    }
    if (a.must_be_null && get(body, a.must_be_null) !== null)
      return out('indeterminate', {why: 'impersonation'});
    if (a.claim_field && (claim === null || get(body, a.claim_field) !== claim))
      return out('indeterminate', {why: 'claim'});
    const id = norm(get(body, a.id_field));
    if (id === null) return out('indeterminate', {why: 'identity'});
    let admin = null;
    if (a.admin_field) {
      const v = get(body, a.admin_field);
      if (v === undefined && a.absent_admin_is_false) admin = false;
      else if (a.admin_true.indexOf(v) >= 0) admin = true;
      else if (a.admin_false.indexOf(v) >= 0) admin = false;
    }
    return out('found', {digest: await digestOf(id), admin: admin});
  };
  let timer;
  const cap = new Promise(res => {
    timer = setTimeout(() => res(out('indeterminate', {why: 'deadline'})), a.total_ms);
  });
  try { return await Promise.race([work(), cap]); }
  catch (e) { return out('indeterminate', {why: 'error'}); }
  finally { clearTimeout(timer); }
}"""


def check_origin(check_url: str) -> str:
    """``scheme://host[:port]`` of a check URL, lower-case ('' when none)."""
    try:
        parts = urllib.parse.urlsplit(str(check_url or ""))
    except ValueError:
        return ""
    if parts.scheme not in ("https", "http") or not parts.netloc:
        return ""
    return f"{parts.scheme}://{parts.netloc}".lower()


def recipe_path(recipe: IdentityRecipe, check_url: str) -> str:
    """The recipe's fixed path, prefixed by the check URL's first path
    segment when the recipe allows exactly that one (ABS's /audiobookshelf)."""
    try:
        first = urllib.parse.urlsplit(str(check_url or "")).path.split("/")[1:2]
    except ValueError:
        first = []
    if first and first[0] in recipe.base_segments:
        return f"/{first[0]}{recipe.path}"
    return recipe.path


def recipe_args(
    recipe: IdentityRecipe, check_url: str, nonce_hex: str
) -> dict[str, object]:
    """The argument of ``RECIPE_JS``: `recipe` on the origin of `check_url`
    with `nonce_hex` — everything from the reviewed table."""

    def opt(path: tuple[str, ...] | None) -> list[str] | None:
        return list(path) if path else None

    return {
        "origin": recipe.origin or check_origin(check_url),
        "path": recipe_path(recipe, check_url),
        "nonce": nonce_hex,
        "auth": recipe.auth,
        "token_key": recipe.token_key,
        "auth_header": recipe.auth_header,
        "auth_scheme": recipe.auth_scheme,
        "path_claim": recipe.path_claim,
        "claim_field": opt(recipe.claim_field),
        "id_field": list(recipe.id_field),
        "admin_field": opt(recipe.admin_field),
        "admin_true": list(recipe.admin_true),
        "admin_false": list(recipe.admin_false),
        "absent_admin_is_false": recipe.absent_admin_is_false,
        "ok_field": opt(recipe.ok_field),
        "error_code_field": opt(recipe.error_code_field),
        "logged_out_codes": list(recipe.logged_out_codes),
        "must_be_null": opt(recipe.must_be_null),
        "token_body": dict(recipe.token_body),
        "token_field": opt(recipe.token_field),
        "claim_pins": [list(pin) for pin in recipe.claim_pins],
        "issuer": recipe.issuer,
        "admin_probe": recipe.admin_probe,
        "admin_probe_true": list(recipe.admin_probe_true),
        "admin_probe_false": list(recipe.admin_probe_false),
        "admin_probe_error_shape": list(recipe.admin_probe_error_shape),
        "probe_body_max": PROBE_BODY_MAX,
        "fetch_ms": FETCH_MS,
        "total_ms": TOTAL_MS,
    }


def foreign_storage_keys(entry: Mapping[str, object]) -> dict[str, list[str]]:
    """The localStorage keys a check clears, besides the cookies, when it
    finds ANOTHER account's session of a multi-account item: only for an
    item whose recipe authenticates from localStorage (`LOCAL_STORAGE_AUTHS`;
    a cookie session has nothing there), and only on its check and fill
    origins (https): on each, the item's declared keys of that origin
    (``storage_keys``, the keys its session bundle injects); on the CHECK
    origin — where the recipe reads it — also the recipe's own token key. A
    fill origin may be an SSO provider other sites share: it never loses an
    undeclared key. ``{origin: sorted keys}`` (an origin without a key is
    left out); {} for any other item.

    S4c: a recipe's `identity_storage_keys` (the page's own account claim,
    Run:ai's `logged-in-user-email`) go too, on the check origin — for a
    token-endpoint recipe only there and only when it is the recipe's
    `origin` — so a foreign account's e-mail does not linger in the UI."""
    recipe = usable_recipe(entry.get("identity"))
    if recipe is None:
        return {}
    check = _https_origin(entry.get("check_url") or entry.get("login_url"))
    if recipe.auth not in LOCAL_STORAGE_AUTHS:
        claim = sorted({k for k in recipe.identity_storage_keys if k})
        if claim and recipe.origin and check == recipe.origin:
            return {check: claim}
        return {}
    origins = [check, *(_https_origin(o) for o in _list(entry.get("fill_origins")))]
    declared: dict[str, set[str]] = {}
    raw = entry.get("storage_keys")
    for origin, keys in raw.items() if isinstance(raw, Mapping) else []:
        norm = _https_origin(origin)
        if norm:
            declared.setdefault(norm, set()).update(_list(keys))
    out: dict[str, list[str]] = {}
    for origin in origins:
        if origin and origin not in out:
            names = set(declared.get(origin, ()))
            if origin == check:
                names.add(recipe.token_key)
                names.update(recipe.identity_storage_keys)
            out[origin] = sorted(k for k in names if k)
    return {origin: names for origin, names in out.items() if names}
