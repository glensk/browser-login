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
host level (parent domains included, cookie names and paths ignored), and every
listed item takes part, refused ones included (their cookies may still be in
the browser).

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

from __future__ import annotations

import hashlib
import hmac
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


def _list(value: object) -> list[str]:
    """A field that holds one string or a list of strings, as a list."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if isinstance(v, str)]
    return []


def scope_hosts(entry: Mapping[str, object]) -> frozenset[str]:
    """Every host an item's session lives on or is typed into: its cookie
    hosts, and the hosts of its fill and storage origins."""
    hosts = {_norm_host(h) for h in _list(entry.get("cookie_hosts"))}
    for key in ("fill_origins", "storage_origins"):
        hosts |= {_norm_host(o) for o in _list(entry.get(key))}
    hosts.discard("")
    return frozenset(hosts)


def hosts_overlap(a: Iterable[str], b: Iterable[str]) -> bool:
    """Any host of `a` equals, or is a parent or a subdomain of, a host of
    `b` (cookie domain matching in both directions: ``docker.com`` covers
    ``app.docker.com``)."""
    bs = list(b)
    for x in a:
        for y in bs:
            if x == y or x.endswith("." + y) or y.endswith("." + x):
                return True
    return False


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
        (str(e.get("site")), e, scope_hosts(e))
        for e in sites
        if isinstance(e, Mapping) and isinstance(e.get("site"), str) and e.get("site")
    ]
    out: dict[str, set[str]] = {}
    for i, (sa, ea, ha) in enumerate(items):
        for sb, eb, hb in items[i + 1 :]:
            if sa == sb or not ha or not hb:
                continue
            if hosts_overlap(ha, hb) and not _same_account(ea, eb):
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
    # the origin's localStorage) or "syno-token" (DSM's in-page SynoToken).
    auth: str = "cookie"
    token_key: str = ""
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


# Reviewed recipes only. navidrome and Run:ai are absent on purpose: no
# server-bound endpoint is confirmed yet, so their items stay unproven (an
# `agent_identity` naming them is refused).
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
    bit (the privilege check needs one). None for anything else — dsm and
    authentik until S4 confirms them live; their items stay unproven."""
    recipe = IDENTITIES.get(name) if isinstance(name, str) else None
    if recipe is None or not recipe.live_confirmed or recipe.admin_field is None:
        return None
    return recipe


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
    return (
        usable_recipe(entry.get("identity")) is not None
        and entry.get("privilege") in PRIVILEGES
    )


FETCH_MS = 8000
TOTAL_MS = 12000

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
  const work = async () => {
    const origin = location.origin;
    if (!origin || origin === 'null' || origin !== a.origin)
      return out('indeterminate', {why: 'origin'});
    if (!/^[0-9a-f]{64}$/.test(a.nonce)) return out('indeterminate', {why: 'nonce'});
    if (!window.crypto || !crypto.subtle) return out('indeterminate', {why: 'crypto'});
    const url = new URL(a.path, origin);
    if (url.origin !== origin) return out('indeterminate', {why: 'origin'});
    const headers = {Accept: 'application/json'};
    if (a.auth === 'bearer-local-storage') {
      let t = null;
      try { t = localStorage.getItem(a.token_key); } catch (e) { t = null; }
      if (typeof t !== 'string' || !t) return out('logged_out', {why: 'no token'});
      headers.Authorization = 'Bearer ' + t;
    } else if (a.auth === 'syno-token') {
      let t = null;
      try { t = window.SYNO.SDS.Session.SynoToken; } catch (e) { t = null; }
      if (typeof t !== 'string' || !t) return out('indeterminate', {why: 'no token'});
      headers['X-SYNO-TOKEN'] = t;
    } else if (a.auth !== 'cookie') {
      return out('indeterminate', {why: 'auth'});
    }
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
    const id = norm(get(body, a.id_field));
    if (id === null) return out('indeterminate', {why: 'identity'});
    let admin = null;
    if (a.admin_field) {
      const v = get(body, a.admin_field);
      if (v === undefined && a.absent_admin_is_false) admin = false;
      else if (a.admin_true.indexOf(v) >= 0) admin = true;
      else if (a.admin_false.indexOf(v) >= 0) admin = false;
    }
    const data = new Uint8Array(32 + id.length);
    for (let i = 0; i < 32; i++) data[i] = parseInt(a.nonce.substr(2 * i, 2), 16);
    for (let i = 0; i < id.length; i++) data[32 + i] = id.charCodeAt(i);
    const d = new Uint8Array(await crypto.subtle.digest('SHA-256', data));
    const digest = Array.from(d, x => x.toString(16).padStart(2, '0')).join('');
    return out('found', {digest: digest, admin: admin});
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
        "origin": check_origin(check_url),
        "path": recipe_path(recipe, check_url),
        "nonce": nonce_hex,
        "auth": recipe.auth,
        "token_key": recipe.token_key,
        "id_field": list(recipe.id_field),
        "admin_field": opt(recipe.admin_field),
        "admin_true": list(recipe.admin_true),
        "admin_false": list(recipe.admin_false),
        "absent_admin_is_false": recipe.absent_admin_is_false,
        "ok_field": opt(recipe.ok_field),
        "error_code_field": opt(recipe.error_code_field),
        "logged_out_codes": list(recipe.logged_out_codes),
        "must_be_null": opt(recipe.must_be_null),
        "fetch_ms": FETCH_MS,
        "total_ms": TOTAL_MS,
    }
