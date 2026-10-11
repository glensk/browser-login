"""Where the broker's site list and secrets come from: Bitwarden (or a dev fixture).

Whitelisting a site = its login item sits in the ``agent-logins`` collection AND
carries the custom field ``agent_fill_origins``. Items without it are listed as
refused, and so are items with neither a check URL (``agent_check_url`` or a
built-in default for the site id) nor a sentinel (``agent_logged_in_selector``):
without one the broker cannot PROVE a login worked. Secrets never leave this
module except as a ``Secret`` handed to a recipe; ``Secret`` has a redacting
``repr`` so a stray log line shows nothing.

Accounts that share one cookie scope (WS5, tp#833): ``agent_instance``,
``agent_privilege``, ``agent_identity``, ``agent_same_account_as`` and
``agent_alias`` are validated per item, then ``identity_rules`` runs over the
whole collection — at most one account per scope per browser instance, a
privilege on every multi-account item, symmetric same-account declarations,
unique aliases. A refused item keeps its scope: it still takes part in the
conflict check.

``BwVault`` drives the ``bw`` CLI with secrets in the ENVIRONMENT only (never
argv): the API key logs the broker's own Vaultwarden user in, the master
password unlocks (``--passwordenv``), the session key lives in memory and is
passed as ``BW_SESSION``, and the vault is locked again after every call.
Every ``bw`` read (unlock + sync + list + lock) runs under ONE process-wide
lock, ``BW_LOCK``: the CLI's appdata dir is shared state, and concurrent misses
of the secret cache wait for the read in flight and reuse its result.

Secrets for agents (``secret-run``) come from a SECOND collection,
``secrets_collection_id`` in the bootstrap: ``SecretItem`` is the metadata
(id, exposed field names, TOTP present) and ``SecretValues`` the values, kept in
``VaultCache`` for ``SECRET_TTL_S``. A cache entry from an older generation
(bumped by every ``bw sync`` and by ``invalidate``) is never served. Python
cannot zero ``str``/JSON copies: dropping a cache entry does not erase memory.
"""

from __future__ import annotations

# item parsing, bootstrap and the bw CLI belong together.
# pylint: disable=too-many-lines
import json
import os
import re
import subprocess
import threading
import urllib.parse
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Protocol

from broker import identity as _identity
from broker.bundle import SiteBundleSpec, is_idp_host
from broker.origins import parse_fill_origins
from broker.recipes import (
    DEFAULT_CHECK_URLS,
    DEFAULT_LOGGED_IN_SELECTORS,
    SESSION_REFRESHERS,
    USERNAME_ONLY_MODE,
    generic_login,
    has_server_proof,
    recipe_for,
    session_refresh_name,
)
from broker.vault_cache import (
    VaultCache,
)

SITE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
# Sites the broker NEVER submits a password for, whatever the item says: their
# IdP answers the headless broker's password with "credentials wrong" (a bot
# check), and every such submit risks a vendor-side lock. Agents use Albert's
# session there (Safari import, guided login). Any other item opts in with the
# custom field ``agent_no_submit=true``. This set cannot be lifted from the
# vault (``agent_no_submit=false`` keeps it), only by a code change.
NO_SUBMIT_SITES = frozenset({"galaxus", "galaxus-de"})
# The same by WHERE the password would be typed, whatever the item is called
# (a renamed or duplicate item, e.g. "digitec.ch galaxus.ch"): a fill origin on
# one of these registrable domains (or a subdomain) makes the item no-submit.
# Digitec Galaxus' IdPs: id.digitecgalaxus.ch (CH, digitec.ch shares it) and
# id.galaxus.eu (the EU shops), plus every shop's own domain.
NO_SUBMIT_DOMAINS = (
    "digitecgalaxus.ch",
    "galaxus.eu",
    "galaxus.ch",
    "galaxus.de",
    "galaxus.at",
    "galaxus.fr",
    "galaxus.it",
    "galaxus.nl",
    "galaxus.be",
    "digitec.ch",
)
# A no-submit domain anywhere in a URI as written — also inside a Bitwarden
# regex URI (`^https://.*\.galaxus\.ch`, backslashes dropped first): a label
# boundary on both sides, so `notgalaxus.ch` does not match.
_NO_SUBMIT_TOKEN_RE = re.compile(
    r"(?<![a-z0-9-])(?:"
    + "|".join(re.escape(d) for d in NO_SUBMIT_DOMAINS)
    + r")(?![a-z0-9-])"
)
NO_SUBMIT_SECRET = "a no-submit login item is never exposed as a secret"
# `agent_login_mode`: how the broker logs in with an item. `password` (the
# default) types username + password; `username-only` types ONLY the item's
# username — e.g. Mullvad's account number, which is the whole credential.
# Such a username is a secret like a password: it reaches the recipe as
# ``Secret.password`` (so every masking path treats it as one) and the secret
# ops never expose the item.
PASSWORD_MODE = "password"
USERNAME_ONLY = USERNAME_ONLY_MODE
LOGIN_MODES = (PASSWORD_MODE, USERNAME_ONLY)
USERNAME_ONLY_SECRET = "a username-only login item is never exposed as a secret"
NO_PASSWORD = (
    "the item has no password (if it logs in with only a username/account "
    "number, set agent_login_mode=username-only; if it should have one, check "
    "the item or the collection permission 'Can view' vs 'except passwords')"
)
NO_USERNAME = (
    "the item has no username (agent_login_mode=username-only logs in with "
    "the username/account number alone)"
)
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9._ -]{1,64}$")
BW_TIMEOUT_S = 120.0
# A value shorter than this is refused unless the item sets
# agent_secret_allow_short=true (then it is masked raw-only).
SHORT_BELOW_BYTES = 8
MIN_SECRET_BYTES = 6
NO_SECRETS_COLLECTION = "no secrets collection configured"
# Every `bw` CLI read of this process (one appdata dir) is serialised here.
# Re-entrant: a secret-cache fill holds it across its own `bw` read.
BW_LOCK = threading.RLock()


class VaultError(RuntimeError):
    """The vault could not be read. The message never carries a secret."""

    code = "vault_error"


class MissingSecret(VaultError):
    """The item was read but lacks the secret its login mode needs: no
    password (``no_password``), or a username-only item without a username
    (``no_username``). Not a Bitwarden read failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class SecretsNotConfigured(VaultError):
    """The bootstrap names no secrets collection (``secret``/``totp`` refuse)."""


@dataclass(frozen=True)
class Secret:
    """Login secret for one site. ``repr`` is redacted on purpose.

    `mode` ``username-only``: the item's username IS the credential (an
    account number). It is carried as `password` — the fingerprint, the
    diagnostics' masking, the field checks and the tripwire treat it as the
    secret — and `username` stays empty, so no path types or shows it as a
    user name."""

    username: str = field(repr=False)
    password: str = field(repr=False)
    totp_seed: str | None = field(default=None, repr=False)
    mode: str = PASSWORD_MODE

    def __repr__(self) -> str:
        return "Secret(<redacted>)"

    @property
    def identity(self) -> str:
        """WHICH account this secret logs into, for an identity proof (WS5):
        the username — for a username-only login the account number, which
        is the secret itself (compare it in the page, never print it)."""
        return self.password if self.mode == USERNAME_ONLY else self.username


@dataclass(frozen=True)
class SiteItem:  # pylint: disable=too-many-instance-attributes
    """One vault item as the broker sees it — no secret fields."""

    site: str
    name: str
    fill_origins: list[str] = field(default_factory=list)
    cookie_hosts: list[str] = field(default_factory=list)
    cookie_names: list[str] | None = None
    storage_keys: dict[str, list[str]] = field(default_factory=dict)
    # `agent_cookie_scopes` (WS5 S4c): the cookie scopes WITH a path (a
    # Keycloak realm); () = every cookie host at path "/". `cookie_hosts`
    # then holds their hosts, for readers that predate `scope_v`.
    cookie_scopes: tuple[_identity.CookieScope, ...] = ()
    login_url: str = ""
    check_url: str = ""
    logged_in_selector: str | None = None
    # Which authenticator to answer when the account has several (Keycloak's
    # "selectedCredentialId" choice): a substring of its label, e.g. "Mac m1".
    otp_label: str | None = None
    # `agent_fresh_login`: every login first clears the broker profile's cookies
    # for the site's cookie hosts and fill origins, so the login runs through
    # the identity provider again and its session-only SSO cookie is created in
    # THIS run (and exported, when `cookie_hosts` names the IdP host).
    fresh_login: bool = False
    # `agent_pre_click`: CSS of an element clicked ONCE (if it shows, and only
    # while page and element are on a fill origin) before the login fields are
    # looked for — e.g. Jellyfin's "Manual login" button behind its user picker.
    pre_click: str | None = None
    # `agent_attempt_group`: an opaque slug shared by every item that logs into
    # ONE account (e.g. two shop domains on one identity provider); the broker
    # limiter then enforces its rules on `group:<id>` too.
    attempt_group: str | None = None
    # `agent_proof_origins`: further origins (besides the check URL's) where
    # the logged-in proof may end after redirects.
    proof_origins: list[str] = field(default_factory=list)
    # `agent_session_refresh`: the refresher (``recipes.SESSION_REFRESHERS``)
    # that renews a storage token before a reused profile is exported; "none"
    # switches a built-in default off; None = the default for the site id.
    session_refresh: str | None = None
    # `agent_no_submit`, the site in ``NO_SUBMIT_SITES`` or a fill origin on
    # ``NO_SUBMIT_DOMAINS``: the login runner never asks for the secret, so it
    # never types or submits a password for this site (``submit_disabled``); a
    # reusable broker profile is still exported. (The `fingerprint` op still
    # hashes the password: it never logs in.)
    no_submit: bool = False
    # `agent_max_session_days`: the server ends a session this many days after
    # its login, however much it is used (Calibre-Web Automated: 31 days, the
    # row's expiry is set at login and never extended). The client then asks
    # for a fresh login once its last proven fresh authentication is this old,
    # while the session still works. Only with `agent_fresh_login` (a reused
    # broker profile would hand back the same ageing session). None = no limit.
    max_session_days: int | None = None
    # `agent_login_mode`: ``password`` (default) or ``username-only`` (the
    # username alone is typed and submitted; see ``Secret``).
    login_mode: str = PASSWORD_MODE
    refused: str | None = None
    item_id: str = ""
    # --- WS5 (tp#833, broker/identity.py): accounts sharing one cookie scope.
    # `agent_instance`: the browser instance the item lives in ("" = the
    # shared 9222 browser, else identity.ROLE_INSTANCES).
    instance: str = ""
    # `agent_privilege`: admin | user | readonly ("" = not declared;
    # mandatory on a multi-account item and with `agent_identity`).
    privilege: str = ""
    # `agent_identity`: the reviewed recipe (identity.IDENTITIES) that proves
    # WHICH account a session holds; "" = none.
    identity: str = ""
    # `agent_same_account_as`: the site id of the item that logs into the
    # same account — declared on BOTH items, else both are refused.
    same_account_as: str = ""
    # `agent_alias`: a name the group's default member also answers to.
    alias: str = ""
    # The item's scope overlaps another account's item (any instance): set
    # by `build_items` over the whole collection.
    multi_account: bool = False
    # The login's username, for the broker's identity proof, the challenge
    # ops and the account tag ONLY: never in `public()`, a log or an error.
    account_name: str = field(default="", repr=False, compare=False)

    def identity_view(self) -> dict[str, Any]:
        """The WS5 fields of the ``sites`` view (no account name, no tag)."""
        return {
            "instance": self.instance,
            "privilege": self.privilege or None,
            "identity": self.identity or None,
            "alias": self.alias or None,
            "same_account_as": [self.same_account_as] if self.same_account_as else [],
            "multi_account": self.multi_account,
            "identity_v": _identity.IDENTITY_V,
        }

    @property
    def scopes(self) -> tuple[_identity.CookieScope, ...]:
        """The item's cookie scopes: `cookie_scopes`, else every cookie host
        at path "/" (the whole host)."""
        if self.cookie_scopes:
            return tuple(self.cookie_scopes)
        return tuple(
            s for s in (_identity.CookieScope(h) for h in self.cookie_hosts) if s.host
        )

    @property
    def identity_recipe(self) -> _identity.IdentityRecipe | None:
        """The recipe this item may use (`identity.item_recipe`: usable, its
        site and check origin allowed, its privilege covered), else None."""
        return _identity.item_recipe(
            self.identity,
            site=self.site,
            check_url=self.check_url or self.login_url,
            privilege=self.privilege,
        )

    @property
    def has_proof(self) -> bool:
        """The STRICT proof is possible: an authenticated DOM sentinel exists,
        or the site has a registered server proof (``recipes.PROOFS``: CSCS
        asks its API with the stored token). Without one only the old, weaker
        proof is left: never for a scheduled login."""
        return bool(self.logged_in_selector) or has_server_proof(self.site)

    @property
    def limiter_keys(self) -> list[str]:
        """The broker limiter keys of a login: the site, plus its group."""
        keys = [self.site]
        if self.attempt_group:
            keys.append(f"group:{self.attempt_group}")
        return keys

    @property
    def bundle_spec(self) -> SiteBundleSpec:
        """What may be exported for this site."""
        return SiteBundleSpec(
            cookie_hosts=list(self.cookie_hosts),
            cookie_names=list(self.cookie_names) if self.cookie_names else None,
            storage_keys={k: list(v) for k, v in self.storage_keys.items()},
            cookie_scopes=self.scopes,
        )

    def public(self) -> dict[str, Any]:
        """The ``sites`` view: ids, origins and scope — never a secret."""
        return {
            "site": self.site,
            "name": self.name,
            "fill_origins": list(self.fill_origins),
            "cookie_hosts": list(self.cookie_hosts),
            # WS5 S4c: the scopes with their paths; a reader that predates
            # `scope_v` uses `cookie_hosts` (host-wide: fail closed)
            "cookie_scopes": [s.view() for s in self.scopes],
            "scope_v": _identity.SCOPE_V,
            "cookie_names": list(self.cookie_names) if self.cookie_names else None,
            "storage_origins": sorted(self.storage_keys),
            "login_url": self.login_url,
            "check_url": self.check_url,
            "logged_in_selector": self.logged_in_selector,
            "fresh_login": self.fresh_login,
            "pre_click": self.pre_click,
            **self.identity_view(),
            "attempt_group": self.attempt_group,
            "sentinel": bool(self.logged_in_selector),
            # the strict proof is possible (sentinel OR a server proof): what
            # agent-login's needs-sentinel / promotion gates read
            "strict_proof": self.has_proof,
            "proof_origins": list(self.proof_origins),
            "storage_keys": {o: list(k) for o, k in self.storage_keys.items()},
            "session_refresh": session_refresh_name(self),
            "no_submit": self.no_submit or self.site in NO_SUBMIT_SITES,
            "max_session_days": self.max_session_days,
            # a flag, not the mode's name: the `sites` view never says
            # "password" (a leak canary in the tests checks for the word)
            "username_only": self.login_mode == USERNAME_ONLY,
            "refused": self.refused is not None,
            "reason": self.refused or "",
        }


class Vault(Protocol):
    """The broker's view of the credential store."""

    def items(self) -> list[SiteItem]:
        """Every item of the collection, refused ones included."""

    def secret(self, site: str) -> Secret:
        """The LOGIN secret of a non-refused site (VaultError otherwise, and for
        a no-submit site)."""

    def fingerprint_secret(self, site: str) -> Secret:
        """The secret for the `fingerprint` op only (no-submit sites too: it
        never logs in)."""

    def secret_items(self) -> list[SecretItem]:
        """Items of the secrets collection (SecretsNotConfigured without one)."""

    def secret_values(self, secret_id: str) -> SecretValues:
        """The exposed values of one secrets item (VaultError when unknown)."""

    def invalidate(self) -> int:
        """Drop every cached value; returns the new cache generation."""


def safe_name(text: str, n: int, *, prefix: str = "item") -> str:
    """`text` when it matches ``SAFE_NAME_RE``, else ``<prefix>-<n>``: names that
    reach a response, an audit line or ``agents.md`` can never carry a value
    somebody stored AS a name."""
    return text if SAFE_NAME_RE.match(text) else f"{prefix}-{n}"


@dataclass(frozen=True)
class SecretValues:
    """The exposed values of one secrets item. ``repr`` is redacted on purpose."""

    fields: Mapping[str, str] = field(default_factory=dict, repr=False)
    totp_seed: str | None = field(default=None, repr=False)

    def __repr__(self) -> str:
        return "SecretValues(<redacted>)"

    def nbytes(self) -> int:
        """Approximate size, for the cache's byte cap."""
        size = sum(
            len(k) + len(v.encode("utf-8", "surrogateescape"))
            for k, v in self.fields.items()
        )
        return size + len(self.totp_seed or "")


@dataclass(frozen=True)
class SecretItem:  # pylint: disable=too-many-instance-attributes
    """One item of the secrets collection as agents may see it — no values.

    `listed` = the field names an agent may request (``password`` + the item's
    ``agent_secret_fields``); `fields` = those of them that hold a value.
    """

    secret_id: str
    name: str
    fields: tuple[str, ...] = ()
    listed: tuple[str, ...] = ()
    has_totp: bool = False
    allow_short: bool = False
    short: bool = False
    refused: str | None = None
    item_id: str = ""

    def public(self) -> dict[str, Any]:
        """The ``secrets`` view: ids and field NAMES — never a value or seed."""
        return {
            "id": self.secret_id,
            "name": self.name,
            "fields": list(self.fields),
            "has_totp": self.has_totp,
            "short": self.short,
            "refused": self.refused is not None,
            "reason": self.refused or "",
        }


_BUILTIN_FIELDS = ("password", "username", "notes")


def _custom_field_counts(item: Mapping[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in item.get("fields") or []:
        if isinstance(f, Mapping) and f.get("name"):
            name = str(f["name"])
            counts[name] = counts.get(name, 0) + 1
    return counts


def _builtin_value(item: Mapping[str, Any], name: str) -> str:
    login = item.get("login") or {}
    if not isinstance(login, Mapping):
        login = {}
    if name == "notes":
        raw = item.get("notes")
    else:
        raw = login.get(name)
    return "" if raw is None else str(raw)


def value_bytes(value: str) -> int:
    """UTF-8 length of `value` (what the variant policy measures)."""
    return len(value.encode("utf-8", "surrogateescape"))


def is_short(value: str) -> bool:
    """Shorter than the variant policy's 8 bytes: masked and registered
    raw-only, so the item must opt in with ``agent_secret_allow_short``."""
    return value_bytes(value) < SHORT_BELOW_BYTES


def mentions_no_submit_domain(text: str) -> bool:
    """True when `text` (a URI as written, a Bitwarden regex included) names a
    ``NO_SUBMIT_DOMAINS`` domain: lowercased, backslashes and ``[.]`` dropped."""
    norm = text.lower().replace("\\", "").replace("[.]", ".")
    return _NO_SUBMIT_TOKEN_RE.search(norm) is not None


def _no_submit_reason(item: Mapping[str, Any], fields: Mapping[str, str]) -> str | None:
    """Why the secret ops refuse a secrets-collection item that is (a copy of)
    a no-submit login, else None: its ``agent_no_submit`` says so (or is
    malformed), its ``agent_site`` is in ``NO_SUBMIT_SITES``, or a fill origin /
    login URI names a ``NO_SUBMIT_DOMAINS`` domain. An origin or URI that
    cannot be read is refused too (``malformed URI``: fail closed) — covers a
    secrets collection holding a copy, or one configured equal to agent-logins."""
    texts, problem = _item_origin_texts(item, fields)
    if (
        # true, or a malformed value: fail closed
        _parse_flag(fields.get("agent_no_submit", "")) is not False
        or (fields.get("agent_site") or "").strip().lower() in NO_SUBMIT_SITES
        or any(mentions_no_submit_domain(t) for t in texts)
    ):
        return NO_SUBMIT_SECRET
    if not problem:
        try:
            return NO_SUBMIT_SECRET if no_submit_by_origin(texts) else None
        except ValueError:
            problem = "unparsable"
    return f"malformed URI ({problem}): cannot tell whether it is a no-submit login"


def _item_origin_texts(
    item: Mapping[str, Any], fields: Mapping[str, str]
) -> tuple[list[str], str]:
    """(an item's ``agent_fill_origins`` + login URIs as written, the first
    structural problem or ''). Fixed problem texts only (never a value)."""
    raw_origins = fields.get("agent_fill_origins", "").strip()
    texts = _split_list(raw_origins)
    problem = ""
    if raw_origins:
        try:
            parse_fill_origins(raw_origins)  # the login items' strict parser
        except ValueError:
            problem = "bad agent_fill_origins"
    login = item.get("login") or {}
    uris = login.get("uris") if isinstance(login, Mapping) else None
    if not isinstance(login, Mapping) or not isinstance(uris or [], list):
        return texts, "login block"
    for uri in uris or []:
        if not isinstance(uri, Mapping):
            problem = problem or "login URI entry"
        elif uri.get("uri"):
            texts.append(str(uri["uri"]))
    return texts, problem


# A flat validator: one early refusal per rule, in field order.
# pylint: disable-next=too-many-locals,too-many-return-statements,too-many-branches
def secret_item_from_json(
    item: Mapping[str, Any], n: int
) -> tuple[SecretItem, SecretValues | None]:
    """Build a ``SecretItem`` (+ its values) from a Bitwarden item JSON; problems
    become ``refused`` and carry no values. `n` numbers unsafe names."""
    raw_name = str(item.get("name") or "")
    name = safe_name(raw_name, n)
    fields = _fields(item)
    item_id = str(item.get("id") or "")
    raw_id = (fields.get("agent_secret_id") or "").strip().lower() or slugify(raw_name)
    secret_id = raw_id if SITE_ID_RE.match(raw_id) else f"item-{n}"

    def refused(reason: str) -> tuple[SecretItem, None]:
        return SecretItem(secret_id, name, item_id=item_id, refused=reason), None

    if not SITE_ID_RE.match(raw_id):
        return refused("invalid agent_secret_id")
    why = _no_submit_reason(item, fields)
    if why:
        return refused(why)
    mode, _problem = login_mode(fields.get("agent_login_mode", ""))
    if mode != PASSWORD_MODE:
        # A (copy of a) username-only login: its username is the credential.
        # A malformed mode fails closed: it may be meant as username-only.
        return refused(
            USERNAME_ONLY_SECRET
            if mode == USERNAME_ONLY
            else "bad agent_login_mode: cannot tell whether it is a username-only login"
        )
    counts = _custom_field_counts(item)
    if any(c > 1 for c in counts.values()):
        return refused("duplicate custom field names")
    allow_short = _parse_flag(fields.get("agent_secret_allow_short", ""))
    if allow_short is None:
        return refused("bad agent_secret_allow_short (true or false)")
    listed_raw = ["password", *_split_list(fields.get("agent_secret_fields", ""))]
    listed: list[str] = []
    values: dict[str, str] = {}
    for k, fname in enumerate(listed_raw):
        if fname.lower() in ("totp", "seed", "totp_seed"):
            return refused("the TOTP seed is never a field (use the totp op)")
        if fname.startswith("agent_"):
            return refused(
                f"configuration field {safe_name(fname, k, prefix='field')} cannot be exposed"
            )
        shown = safe_name(fname, k, prefix="field")
        if shown in listed:
            continue
        listed.append(shown)
        if fname in _BUILTIN_FIELDS:
            value = _builtin_value(item, fname)
        else:
            value = fields.get(fname, "")
        if value:
            values[shown] = value
    short = False
    for value in values.values():
        if not value.strip():
            return refused("a value is whitespace only")
        if value_bytes(value) < MIN_SECRET_BYTES:
            return refused(
                f"a value is shorter than {MIN_SECRET_BYTES} bytes (too short to mask)"
            )
        if is_short(value):
            if not allow_short:
                return refused(
                    f"a value is shorter than {SHORT_BELOW_BYTES} bytes (too short to mask; "
                    "set agent_secret_allow_short=true to mask it raw-only)"
                )
            short = True
    login = item.get("login") or {}
    totp = login.get("totp") if isinstance(login, Mapping) else None
    seed = str(totp) if totp else None
    public = SecretItem(
        secret_id=secret_id,
        name=name,
        fields=tuple(f for f in listed if f in values),
        listed=tuple(listed),
        has_totp=seed is not None,
        allow_short=allow_short,
        short=short,
        item_id=item_id,
    )
    return public, SecretValues(fields=values, totp_seed=seed)


def build_secret_items(
    raw_items: list[Any],
) -> tuple[list[SecretItem], dict[str, SecretValues]]:
    """All secrets items (a second item claiming a taken id is refused) and the
    values of the non-refused ones, keyed by id."""
    items: list[SecretItem] = []
    values: dict[str, SecretValues] = {}
    seen: set[str] = set()
    n = 0
    for raw in raw_items:
        if not isinstance(raw, Mapping):
            continue
        n += 1
        it, vals = secret_item_from_json(raw, n)
        if it.secret_id in seen:
            it = SecretItem(
                it.secret_id,
                it.name,
                item_id=it.item_id,
                refused="duplicate agent_secret_id",
            )
            vals = None
        seen.add(it.secret_id)
        items.append(it)
        if vals is not None and it.refused is None:
            values[it.secret_id] = vals
    return items, values


def filter_org(raw_items: list[Any], org_id: str | None, coll_id: str) -> list[Any]:
    """With `org_id` set: only items of that organisation that list `coll_id`
    (a collection id is only unique together with its organisation)."""
    if not org_id:
        return list(raw_items)
    out = []
    for raw in raw_items:
        if not isinstance(raw, Mapping):
            continue
        colls = raw.get("collectionIds") or []
        if (
            raw.get("organizationId") == org_id
            and isinstance(colls, list)
            and coll_id in colls
        ):
            out.append(raw)
    return out


class _SecretSource:
    """Cached, single-flight access to a secrets collection (mixin).

    Subclasses provide ``cache``, ``_secrets_key`` (raises SecretsNotConfigured)
    and ``_load_secrets`` (one uncached read; a ``bw sync`` in it bumps the
    cache generation).
    """

    cache: VaultCache

    def _secrets_key(self) -> tuple[str, ...]:
        raise SecretsNotConfigured(NO_SECRETS_COLLECTION)

    def _load_secrets(self, key: tuple[str, ...]) -> list[Any]:
        raise SecretsNotConfigured(NO_SECRETS_COLLECTION)

    def _fill(self, key: tuple[str, ...], want: tuple[str, ...]) -> Any:
        """Under BW_LOCK: the cache again (a concurrent miss may have filled it),
        else ONE read that fills every entry of the collection."""
        with BW_LOCK:
            hit = self.cache.get(want)
            if hit is not None:
                return hit
            raw = self._load_secrets(key)
            gen = self.cache.generation
            items, values = build_secret_items(raw)
            for sid, vals in values.items():
                self.cache.put(
                    ("values", *key, sid), vals, size=vals.nbytes(), generation=gen
                )
            listing = tuple(items)
            size = sum(len(json.dumps(it.public())) for it in items)
            self.cache.put(("items", *key), listing, size=size, generation=gen)
            if want[0] == "items":
                return listing
            return values.get(want[-1])

    def secret_items(self) -> list[SecretItem]:
        """Every item of the secrets collection, refused ones included."""
        key = self._secrets_key()
        want = ("items", *key)
        hit = self.cache.get(want)
        if hit is None:
            hit = self._fill(key, want)
        return list(hit)

    def secret_values(self, secret_id: str) -> SecretValues:
        """The values of a non-refused secrets item."""
        key = self._secrets_key()
        want = ("values", *key, secret_id)
        hit = self.cache.get(want)
        if hit is None:
            hit = self._fill(key, want)
        if hit is None:
            raise VaultError(f"unknown or refused secret {secret_id!r}")
        assert isinstance(hit, SecretValues)
        return hit

    def invalidate(self) -> int:
        """Bump the cache generation (rotation, SIGHUP)."""
        return self.cache.bump()


def slugify(name: str) -> str:
    """Default site id from an item name: lowercase, runs of non-alnum -> ``-``."""
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:64]


def _fields(item: Mapping[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for f in item.get("fields") or []:
        if isinstance(f, Mapping) and f.get("name"):
            out[str(f["name"])] = "" if f.get("value") is None else str(f["value"])
    return out


def _page_url_ok(url: str, *, dev: bool) -> bool:
    """An https page URL (``http://127.0.0.1…`` only in dev)."""
    if url.startswith("https://"):
        return True
    return dev and url.startswith("http://127.0.0.1")


def login_mode(raw: str) -> tuple[str | None, str]:
    """(mode, refusal reason or '') of an ``agent_login_mode`` value: empty or
    ``password`` -> ``password``, ``username-only`` -> ``username-only``
    (case-insensitive); anything else -> (None, reason)."""
    value = raw.strip().lower() or PASSWORD_MODE
    if value in LOGIN_MODES:
        return value, ""
    return None, f"bad agent_login_mode ({' or '.join(LOGIN_MODES)})"


_TRUE = frozenset({"true", "1", "yes", "on"})
_FALSE = frozenset({"", "false", "0", "no", "off"})


def _parse_flag(raw: str) -> bool | None:
    """A boolean custom field (``true``/``1``/``yes``/``on`` or the opposites,
    case-insensitive; empty = false); None for anything else."""
    value = raw.strip().lower()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    return None


# Playwright's own selector engines and pseudo-classes: not plain CSS, so a
# sentinel or click target would mean something else in the client's probe.
_PLAYWRIGHT_SELECTOR_RE = re.compile(
    r"(>>|^\s*//|^\s*\.\.|"
    # an engine prefix (`text=…`) — at the START only: `[data-testid=x]` is CSS
    r"^\s*(text|xpath|css|id|data-testid|data-test-id|data-test|role|nth|"
    r"internal|_react|_vue|visible)\s*=|"
    r":(has-text|text|text-is|text-matches|nth-match|right-of|left-of|above|"
    r"below|near)\(|:visible\b)",
    re.IGNORECASE,
)


def selector_ok(selector: str) -> bool:
    """One plain CSS selector on one line, at most 512 characters — no
    Playwright engine (``text=``, ``xpath=``, ``>>``, ``:has-text(`` …)."""
    if len(selector) > 512 or "\n" in selector or "\r" in selector:
        return False
    return _PLAYWRIGHT_SELECTOR_RE.search(selector) is None


def _split_list(raw: str) -> list[str]:
    return [p.strip() for p in re.split(r"[,\n]", raw) if p.strip()]


def no_submit_by_origin(fill_origins: list[str]) -> bool:
    """True when an origin/URL's host is on a ``NO_SUBMIT_DOMAINS`` domain.

    Canonical host: a value without a scheme is read as ``https://VALUE``,
    the host is lowercased and loses a trailing DNS dot (``id.galaxus.eu.``).
    An unparsable value raises ValueError (callers fail closed)."""
    for origin in fill_origins:
        raw = origin.strip()
        url = raw if "://" in raw else "https://" + raw
        host = (urllib.parse.urlsplit(url).hostname or "").lower().rstrip(".")
        if any(host == d or host.endswith("." + d) for d in NO_SUBMIT_DOMAINS):
            return True
    return False


def _site_domain(host: str) -> str:
    """``www.kleinanzeigen.de`` -> ``kleinanzeigen.de`` (last two labels; enough for
    the .de/.ch/.com sites this broker serves, and an IP or bare host stays as is)."""
    labels = host.split(".")
    if len(labels) <= 2 or host.replace(".", "").isdigit():
        return host
    return ".".join(labels[-2:])


def _known_site_for(fill_origins: list[str]) -> str | None:
    """The built-in site whose check URL shares a site domain with `fill_origins`."""
    domains = {
        _site_domain(o.split("://", 1)[1].split(":", 1)[0]) for o in fill_origins
    }
    for known, url in DEFAULT_CHECK_URLS.items():
        host = (urllib.parse.urlsplit(url).hostname or "").lower()
        if _site_domain(host) in domains:
            return known
    return None


def _default_cookie_hosts(fill_origins: list[str], check_url: str) -> list[str]:
    """Default cookie scope: the check page's site domain (the session usually lives
    on ``.site.tld`` / ``www.``, not on the login host) plus the fill-origin hosts,
    minus identity providers. Cookies of an IdP host below an allowed domain are
    still dropped by the bundle filter."""
    hosts: list[str] = []
    candidates = [o.split("://", 1)[1].split(":", 1)[0] for o in fill_origins]
    if check_url:
        check_host = (urllib.parse.urlsplit(check_url).hostname or "").lower()
        if check_host:
            candidates.insert(0, _site_domain(check_host))
    for host in candidates:
        if host and not is_idp_host(host) and host not in hosts:
            hosts.append(host)
    return hosts


# A flat validator: one early `refused(...)` per field rule, in field order.
# pylint: disable-next=too-many-return-statements,too-many-branches,too-many-statements,too-many-locals
def site_item_from_json(item: Mapping[str, Any], *, dev: bool = False) -> SiteItem:
    """Build a ``SiteItem`` from a Bitwarden item JSON; problems become ``refused``."""
    name = str(item.get("name") or "")
    fields = _fields(item)
    site = (fields.get("agent_site") or "").strip().lower() or slugify(name)
    item_id = str(item.get("id") or "")

    def refused(reason: str) -> SiteItem:
        return SiteItem(site=site, name=name, item_id=item_id, refused=reason)

    if not SITE_ID_RE.match(site):
        return refused("invalid agent_site id")
    raw_origins = fields.get("agent_fill_origins", "").strip()
    if not raw_origins:
        return refused("missing agent_fill_origins")
    try:
        fill_origins = parse_fill_origins(raw_origins, dev=dev)
    except ValueError as exc:
        return refused(f"bad agent_fill_origins: {exc}")
    if not fields.get("agent_site") and site not in DEFAULT_CHECK_URLS:
        # An item named e.g. "tutti.ch" still means the known site "tutti":
        # match the built-in sites by the fill origins' site domain.
        known = _known_site_for(fill_origins)
        if known and site.startswith(known):
            site = known

    names_raw = fields.get("agent_cookie_names", "").strip()
    cookie_names = _split_list(names_raw) or None

    storage_keys: dict[str, list[str]] = {}
    storage_raw = fields.get("agent_storage_keys", "").strip()
    if storage_raw:
        try:
            parsed = json.loads(storage_raw)
            if not isinstance(parsed, dict):
                raise ValueError("not an object")
            for origin, keys in parsed.items():
                norm = parse_fill_origins(str(origin), dev=dev)
                if len(norm) != 1 or not isinstance(keys, list):
                    raise ValueError("expected {origin: [keys]}")
                storage_keys[norm[0]] = [str(k) for k in keys]
        except ValueError as exc:
            return refused(f"bad agent_storage_keys: {exc}")

    check_url = fields.get("agent_check_url", "").strip()
    if check_url and not _page_url_ok(check_url, dev=dev):
        return refused("bad agent_check_url")
    check_url = check_url or DEFAULT_CHECK_URLS.get(site, "")
    sentinel = (
        fields.get("agent_logged_in_selector", "").strip()
        or DEFAULT_LOGGED_IN_SELECTORS.get(site)
        or None
    )
    if not check_url and not sentinel:
        return refused("needs agent_check_url (or agent_logged_in_selector)")
    if sentinel is not None and not selector_ok(sentinel):
        return refused(
            "bad agent_logged_in_selector (one plain CSS selector, one line, ≤512 "
            "chars; no Playwright text=/xpath=/>>)"
        )
    hosts_raw = fields.get("agent_cookie_hosts", "").strip()
    cookie_scopes, problem = _cookie_scopes(
        fields.get("agent_cookie_scopes", ""), hosts_raw
    )
    if problem:
        return refused(problem)
    if cookie_scopes:
        cookie_hosts = list(dict.fromkeys(s.host for s in cookie_scopes))
    elif hosts_raw:
        cookie_hosts = [h.lstrip(".").lower() for h in _split_list(hosts_raw)]
    else:
        cookie_hosts = _default_cookie_hosts(fill_origins, check_url)
    if not cookie_hosts:
        return refused("no cookie host (set agent_cookie_hosts)")
    # No explicit login URL: start at the check URL — it redirects to the
    # login page WITH the state an Auth0-style login needs.
    login_url = (
        fields.get("agent_login_url", "").strip() or check_url or fill_origins[0] + "/"
    )
    if not _page_url_ok(login_url, dev=dev):
        return refused("bad agent_login_url")
    fresh_login = _parse_flag(fields.get("agent_fresh_login", ""))
    if fresh_login is None:
        return refused("bad agent_fresh_login (true or false)")
    pre_click = fields.get("agent_pre_click", "").strip() or None
    if pre_click is not None and not selector_ok(pre_click):
        return refused("bad agent_pre_click (one CSS selector, one line, ≤512 chars)")
    group, problem = _attempt_group(fields.get("agent_attempt_group", ""), item)
    if problem:
        return refused(problem)
    raw_proof = fields.get("agent_proof_origins", "").strip()
    try:
        proof_origins = parse_fill_origins(raw_proof, dev=dev) if raw_proof else []
    except ValueError as exc:
        return refused(f"bad agent_proof_origins: {exc}")
    session_refresh = fields.get("agent_session_refresh", "").strip().lower() or None
    if session_refresh not in (None, "none", *SESSION_REFRESHERS):
        known = ", ".join(sorted(SESSION_REFRESHERS))
        return refused(f"bad agent_session_refresh (none, {known})")
    no_submit = _parse_flag(fields.get("agent_no_submit", ""))
    if no_submit is None:
        return refused("bad agent_no_submit (true or false)")
    max_days, problem = _max_session_days(
        fields.get("agent_max_session_days", ""), fresh_login=bool(fresh_login)
    )
    if problem:
        return refused(problem)
    mode, problem = login_mode(fields.get("agent_login_mode", ""))
    if problem:
        return refused(problem)
    # (an empty username is the login's `no_username`, from `secret_from_json`)
    if mode == USERNAME_ONLY and recipe_for(site) is not generic_login:
        return refused(
            "agent_login_mode=username-only needs the generic login recipe "
            "(this site has its own)"
        )
    built = SiteItem(
        fill_origins=fill_origins,
        cookie_hosts=cookie_hosts,
        cookie_scopes=cookie_scopes,
        cookie_names=cookie_names,
        storage_keys=storage_keys,
        login_url=login_url,
        check_url=check_url,
        logged_in_selector=sentinel,
        otp_label=fields.get("agent_otp_label", "").strip() or None,
        fresh_login=fresh_login,
        pre_click=pre_click,
        attempt_group=group,
        proof_origins=proof_origins,
        session_refresh=session_refresh,
        no_submit=no_submit
        or site in NO_SUBMIT_SITES
        or no_submit_by_origin(fill_origins),
        max_session_days=max_days,
        login_mode=mode or PASSWORD_MODE,
        site=site,
        name=name,
        item_id=item_id,
    )
    return _with_identity_fields(built, item, fields)


def _cookie_scopes(
    raw: str, hosts_raw: str
) -> tuple[tuple[_identity.CookieScope, ...], str]:
    """(scopes, '') of `agent_cookie_scopes` — a JSON list of ``{host,
    path}`` (`identity.parse_cookie_scopes`) — or ((), why it is refused).
    Next to `agent_cookie_hosts` the two must name the same hosts (one
    field narrows the other's hosts to paths, never adds a host)."""
    text = raw.strip()
    if not text:
        return (), ""
    scopes, problem = _identity.parse_cookie_scopes(text)
    if problem:
        return (), f"bad agent_cookie_scopes: {problem}"
    if hosts_raw:
        named = {h.strip().lstrip(".").lower() for h in _split_list(hosts_raw)}
        if named != {s.host for s in scopes}:
            return (), (
                "agent_cookie_scopes and agent_cookie_hosts name different hosts "
                "(set the same hosts, or only agent_cookie_scopes)"
            )
    return scopes, ""


MAX_SESSION_DAYS_RANGE = (1, 365)


def _max_session_days(raw: str, *, fresh_login: bool) -> tuple[int | None, str]:
    """(days or None, refusal reason or ''): a whole number of days in
    ``MAX_SESSION_DAYS_RANGE``, and only on an `agent_fresh_login` item."""
    text = raw.strip()
    if not text:
        return None, ""
    low, high = MAX_SESSION_DAYS_RANGE
    if not re.fullmatch(r"[0-9]{1,3}", text) or not low <= int(text) <= high:
        return None, f"bad agent_max_session_days (whole days, {low}-{high})"
    if not fresh_login:
        return None, "agent_max_session_days needs agent_fresh_login true"
    return int(text), ""


def _attempt_group(raw: str, item: Mapping[str, Any]) -> tuple[str | None, str]:
    """(group id or None, refusal reason or ''): an opaque slug that must not
    reveal the account (neither the username nor its local part, >= 3 chars)."""
    group = raw.strip().lower()
    if not group:
        return None, ""
    if not SITE_ID_RE.match(group):
        return None, "bad agent_attempt_group (a slug: a-z 0-9 . _ -, ≤64 chars)"
    if _reveals_account(group, item):
        return None, "agent_attempt_group must not reveal the account name"
    return group, ""


def _login_username(item: Mapping[str, Any]) -> str:
    """The login's username as stored ('' when none)."""
    login = item.get("login") or {}
    return str(login.get("username") or "") if isinstance(login, Mapping) else ""


def _reveals_account(slug: str, item: Mapping[str, Any]) -> bool:
    """`slug` contains the item's username or its local part (>= 3 chars)."""
    user = _login_username(item).strip().lower()
    return any(
        len(part) >= 3 and part in slug for part in (user, user.split("@", 1)[0])
    )


# ---------------------------------------------------------------------------
# WS5 (tp#833): account identity of items that share one cookie scope
# ---------------------------------------------------------------------------


# One early return per field rule, in field order.
def _identity_problem(  # pylint: disable=too-many-return-statements
    site: str, fields: Mapping[str, str], item: Mapping[str, Any]
) -> str:
    """The refusal reason of the item's own WS5 fields ('' = fine). The
    rules that need the whole collection are `identity_rules`."""
    instance = fields.get("agent_instance", "").strip().lower()
    privilege = fields.get("agent_privilege", "").strip().lower()
    ident = fields.get("agent_identity", "").strip().lower()
    same = fields.get("agent_same_account_as", "").strip().lower()
    alias = fields.get("agent_alias", "").strip().lower()
    if instance not in _identity.INSTANCES:
        known = ", ".join(_identity.ROLE_INSTANCES)
        return f"bad agent_instance ({known}, or empty for the shared browser)"
    if privilege and privilege not in _identity.PRIVILEGES:
        return "bad agent_privilege (" + ", ".join(_identity.PRIVILEGES) + ")"
    if ident and ident not in _identity.IDENTITIES:
        known = ", ".join(sorted(_identity.IDENTITIES))
        return f"bad agent_identity (a reviewed recipe: {known})"
    if ident and _identity.usable_recipe(ident) is None:
        return (
            f"agent_identity {ident} is not live-confirmed with an admin bit yet "
            "(the item stays unproven)"
        )
    if ident and not privilege:
        return "agent_identity needs agent_privilege"
    if ident:
        problem = _identity_user_problem(ident, _login_username(item))
        if problem:
            return problem
    if same and (not SITE_ID_RE.match(same) or same == site):
        return "bad agent_same_account_as (the agent_site of another item)"
    if alias:
        if not SITE_ID_RE.match(alias):
            return "bad agent_alias (a slug: a-z 0-9 . _ -, ≤64 chars)"
        if alias in _identity.STATIC_SITE_NAMES or alias == site:
            return "agent_alias collides with a site name"
        if _reveals_account(alias, item):
            return "agent_alias must not reveal the account name"
    return ""


def _identity_user_problem(ident: str, user: str) -> str:
    """'' when recipe `ident` can compare the login's username `user`, else
    why not — decided here, at validation, never per challenge (no
    per-request answer says anything about the stored name)."""
    if not user.strip():
        return "agent_identity needs the login's username"
    form = _identity.identity_form(user)
    if form is None:
        return "agent_identity needs a plain-ASCII login username"
    forms = _identity.IDENTITIES[ident].forms
    if form not in forms:
        return (
            f"the vault holds an {form}; the {ident} identity proof "
            f"compares the {' or '.join(forms)}"
        )
    return ""


def _with_identity_fields(
    built: SiteItem, item: Mapping[str, Any], fields: Mapping[str, str]
) -> SiteItem:
    """`built` with its WS5 fields (`agent_instance`, `agent_privilege`,
    `agent_identity`, `agent_same_account_as`, `agent_alias`) and the login's
    username. A bad field refuses the item WITH its scope kept: a refused
    item still takes part in the conflict check."""
    if built.refused:
        return built
    filled = replace(
        built,
        instance=fields.get("agent_instance", "").strip().lower(),
        privilege=fields.get("agent_privilege", "").strip().lower(),
        identity=fields.get("agent_identity", "").strip().lower(),
        same_account_as=fields.get("agent_same_account_as", "").strip().lower(),
        alias=fields.get("agent_alias", "").strip().lower(),
        account_name=_login_username(item),
    )
    problem = _identity_problem(built.site, fields, item) or _recipe_item_problem(
        filled
    )
    if problem:
        return replace(filled, refused=problem, same_account_as="", alias="")
    return filled


def _recipe_item_problem(item: SiteItem) -> str:
    """WS5 S4c: '' when the item is configured for its `agent_identity`
    recipe — its site id and check origin allowed by the recipe
    (`identity.recipe_config_problem`) — and lists none of the page's own
    identity claim keys (`identity_storage_keys`) in `agent_storage_keys`:
    those are never exported or injected. (An admin item of a recipe whose
    "admin" answer is unconfirmed is NOT refused: it stays unproven —
    `identity_recipe` is None — until the recipe's flag flips.)"""
    if not item.identity:
        return ""
    why = _identity.recipe_config_problem(
        item.identity, site=item.site, check_url=item.check_url or item.login_url
    )
    if why:
        return f"agent_identity {item.identity}: {why} (the item stays unproven)"
    recipe = _identity.IDENTITIES[item.identity]
    listed = {k for keys in item.storage_keys.values() for k in keys}
    if listed & set(recipe.identity_storage_keys):
        return (
            f"agent_identity {item.identity}: agent_storage_keys may not list the "
            "page's own account claim (an identity-source key)"
        )
    return ""


def _raw_scope_hosts(raw: Mapping[str, Any]) -> list[str]:
    """Best-effort hosts of an item refused before its scope was parsed: its
    agent_cookie_hosts and the hosts of its fill origins — what a valid
    item's scope holds too. Never its check or login URL hosts (an IdP host
    there would pull unrelated items into multi-account) and never its
    generic login URIs."""
    fields = _fields(raw)
    hosts = list(_split_list(fields.get("agent_cookie_hosts", "")))
    hosts += _raw_scope_field_hosts(fields.get("agent_cookie_scopes", ""))
    for key in ("agent_fill_origins",):
        for value in _split_list(fields.get(key, "")):
            url = value if "://" in value else "https://" + value
            try:
                host = urllib.parse.urlsplit(url).hostname or ""
            except ValueError:
                continue
            hosts.append(host)
    return sorted({h.strip().lstrip(".").lower() for h in hosts if h.strip()})


def _raw_scope_field_hosts(raw: str) -> list[str]:
    """Best effort: every host string in a (possibly malformed)
    `agent_cookie_scopes` — at path "/" in a refused item's scope, the
    over-inclusive reading."""
    try:
        value = json.loads(raw) if raw.strip() else []
    except ValueError:
        return []
    if not isinstance(value, list):
        return []
    return [
        str(one["host"])
        for one in value
        if isinstance(one, Mapping) and isinstance(one.get("host"), str)
    ]


def _refuse(it: SiteItem, reason: str) -> SiteItem:
    """`it` refused, its scope kept, its same-account declaration dropped (a
    refused item then conflicts with its former partner: fail closed)."""
    return replace(it, refused=reason, same_account_as="")


def identity_rules(  # pylint: disable=too-many-branches
    items: list[SiteItem], raws: list[Mapping[str, Any]]
) -> list[SiteItem]:
    """The WS5 rules over the whole collection, in this order:

    1. an item refused before its scope was parsed gets a best-effort scope
       (`_raw_scope_hosts`), so its siblings still count as multi-account;
    2. `agent_same_account_as` must be declared on BOTH items (else every
       one-sided declarer is refused);
    3. an `agent_alias` equal to any site id or to another item's alias is
       refused (all items sharing it);
    4. `multi_account` = the scope overlaps an item of another account in
       ANY instance (``identity.scope_conflicts``, refused items included);
    5. a multi-account item without `agent_privilege` is refused;
    6. inside ONE instance at most one item per conflict: of two overlapping
       items not declared the same account, the later (by site id) is refused.
    """
    out = list(items)
    for i, it in enumerate(out):
        if it.refused and not it.cookie_hosts:
            out[i] = replace(it, cookie_hosts=_raw_scope_hosts(raws[i]))
    live = {it.site: it for it in out if not it.refused}
    for i, it in enumerate(out):
        partner = live.get(it.same_account_as) if it.same_account_as else None
        if it.same_account_as and (
            partner is None or partner.same_account_as != it.site
        ):
            out[i] = _refuse(
                it,
                f"agent_same_account_as {it.same_account_as}: that item must "
                "name this one back",
            )
    site_ids = {it.site for it in out}
    aliases: dict[str, int] = {}
    for it in out:
        if it.alias and not it.refused:
            aliases[it.alias] = aliases.get(it.alias, 0) + 1
    for i, it in enumerate(out):
        if it.alias and not it.refused:
            if it.alias in site_ids:
                out[i] = _refuse(it, "agent_alias collides with a site id")
            elif aliases[it.alias] > 1:
                out[i] = _refuse(it, "agent_alias is used by another item")
    conflicts = _identity.scope_conflicts([it.public() for it in out])
    for i, it in enumerate(out):
        if it.site in conflicts:
            out[i] = replace(it, multi_account=True)
            if not it.refused and not it.privilege:
                out[i] = _refuse(
                    out[i],
                    "shares its login scope with another account: set "
                    "agent_privilege (" + ", ".join(_identity.PRIVILEGES) + ")",
                )
    kept: dict[str, list[SiteItem]] = {}
    for i in sorted(range(len(out)), key=lambda n: out[n].site):
        it = out[i]
        if it.refused:
            continue
        mine = _identity.item_scopes(it.public())
        clash = next(
            (
                other
                for other in kept.get(it.instance, [])
                if _identity.scopes_overlap(mine, _identity.item_scopes(other.public()))
                and not (
                    other.same_account_as == it.site
                    and it.same_account_as == other.site
                )
            ),
            None,
        )
        if clash is not None:
            where = it.instance or "default (shared browser)"
            out[i] = _refuse(
                it,
                f"scope conflict in instance {where} with {clash.site}: set "
                "agent_instance on one of them",
            )
            continue
        kept.setdefault(it.instance, []).append(it)
    return out


def build_items(raw_items: list[Any], *, dev: bool = False) -> list[SiteItem]:
    """All items; a second item claiming an already-taken site id is refused;
    then the collection-wide WS5 rules (`identity_rules`)."""
    out: list[SiteItem] = []
    raws: list[Mapping[str, Any]] = []
    seen: set[str] = set()
    for raw in raw_items:
        if not isinstance(raw, Mapping):
            continue
        it = site_item_from_json(raw, dev=dev)
        if it.site in seen:
            it = SiteItem(
                site=it.site,
                name=it.name,
                item_id=it.item_id,
                refused="duplicate agent_site",
            )
        seen.add(it.site)
        out.append(it)
        raws.append(raw)
    return identity_rules(out, raws)


def secret_from_json(item: Mapping[str, Any]) -> Secret:
    """The login part of a Bitwarden item, for its ``agent_login_mode``:
    username + password, or (``username-only``) the username alone, carried
    as the secret (``Secret``). A missing one raises ``MissingSecret``."""
    login = item.get("login") or {}
    if not isinstance(login, Mapping):
        login = {}
    totp = login.get("totp")
    seed = str(totp) if totp else None
    mode, _problem = login_mode(_fields(item).get("agent_login_mode", ""))
    if mode == USERNAME_ONLY:
        # The username IS the credential; a password on the item is ignored.
        account = str(login.get("username") or "").strip()
        if not account:
            raise MissingSecret("no_username", NO_USERNAME)
        return Secret(username="", password=account, totp_seed=seed, mode=USERNAME_ONLY)
    password = str(login.get("password") or "")
    if not password:
        # Typing an empty password only produces "invalid username or password"
        # at the site (and counts as a failed login). Bitwarden hands an item over
        # WITHOUT its password when the broker account's collection permission is
        # "Can view, except passwords" — or the item has none at all (an
        # account-number login: agent_login_mode=username-only).
        raise MissingSecret("no_password", NO_PASSWORD)
    return Secret(
        username=str(login.get("username") or ""),
        password=password,
        totp_seed=seed,
    )


def _find(
    raw_items: list[Any], site: str, *, dev: bool, login: bool = True
) -> Mapping[str, Any]:
    """The raw item of `site` from a FRESH read. `login`: the secret is for a
    login, so a no-submit item (``SiteItem.no_submit``, judged on this fresh
    read, not on a cached list) is refused; the fingerprint passes False."""
    items = build_items(raw_items, dev=dev)
    for it, raw in zip(items, [r for r in raw_items if isinstance(r, Mapping)]):
        if it.site == site:
            if it.refused:
                raise VaultError(f"site {site!r} is refused: {it.refused}")
            if login and it.no_submit:
                raise VaultError(
                    f"site {site!r} is no-submit: the broker never logs in with "
                    "its password"
                )
            return raw
    raise VaultError(f"unknown site {site!r}")


class FixtureVault(_SecretSource):
    """Items from a JSON file. Dev mode only.

    The file is either a list of Bitwarden-shaped login items, or an object
    ``{"logins": [...], "secrets": [...], "collections": [...]}`` — ``secrets``
    (optional) is the secrets collection, optionally filtered like ``bw`` by
    ``secrets_organization_id`` + ``secrets_collection_id``; ``collections``
    (optional) is what ``daemon.py -C`` lists.
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        dev: bool,
        cache: VaultCache | None = None,
    ) -> None:
        if not dev:
            raise VaultError("FixtureVault is only usable with --dev")
        self.path = Path(path)
        self.dev = dev
        self.cache = cache if cache is not None else VaultCache()

    def _data(self) -> list[Any] | dict[str, Any]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise VaultError(f"cannot read fixture vault {self.path}") from exc
        if isinstance(data, dict):
            if not isinstance(data.get("logins", []), list):
                raise VaultError("fixture vault: logins must be a list")
            return data
        if not isinstance(data, list):
            raise VaultError("fixture vault must be a JSON list of items")
        return data

    def _raw(self) -> list[Any]:
        data = self._data()
        return list(data.get("logins", [])) if isinstance(data, dict) else data

    def items(self) -> list[SiteItem]:
        """Every fixture item, refused ones included."""
        return build_items(self._raw(), dev=self.dev)

    def secret(self, site: str) -> Secret:
        """The fixture LOGIN secret of `site` (never for a no-submit site)."""
        return secret_from_json(_find(self._raw(), site, dev=self.dev))

    def fingerprint_secret(self, site: str) -> Secret:
        """The fixture secret of `site` for the `fingerprint` op."""
        return secret_from_json(_find(self._raw(), site, dev=self.dev, login=False))

    def _secrets_key(self) -> tuple[str, ...]:
        data = self._data()
        if not isinstance(data, dict) or not isinstance(data.get("secrets"), list):
            raise SecretsNotConfigured(NO_SECRETS_COLLECTION)
        return (
            "fixture",
            str(self.path),
            str(data.get("secrets_organization_id") or ""),
            str(data.get("secrets_collection_id") or ""),
        )

    def _load_secrets(self, key: tuple[str, ...]) -> list[Any]:
        data = self._data()
        if not isinstance(data, dict) or not isinstance(data.get("secrets"), list):
            raise SecretsNotConfigured(NO_SECRETS_COLLECTION)
        raw = list(data["secrets"])
        coll = str(data.get("secrets_collection_id") or "")
        org = str(data.get("secrets_organization_id") or "")
        return filter_org(raw, org, coll) if org and coll else raw

    def collections(self) -> list[tuple[str, str, str, str]]:
        """``(org_id, org_name, collection_id, collection_name)`` rows."""
        data = self._data()
        rows = data.get("collections", []) if isinstance(data, dict) else []
        return [
            (
                str(r.get("organizationId") or ""),
                str(r.get("organizationName") or ""),
                str(r.get("id") or ""),
                str(r.get("name") or ""),
            )
            for r in rows
            if isinstance(r, Mapping)
        ]


# Known bw failure messages -> a fixed reason (never the message itself).
_BW_REASONS = (
    ("invalid master password", "wrong master password in bootstrap.json"),
    ("invalid api key", "wrong client_id/client_secret in bootstrap.json"),
    ("client_id", "wrong client_id/client_secret in bootstrap.json"),
    ("username or password is incorrect", "wrong credentials in bootstrap.json"),
    ("you are not logged in", "bw is not logged in"),
    ("collection", "collection id not found or not accessible"),
    ("certificate", "TLS certificate problem reaching Vaultwarden"),
    ("econnrefused", "Vaultwarden not reachable"),
    ("enotfound", "Vaultwarden host not resolvable"),
    ("getaddrinfo", "Vaultwarden host not resolvable"),
    ("timed out", "Vaultwarden timed out"),
)


def _bw_reason(text: str) -> str:
    """': <fixed reason>' for a recognised bw error, else ''."""
    low = text.lower()
    for needle, reason in _BW_REASONS:
        if needle in low:
            return f": {reason}"
    return ""


# The self-hosted Vaultwarden the broker account lives on.
DEFAULT_SERVER_URL = "https://vaultwarden.dom42.space"


_OPTIONAL_IDS = ("organization_id", "secrets_organization_id", "secrets_collection_id")


@dataclass(frozen=True)
class BwBootstrap:  # pylint: disable=too-many-instance-attributes
    """Contents of ``<home>/bootstrap.json`` (written by ``install.sh -e``; the
    ID keys by ``install.sh -C`` / ``-X``).

    ``organization_id`` (optional) pins the login collection to its
    organisation; ``secrets_organization_id`` + ``secrets_collection_id``
    (optional) name the collection the ``secret``/``totp`` ops read. All absent
    = the original behaviour, and ``secret``/``totp`` refuse.
    """

    client_id: str = field(repr=False)
    client_secret: str = field(repr=False)
    master_password: str = field(repr=False)
    collection_id: str
    server_url: str = DEFAULT_SERVER_URL
    organization_id: str | None = None
    secrets_organization_id: str | None = None
    secrets_collection_id: str | None = None

    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> BwBootstrap:
        """Read and validate the bootstrap file (no value is ever logged)."""
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise VaultError(f"cannot read bootstrap {path}") from exc
        keys = ("client_id", "client_secret", "master_password", "collection_id")
        if not isinstance(data, dict) or not all(
            isinstance(data.get(k), str) and data[k] for k in keys
        ):
            raise VaultError(f"bootstrap {path} lacks one of {', '.join(keys)}")
        server = data.get("server_url") or DEFAULT_SERVER_URL
        if not isinstance(server, str) or not server.startswith("https://"):
            raise VaultError(f"bootstrap {path}: server_url must be an https:// URL")
        optional: dict[str, str | None] = {}
        for k in _OPTIONAL_IDS:
            value = data.get(k)
            if value is not None and (not isinstance(value, str) or not value):
                raise VaultError(f"bootstrap {path}: {k} must be a non-empty string")
            optional[k] = value
        return cls(
            client_id=data["client_id"],
            client_secret=data["client_secret"],
            master_password=data["master_password"],
            collection_id=data["collection_id"],
            server_url=server,
            organization_id=optional["organization_id"],
            secrets_organization_id=optional["secrets_organization_id"],
            secrets_collection_id=optional["secrets_collection_id"],
        )


class BwVault(_SecretSource):
    """The broker's own Vaultwarden account, read through the ``bw`` CLI."""

    def __init__(
        self,
        bootstrap: BwBootstrap,
        appdata_dir: str | os.PathLike[str],
        *,
        bw_bin: str = "bw",
        cache: VaultCache | None = None,
    ) -> None:
        self.boot = bootstrap
        self.appdata_dir = str(appdata_dir)
        self.bw_bin = bw_bin
        self.cache = cache if cache is not None else VaultCache()

    def _env(self, **extra: str) -> dict[str, str]:
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", self.appdata_dir),
            "BITWARDENCLI_APPDATA_DIR": self.appdata_dir,
            "BW_NOINTERACTION": "true",
        }
        env.update(extra)
        return env

    def _run(self, args: list[str], env: dict[str, str]) -> str:
        try:
            proc = subprocess.run(
                [self.bw_bin, *args],
                env=env,
                capture_output=True,
                text=True,
                timeout=BW_TIMEOUT_S,
                check=False,
                stdin=subprocess.DEVNULL,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise VaultError(f"bw {args[0]} could not run") from exc
        if proc.returncode != 0:
            # stderr is NOT echoed (bw may quote input back); only a fixed,
            # secret-free reason picked from known messages is reported.
            reason = _bw_reason(proc.stderr + proc.stdout)
            raise VaultError(f"bw {args[0]} failed (exit {proc.returncode}){reason}")
        return proc.stdout

    def _status(self) -> str:
        try:
            data = json.loads(self._run(["status"], self._env()))
        except ValueError as exc:
            raise VaultError("bw status returned no JSON") from exc
        return str(data.get("status") or "") if isinstance(data, dict) else ""

    @contextmanager
    def _session(self) -> Iterator[str]:
        if self._status() == "unauthenticated":
            # bw defaults to the Bitwarden cloud; point it at Vaultwarden first
            # (only allowed while logged out).
            self._run(["config", "server", self.boot.server_url], self._env())
            self._run(
                ["login", "--apikey"],
                self._env(
                    BW_CLIENTID=self.boot.client_id,
                    BW_CLIENTSECRET=self.boot.client_secret,
                ),
            )
        session = self._run(
            ["unlock", "--passwordenv", "BW_PASSWORD", "--raw"],
            self._env(BW_PASSWORD=self.boot.master_password),
        ).strip()
        if not session:
            raise VaultError("bw unlock returned no session")
        try:
            yield session
        finally:
            try:
                self._run(["lock"], self._env())
            except VaultError:
                pass

    @staticmethod
    def _json_list(out: str, what: str) -> list[Any]:
        try:
            data = json.loads(out)
        except ValueError as exc:
            raise VaultError(f"bw list {what} returned no JSON") from exc
        if not isinstance(data, list):
            raise VaultError(f"bw list {what} returned no list")
        return data

    def _raw(self, org_id: str | None, coll_id: str) -> list[Any]:
        """unlock + sync + list + lock under BW_LOCK; with `org_id` only that
        organisation's items that list `coll_id` are kept."""
        with BW_LOCK, self._session() as session:
            env = self._env(BW_SESSION=session)
            self._run(["sync"], env)
            self.cache.bump()  # the vault may have changed: no older value served
            out = self._run(["list", "items", "--collectionid", coll_id], env)
        return filter_org(self._json_list(out, "items"), org_id, coll_id)

    def items(self) -> list[SiteItem]:
        """Every item of the ``agent-logins`` collection."""
        return build_items(
            self._raw(self.boot.organization_id, self.boot.collection_id)
        )

    def secret(self, site: str) -> Secret:
        """Username, password and TOTP seed of `site` for a LOGIN (fresh unlock,
        then lock); a no-submit item is refused on this fresh read, so an item
        flagged since the cached site list was filled never reaches a login."""
        raw = self._raw(self.boot.organization_id, self.boot.collection_id)
        return secret_from_json(_find(raw, site, dev=False))

    def fingerprint_secret(self, site: str) -> Secret:
        """`secret` for the `fingerprint` op (no-submit sites too)."""
        raw = self._raw(self.boot.organization_id, self.boot.collection_id)
        return secret_from_json(_find(raw, site, dev=False, login=False))

    def _secrets_key(self) -> tuple[str, ...]:
        if not self.boot.secrets_collection_id:
            raise SecretsNotConfigured(NO_SECRETS_COLLECTION)
        return (
            "bw",
            self.boot.secrets_organization_id or "",
            self.boot.secrets_collection_id,
        )

    def _load_secrets(self, key: tuple[str, ...]) -> list[Any]:
        return self._raw(key[1] or None, key[2])

    def collections(self) -> list[tuple[str, str, str, str]]:
        """``(org_id, org_name, collection_id, collection_name)`` of every
        collection the broker account sees — no item data."""
        with BW_LOCK, self._session() as session:
            env = self._env(BW_SESSION=session)
            self._run(["sync"], env)
            orgs = self._json_list(
                self._run(["list", "organizations"], env), "organizations"
            )
            colls = self._json_list(
                self._run(["list", "collections"], env), "collections"
            )
        names = {
            str(o.get("id")): str(o.get("name") or "")
            for o in orgs
            if isinstance(o, Mapping)
        }
        return [
            (
                str(c.get("organizationId") or ""),
                names.get(str(c.get("organizationId")), ""),
                str(c.get("id") or ""),
                str(c.get("name") or ""),
            )
            for c in colls
            if isinstance(c, Mapping)
        ]
