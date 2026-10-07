"""Where the broker's site list and secrets come from: Bitwarden (or a dev fixture).

Whitelisting a site = its login item sits in the ``agent-logins`` collection AND
carries the custom field ``agent_fill_origins``. Items without it are listed as
refused, and so are items with neither a check URL (``agent_check_url`` or a
built-in default for the site id) nor a sentinel (``agent_logged_in_selector``):
without one the broker cannot PROVE a login worked. Secrets never leave this
module except as a ``Secret`` handed to a recipe; ``Secret`` has a redacting
``repr`` so a stray log line shows nothing.

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

import json
import os
import re
import subprocess
import threading
import urllib.parse
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from broker.bundle import SiteBundleSpec, is_idp_host
from broker.origins import parse_fill_origins
from broker.recipes import DEFAULT_CHECK_URLS, DEFAULT_LOGGED_IN_SELECTORS
from broker.vault_cache import (
    VaultCache,
)

SITE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
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


class SecretsNotConfigured(VaultError):
    """The bootstrap names no secrets collection (``secret``/``totp`` refuse)."""


@dataclass(frozen=True)
class Secret:
    """Login secret for one site. ``repr`` is redacted on purpose."""

    username: str = field(repr=False)
    password: str = field(repr=False)
    totp_seed: str | None = field(default=None, repr=False)

    def __repr__(self) -> str:
        return "Secret(<redacted>)"


@dataclass(frozen=True)
class SiteItem:  # pylint: disable=too-many-instance-attributes
    """One vault item as the broker sees it — no secret fields."""

    site: str
    name: str
    fill_origins: list[str] = field(default_factory=list)
    cookie_hosts: list[str] = field(default_factory=list)
    cookie_names: list[str] | None = None
    storage_keys: dict[str, list[str]] = field(default_factory=dict)
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
    refused: str | None = None
    item_id: str = ""

    @property
    def bundle_spec(self) -> SiteBundleSpec:
        """What may be exported for this site."""
        return SiteBundleSpec(
            cookie_hosts=list(self.cookie_hosts),
            cookie_names=list(self.cookie_names) if self.cookie_names else None,
            storage_keys={k: list(v) for k, v in self.storage_keys.items()},
        )

    def public(self) -> dict[str, Any]:
        """The ``sites`` view: ids, origins and scope — never a secret."""
        return {
            "site": self.site,
            "name": self.name,
            "fill_origins": list(self.fill_origins),
            "cookie_hosts": list(self.cookie_hosts),
            "cookie_names": list(self.cookie_names) if self.cookie_names else None,
            "storage_origins": sorted(self.storage_keys),
            "login_url": self.login_url,
            "check_url": self.check_url,
            "logged_in_selector": self.logged_in_selector,
            "fresh_login": self.fresh_login,
            "refused": self.refused is not None,
            "reason": self.refused or "",
        }


class Vault(Protocol):
    """The broker's view of the credential store."""

    def items(self) -> list[SiteItem]:
        """Every item of the collection, refused ones included."""

    def secret(self, site: str) -> Secret:
        """The secret of a non-refused site (VaultError otherwise)."""

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


def _split_list(raw: str) -> list[str]:
    return [p.strip() for p in re.split(r"[,\n]", raw) if p.strip()]


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
# pylint: disable-next=too-many-return-statements,too-many-branches
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
    hosts_raw = fields.get("agent_cookie_hosts", "").strip()
    if hosts_raw:
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
    return SiteItem(
        fill_origins=fill_origins,
        cookie_hosts=cookie_hosts,
        cookie_names=cookie_names,
        storage_keys=storage_keys,
        login_url=login_url,
        check_url=check_url,
        logged_in_selector=sentinel,
        otp_label=fields.get("agent_otp_label", "").strip() or None,
        fresh_login=fresh_login,
        site=site,
        name=name,
        item_id=item_id,
    )


def build_items(raw_items: list[Any], *, dev: bool = False) -> list[SiteItem]:
    """All items; a second item claiming an already-taken site id is refused."""
    out: list[SiteItem] = []
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
    return out


def secret_from_json(item: Mapping[str, Any]) -> Secret:
    """The login part of a Bitwarden item."""
    login = item.get("login") or {}
    if not isinstance(login, Mapping):
        login = {}
    totp = login.get("totp")
    password = str(login.get("password") or "")
    if not password:
        # Typing an empty password only produces "invalid username or password"
        # at the site (and counts as a failed login). Bitwarden hands an item over
        # WITHOUT its password when the broker account's collection permission is
        # "Can view, except passwords".
        raise VaultError(
            "the item has no password for the broker — set the broker account's "
            "permission on the agent-login collection to 'Can view' "
            "(not 'Can view, except passwords')"
        )
    return Secret(
        username=str(login.get("username") or ""),
        password=password,
        totp_seed=str(totp) if totp else None,
    )


def _find(raw_items: list[Any], site: str, *, dev: bool) -> Mapping[str, Any]:
    items = build_items(raw_items, dev=dev)
    for it, raw in zip(items, [r for r in raw_items if isinstance(r, Mapping)]):
        if it.site == site:
            if it.refused:
                raise VaultError(f"site {site!r} is refused: {it.refused}")
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
        """The fixture secret of `site`."""
        return secret_from_json(_find(self._raw(), site, dev=self.dev))

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
        """Username, password and TOTP seed of `site` (fresh unlock, then lock)."""
        raw = self._raw(self.boot.organization_id, self.boot.collection_id)
        return secret_from_json(_find(raw, site, dev=False))

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
