"""WS3 — the onboarding review of a broker item (pure; no browser, no vault).

One review, two consumers: ``agent-login.py -V`` (every live item, and a
PLANNED item / batch with ``-V -i MANIFEST``) and broker-add's dry run (its
mirror of the single-item checks is pinned to ``PIN_CASES``). The verdicts
the broker enforces are the broker's OWN code: a planned item is built with
``vault.site_item_from_json`` and judged with ``vault.identity_rules`` over
the whole collection, so the review and the broker can never disagree on a
refusal.

Levels (``LEVELS``), most severe first:

* ``refused``  — the broker refuses it (its own rules), or the change makes
  it refuse an established item (``displaced``);
* ``unusable`` — accepted, but it can never become a proven ✅: no strict
  proof, an account the client cannot prove (WS5), a planned item whose
  username-dependent rules could not be checked;
* ``risk``     — accepted and usable, but dangerous: a public-suffix cookie
  host, a scope or storage origin unrelated to the item, malformed storage
  keys. ``-p`` refuses and ``-c`` never logs it in;
* ``hint``     — a suggestion (attempt group, refresher, wide scope, an IdP
  host in the scope). Never enforced.

Every text is built from fixed words, validated site ids and hosts
(``safe_id`` / ``safe_host``); the broker's refusal reason is the only free
text, stripped of control characters and capped (``safe_reason``) — it goes
to Albert's terminal, never into agents.md.

``config_digest`` names the part of an item's ``sites`` view that changes
what a login does or proves: a promotion holds for that digest only.
"""

from __future__ import annotations

# The review, its manifest parsing and the pin cases belong together.
# pylint: disable=too-many-lines
import hashlib
import ipaddress
import json
import re
import urllib.parse
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any

from broker import identity as _identity
from broker.bundle import is_idp_host
from broker.storage_rules import storage_keys_problem

if TYPE_CHECKING:  # imported lazily at run time: the vault is the heavier module
    from broker.vault import SiteItem

LEVELS = ("refused", "unusable", "risk", "hint")
# Levels that block a promotion (`agent-login.py -p`) and `-V`'s exit 0.
BLOCKING = frozenset({"refused", "unusable", "risk"})

# The vendored Public Suffix List (https://publicsuffix.org, MPL-2.0): ICANN
# and PRIVATE sections. Refresh: download the list, replace the file, update
# both constants (the loader refuses a file whose digest differs).
PSL_FILE = Path(__file__).with_name("public_suffix_list.dat")
PSL_VERSION = "2026-10-07_07-28-19_UTC"
PSL_SHA256 = "ba7d836c0ea57a8bcf9f1fcb868066a7554bed029b441ecc6204ad8494a32612"

_SITE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_HOST = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
# A storage key named like an account claim (a page claim, never a proof).
_IDENTITY_KEY = re.compile(r"e-?mail|user(name)?|login|account", re.IGNORECASE)
# The fields an onboarding manifest item may carry besides its agent_* fields.
_MANIFEST_KEYS = frozenset(
    {
        "name",
        "fields",
        "login",
        "replaces",
        "username_form",
        "reveals",
        "id",
        "collectionIds",
    }
)


class PslError(RuntimeError):
    """The vendored Public Suffix List is missing or not the pinned version."""


@dataclass(frozen=True)
class Finding:
    """One review finding: `site` (a validated id or ``<invalid>``), its
    level, a fixed code, a text of fixed words / ids / hosts, and the other
    sites it names."""

    site: str
    level: str
    code: str
    text: str
    related: tuple[str, ...] = ()

    @property
    def blocking(self) -> bool:
        """Blocks a promotion."""
        return self.level in BLOCKING


@dataclass
class Review:
    """A planned change: findings of the planned items, the established items
    it displaces, and the collection after it (``sites`` views)."""

    findings: list[Finding] = field(default_factory=list)
    planned: list[str] = field(default_factory=list)
    after: list[dict[str, Any]] = field(default_factory=list)

    @property
    def blocking(self) -> bool:
        """Any finding blocks."""
        return any(f.blocking for f in self.findings)


# ---------------------------------------------------------------------------
# safe rendering
# ---------------------------------------------------------------------------


def safe_id(value: object) -> str:
    """`value` when it is a site id, else ``<invalid>``."""
    text = str(value or "")
    return text if _SITE_ID.match(text) else "<invalid>"


def safe_host(value: object) -> str:
    """`value` when it is a plain lower-case DNS name or IP, else ``<invalid>``."""
    text = str(value or "")
    return text if len(text) <= 253 and _HOST.match(text) else "<invalid>"


def safe_reason(value: object, n: int = 200) -> str:
    """Free text (the broker's refusal reason) without control characters,
    at most `n` characters."""
    text = _CONTROL.sub(" ", str(value or "")).strip()
    return text if len(text) <= n else text[: n - 1] + "…"


def _ids(values: Iterable[object]) -> tuple[str, ...]:
    return tuple(safe_id(v) for v in values)


# ---------------------------------------------------------------------------
# the Public Suffix List
# ---------------------------------------------------------------------------


def _ascii(label: str) -> str:
    try:
        return label.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return label.lower()


@lru_cache(maxsize=1)
def _psl() -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    """(rules, wildcard parents, exceptions), ASCII; raises PslError."""
    try:
        raw = PSL_FILE.read_bytes()
    except OSError as exc:
        raise PslError(f"cannot read {PSL_FILE.name}") from exc
    if hashlib.sha256(raw).hexdigest() != PSL_SHA256:
        raise PslError(f"{PSL_FILE.name} is not the pinned version {PSL_VERSION}")
    rules: set[str] = set()
    wild: set[str] = set()
    exc_rules: set[str] = set()
    for line in raw.decode("utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        rule = line.split()[0]
        if rule.startswith("!"):
            exc_rules.add(".".join(_ascii(p) for p in rule[1:].split(".")))
        elif rule.startswith("*."):
            wild.add(".".join(_ascii(p) for p in rule[2:].split(".")))
        else:
            rules.add(".".join(_ascii(p) for p in rule.split(".")))
    return frozenset(rules), frozenset(wild), frozenset(exc_rules)


def public_suffix_labels(host: str) -> int:
    """How many trailing labels of `host` are its public suffix (the PSL
    algorithm: the longest matching rule, an exception rule wins and drops
    its leftmost label, the default rule ``*`` = one label). PslError when
    the list cannot be used."""
    rules, wild, exceptions = _psl()
    labels = host.lower().strip(".").split(".")
    n = len(labels)
    for i in range(n):
        if ".".join(labels[i:]) in exceptions:
            return n - i - 1
    best = 1
    for i in range(n):
        suffix = ".".join(labels[i:])
        if suffix in rules:
            best = max(best, n - i)
        if i + 1 < n and ".".join(labels[i + 1 :]) in wild:
            best = max(best, n - i)
    return best


def psl_problem() -> str:
    """'' when the vendored Public Suffix List is usable, else why not (one
    infrastructure error for the caller to report once; the public-suffix
    judgement of every item is then unknown, nothing else)."""
    try:
        _psl()
    except PslError as exc:
        return str(exc)
    return ""


def is_public_suffix(host: str) -> bool:
    """`host` IS a public suffix (``ch``, ``co.uk``, ``github.io``), so a
    cookie scope on it covers unrelated sites. PslError when unusable."""
    h = host.lower().strip(".")
    return bool(h) and public_suffix_labels(h) >= len(h.split("."))


def registrable_domain(host: str) -> str:
    """eTLD+1 of `host` ('' for a public suffix or an IP)."""
    h = host.lower().strip(".")
    if _ip(h) is not None:
        return ""
    labels = h.split(".")
    n = public_suffix_labels(h)
    return ".".join(labels[-(n + 1) :]) if len(labels) > n else ""


def _ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# the config digest
# ---------------------------------------------------------------------------

# The config digest's version (stored with every promotion as `config_v`):
# bump it whenever `config_canon` changes; a promotion of an older version
# re-adopts the current digest only after a fresh strict check
# (agent_login_state.adopt_configs).
CONFIG_V = 1


def _strs(value: object) -> list[str]:
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if isinstance(v, str) and v]
    return []


def _scope_canon(view: Mapping[str, Any]) -> list[str]:
    """The cookie scope, independent of the view format: the sorted hosts
    when every scope is host-wide (path ``/`` - also a pre-S4c view without
    ``cookie_scopes``), else the sorted ``host`` + ``path`` strings."""
    scopes = _identity.entry_cookie_scopes(view)
    if all(s.path == "/" for s in scopes):
        return sorted({s.host for s in scopes})
    return sorted({f"{s.host}{s.path}" for s in scopes})


def config_canon(view: Mapping[str, Any]) -> dict[str, Any]:
    """The configuration a promotion holds for: what the VAULT item says,
    canonicalised - never a view-format detail or a flag the broker's code
    derives (``strict_proof``, a default ``session_refresh``, the built-in
    ``no_submit`` sites), so a broker release does not change it.

    The check URL, the sentinel and the cookie hosts are their resolved
    values (a built-in default counts as that field's value: changing it
    changes what the proof means); a login URL equal to its default (the
    check URL, else the first fill origin's root) is dropped; lists whose
    order carries no meaning are sorted, empty values normalised; `alias`
    and `name` are labels, not behaviour."""
    fill = sorted(o.lower() for o in _strs(view.get("fill_origins")))
    check = str(view.get("check_url") or "")
    login = str(view.get("login_url") or "")
    first = _strs(view.get("fill_origins"))[:1]
    defaults = {check} if check else {f"{o}/" for o in first}
    raw_storage = view.get("storage_keys")
    pairs = raw_storage.items() if isinstance(raw_storage, Mapping) else []
    storage = {str(o).lower(): sorted(_strs(k)) for o, k in pairs}
    days = view.get("max_session_days")
    return {
        "v": CONFIG_V,
        "fill_origins": fill,
        "check_url": check,
        "login_url": "" if login in defaults else login,
        "logged_in_selector": str(view.get("logged_in_selector") or ""),
        "pre_click": str(view.get("pre_click") or ""),
        "cookie_scope": _scope_canon(view),
        "cookie_names": sorted(set(_strs(view.get("cookie_names")))),
        "storage_keys": dict(sorted(storage.items())),
        "proof_origins": sorted(o.lower() for o in _strs(view.get("proof_origins"))),
        "fresh_login": view.get("fresh_login") is True,
        "max_session_days": days
        if isinstance(days, int) and not isinstance(days, bool)
        else None,
        "username_only": view.get("username_only") is True,
        "attempt_group": str(view.get("attempt_group") or ""),
        "instance": _identity.instance_of(view),
        "privilege": str(view.get("privilege") or ""),
        "identity": str(view.get("identity") or ""),
        "same_account_as": sorted(set(_strs(view.get("same_account_as")))),
    }


def config_digest(view: Mapping[str, Any]) -> str:
    """sha256 (hex) of `config_canon` (canonical JSON; the version is part
    of it, so digests of two versions never compare equal)."""
    text = json.dumps(config_canon(view), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode()).hexdigest()


# ---------------------------------------------------------------------------
# item findings (over `sites` views)
# ---------------------------------------------------------------------------


def _host(value: object) -> str:
    raw = str(value or "").strip()
    if "://" not in raw:
        return raw.lstrip(".").lower()
    try:
        return (urllib.parse.urlsplit(raw).hostname or "").lower()
    except ValueError:
        return ""


def _origin(value: object) -> str:
    """``scheme://host[:port]`` (the default port dropped; '' if unparsable)."""
    try:
        parts = urllib.parse.urlsplit(str(value or ""))
        netloc = (parts.hostname or "").lower()
        if netloc and parts.port not in (
            None,
            {"https": 443, "http": 80}.get(parts.scheme),
        ):
            netloc += f":{parts.port}"
    except ValueError:
        return ""
    return f"{parts.scheme}://{netloc}" if netloc else ""


def _list(view: Mapping[str, Any], key: str) -> list[str]:
    return _identity.str_list(view.get(key))


def own_hosts(view: Mapping[str, Any]) -> set[str]:
    """Hosts the item visits: fill, check, login, proof and storage origins."""
    hosts = {_host(o) for o in _list(view, "fill_origins")}
    hosts |= {_host(view.get("check_url")), _host(view.get("login_url"))}
    hosts |= {_host(o) for o in _list(view, "proof_origins")}
    hosts |= {_host(o) for o in _storage(view)}
    hosts.discard("")
    return hosts


def _storage(view: Mapping[str, Any]) -> dict[str, Any]:
    raw = view.get("storage_keys")
    return dict(raw) if isinstance(raw, Mapping) else {}


def _strict_proof(view: Mapping[str, Any]) -> bool:
    """The broker's own word (`strict_proof`, = ``SiteItem.has_proof``), else
    an older broker's `sentinel` / `logged_in_selector`."""
    for key in ("strict_proof", "sentinel"):
        if isinstance(view.get(key), bool):
            return bool(view[key])
    return bool(view.get("logged_in_selector"))


def _scope_findings(site: str, view: Mapping[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    mine = own_hosts(view)
    related = mine | _identity.recipe_hosts(view)
    for raw in _list(view, "cookie_hosts"):
        host = _host(raw)
        shown = safe_host(host)
        ip = _ip(host)
        try:
            public = ip is None and ("." not in host or is_public_suffix(host))
        except PslError:
            # An infrastructure error, reported ONCE (`psl_problem`) by -V,
            # -p and -c — never a per-item finding, never a gate on every
            # site: only this one judgement stays unknown.
            public = ip is None and "." not in host
        if public or (ip is not None and ip.is_global):
            out.append(
                Finding(
                    site,
                    "risk",
                    "public_suffix_scope",
                    f"cookie host {shown} is a public suffix / public address: the "
                    "bundle would carry cookies of unrelated sites",
                )
            )
            continue
        if not any(_identity.domains_related(host, h) for h in related):
            out.append(
                Finding(
                    site,
                    "risk",
                    "unrelated_cookie_host",
                    f"cookie host {shown} is related to none of the item's fill, "
                    "check, login, proof, storage or identity-recipe hosts",
                )
            )
            continue
        if is_idp_host(host):
            out.append(
                Finding(
                    site,
                    "hint",
                    "idp_cookie_host",
                    f"identity-provider host {shown} is in the scope: its SSO "
                    "session reaches the shared browser (wanted for eduid, not "
                    "for cscs)",
                )
            )
        strict_parent = mine and all(h != host and h.endswith("." + host) for h in mine)
        if strict_parent and not view.get("cookie_names"):
            out.append(
                Finding(
                    site,
                    "hint",
                    "wide_scope",
                    f"cookie host {shown} covers every *.{shown} host: narrow it to "
                    "the app host or set agent_cookie_names, unless the session "
                    "cookie lives on the parent",
                )
            )
    return out


def _storage_findings(
    site: str, view: Mapping[str, Any], *, dev: bool = False
) -> list[Finding]:
    storage = _storage(view)
    if not storage:
        return []
    out: list[Finding] = []
    problem = storage_keys_problem(storage, dev=dev)
    if problem:
        out.append(
            Finding(site, "risk", "storage_keys", f"agent_storage_keys: {problem}")
        )
    visits = {_host(o) for o in _list(view, "fill_origins")}
    visits |= {_host(view.get("check_url")), _host(view.get("login_url"))}
    visits |= {_host(o) for o in _list(view, "proof_origins")}
    visits.discard("")
    for origin in storage:
        host = _host(origin)
        if not any(_identity.domains_related(host, h) for h in visits):
            out.append(
                Finding(
                    site,
                    "risk",
                    "storage_origin_unrelated",
                    f"storage origin {safe_host(host)} is none of the item's fill, "
                    "check, login or proof hosts",
                )
            )
    keys = [k for ks in storage.values() if isinstance(ks, list) for k in ks]
    if any(isinstance(k, str) and _IDENTITY_KEY.search(k) for k in keys):
        out.append(
            Finding(
                site,
                "hint",
                "identity_like_key",
                "a storage key is named like an account claim: it is exported to "
                "the shared browser and proves nothing about the account",
            )
        )
    if view.get("session_refresh") in (None, "", "none"):
        out.append(
            Finding(
                site,
                "hint",
                "storage_no_refresher",
                "storage-token session without a refresher: if the token expires "
                "or rotates (NPM: 1 day), the daily check may cost a password submit",
            )
        )
    return out


def _proof_findings(site: str, view: Mapping[str, Any]) -> list[Finding]:
    if _strict_proof(view):
        return []
    out = [
        Finding(
            site,
            "unusable",
            "no_proof",
            "no agent_logged_in_selector and no server proof: a login can never be "
            f"proven strictly — find one: browser.py logged-in {site} -x 'CSS'",
        )
    ]
    check = _origin(view.get("check_url"))
    if check and check in {_origin(o) for o in _list(view, "fill_origins")}:
        out.append(
            Finding(
                site,
                "unusable",
                "check_on_fill_origin",
                f"the check URL's origin {safe_host(_host(check))} is a fill origin: "
                "without a sentinel the proof can never pass",
            )
        )
    return out


def _account_findings(
    site: str, view: Mapping[str, Any], siblings: Sequence[str]
) -> list[Finding]:
    multi = bool(siblings) or view.get("multi_account") is True
    if not multi or _identity.proof_ready(dict(view)):
        return []
    names = ", ".join(_ids(siblings)) or "another item"
    return [
        Finding(
            site,
            "unusable",
            "account_unproven",
            f"shares its login scope with {names}: declare agent_instance, "
            "agent_privilege and agent_identity (a usable recipe), or "
            "agent_same_account_as on both items",
            _ids(siblings),
        )
    ]


def _group_findings(
    site: str, view: Mapping[str, Any], views: Sequence[Mapping[str, Any]]
) -> list[Finding]:
    """Attempt groups: suggested, never enforced (master plan O6)."""
    out: list[Finding] = []
    mine = view.get("attempt_group") or None
    same = set(_list(view, "same_account_as"))
    for other in views:
        osite = str(other.get("site") or "")
        if osite == site or other.get("refused") or osite not in same:
            continue
        if site not in _list(other, "same_account_as"):
            continue  # one-sided: the broker refuses it (identity_rules)
        theirs = other.get("attempt_group") or None
        if mine is not None and mine == theirs:
            continue
        out.append(
            Finding(
                site,
                "hint",
                "attempt_group",
                f"is declared the same account as {safe_id(osite)}: set the same "
                "agent_attempt_group on both (an IdP lockout counts per account)",
                (safe_id(osite),),
            )
        )
    return out


def item_findings(
    view: Mapping[str, Any], views: Sequence[Mapping[str, Any]], *, dev: bool = False
) -> list[Finding]:
    """Every finding of ONE item (a ``sites`` view) inside the collection
    `views` (which may or may not contain it); `dev`: a dev broker's
    ``http://127.0.0.1`` origins are fine."""
    site = safe_id(view.get("site"))
    out: list[Finding] = []
    if view.get("refused"):
        out.append(
            Finding(
                site,
                "refused",
                "broker_refused",
                f"the broker refuses it: {safe_reason(view.get('reason'))}",
            )
        )
        if not _list(view, "fill_origins"):
            return out
    others = [v for v in views if v.get("site") != view.get("site")]
    siblings = _identity.scope_conflicts([dict(view), *others]).get(
        str(view.get("site")), ()
    )
    if not view.get("refused"):
        out += _proof_findings(site, view)
        out += _account_findings(site, view, siblings)
    out += _scope_findings(site, view)
    out += _storage_findings(site, view, dev=dev)
    out += _group_findings(site, view, others)
    return sorted(out, key=lambda f: (LEVELS.index(f.level), f.code))


def collection_findings(
    views: Sequence[Mapping[str, Any]], *, dev: bool = False
) -> dict[str, list[Finding]]:
    """``{site: findings}`` for every listed item (`-V`)."""
    out: dict[str, list[Finding]] = {}
    for view in views:
        site = str(view.get("site") or "")
        if site:
            out[safe_id(site)] = item_findings(view, views, dev=dev)
    return out


def blocking_findings(
    view: Mapping[str, Any], views: Sequence[Mapping[str, Any]], *, dev: bool = False
) -> list[Finding]:
    """The findings of `view` that block a promotion."""
    return [f for f in item_findings(view, views, dev=dev) if f.blocking]


def risk_findings(
    view: Mapping[str, Any], views: Sequence[Mapping[str, Any]], *, dev: bool = False
) -> list[Finding]:
    """The `risk` findings of `view` (`-c` never logs such an item in)."""
    return [f for f in item_findings(view, views, dev=dev) if f.level == "risk"]


# ---------------------------------------------------------------------------
# planned items (`-V -i MANIFEST`): the broker's own rules, before the write
# ---------------------------------------------------------------------------


def item_from_view(view: Mapping[str, Any]) -> SiteItem:
    """A stand-in ``SiteItem`` for a listed item, rebuilt from its ``sites``
    view: scope, URLs, WS5 fields and its refusal — what
    ``vault.identity_rules`` reads. (No username: the collection rules do
    not need one; the item rules were applied by the broker already.)"""
    from broker.vault import SiteItem  # pylint: disable=import-outside-toplevel

    scopes = _identity.entry_cookie_scopes(view) if view.get("cookie_scopes") else ()
    same = _list(view, "same_account_as")
    refused = (view.get("reason") or "refused") if view.get("refused") else None
    return SiteItem(
        site=str(view.get("site") or ""),
        name=str(view.get("name") or ""),
        fill_origins=_list(view, "fill_origins"),
        cookie_hosts=_list(view, "cookie_hosts"),
        cookie_scopes=tuple(scopes) if view.get("scope_v") else (),
        cookie_names=_list(view, "cookie_names") or None,
        storage_keys={
            str(o): [str(k) for k in ks]
            for o, ks in _storage(view).items()
            if isinstance(ks, list)
        },
        login_url=str(view.get("login_url") or ""),
        check_url=str(view.get("check_url") or ""),
        logged_in_selector=view.get("logged_in_selector") or None,
        attempt_group=view.get("attempt_group") or None,
        proof_origins=_list(view, "proof_origins"),
        refused=str(refused) if refused else None,
        instance=_identity.instance_of(view),
        privilege=str(view.get("privilege") or ""),
        identity=str(view.get("identity") or ""),
        same_account_as=same[0] if same else "",
        alias=str(view.get("alias") or ""),
    )


def _stand_in_raw(item: SiteItem) -> dict[str, Any]:
    """The Bitwarden-shaped raw `identity_rules` reads for a refused item's
    best-effort scope: its cookie hosts and fill origins."""
    return {
        "name": item.name,
        "fields": [
            {"name": "agent_cookie_hosts", "value": ",".join(item.cookie_hosts)},
            {"name": "agent_fill_origins", "value": ",".join(item.fill_origins)},
        ],
    }


# The username-dependent item rules of the broker (vault._identity_problem,
# _attempt_group): with no username in the manifest they cannot be decided.
_USER_FIELDS = ("agent_identity", "agent_alias", "agent_attempt_group")
_PLACEHOLDER = {
    "username": "onboarding-review",
    "email": "onboarding-review@example.invalid",
}


def _manifest_collections(manifest: Mapping[str, Any]) -> tuple[str, str | None] | None:
    """tp#965: the manifest's ``"collections": {"login": ID, "secrets": ID}``
    (the login and secrets collection ids the planned items' membership is
    judged against), or None when it names none. Raises ValueError."""
    raw = manifest.get("collections")
    if raw is None:
        return None
    if not isinstance(raw, Mapping) or set(raw) - {"login", "secrets"}:
        raise ValueError('collections must be {"login": ID, "secrets": ID}')
    login, secrets_coll = raw.get("login"), raw.get("secrets")
    if not isinstance(login, str) or not login:
        raise ValueError("collections.login must be a collection id")
    if secrets_coll is not None and (
        not isinstance(secrets_coll, str) or not secrets_coll
    ):
        raise ValueError("collections.secrets must be a collection id")
    return login, secrets_coll


def _manifest_items(
    manifest: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], list[str]]:
    """(planned items, removed site ids) of a manifest: ``{"items": [...],
    "removes": [...]}`` or one item (``{"name", "fields", ...}``). Raises
    ValueError on anything else (and on a password)."""
    if "items" in manifest or "removes" in manifest:
        items = manifest.get("items") or []
        removes = manifest.get("removes") or []
    else:  # one item; `collections` is the manifest's, not the item's
        items = [{k: v for k, v in manifest.items() if k != "collections"}]
        removes = []
    if not isinstance(items, list) or not isinstance(removes, list):
        raise ValueError("items and removes must be lists")
    out = []
    for raw in items:
        if not isinstance(raw, Mapping):
            raise ValueError("an item is not an object")
        unknown = set(raw) - _MANIFEST_KEYS
        if unknown:
            raise ValueError(
                f"unknown item keys: {', '.join(sorted(map(str, unknown)))}"
            )
        login = raw.get("login") or {}
        if not isinstance(login, Mapping) or set(login) - {"username"}:
            raise ValueError("login may hold a username only — no secrets here")
        out.append(dict(raw))
    return out, [str(r) for r in removes]


def _fields_list(fields: object) -> list[dict[str, str]]:
    if isinstance(fields, Mapping):
        return [{"name": str(k), "value": str(v)} for k, v in fields.items()]
    if isinstance(fields, list):
        return [
            {"name": str(f.get("name")), "value": str(f.get("value") or "")}
            for f in fields
            if isinstance(f, Mapping)
        ]
    raise ValueError("fields must be an object or a list of {name, value}")


def _planned_raw(item: Mapping[str, Any]) -> tuple[dict[str, Any], list[Finding]]:
    """The Bitwarden-shaped raw of a planned item, and the findings about
    what the manifest could not tell (the username)."""
    fields = _fields_list(item.get("fields"))
    names = {f["name"] for f in fields}
    login = item.get("login") or {}
    user = str(login.get("username") or "") if isinstance(login, Mapping) else ""
    notes: list[Finding] = []
    if not user and names & set(_USER_FIELDS):
        form = item.get("username_form")
        site = safe_id(
            next((f["value"] for f in fields if f["name"] == "agent_site"), "")
            or item.get("name")
        )
        if form in _PLACEHOLDER:
            user = _PLACEHOLDER[str(form)]
        else:
            user = _PLACEHOLDER["username"]
            notes.append(
                Finding(
                    site,
                    "unusable",
                    "username_unchecked",
                    "agent_identity / agent_alias / agent_attempt_group depend on the "
                    "login's username, which the manifest does not carry (no "
                    "username_form): broker-add checks them, this review cannot",
                )
            )
        reveals = item.get("reveals") or {}
        if isinstance(reveals, Mapping):
            for key, field_name in (
                ("alias", "agent_alias"),
                ("attempt_group", "agent_attempt_group"),
            ):
                if reveals.get(key) is True:
                    notes.append(
                        Finding(
                            site,
                            "refused",
                            "reveals_account",
                            f"{field_name} must not reveal the account name",
                        )
                    )
    raw = {
        "id": str(item.get("id") or ""),
        "name": str(item.get("name") or ""),
        "login": {"username": user},
        "fields": fields,
    }
    if "collectionIds" in item:  # as written: the membership rule judges it
        raw["collectionIds"] = item["collectionIds"]
    return raw, notes


def _membership_refusal(
    item: Mapping[str, Any],
    raw: Mapping[str, Any],
    collections: tuple[str, str | None] | None,
    gate: str = "collections",
) -> str:
    """tp#965: the broker's own membership refusal (``vault.membership_refusal``,
    never a copy of the rule) of a planned item, '' when fine. With the
    manifest's ``collections``, an item without ``collectionIds`` is a NEW
    item that goes into the login collection only. Without them, an item
    that names ``collectionIds`` cannot be judged (ValueError)."""
    from broker import vault  # pylint: disable=import-outside-toplevel

    if collections is None:
        if "collectionIds" in item:
            raise ValueError(
                "an item with collectionIds needs the manifest's "
                '"collections": {"login": ID, "secrets": ID}'
            )
        return ""
    judged = dict(raw)
    judged.setdefault("collectionIds", [collections[0]])
    return vault.membership_refusal(judged, collections, gate)


def _gate_findings(raw: Mapping[str, Any], gate: str) -> list[Finding]:
    """tp#991: a planned item's ``agent_script`` (the broker's own
    ``vault.agent_script_flag``): malformed is refused; ``true`` on an admin
    login is a risk (O1: raw disclosure to any child a script picks)."""
    from broker import vault  # pylint: disable=import-outside-toplevel

    fields = {
        str(f.get("name")): str(f.get("value") or "")
        for f in raw.get("fields") or []
        if isinstance(f, Mapping)
    }
    site = safe_id(
        fields.get("agent_site") or vault.slugify(str(raw.get("name") or ""))
    )
    flag = vault.agent_script_flag(fields)
    if flag is None:
        return [
            Finding(
                site,
                "refused",
                "bad_agent_script",
                "agent_script must be true or false: secret-run refuses the item "
                "(fail closed)",
            )
        ]
    out: list[Finding] = []
    if flag and fields.get("agent_privilege", "").strip().lower() == "admin":
        out.append(
            Finding(
                site,
                "risk",
                "agent_script_admin",
                "agent_script on an admin login: secret-run hands its raw "
                "password to any command an agent picks (O1) — only for a "
                "script that really reads it",
            )
        )
    if flag and gate != vault.GATE_AGENT_SCRIPT:
        out.append(
            Finding(
                site,
                "hint",
                "agent_script_not_enforced",
                f"the broker gate is {safe_id(gate)}: agent_script takes effect "
                "once it is agent_script",
            )
        )
    return out


def _ok(item: SiteItem) -> bool:
    return item.refused is None


# One pass per rule of the review, in the order the broker applies them.
# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def review_planned(
    manifest: Mapping[str, Any],
    views: Sequence[Mapping[str, Any]],
    *,
    dev: bool = False,
    gate: str = "collections",
) -> Review:
    """Review a planned change (additions, ``replaces`` updates, ``removes``)
    against the live collection `views`, with the broker's own item and
    collection rules, BEFORE anything is written. The planned items' own
    findings, plus every established item the change refuses (``displaced``)
    or turns into an unprovable multi-account item (``made_unproven``).

    `gate` (tp#991) is the broker's ``secret_gate`` as the caller read it:
    membership is judged for that mode, a script-only item (no agent_site,
    no fill origins, ``agent_script=true``) is no site under
    ``agent_script``, and a gate the caller could not read (``unknown`` or
    anything else) is ONE blocking finding."""
    from broker import vault  # pylint: disable=import-outside-toplevel

    planned_raw, removes = _manifest_items(manifest)
    collections = _manifest_collections(manifest)
    review = Review()
    if gate not in vault.SECRET_GATES:
        review.findings.append(
            Finding(
                "<review>",
                "refused",
                "gate_unknown",
                "broker gate unknown: refresh the broker listing "
                "(agent-login.py -V -r) — membership cannot be judged",
            )
        )
        gate = vault.GATE_COLLECTIONS
    listed = {str(v.get("site")): v for v in views if isinstance(v.get("site"), str)}
    built: list[SiteItem] = []
    raws: list[Mapping[str, Any]] = []
    replaced: set[str] = set()
    seen: set[str] = set()
    for item in planned_raw:
        raw, notes = _planned_raw(item)
        review.findings += notes
        review.findings += _gate_findings(raw, gate)
        if gate == vault.GATE_AGENT_SCRIPT and vault.is_script_only(raw):
            # a secret-run item, not a login: no site rules apply
            _membership_refusal(item, raw, collections, gate)
            review.planned.append(safe_id(vault.slugify(str(raw.get("name") or ""))))
            continue
        it = vault.site_item_from_json(raw, dev=dev)
        why = _membership_refusal(item, raw, collections, gate)
        if why:  # dual / unreadable membership: refused, its scope kept
            it = replace(it, refused=why, same_account_as="")
        target = str(item.get("replaces") or "")
        if it.site in seen or (it.site in listed and it.site != target):
            it = vault.SiteItem(
                site=it.site, name=it.name, refused="duplicate agent_site"
            )
        if target:
            replaced.add(target)
        seen.add(it.site)
        built.append(it)
        raws.append(raw)
        review.planned.append(safe_id(it.site))
    gone = replaced | set(removes)
    before_items = [item_from_view(v) for v in views]
    stand_in_raws: list[Mapping[str, Any]] = [_stand_in_raw(i) for i in before_items]
    before = vault.identity_rules(before_items, stand_in_raws)
    kept = [i for i in before_items if i.site not in gone]
    kept_raws: list[Mapping[str, Any]] = [_stand_in_raw(i) for i in kept]
    after = vault.identity_rules(kept + built, kept_raws + raws)
    after_views = [i.public() for i in after]
    review.after = after_views
    planned_ids = {i.site for i in built}
    before_by = {i.site: i for i in before}
    for it in after:
        if it.site in planned_ids:
            continue
        old = before_by.get(it.site)
        if old is None:
            continue
        cause = tuple(
            sorted(
                safe_id(p.site)
                for p in built
                if _identity.scopes_overlap(
                    _identity.item_scopes(p.public()),
                    _identity.item_scopes(it.public()),
                )
            )
        )
        if _ok(old) and not _ok(it):
            review.findings.append(
                Finding(
                    safe_id(it.site),
                    "refused",
                    "displaced",
                    f"this change makes the broker refuse established {safe_id(it.site)}: "
                    f"{safe_reason(it.refused)}",
                    cause,
                )
            )
        elif (
            _ok(it)
            and it.multi_account
            and not old.multi_account
            and not _identity.proof_ready(it.public())
        ):
            review.findings.append(
                Finding(
                    safe_id(it.site),
                    "unusable",
                    "made_unproven",
                    f"this change makes established {safe_id(it.site)} share its login "
                    "scope with another account: it turns ⚠ unproven until it "
                    "declares agent_identity",
                    cause,
                )
            )
    for it in after:
        if it.site in planned_ids:
            review.findings += item_findings(it.public(), after_views, dev=dev)
    review.findings.sort(key=lambda f: (LEVELS.index(f.level), f.site, f.code))
    return review


# ---------------------------------------------------------------------------
# pin cases: broker-add's mirror of the single-item checks must agree
# ---------------------------------------------------------------------------


def _pin_view(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "site": "pin-app",
        "fill_origins": ["https://app.pin.example.com"],
        "cookie_hosts": ["app.pin.example.com"],
        "check_url": "https://app.pin.example.com/home",
        "login_url": "https://app.pin.example.com/home",
        "logged_in_selector": "#me",
        "strict_proof": True,
        "storage_keys": {},
        "refused": False,
    }
    base.update(over)
    return base


# (view, the single-item finding codes) — what `broker_add_fields`'s mirror
# must answer for the same final fields (test-broker-add.py
# `case_onboarding_pins`).
PIN_CASES: tuple[tuple[dict[str, Any], frozenset[str]], ...] = (
    (_pin_view(), frozenset()),
    (
        _pin_view(logged_in_selector=None, strict_proof=False),
        frozenset({"no_proof", "check_on_fill_origin"}),
    ),
    (
        _pin_view(
            logged_in_selector=None,
            strict_proof=False,
            check_url="https://www.pin.example.com/",
        ),
        frozenset({"no_proof"}),
    ),
    (_pin_view(cookie_hosts=["github.io"]), frozenset({"public_suffix_scope"})),
    (_pin_view(cookie_hosts=["co.uk"]), frozenset({"public_suffix_scope"})),
    (_pin_view(cookie_hosts=["com"]), frozenset({"public_suffix_scope"})),
    (
        _pin_view(cookie_hosts=["other.example.org"]),
        frozenset({"unrelated_cookie_host"}),
    ),
    (_pin_view(cookie_hosts=["pin.example.com"]), frozenset({"wide_scope"})),
    (
        _pin_view(cookie_hosts=["pin.example.com"], cookie_names=["sid"]),
        frozenset(),
    ),
    (
        _pin_view(storage_keys={"https://app.pin.example.com": ["token"]}),
        frozenset({"storage_no_refresher"}),
    ),
    (
        _pin_view(
            storage_keys={"https://app.pin.example.com": ["token"]},
            session_refresh="npm-jwt",
        ),
        frozenset(),
    ),
    (
        _pin_view(
            storage_keys={"https://cdn.other.example.org": ["token"]},
            session_refresh="npm-jwt",
        ),
        frozenset({"storage_origin_unrelated"}),
    ),
    (
        _pin_view(
            storage_keys={"https://app.pin.example.com": ["user email"]},
            session_refresh="npm-jwt",
        ),
        frozenset({"storage_keys", "identity_like_key"}),
    ),
    (
        _pin_view(
            storage_keys={"https://app.pin.example.com": []}, session_refresh="npm-jwt"
        ),
        frozenset({"storage_keys"}),
    ),
    (
        _pin_view(
            fill_origins=["https://idp.pin.example.com"],
            cookie_hosts=["app.pin.example.com", "idp.pin.example.com"],
        ),
        frozenset({"idp_cookie_host"}),
    ),
)


def single_item_codes(view: Mapping[str, Any]) -> frozenset[str]:
    """The codes of `view`'s single-item findings (no collection context):
    what broker-add's mirror computes from the final fields alone."""
    return frozenset(f.code for f in item_findings(view, [view]))


__all__ = [
    "BLOCKING",
    "LEVELS",
    "PIN_CASES",
    "Finding",
    "PslError",
    "Review",
    "blocking_findings",
    "collection_findings",
    "config_digest",
    "is_public_suffix",
    "item_findings",
    "item_from_view",
    "registrable_domain",
    "review_planned",
    "risk_findings",
    "single_item_codes",
    "storage_keys_problem",
]
