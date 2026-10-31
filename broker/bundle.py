"""Session bundle: which cookies and storage keys of a site leave the broker.

Never the whole cookie jar: a cookie is exported only when its domain is one of
the site's ``cookie_hosts`` (or a subdomain of one) — with ``cookie_scopes``
(WS5 S4c), also only when its path lies in the scope's path
(``identity.CookieScope.holds``: one realm of a Keycloak host, not its sibling)
— and, when the item lists ``cookie_names``, its name is listed.
Identity-provider hosts are always excluded unless the site names that exact
host — an IdP session cookie would let the agent log into every other site
behind that IdP. A Cloudflare Access team-domain cookie (``*.cloudflareaccess.com``)
is never exported at all (tp#1466, ``broker.access_team``).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from broker.access_team import is_team_host as is_access_team_host
from broker.identity import CookieScope, domains_related, scopes_hold

# Exact IdP hosts, plus first-label wildcards (``idp.*``, ``sso.*``, ``keycloak.*``).
# browser.py mirrors this list for the client-side cookie delete (a test pins
# both copies to the same values).
IDP_HOSTS: frozenset[str] = frozenset(
    {
        "accounts.google.com",
        "login.microsoftonline.com",
        "appleid.apple.com",
        "auth.cscs.ch",
        "login.eduid.ch",
    }
)
IDP_LABELS: frozenset[str] = frozenset({"idp", "sso", "keycloak"})


@dataclass(frozen=True)
class SiteBundleSpec:
    """What may leave the broker for one site."""

    cookie_hosts: list[str]
    cookie_names: list[str] | None = None
    storage_keys: dict[str, list[str]] = field(default_factory=dict)
    # WS5 S4c: the item's cookie scopes with their paths; None = its
    # cookie hosts, each at path "/" (the whole host).
    cookie_scopes: tuple[CookieScope, ...] | None = None

    @property
    def scopes(self) -> tuple[CookieScope, ...]:
        """The scopes a cookie must lie in (`cookie_scopes`, else every
        cookie host at path "/")."""
        if self.cookie_scopes is not None:
            return tuple(self.cookie_scopes)
        return tuple(CookieScope(h) for h in self.cookie_hosts if _norm_host(h))


def _norm_host(domain: str) -> str:
    return domain.strip().lstrip(".").lower()


def is_idp_host(host: str) -> bool:
    """True for a built-in identity-provider host (exact or ``idp./sso./keycloak.*``)."""
    h = _norm_host(host)
    return h in IDP_HOSTS or h.split(".", 1)[0] in IDP_LABELS


def cookie_drop_reason(
    domain: str, name: str, spec: SiteBundleSpec, path: str = "/"
) -> str:
    """Why the export rule drops one cookie of `domain`, `name` and `path`
    ('' = it is exported; see the module docstring): ``no_domain``,
    ``out_of_scope`` (not on a scope host or a subdomain of one: a parent
    or unrelated domain), ``out_of_path`` (on a scope host, outside every
    path of its scopes), ``access_team`` (a Cloudflare Access team-domain
    cookie, `broker.access_team`: never exported), ``idp_host`` or
    ``not_in_cookie_names``. The ONE
    rule behind `cookie_in_scope` and `cookie_diag`."""
    d = _norm_host(domain)
    if not d:
        return "no_domain"
    scopes = spec.scopes
    if not scopes_hold(scopes, d, path):
        if any(d == s.host or d.endswith("." + s.host) for s in scopes):
            return "out_of_path"
        return "out_of_scope"
    if is_access_team_host(d):
        # tp#1466: a Cloudflare Access team session opens every app of the
        # team (decide too) — never exported, even for a site naming it.
        return "access_team"
    if is_idp_host(d) and d not in {s.host for s in scopes}:
        return "idp_host"
    unnamed = spec.cookie_names is not None and name not in spec.cookie_names
    return "not_in_cookie_names" if unnamed else ""


def cookie_in_scope(
    domain: str, name: str, spec: SiteBundleSpec, path: str = "/"
) -> bool:
    """The export rule for one cookie of `domain`, `name` and `path` (see
    the module docstring)."""
    return not cookie_drop_reason(domain, name, spec, path)


def filter_cookies(
    cookies: Iterable[Mapping[str, Any]], spec: SiteBundleSpec
) -> list[dict[str, Any]]:
    """Cookies in scope, as plain dicts for CDP ``Storage.setCookies`` / Playwright.

    Session cookies (``expires`` < 0 or absent) carry no ``expires`` key.
    """
    out: list[dict[str, Any]] = []
    for c in cookies:
        domain = str(c.get("domain") or "")
        name = str(c.get("name") or "")
        if not name or not cookie_in_scope(
            domain, name, spec, str(c.get("path") or "/")
        ):
            continue
        item: dict[str, Any] = {
            "name": name,
            "value": str(c.get("value") or ""),
            "domain": domain,
            "path": str(c.get("path") or "/"),
            "secure": bool(c.get("secure", False)),
            "httpOnly": bool(c.get("httpOnly", False)),
        }
        same_site = c.get("sameSite")
        if same_site in ("Strict", "Lax", "None"):
            item["sameSite"] = same_site
        expires = c.get("expires")
        if isinstance(expires, (int, float)) and expires > 0:
            item["expires"] = expires
        out.append(item)
    return out


# At most this many cookies are described by `cookie_diag`.
DIAG_CAP = 64
DIAG_V = 1


def _diag_entry(c: Mapping[str, Any], spec: SiteBundleSpec) -> dict[str, Any]:
    """One cookie's metadata and export verdict — NEVER its value (nor a
    digest or length of it)."""
    domain = str(c.get("domain") or "")
    name = str(c.get("name") or "")
    path = str(c.get("path") or "/")
    why = "no_name" if not name else cookie_drop_reason(domain, name, spec, path)
    if why == "out_of_scope":
        d = _norm_host(domain)
        if any(s.host.endswith("." + d) for s in spec.scopes):
            why = "parent_domain"  # sent to a scope host, never exported
    expires = c.get("expires")
    same_site = c.get("sameSite")
    return {
        "domain": domain,
        "path": path,
        "name": name,
        "session": not (isinstance(expires, (int, float)) and expires > 0),
        "httpOnly": bool(c.get("httpOnly", False)),
        "secure": bool(c.get("secure", False)),
        "sameSite": same_site if same_site in ("Strict", "Lax", "None") else None,
        "partitioned": bool(c.get("partitionKey")),
        "kept": not why,
        "why_dropped": why or None,
    }


def cookie_diag(
    cookies: Iterable[Mapping[str, Any]], spec: SiteBundleSpec, cap: int = DIAG_CAP
) -> dict[str, Any]:
    """Value-free picture of the jar the export read (`filter_cookies`' own
    input): every cookie on a scope host, a subdomain of one or a parent
    domain of one (sent there too) — kept or dropped, and why
    (`cookie_drop_reason`, plus ``parent_domain`` / ``no_name``). Names and
    metadata only: a cookie's value, a digest or its length never appear.
    Scope-host cookies come first, then parent domains, each sorted by
    domain, path and name; at most `cap` entries (``truncated``)."""
    hosts = [s.host for s in spec.scopes if s.host]
    jar = list(cookies)
    related = [
        c
        for c in jar
        if (d := _norm_host(str(c.get("domain") or "")))
        and any(domains_related(d, h) for h in hosts)
    ]
    entries = [_diag_entry(c, spec) for c in related]
    entries.sort(
        key=lambda e: (
            e["why_dropped"] == "parent_domain",
            _norm_host(e["domain"]),
            e["path"],
            e["name"],
        )
    )
    return {
        "v": DIAG_V,
        "jar_total": len(jar),
        "matched": len(entries),
        "kept": sum(1 for e in entries if e["kept"]),
        "truncated": len(entries) > cap,
        "cookies": entries[:cap],
    }


def filter_storage(
    storage: Mapping[str, Mapping[str, Any]], spec: SiteBundleSpec
) -> dict[str, dict[str, str]]:
    """Only the listed localStorage keys of the listed origins; None values dropped."""
    out: dict[str, dict[str, str]] = {}
    for origin, keys in spec.storage_keys.items():
        values = storage.get(origin) or {}
        kept = {k: str(values[k]) for k in keys if values.get(k) is not None}
        if kept:
            out[origin] = kept
    return out
