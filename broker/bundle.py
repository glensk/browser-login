"""Session bundle: which cookies and storage keys of a site leave the broker.

Never the whole cookie jar: a cookie is exported only when its domain is one of
the site's ``cookie_hosts`` (or a subdomain of one) and, when the item lists
``cookie_names``, its name is listed. Identity-provider hosts are always
excluded unless the site names that exact host — an IdP session cookie would
let the agent log into every other site behind that IdP.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

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


def _norm_host(domain: str) -> str:
    return domain.strip().lstrip(".").lower()


def is_idp_host(host: str) -> bool:
    """True for a built-in identity-provider host (exact or ``idp./sso./keycloak.*``)."""
    h = _norm_host(host)
    return h in IDP_HOSTS or h.split(".", 1)[0] in IDP_LABELS


def cookie_in_scope(domain: str, name: str, spec: SiteBundleSpec) -> bool:
    """The export rule for one cookie (see the module docstring)."""
    d = _norm_host(domain)
    if not d:
        return False
    hosts = [_norm_host(h) for h in spec.cookie_hosts if _norm_host(h)]
    if not any(d == h or d.endswith("." + h) for h in hosts):
        return False
    if is_idp_host(d) and d not in hosts:
        return False
    return spec.cookie_names is None or name in spec.cookie_names


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
        if not name or not cookie_in_scope(domain, name, spec):
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
