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

Pure: no I/O, no imports beyond the standard library. Imported by
``bin/browser.py`` (the client guard) and ``agent-login.py`` (rows, agents.md).
"""

from __future__ import annotations

import urllib.parse
from collections.abc import Iterable, Mapping

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
    graph = scope_conflicts(sites)
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
