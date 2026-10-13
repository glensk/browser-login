"""The broker's proxy auto-config (PAC): the home-proxy route for dom42 hosts.

The Cloudflare-Access-gated ``*.dom42.space`` hosts answer without Access only
from the home LAN. ``vpn.sh homeproxy`` runs a restricted SSH dynamic forward
to nixos on ``127.0.0.1:1082``; through it those names resolve at nixos'
dnsmasq and land on NPM directly. The broker's headless Chromium routes
EXACTLY these hosts through that SOCKS5 proxy (``; DIRECT`` when it is down —
then Access answers, as before) and everything else DIRECT.

The host list is a CONSTANT of the installed release, on purpose: the
agent-writable ``bin/pac_hosts.json`` (the shared browser's map) must never
steer the broker, which types passwords. A hostile listener on 1082 cannot
read them either: TLS validation is unchanged. ``tests/test_broker_pac.py``
pins that this tuple and the ``:1082`` entries of ``bin/pac_hosts.json`` are
the same set (= nixos' ``accessGatedNames``).

Stdlib only: ``selfcheck.py`` imports it too.
"""

from __future__ import annotations

import base64
import json

HOMEPROXY_PROXY = "SOCKS5 127.0.0.1:1082"
# Exact hosts (no suffix rule), all served by NPM on port 443. Keep in sync
# with nixos `accessGatedNames` and `bin/pac_hosts.json` (parity test).
HOMEPROXY_PAC_HOSTS: tuple[str, ...] = (
    "audiobookshelf.dom42.space",
    "booklore.dom42.space",
    "books.dom42.space",
    "calibre.dom42.space",
    "homepage.dom42.space",
    "jellyfin.dom42.space",
    "kavita.dom42.space",
    "kindle-history.dom42.space",
    "komga.dom42.space",
    "music.dom42.space",
    "vaultwarden.dom42.space",
)
PAC_URL_PREFIX = "data:application/x-ns-proxy-autoconfig;base64,"


def route_for(host: str) -> str:
    """What the rendered PAC answers for `host` (the same rule, in Python)."""
    if host.lower() in HOMEPROXY_PAC_HOSTS:
        return f"{HOMEPROXY_PROXY}; DIRECT"
    return "DIRECT"


def render_pac() -> str:
    """The PAC script: each listed host via the home proxy (then DIRECT), the
    rest DIRECT. Sorted, so the same constant always renders the same bytes."""
    lines = [
        "function FindProxyForURL(url, host) {",
        "  host = host.toLowerCase();",
    ]
    route = json.dumps(f"{HOMEPROXY_PROXY}; DIRECT")
    for host in sorted(HOMEPROXY_PAC_HOSTS):
        lines.append(f"  if (host === {json.dumps(host)}) return {route};")
    lines += ['  return "DIRECT";', "}", ""]
    return "\n".join(lines)


def pac_url(pac: str | None = None) -> str:
    """The inline ``data:`` URL (Chrome for Testing ignores a ``file://`` PAC)."""
    body = render_pac() if pac is None else pac
    return PAC_URL_PREFIX + base64.b64encode(body.encode("utf-8")).decode("ascii")


def pac_flag() -> str:
    """The one Chromium switch: ``--proxy-pac-url=data:…``."""
    return f"--proxy-pac-url={pac_url()}"
