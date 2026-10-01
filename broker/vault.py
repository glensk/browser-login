"""Where the broker's site list and secrets come from: Bitwarden (or a dev fixture).

Whitelisting a site = its login item sits in the ``agent-logins`` collection AND
carries the custom field ``agent_fill_origins``. Items without it are listed as
refused. Secrets never leave this module except as a ``Secret`` handed to a
recipe; ``Secret`` has a redacting ``repr`` so a stray log line shows nothing.

``BwVault`` drives the ``bw`` CLI with secrets in the ENVIRONMENT only (never
argv): the API key logs the broker's own Vaultwarden user in, the master
password unlocks (``--passwordenv``), the session key lives in memory and is
passed as ``BW_SESSION``, and the vault is locked again after every call.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from broker.bundle import SiteBundleSpec, is_idp_host
from broker.origins import parse_fill_origins

SITE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
BW_TIMEOUT_S = 120.0


class VaultError(RuntimeError):
    """The vault could not be read. The message never carries a secret."""


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
    logged_in_selector: str | None = None
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
            "logged_in_selector": self.logged_in_selector,
            "refused": self.refused is not None,
            "reason": self.refused or "",
        }


class Vault(Protocol):
    """The broker's view of the credential store."""

    def items(self) -> list[SiteItem]:
        """Every item of the collection, refused ones included."""

    def secret(self, site: str) -> Secret:
        """The secret of a non-refused site (VaultError otherwise)."""


def slugify(name: str) -> str:
    """Default site id from an item name: lowercase, runs of non-alnum -> ``-``."""
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:64]


def _fields(item: Mapping[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for f in item.get("fields") or []:
        if isinstance(f, Mapping) and f.get("name"):
            out[str(f["name"])] = "" if f.get("value") is None else str(f["value"])
    return out


def _split_list(raw: str) -> list[str]:
    return [p.strip() for p in re.split(r"[,\n]", raw) if p.strip()]


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

    hosts_raw = fields.get("agent_cookie_hosts", "").strip()
    if hosts_raw:
        cookie_hosts = [h.lstrip(".").lower() for h in _split_list(hosts_raw)]
    else:  # default: the fill-origin hosts, minus identity providers
        cookie_hosts = []
        for o in fill_origins:
            host = o.split("://", 1)[1].split(":", 1)[0]
            if not is_idp_host(host) and host not in cookie_hosts:
                cookie_hosts.append(host)
    if not cookie_hosts:
        return refused("no cookie host (set agent_cookie_hosts)")
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

    login_url = fields.get("agent_login_url", "").strip() or fill_origins[0] + "/"
    if not login_url.startswith(("https://", "http://127.0.0.1")):
        return refused("bad agent_login_url")
    if login_url.startswith("http://") and not dev:
        return refused("bad agent_login_url")
    sentinel = fields.get("agent_logged_in_selector", "").strip() or None
    return SiteItem(
        fill_origins=fill_origins,
        cookie_hosts=cookie_hosts,
        cookie_names=cookie_names,
        storage_keys=storage_keys,
        login_url=login_url,
        logged_in_selector=sentinel,
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
    return Secret(
        username=str(login.get("username") or ""),
        password=str(login.get("password") or ""),
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


class FixtureVault:
    """Items from a JSON file (a list of Bitwarden-shaped items). Dev mode only."""

    def __init__(self, path: str | os.PathLike[str], *, dev: bool) -> None:
        if not dev:
            raise VaultError("FixtureVault is only usable with --dev")
        self.path = Path(path)
        self.dev = dev

    def _raw(self) -> list[Any]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise VaultError(f"cannot read fixture vault {self.path}") from exc
        if not isinstance(data, list):
            raise VaultError("fixture vault must be a JSON list of items")
        return data

    def items(self) -> list[SiteItem]:
        """Every fixture item, refused ones included."""
        return build_items(self._raw(), dev=self.dev)

    def secret(self, site: str) -> Secret:
        """The fixture secret of `site`."""
        return secret_from_json(_find(self._raw(), site, dev=self.dev))


# The self-hosted Vaultwarden the broker account lives on.
DEFAULT_SERVER_URL = "https://vaultwarden.dom42.space"


@dataclass(frozen=True)
class BwBootstrap:
    """Contents of ``<home>/bootstrap.json`` (written by ``install.sh -e``)."""

    client_id: str = field(repr=False)
    client_secret: str = field(repr=False)
    master_password: str = field(repr=False)
    collection_id: str
    server_url: str = DEFAULT_SERVER_URL

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
        return cls(**{k: data[k] for k in keys}, server_url=server)


class BwVault:
    """The broker's own Vaultwarden account, read through the ``bw`` CLI."""

    def __init__(
        self,
        bootstrap: BwBootstrap,
        appdata_dir: str | os.PathLike[str],
        *,
        bw_bin: str = "bw",
    ) -> None:
        self.boot = bootstrap
        self.appdata_dir = str(appdata_dir)
        self.bw_bin = bw_bin

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
            # stderr is NOT echoed: bw may quote input back.
            raise VaultError(f"bw {args[0]} failed (exit {proc.returncode})")
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

    def _raw(self) -> list[Any]:
        with self._session() as session:
            env = self._env(BW_SESSION=session)
            self._run(["sync"], env)
            out = self._run(
                ["list", "items", "--collectionid", self.boot.collection_id], env
            )
        try:
            data = json.loads(out)
        except ValueError as exc:
            raise VaultError("bw list returned no JSON") from exc
        if not isinstance(data, list):
            raise VaultError("bw list returned no list")
        return data

    def items(self) -> list[SiteItem]:
        """Every item of the ``agent-logins`` collection."""
        return build_items(self._raw())

    def secret(self, site: str) -> Secret:
        """Username, password and TOTP seed of `site` (fresh unlock, then lock)."""
        return secret_from_json(_find(self._raw(), site, dev=False))
