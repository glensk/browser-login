"""After a Homebrew upgrade of python / node: is Albert's login tooling intact?

Two read-only checks for `agent-login.py` (WS1b, PLAN_ws1b-durability.md D9).
Each gives a one-line ❌ with the exact fix, or nothing:

* **vault-touchid** (mydotfiles ``tools/vault-touchid``, the Touch ID helper
  behind ``broker-add.py``) pins the sha256 of python3, node and the bitwarden
  CLI it may run. After ``brew upgrade`` its pins point at a removed or
  changed binary, and every vault write fails with "bw status (pinned CLI)
  failed" until ``build.sh`` runs again. The build stamp
  (``~/.local/libexec/vault-touchid.stamp``: a ``# vault-touchid build stamp
  v1`` header, then ``<sha256>  <absolute path>`` rows) tells which.
* **python user site**: a new python minor version starts with an EMPTY user
  site (``~/Library/Python/3.X/lib/python/site-packages``); the scripts that
  imported a package from the old one break. The fix pins every missing
  distribution to the version the old site held (``name==version``); a
  distribution installed from a local path or VCS (``direct_url.json``) is
  named, never put into the command.

The automatic remedy (rebuild, re-sync) belongs to mydotfiles' brew
maintenance (spec M3); this module never runs a build or an install.
Stdlib only, no subprocess, no network.
"""

from __future__ import annotations

import hashlib
import os
import re
import site
import time
from dataclasses import dataclass
from pathlib import Path

STAMP_HEADER = "# vault-touchid build stamp v1"
VAULT_TOUCHID_STAMP = Path.home() / ".local" / "libexec" / "vault-touchid.stamp"
VAULT_TOUCHID_BUILD = (
    Path.home() / "obsidian/42-Git/home/mydotfiles/tools/vault-touchid/build.sh"
)
BREW_LINKS = {
    "python3": Path("/opt/homebrew/bin/python3"),
    "node": Path("/opt/homebrew/bin/node"),
}
# Runtime rows of the stamp, by path shape (the stamp rows carry no label).
_RUNTIME_SHAPES = {
    "python3": re.compile(r"/Cellar/python@[^/]+/.*/bin/python3(\.\d+)?$"),
    "node": re.compile(r"/Cellar/node(@[^/]+)?/[^/]+/bin/node$"),
    "bw.js": re.compile(r"/@bitwarden/cli/build/bw\.js$"),
}
_ROW = re.compile(r"^([0-9a-f]{64})  (/.+)$")
_USER_SITE = re.compile(r"/Library/Python/(\d+)\.(\d+)/lib/python/site-packages$")
_DIST = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)-([^-]+)\.dist-info$")


@dataclass(frozen=True)
class Finding:
    """One toolchain problem: what (fixed words + versions/names), the fix,
    and its level: ``fail`` (❌, `-c` counts it), ``warn`` (⚠️, shown only)
    or ``unknown`` (❓, cannot judge)."""

    what: str
    fix: str
    level: str = "fail"

    @property
    def unknown(self) -> bool:
        """True when it is not a failure (a warning or cannot judge)."""
        return self.level != "fail"

    def line(self) -> str:
        """The one-line report."""
        icon = {"fail": "❌", "warn": "⚠️", "unknown": "❓"}.get(self.level, "❓")
        return (
            f"{icon} {self.what} — fix: {self.fix}"
            if self.fix
            else f"{icon} {self.what}"
        )


# A user-site gap is a ❌ only this soon after the python minor version
# changed (afterwards a missing package was most likely dropped on purpose).
USER_SITE_FRESH_S = 14 * 86400.0
# Distributions never reported (comma list; canonical names).
USER_SITE_IGNORE_ENV = "AGENT_LOGIN_USERSITE_IGNORE"


def _sha256(path: Path) -> str | None:
    try:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def stamp_rows(text: str) -> list[tuple[str, Path]] | None:
    """Every ``(sha256, path)`` row of a vault-touchid stamp; None when the
    header is not the known one (cannot judge)."""
    lines = text.splitlines()
    if not lines or lines[0].split(" — ")[0].strip() != STAMP_HEADER:
        return None
    out: list[tuple[str, Path]] = []
    for line in lines[1:]:
        m = _ROW.match(line.strip())
        if m:
            out.append((m.group(1), Path(m.group(2))))
    return out


def stamp_runtime_rows(text: str) -> dict[str, tuple[str, Path]] | None:
    """``{runtime: (sha256, path)}`` of a vault-touchid stamp (python3, node,
    bw.js by path shape); None when the header is unknown."""
    rows = stamp_rows(text)
    if rows is None:
        return None
    out: dict[str, tuple[str, Path]] = {}
    for digest, path in rows:
        for name, shape in _RUNTIME_SHAPES.items():
            if shape.search(str(path)):
                out[name] = (digest, path)
    return out


def _runtime_name(path: Path) -> str | None:
    return next(
        (n for n, shape in _RUNTIME_SHAPES.items() if shape.search(str(path))), None
    )


def vault_touchid_finding(
    stamp: Path = VAULT_TOUCHID_STAMP,
    links: dict[str, Path] | None = None,
    build: Path = VAULT_TOUCHID_BUILD,
) -> Finding | None:
    """A stale vault-touchid build, or None: EVERY pinned file of the stamp
    (Swift sources, build.sh, the bundles, python3 / node / bw.js) must still
    hash to its pin, and the Homebrew links must still name the pinned
    runtimes.

    No stamp at all = the helper is not installed here: nothing to report."""
    try:
        text = stamp.read_text(encoding="utf-8")
    except OSError:
        return None
    rows = stamp_rows(text)
    if rows is None:
        return Finding("vault-touchid: unknown build stamp format", "", level="unknown")
    links = BREW_LINKS if links is None else links
    stale: list[str] = []
    other = 0
    for digest, path in rows:
        name = _runtime_name(path)
        if _sha256(path) != digest:
            if name:
                stale.append(f"{name} {'changed' if path.exists() else 'removed'}")
            else:
                other += 1
            continue
        link = links.get(name or "")
        if link is not None and link.exists() and link.resolve() != path.resolve():
            stale.append(f"{name} upgraded")
    if other:
        stale.append(f"{other} other pinned file(s) changed")
    if not stale:
        return None
    return Finding(
        f"vault-touchid is stale after a Homebrew upgrade ({', '.join(stale)}); "
        "vault writes (broker-add, Touch ID) fail until it is rebuilt",
        str(build),
    )


def _version_of(site_dir: Path) -> tuple[int, int] | None:
    m = _USER_SITE.search(str(site_dir))
    return (int(m.group(1)), int(m.group(2))) if m else None


def _norm(name: str) -> str:
    """PEP 503 canonical name: lower case, runs of ``-_.`` → ``-``."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _metadata(dist_info: Path) -> tuple[str, str] | None:
    """(Name, Version) from a ``*.dist-info/METADATA``; the directory name
    when METADATA is unreadable; None when neither gives both."""
    try:
        head = dist_info.joinpath("METADATA").read_text(
            encoding="utf-8", errors="replace"
        )[:4096]
    except OSError:
        head = ""
    name = re.search(r"^Name:\s*(\S+)\s*$", head, re.MULTILINE)
    version = re.search(r"^Version:\s*(\S+)\s*$", head, re.MULTILINE)
    if name and version:
        return name.group(1), version.group(1)
    m = _DIST.match(dist_info.name)
    return (m.group(1), m.group(2)) if m else None


def distributions(site_dir: Path) -> dict[str, tuple[str, bool]]:
    """``{canonical name: (version, reproducible)}`` of a site dir's
    ``*.dist-info`` (reproducible = no ``direct_url.json`` and ONE version
    of that name; two versions of one name = ambiguous, version '?')."""
    out: dict[str, tuple[str, bool]] = {}
    try:
        entries = list(site_dir.iterdir())
    except OSError:
        return out
    for entry in entries:
        if not entry.name.endswith(".dist-info") or not entry.is_dir():
            continue
        meta = _metadata(entry)
        if meta is None:
            continue
        key, version = _norm(meta[0]), meta[1]
        reproducible = not (entry / "direct_url.json").exists()
        if key in out and out[key][0] != version:
            out[key] = ("?", False)  # ambiguous: never pinned
            continue
        out[key] = (version, reproducible and out.get(key, ("", True))[1])
    return out


def previous_user_site(current: Path) -> Path | None:
    """The user site of the newest LOWER python minor version, or None."""
    ver = _version_of(current)
    if ver is None:
        return None
    base = current.parents[3]  # ~/Library/Python
    try:
        dirs = list(base.iterdir())
    except OSError:
        return None
    older: list[tuple[tuple[int, int], Path]] = []
    for d in dirs:
        cand = d / "lib" / "python" / "site-packages"
        v = _version_of(cand)
        if v is None or v >= ver or v[0] != ver[0] or not cand.is_dir():
            continue
        older.append((v, cand))
    return max(older)[1] if older else None


def _changed_at(cur: Path) -> float | None:
    """When this python minor version came: its user site's creation time
    (its parent version dir when the site dir does not exist yet)."""
    for cand in (cur, cur.parents[2]):
        try:
            st = cand.stat()
        except OSError:
            continue
        return float(getattr(st, "st_birthtime", st.st_mtime))
    return None


def user_site_finding(
    current: Path | None = None, now: float | None = None
) -> Finding | None:
    """Packages of the previous python's user site missing from the current
    one, with the pinned install command — or None. A ❌ only within
    ``USER_SITE_FRESH_S`` of the minor-version change, a ⚠️ afterwards;
    names in ``$AGENT_LOGIN_USERSITE_IGNORE`` are never reported."""
    cur = Path(current or site.getusersitepackages())
    prev = previous_user_site(cur)
    ver = _version_of(cur)
    if prev is None or ver is None:
        return None
    ignore = {
        _norm(n) for n in os.environ.get(USER_SITE_IGNORE_ENV, "").split(",") if n
    }
    old = distributions(prev)
    new = distributions(cur)
    missing = sorted(n for n in old if n not in new and n not in ignore)
    if not missing:
        return None
    born = _changed_at(cur)
    now = time.time() if now is None else now
    level = "fail" if born is not None and now - born <= USER_SITE_FRESH_S else "warn"
    pinned = [f"{n}=={old[n][0]}" for n in missing if old[n][1]]
    by_hand = [n for n in missing if not old[n][1]]
    pver = _version_of(prev) or (0, 0)
    what = (
        f"python3 {ver[0]}.{ver[1]} user site lacks {len(missing)} package(s) of "
        f"{pver[0]}.{pver[1]}"
    )
    if by_hand:
        what += (
            f" ({', '.join(by_hand)}: local/VCS install or several versions — "
            "reinstall by hand)"
        )
    fix = ""
    if pinned:
        fix = (
            'uv pip install --python "$(command -v python3)" --target '
            f'"{cur}" ' + " ".join(pinned)
        )
    return Finding(what, fix, level=level)


def findings() -> list[Finding]:
    """Every toolchain problem right now (cheap: file reads and hashes).
    ``$AGENT_LOGIN_TOOLCHAIN=off`` reports nothing (the test suite: the
    machine's own toolchain must not decide a hermetic test)."""
    if os.environ.get("AGENT_LOGIN_TOOLCHAIN") == "off":
        return []
    out = []
    for check in (vault_touchid_finding, user_site_finding):
        try:
            found = check()
        except (OSError, ValueError, IndexError):
            found = None
        if found is not None:
            out.append(found)
    return out


def describe() -> list[str]:
    """One line per finding (empty: nothing to report)."""
    return [f.line() for f in findings()]


if __name__ == "__main__":  # pragma: no cover - manual check
    for text_line in describe() or ["✅ toolchain: nothing to report"]:
        print(text_line)
    raise SystemExit(0 if not findings() else 1)


__all__ = [
    "Finding",
    "describe",
    "distributions",
    "findings",
    "previous_user_site",
    "stamp_runtime_rows",
    "user_site_finding",
    "vault_touchid_finding",
]
