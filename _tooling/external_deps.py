"""External-dependency registry + resolver (VENDORED — pure standard library).

This file is COPIED into each repo at `_tooling/external_deps.py` (scaffolded by
`new-repo.py` from the canonical copy at `42-Git/templates/external_deps.py`). Do
**NOT** import it from a shared package: vendoring keeps every repo self-contained
and avoids re-creating the cross-repo coupling this module exists to manage. Edit
only the `EXTERNAL_DEPS` registry at the bottom to declare *this* repo's external
dependencies.

Convention & rationale: `42-Git/README_INTERDEPENDENCIES.md`.

Contract (kept stable so the staleness audit can compare HELPER_VERSION):
  - `resolve(dep) -> str | None`      — find a path; never raises (degrade/fallback).
  - `require(dep, needed_for=...) -> str` — resolve or raise MissingExternalDependency.
  - `MissingExternalDependency`       — caught at the CLI boundary → message + exit 3.
  - `exit_on_missing(exc)`            — the standard boundary handler.
  - `is_noninteractive()`            — True in CI / no-TTY (interactive deps fail fast).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

# Bump when the engine (not a repo's registry) changes; the audit flags stale copies.
HELPER_VERSION = "2"

# Vendored into each repo at `_tooling/external_deps.py`, so the repo root — used
# for sibling resolution — is the parent of the `_tooling/` dir this file lives in.
REPO_ROOT = Path(__file__).resolve().parent.parent


class MissingExternalDependency(Exception):
    """A dependency a chosen feature genuinely needs could not be resolved.

    Raised by `require()`, caught at the CLI boundary (`exit_on_missing`) which
    prints a standardized, actionable message and exits with code 3 — distinct
    from ordinary errors so callers / CI can tell "unmet dependency" apart.
    """

    EXIT_CODE = 3

    def __init__(self, dep: "Dep", needed_for: str, detail: str = "") -> None:
        self.dep = dep
        self.needed_for = needed_for
        self.detail = detail
        super().__init__(self.message())

    def message(self) -> str:
        out = [
            f"❌ Missing dependency '{self.dep.name}' — needed for: {self.needed_for}."
        ]
        if self.detail:
            out.append(f"   {self.detail}")
        if self.dep.env:
            out.append(
                f"   Fix: set {self.dep.env}=<path> in .env (see .env.example), or —"
            )
        out.append(f"   {self.dep.install_hint}")
        return "\n".join(out)


@dataclass(frozen=True)
class Dep:
    """One external dependency. `name`/`install_hint` are required; the rest tune
    how it is resolved and probed.

    Resolution order (see `resolve`): env override → $PATH → conventional sibling.
    """

    name: str  # logical id, e.g. "browser.py"
    install_hint: str  # how to obtain it (clone/brew/uv/pip …)
    env: str = (
        ""  # per-user override var, e.g. "BROWSER_PY_BIN" / "..._ROOT" / "..._PATH"
    )
    command: str = ""  # $PATH command to resolve (executables)
    siblings: tuple[str, ...] = ()  # candidate paths relative to REPO_ROOT
    interactive: bool = False  # needs TTY/GUI/Touch-ID → forbidden in CI / no-TTY
    requires_subcommand: str = (
        ""  # in-house capability probe: must appear in `<dep> -h`
    )


def is_noninteractive() -> bool:
    """True in CI or without a controlling TTY. Interactive deps must fail fast
    here (never hang waiting for a human, a browser, or Touch ID)."""
    if os.environ.get("CI"):
        return True
    try:
        return not sys.stdin.isatty()
    except (ValueError, OSError):
        return True


def resolve(dep: "Dep") -> str | None:
    """Resolve `dep` to a filesystem path, or None. NEVER raises — use this for
    `degrades` / `preferred_with_fallback` deps and branch on the result.

    Chain: (1) explicit env override → (2) $PATH (`shutil.which`) → (3) a
    conventional sibling candidate (per the side-by-side clone layout).
    """
    override = os.environ.get(dep.env) if dep.env else None
    if override:
        p = Path(os.path.expanduser(override))
        return str(p) if p.exists() else None
    if dep.command:
        found = shutil.which(dep.command)
        if found:
            return found
    for rel in dep.siblings:
        cand = (REPO_ROOT / rel).expanduser()
        if cand.exists():
            return str(cand.resolve())
    return None


def _probe_ok(path: str, dep: "Dep") -> bool:
    """Cheap capability probe for in-house deps: the required subcommand must
    appear in `<dep> -h`. Skipped when `requires_subcommand` is empty."""
    if not dep.requires_subcommand:
        return True
    try:
        res = subprocess.run(  # noqa: S603
            [path, "-h"], capture_output=True, text=True, timeout=15, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return dep.requires_subcommand in (res.stdout + res.stderr)


def require(dep: "Dep", *, needed_for: str) -> str:
    """Resolve `dep` or raise `MissingExternalDependency`. Use for deps a feature
    genuinely REQUIRES. Enforces the interactive→CI guard and the capability probe.
    """
    if dep.interactive and is_noninteractive():
        raise MissingExternalDependency(
            dep,
            needed_for,
            detail="needs an interactive terminal/GUI; refusing in CI / no-TTY.",
        )
    path = resolve(dep)
    if not path:
        raise MissingExternalDependency(dep, needed_for)
    if not _probe_ok(path, dep):
        raise MissingExternalDependency(
            dep,
            needed_for,
            detail=(
                f"found at {path}, but it lacks the required "
                f"'{dep.requires_subcommand}' subcommand — likely an outdated version."
            ),
        )
    return path


def exit_on_missing(exc: "MissingExternalDependency") -> None:
    """Standard CLI-boundary handler: print the message and exit 3.

    Usage in `__main__` (or wrap `main()`):
        try:
            main()
        except MissingExternalDependency as exc:
            exit_on_missing(exc)
    """
    print(exc.message(), file=sys.stderr)
    sys.exit(MissingExternalDependency.EXIT_CODE)


# ---------------------------------------------------------------------------
# REPO DEPENDENCY REGISTRY — edit this block per repo. Declare every external
# repo/script and every system executable the code shells out to. Document each
# override var in `.env.example`. Then, at the call site of the feature that
# needs it: `require(EXTERNAL_DEPS["name"], needed_for="--flag")` (hard) or
# `resolve(EXTERNAL_DEPS["name"])` (soft / degrade).
# ---------------------------------------------------------------------------
EXTERNAL_DEPS: dict[str, "Dep"] = {
    # Example — the shared logged-in browser (an in-house, OPTIONAL dependency):
    # "browser.py": Dep(
    #     name="browser.py",
    #     command="browser.py",
    #     env="BROWSER_PY_BIN",
    #     siblings=(
    #         "../shared-browser/bin/browser.py",        # future own-repo layout
    #         "../../private/mydotfiles/bin/browser.py",  # current layout
    #     ),
    #     requires_subcommand="login",
    #     interactive=False,  # auto-login needs no TTY; assisted fallback does
    #     install_hint=(
    #         "Clone shared-browser (or mydotfiles) and put browser.py on $PATH, "
    #         "or set BROWSER_PY_BIN to its absolute path."
    #     ),
    # ),
    # Example — a system executable (REQUIRED for a feature, degrades elsewhere):
    # "age": Dep(
    #     name="age",
    #     command="age",
    #     env="AGE_BIN",
    #     install_hint="Install age: `brew install age` (or see https://age-encryption.org).",
    # ),
}
