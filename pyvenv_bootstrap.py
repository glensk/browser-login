# pyvenv_bootstrap v6 — managed copy of mydotfiles/bin/pyvenv_bootstrap.py; edit there, pyvenv.py -S
"""Run a repo's executable Python scripts under the repo's own ``.venv`` — from any
cwd, however the script was started, creating the venv on first use.

This is the ONE bootstrap every dependency root in ``42-Git`` carries as a
byte-identical managed copy (``pyvenv.py -k`` checks, ``pyvenv.py -S`` syncs).
It replaced the per-script ``ensure_deps()`` template in 2026-09 (tp#265).

Usage — inside ``main()``, AFTER ``parse_args()`` so ``-h`` needs no venv::

    def main() -> None:
        args = parse_args()
        from pyvenv_bootstrap import ensure_venv  # pylint: disable=import-outside-toplevel

        ensure_venv(__file__, requires=("requests", "dotenv"))

A script below the dependency root inserts the root first::

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from pyvenv_bootstrap import ensure_venv  # pylint: disable=import-outside-toplevel

The import is deliberately lazy: importing the SCRIPT as a module (tests,
sdsc-automations' import-by-path of ``zoho-api.py``) never executes it, so a
foreign interpreter never needs this file on its path.

Dependency root
---------------
The directory holding this copy (``REPO_ROOT``), or ``root=`` when a script
names another. It owns ``.venv`` and ONE dependency source, chosen in this order:

* **project mode** — ``pyproject.toml`` with a ``[project]`` table AND a
  ``uv.lock`` that lists packages → ``uv sync --frozen``. A tool-only pyproject
  (ruff/mypy config, no ``[project]``) or an empty lock is NOT project mode:
  ``uv sync`` there yields an empty venv (runai, 2026-09). Needs ``uv``.
* **requirements mode** — ``requirements.lock`` (``uv pip compile --universal``,
  policy: enabled unattended callers only) else ``requirements.txt`` →
  ``uv venv`` + ``uv pip install -r``; without ``uv``: a PATH interpreter that
  satisfies ``python_min`` + ``python -m venv`` + ``pip install -r``.

State table (each state → exactly one action)
---------------------------------------------
usable        python_min holds and every ``requires`` name really imports
              (``importlib.import_module``, in-process — what the old
              try-import did; ``find_spec`` misses broken packages) → return.
              ``force_repo_venv=True`` skips this state.
in the venv   ``sys.prefix`` IS ``<root>/.venv`` (the interpreter path cannot
              tell uv venvs apart — they share one base interpreter):
              stamp current and usable → return; stamp stale → repair
              (install again) → return; not usable after a re-exec → fail
              (a broken venv, never an exec loop).
venv absent   create → install → probe → exec (``allow_create=False`` →
              ``VenvMissing`` instead of any uv/pip call).
venv present  probe (real imports + version, in a subprocess) fails, or the
              stamp is stale → ONE repair install → probe → exec; still failing
              → fail with the repair command. Under ``allow_create=False`` a
              venv that probes fine with a stale/missing stamp is selected
              as is (inside it: accepted), the stamp left for the next run
              that may install (tp#430) — ``-h`` never fails on a stamp.
entry         the exec restarts ``sys.modules["__main__"]``, never the caller:
              ``-m pkg.mod`` → ``-m pkg.mod``, a script → its absolute path, a
              dir/zipapp → ``argv[0]``; ``-c``/REPL (no entry) → fail, or
              ``VenvMissing`` under ``allow_create=False`` — before any install.
sentinel      ``PYVENV_BOOTSTRAPPED=<root>`` is set by the exec. It is trusted
              ONLY when the process is in the venv; a child started with a bare
              interpreter inherits it, so outside the venv it is cleared and the
              normal path runs.

Constraints — do not break these
--------------------------------
* stdlib only, Python 3.9 syntax (runs before any dependency exists, on the
  NixOS/HA interpreters too); no ``extdeps`` here.
* never ``os.chdir()`` — scripts resolve relative paths against the caller's cwd.
* at most one exec per process (the sentinel), argv[0] absolutised first.
* the exec target is ``__main__``, never ``script_file``: a library calling
  ``ensure_venv(__file__)`` at import time restarts its importer (tp#301).
* creation/repair happens under an ``fcntl.flock`` (``~/.cache/pyvenv/locks/``) with an
  ``.venv/.pyvenv-incomplete`` marker, so two unattended jobs starting on a
  fresh clone cannot corrupt one another's install; a marked venv is rebuilt.
* the dependency input's sha256 is stamped into ``.venv/.pyvenv-input-sha256``;
  a changed requirements/lock re-installs into the EXISTING venv.
* ``PYVENV_DEBUG=1`` prints one ``pyvenv: <decision>`` line per decision on
  stderr (``usable``, ``exec …``, ``create …``, ``repair …``, ``stale-stamp``).
"""

from __future__ import annotations

import fcntl
import hashlib
import importlib
import os
import re
import shutil
import subprocess
import sys
import time
from typing import Any, NoReturn, TextIO

VERSION = 7

_SENTINEL_ENV = "PYVENV_BOOTSTRAPPED"
_STAMP = ".pyvenv-input-sha256"
_INCOMPLETE = ".pyvenv-incomplete"
_LOCK_DIR = os.path.join(
    os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache"),
    "pyvenv",
    "locks",
)
_LOCK_TIMEOUT_S = 900
_LOCK_NOTE_EVERY_S = 30

# The directory holding this copy == the default dependency root.
REPO_ROOT = os.path.dirname(os.path.abspath(__file__))


class VenvMissing(RuntimeError):
    """The venv is absent/unusable and ``allow_create=False`` forbade a fix.

    Raised ONLY on that path, for callers with a machine-readable stdout
    contract that must answer ``reason=deps`` instead of silently spending
    minutes in uv/pip. The message is the reason, ready to forward.
    """


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def _debug(message: str) -> None:
    if os.environ.get("PYVENV_DEBUG"):
        sys.stderr.write(f"pyvenv: {message}\n")


def _fail(message: str) -> NoReturn:
    """Abort with one actionable line on stderr — never a traceback."""
    sys.stderr.write(f"ERROR: pyvenv: {message}\n")
    raise SystemExit(1)


def _venv_dir(root: str) -> str:
    return os.path.join(root, ".venv")


def _venv_python(root: str) -> str:
    return os.path.join(_venv_dir(root), "bin", "python3")


def _same_path(a: str, b: str) -> bool:
    return os.path.realpath(a) == os.path.realpath(b)


def _version_ok(
    python_min: tuple[int, int] | None, info: tuple[int, ...] | None = None
) -> bool:
    if python_min is None:
        return True
    current = sys.version_info[:2] if info is None else (info[0], info[1])
    return current >= (python_min[0], python_min[1])


def _imports_ok(requires: tuple[str, ...]) -> bool:
    """Every name really imports in THIS interpreter (side effects included —
    that is the point: a package whose spec exists but whose import raises is
    not usable)."""
    importlib.invalidate_caches()
    for name in requires:
        try:
            importlib.import_module(name)
        except Exception:  # noqa: BLE001  # pylint: disable=broad-exception-caught
            return False
    return True


def _usable(requires: tuple[str, ...], python_min: tuple[int, int] | None) -> bool:
    return _version_ok(python_min) and _imports_ok(requires)


def _run(argv: list[str], **kwargs: Any) -> bool:
    """Run ``argv`` quietly; True on exit 0, False on failure or a missing binary."""
    try:
        return (
            subprocess.call(
                argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kwargs
            )
            == 0
        )
    except OSError:
        return False


def _probe_venv(
    venv_python: str, requires: tuple[str, ...], python_min: tuple[int, int] | None
) -> bool:
    """True when ``venv_python`` runs, satisfies ``python_min`` and imports
    every ``requires`` name — real imports in a short subprocess."""
    if not os.path.exists(venv_python):
        return False
    floor = list(python_min) if python_min else [0, 0]
    code = (
        "import importlib,sys\n"
        f"sys.exit(3) if tuple(sys.version_info[:2]) < tuple({floor!r}) else None\n"
        f"[importlib.import_module(m) for m in {list(requires)!r}]\n"
    )
    return _run([venv_python, "-c", code])


# --------------------------------------------------------------------------- #
# Dependency input (what gets installed) and its stamp
# --------------------------------------------------------------------------- #
def _dep_input(root: str) -> tuple[str, list[str]]:
    """``(mode, files)``: ``("project", [pyproject, uv.lock])`` when the
    pyproject has a ``[project]`` table and the lock lists packages,
    ``("requirements", [requirements.lock | requirements.txt])`` otherwise,
    ``("none", [])`` when the root declares nothing."""
    pyproject = os.path.join(root, "pyproject.toml")
    lock = os.path.join(root, "uv.lock")
    if os.path.isfile(pyproject) and os.path.isfile(lock):
        try:
            with open(pyproject, encoding="utf-8") as fh:
                has_project = re.search(r"(?m)^\[project\]\s*$", fh.read()) is not None
            with open(lock, encoding="utf-8") as fh:
                has_packages = "[[package]]" in fh.read()
        except OSError:
            has_project = has_packages = False
        if has_project and has_packages:
            return "project", [pyproject, lock]
    for name in ("requirements.lock", "requirements.txt"):
        path = os.path.join(root, name)
        if os.path.isfile(path):
            return "requirements", [path]
    return "none", []


def _input_digest(files: list[str]) -> str:
    digest = hashlib.sha256()
    for path in files:
        digest.update(os.path.basename(path).encode())
        try:
            with open(path, "rb") as fh:
                digest.update(fh.read())
        except OSError:
            digest.update(b"<unreadable>")
    return digest.hexdigest()


def _read_stamp(root: str) -> str:
    try:
        with open(os.path.join(_venv_dir(root), _STAMP), encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def _write_stamp(root: str, digest: str) -> None:
    try:
        with open(os.path.join(_venv_dir(root), _STAMP), "w", encoding="utf-8") as fh:
            fh.write(digest + "\n")
    except OSError:
        pass  # a missing stamp only costs one extra install later


def _incomplete(root: str) -> bool:
    """An install was started in this venv and never finished (crash, kill)."""
    return os.path.exists(os.path.join(_venv_dir(root), _INCOMPLETE))


def _venv_ready(
    root: str, requires: tuple[str, ...], python_min: tuple[int, int] | None
) -> bool:
    """The venv can be exec'd into as is: complete, current, and it imports."""
    return (
        not _incomplete(root)
        and _stamp_current(root)
        and _probe_venv(_venv_python(root), requires, python_min)
    )


def _stamp_current(root: str) -> bool:
    _mode, files = _dep_input(root)
    if not files:
        return True
    return _read_stamp(root) == _input_digest(files)


# --------------------------------------------------------------------------- #
# Creation / repair (always under the root lock)
# --------------------------------------------------------------------------- #
def _find_python(python_min: tuple[int, int] | None) -> str | None:
    """An interpreter for ``python -m venv`` (the no-uv path): this one when it
    satisfies the floor, else the newest ``python3.Y`` on PATH that does."""
    if _version_ok(python_min):
        return sys.executable
    floor_minor = python_min[1] if python_min else 0
    for minor in range(20, floor_minor - 1, -1):
        found = shutil.which(f"python3.{minor}")
        if found:
            return found
    return None


def _lock_path(root: str) -> str:
    """Per-root lock file OUTSIDE the repo (no untracked file to gitignore):
    ``~/.cache/pyvenv/locks/<sha256 of the root path>.lock``."""
    digest = hashlib.sha256(os.path.realpath(root).encode()).hexdigest()[:32]
    try:
        os.makedirs(_LOCK_DIR, exist_ok=True)
        return os.path.join(_LOCK_DIR, digest + ".lock")
    except OSError:
        import tempfile  # pylint: disable=import-outside-toplevel

        return os.path.join(tempfile.gettempdir(), f"pyvenv-{digest}.lock")


class _RootLock:
    """``fcntl.flock`` on the root's lock file with a bounded wait."""

    def __init__(self, root: str) -> None:
        self.path = _lock_path(root)
        self.fh: TextIO | None = None

    def __enter__(self) -> _RootLock:
        self.fh = open(self.path, "a", encoding="utf-8")  # noqa: SIM115  # pylint: disable=consider-using-with
        deadline = time.monotonic() + _LOCK_TIMEOUT_S
        last_note = time.monotonic()
        fh = self.fh
        while True:
            try:
                fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except OSError:
                now = time.monotonic()
                if now >= deadline:
                    _fail(f"gave up waiting {_LOCK_TIMEOUT_S}s for {self.path}")
                if now - last_note >= _LOCK_NOTE_EVERY_S:
                    sys.stderr.write(
                        f"pyvenv: waiting for another process to finish {self.path}\n"
                    )
                    last_note = now
                time.sleep(0.5)

    def __exit__(self, *_exc: object) -> None:
        if self.fh is not None:
            try:
                fcntl.flock(self.fh, fcntl.LOCK_UN)
            finally:
                self.fh.close()


def _install(
    root: str, mode: str, files: list[str], uv: str | None, venv_python: str
) -> bool:
    if mode == "project":
        if uv is None:
            _fail(
                f"{root} is a uv project ([project] + uv.lock) but `uv` is not on PATH; "
                "install uv or export requirements: uv export --format requirements-txt "
                "> requirements.txt"
            )
        return _run([uv, "sync", "--frozen", "--project", root]) if uv else False
    if mode == "requirements":
        if uv is not None:
            return _run([uv, "pip", "install", "--python", venv_python, "-r", files[0]])
        return _run([venv_python, "-m", "pip", "install", "-r", files[0]])
    return True  # nothing declared, nothing to install


def _make_venv(
    venv_dir: str, venv_python: str, python_min: tuple[int, int] | None, uv: str | None
) -> None:
    """Create the bare venv directory (no packages yet) with uv or python -m venv."""
    _debug(f"create {venv_dir}")
    if uv is not None:
        argv: list[str] = [uv, "venv", venv_dir]
        if python_min:
            argv += ["--python", f">={python_min[0]}.{python_min[1]}"]
        created = _run(argv) and os.path.exists(venv_python)
    else:
        base = _find_python(python_min)
        if base is None:
            floor = f"{python_min[0]}.{python_min[1]}" if python_min else "3"
            _fail(
                f"no interpreter >= {floor} found and `uv` is not on PATH; install uv "
                f"(https://docs.astral.sh/uv/) or a python{floor}"
            )
        created = _run([base, "-m", "venv", venv_dir]) and os.path.exists(venv_python)
    if not created:
        _fail(
            f"could not create {venv_dir} (tried {'uv venv' if uv else 'python -m venv'})"
        )


def _create_or_repair(
    root: str,
    requires: tuple[str, ...],
    python_min: tuple[int, int] | None,
    *,
    reason: str,
) -> str:
    """Create ``<root>/.venv`` or re-install into it; return its interpreter.

    Serialised per root; re-checks the state after acquiring the lock, so the
    second of two concurrent cold starts finds the venv the first one built.
    """
    venv_dir = _venv_dir(root)
    venv_python = _venv_python(root)
    mode, files = _dep_input(root)
    if requires and mode == "none":
        _fail(
            f"{root} declares no dependencies (no requirements.txt/.lock, no [project] + "
            f"uv.lock) but the script requires {', '.join(requires)}"
        )
    uv = shutil.which("uv")
    with _RootLock(root):
        # Another process may have finished the job while we waited.
        if reason != "repair" and _venv_ready(root, requires, python_min):
            return venv_python
        incomplete = os.path.join(venv_dir, _INCOMPLETE)
        if os.path.exists(incomplete) or (
            os.path.isdir(venv_dir) and not os.path.exists(venv_python)
        ):
            _debug(f"rebuild {venv_dir} (incomplete)")
            shutil.rmtree(venv_dir, ignore_errors=True)
        if os.path.exists(venv_python) and not _probe_venv(venv_python, (), python_min):
            _debug(f"rebuild {venv_dir} (interpreter below the floor)")
            shutil.rmtree(venv_dir, ignore_errors=True)
        if not os.path.exists(venv_python):
            _make_venv(venv_dir, venv_python, python_min, uv)
        else:
            _debug(f"repair {venv_dir}")
        try:
            with open(incomplete, "w", encoding="utf-8") as fh:
                fh.write(reason + "\n")
        except OSError:
            pass
        if not _install(root, mode, files, uv, venv_python):
            _fail(
                f"installing into {venv_dir} failed; run by hand: "
                + (
                    f"uv sync --frozen --project {root}"
                    if mode == "project"
                    else f"uv pip install --python {venv_python} -r {files[0]}"
                    if files
                    else "(nothing declared)"
                )
            )
        if not _probe_venv(venv_python, requires, python_min):
            _fail(
                f"{venv_dir} exists but cannot import {', '.join(requires) or '(nothing)'}"
                + (
                    f" under python >= {python_min[0]}.{python_min[1]}"
                    if python_min
                    else ""
                )
                + f"; inspect {files[0] if files else root}"
            )
        _write_stamp(root, _input_digest(files) if files else "")
        try:
            os.remove(incomplete)
        except OSError:
            pass
    return venv_python


def _settle_in_venv(
    root: str,
    requires: tuple[str, ...],
    python_min: tuple[int, int] | None,
    after_exec: bool,
    allow_create: bool,
) -> None:
    """The process already runs under ``<root>/.venv``: return when it is
    usable and current, repair it when it is stale, fail (never loop) when it
    is broken right after the re-exec."""
    venv_dir = _venv_dir(root)
    if _stamp_current(root) and not _incomplete(root):
        if _usable(requires, python_min):
            _debug("usable (in the venv)")
            return
        if after_exec:
            message = (
                f"{venv_dir} cannot import {', '.join(requires)} after the re-exec; "
                f"repair it: uv pip install --python {_venv_python(root)} -r "
                f"{root}/requirements.txt"
            )
            if not allow_create:
                raise VenvMissing(message)
            _fail(message)
        _debug("repair (in the venv)")
    else:
        _debug("incomplete" if _incomplete(root) else "stale-stamp")
        if not allow_create and not _incomplete(root) and _usable(requires, python_min):
            # Selection, not repair (tp#430): the stamp stays stale, so the next
            # run that may install re-syncs the venv and writes it.
            _debug("usable (in the venv, stale stamp kept: repair not allowed)")
            return
    if not allow_create:
        raise VenvMissing(
            f"{venv_dir} is stale or incomplete and repairing it is not allowed here"
        )
    _create_or_repair(root, requires, python_min, reason="repair")
    importlib.invalidate_caches()
    if not _usable(requires, python_min):
        _fail(f"{venv_dir} still cannot import {', '.join(requires)} after repair")


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def _entry_argv() -> list[str] | None:
    """The interpreter arguments that restart THIS process's ``__main__``.

    The exec target is the program being run, never the module that happens to
    call ``ensure_venv`` — a library bootstrapping at import time would
    otherwise re-exec itself with the importer's argv (tp#301).

    ``python -m pkg.mod`` → ``["-m", "pkg.mod"]``; a directory/zipapp run →
    ``[abspath(argv[0])]``; a plain script → ``[abspath(__main__.__file__)]``;
    ``-c``, the REPL or an embedded interpreter → ``None`` (nothing to re-exec).
    """
    main = sys.modules.get("__main__")
    if main is None:
        return None
    spec = getattr(main, "__spec__", None)
    if spec is not None:
        if spec.name != "__main__":
            return ["-m", spec.name]
        if sys.argv and sys.argv[0]:
            return [os.path.abspath(sys.argv[0])]
        return None
    main_file = getattr(main, "__file__", None)
    if isinstance(main_file, str) and main_file:
        return [os.path.abspath(main_file)]
    return None


def _exec_entry(
    venv_python: str, entry: list[str], root: str, script_file: str
) -> NoReturn:
    """Replace this process with ``venv_python`` restarting ``entry``."""
    os.environ[_SENTINEL_ENV] = root
    if entry[0] != "-m":
        if sys.argv:
            sys.argv[0] = entry[0]  # a relative argv[0] would not survive the exec
        if not _same_path(entry[0], script_file):
            _debug(f"exec {venv_python} (entry {entry[0]}; called from {script_file})")
        else:
            _debug(f"exec {venv_python}")
    else:
        _debug(f"exec {venv_python} (entry -m {entry[1]}; called from {script_file})")
    try:
        os.execv(venv_python, [venv_python] + entry + sys.argv[1:])
    except OSError as exc:
        _fail(f"could not re-exec {' '.join(entry)} under {venv_python}: {exc}")


# Stable public API of 40+ managed copies; all options are keyword-only.
def ensure_venv(  # pylint: disable=too-many-arguments
    script_file: str,
    *,
    requires: tuple[str, ...],
    python_min: tuple[int, int] | None = None,
    root: str | None = None,
    force_repo_venv: bool = False,
    allow_create: bool = True,
) -> None:
    """Make sure the script runs under a usable interpreter; re-exec if not.

    Args:
        script_file: the caller's ``__file__`` — a hint for the debug line only.
            The re-exec restarts ``__main__`` (see ``_entry_argv``), so a library
            that bootstraps at import time restarts its importer, not itself.
        requires: module names that must import for the interpreter to count as
            usable. REQUIRED — ``()`` means "no third-party modules, this
            interpreter is fine" (a bare call is a TypeError on purpose).
        python_min: ``(3, 10)``-style floor, part of the usability test for the
            current AND the venv interpreter; passed to ``uv venv --python``.
        root: the dependency root (owns ``.venv`` + the dependency source);
            default = the directory of this copy.
        force_repo_venv: run under ``<root>/.venv`` even when the current
            interpreter would do.
        allow_create: False → never create/install; raise ``VenvMissing``
            instead (selection into an already-working venv is still allowed).
    """
    if not isinstance(requires, tuple):
        raise TypeError("requires must be a tuple of module names, e.g. ('requests',)")
    root = os.path.abspath(root or REPO_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)  # root packages import from any cwd

    venv_python = _venv_python(root)
    in_venv = _same_path(sys.prefix, _venv_dir(root))

    sentinel = os.environ.get(_SENTINEL_ENV)
    if sentinel == root and not in_venv:
        # Inherited by a child started with a bare interpreter — not ours.
        del os.environ[_SENTINEL_ENV]
        sentinel = None

    if in_venv:
        _settle_in_venv(root, requires, python_min, sentinel == root, allow_create)
        return

    if not force_repo_venv and _usable(requires, python_min):
        _debug("usable")
        return

    entry = _entry_argv()
    if entry is None:
        message = (
            f"cannot re-exec a -c/interactive entry under {venv_python}; run a "
            f"script file, or install {', '.join(requires)} into {sys.executable}"
        )
        if not allow_create:
            raise VenvMissing(message)
        _fail(message)

    if not _venv_ready(root, requires, python_min):
        if allow_create:
            reason = "repair" if os.path.exists(venv_python) else "create"
            venv_python = _create_or_repair(root, requires, python_min, reason=reason)
        elif not _incomplete(root) and _probe_venv(venv_python, requires, python_min):
            # A stale or missing stamp (a fresh clone, a lock change, a venv made
            # by `uv sync`) is not a missing venv: select it and keep the stamp
            # stale, so the next run that may install re-syncs it (tp#430).
            _debug("stale-stamp (selected: repair not allowed)")
        else:
            raise VenvMissing(
                f"{_venv_dir(root)} is missing or cannot import {', '.join(requires)} "
                "and creating/repairing it is not allowed here"
            )

    _exec_entry(venv_python, entry, root, script_file)


if __name__ == "__main__":
    # Diagnostics only; the module is normally imported, never run.
    _mode, _files = _dep_input(REPO_ROOT)
    print(f"pyvenv_bootstrap v{VERSION}")
    print(f"dependency root: {REPO_ROOT}")
    print(
        f"venv python:     {_venv_python(REPO_ROOT)} "
        f"({'present' if os.path.exists(_venv_python(REPO_ROOT)) else 'absent'})"
    )
    print(f"this python:     {sys.executable} ({sys.version.split()[0]})")
    _is_root_venv = _same_path(sys.prefix, _venv_dir(REPO_ROOT))
    print(
        f"sys.prefix:      {sys.prefix} ({'IS' if _is_root_venv else 'not'} the root venv)"
    )
    print(f"dependency mode: {_mode} {_files}")
    print(f"stamp current:   {_stamp_current(REPO_ROOT)}")
    print(f"uv:              {shutil.which('uv') or 'not on PATH'}")
