# AGENTS.md

Conventions for AI coding agents (and humans) working in this repo.

## What this is

<one-line purpose of browser-login — TODO>

## Environment

- Python projects use **`uv`** (preferred over Homebrew/system installs):
  `uv sync` to install, `uv run <cmd>` to run, `uv tool install <tool>` for CLIs.
  Prefer pip/uv-installable packages (including wheels that bundle native libs)
  over `brew install`; fall back to a system package manager only when no wheel
  exists.
- Secrets live in `.env` (never commit). See `.env.example`.

## Build / test / lint

- Python: `ruff format . && ruff check . && mypy . && pylint <files>`
- Shell: `shellcheck <files>`
- Pre-commit: `pre-commit run --all-files` (gitleaks secret scan)

## Conventions

- Every script supports `-h/--help`.
- Keep external services / LLM providers pluggable; selection is config, not code.
- Declare every external repo/script or system executable in `_tooling/external_deps.py`
  (`EXTERNAL_DEPS`); resolve via `require()` / `resolve()`. Never use a bare
  `shutil.which` or a hard-coded sibling path. Optional deps stay opt-in (the rest of
  the tool works without them); a missing one a chosen feature needs exits 3. See
  `~/obsidian/42-Git/README_INTERDEPENDENCIES.md`.

## Where things live

- Design / roadmap: PLAN.md (if present)
- Private/local notes: CLAUDE.local.md (gitignored); CLAUDE.md is a gitignored
  shim that imports this file.
