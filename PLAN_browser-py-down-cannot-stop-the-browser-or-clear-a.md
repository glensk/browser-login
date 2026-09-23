# PLAN: `browser.py down` deadlocks behind long-lived registered CDP clients (tp#187)

## Session

Resume: `c --resume c86c588e-8427-4d13-a103-0e2eddcc3764`

## Context

Classification: **DEFECT**. `down` cannot do its job while any `register-exec`
client (the Playwright MCP server) is alive, and cannot clear a stale lifecycle
record left behind by a browser that died externally.

**Symptom** (ticket, 2026-09-07): with `browser.py register-exec -t playwright-mcp -- npx @playwright/mcp …`
attached, `browser.py down` fails with `Cannot stop the shared browser:
registered CDP client(s) did not drain within 20s.` After the browser window
was closed by hand, `status` keeps reporting `record says 'running' but there is
no CDP` / `recorded pid … does not validate any more`, and `down` cannot clear it.

**Reproduced 2026-09-23** in an isolated temp `CACHE_DIR` on an unused port
(the live browser was not touched): stale `running` record with a dead pid + one
registration held via `_registry_register` + `REGISTRY_EX_WAIT_S=1` →
`cmd_down` returns 1 with the drain refusal, and the record survives.

**Root cause** (high confidence — code read + reproduction):

1. Every registered client holds the registry gate `LOCK_SH` for its whole
   lifetime (`_registry_register`, `bin/browser.py:1398`); `register-exec`
   keeps its registration exactly as long as CMD runs (`cmd_register_exec`,
   `bin/browser.py:1917`). `cmd_down` (`bin/browser.py:1952`) needs the gate
   `LOCK_EX` (`bin/browser.py:1976`) and refuses after `REGISTRY_EX_WAIT_S=20`
   (`bin/browser.py:1302`, message from `_gate_busy`, `bin/browser.py:1499`).
   A long-lived client never drains, so `down` can never succeed.
2. `down` has no override: its parser is a bare `sub.add_parser("down", …)`
   (`bin/browser.py:300`); only `switch` has `-f/--force`
   (`bin/browser.py:264-270`) — and even that only overrides UNREGISTERED
   clients, not the drain.
3. The only early "nothing to do" exit of `cmd_down` requires `rec is None`
   (`bin/browser.py:1967`). A stale `running` record with no CDP and no root
   pid therefore falls through to the gate acquire, and `_lifecycle_clear`
   (`bin/browser.py:708`) is reachable only after that gate succeeds
   (`bin/browser.py:1993`). With a long-lived client attached the stale record
   is unclearable from the CLI.

Blocked on Albert: **no** (all decisions below are evidence-settled defaults,
recorded with `tp question`).

## Decisions (defaults, overrulable)

- **Stale record, nothing running → clear without the gate.** When there is no
  CDP answer and no root pid for our profile, there is no browser any client
  could lose; waiting for the gate protects nothing. Exception: a FRESH
  transitional record (`starting`/`stopping`/`switching`, age ≤
  `TRANSITION_STALE_S`=120 s, or unparsable age treated as fresh) means another
  process is mid-launch/mid-switch with no CDP yet — leave it and take the normal
  gated path.
- **`down -f/--force`**: first try the gate for a short grace
  (`REGISTRY_UP_WAIT_S`=5 s, so one-shot `open`/`eval` clients can finish), then
  stop the browser WITHOUT the gate, printing on stderr which registered clients
  lose their connection. Registered wrappers are NOT killed — only their CDP
  connection drops (the MCP server reconnects on the next `up`).
- **`--force` never overrides a fresh transitional record** (a live
  `switch`/`up` in flight holds the gate exclusively; flock cannot tell SH from
  EX holders, the record can) — refuse, naming the state.
- **Default `down` stays fail-closed for registered clients** (no silent
  behaviour change for scripts); the refusal text for `down` gains
  `— or re-run with -f/--force to stop anyway`.

## Steps

- [ ] `cmd_down`: add the stale-record early path — `not _is_up(port) and not
      _find_root_pids(port)` and record is absent or not a fresh transitional
      state → `_lifecycle_clear()`, `PID_FILE.unlink(missing_ok=True)`, print
      `Stopped (stale lifecycle record cleared).` (or the existing `Stopped (or
      was not running).` when there was no record), exit 0. Factor the
      "fresh transitional" test into a small helper
      (`_fresh_transition(rec) -> str | None`) reusing `_iso_age_s` +
      `TRANSITIONAL_STATES` + `TRANSITION_STALE_S`.
- [ ] Add `-f/--force` to the `down` subparser (help: stop even while registered
      CDP clients are attached — they lose their connection); wire
      `cmd_down(port, args.force)` in `main` (`bin/browser.py:5055`).
- [ ] `cmd_down(port, force=False)`: with `force`, refuse on a fresh transitional
      record; else `_gate_acquire(LOCK_EX, REGISTRY_UP_WAIT_S)`; on `None`
      print `⚠ --force: stopping without draining — <_describe_client lines>`
      to stderr and run the unchanged stopping/shutdown/clear sequence with
      `gate=None` (release guarded by `if gate is not None`).
- [ ] `_gate_busy(action, hint="")`: append the optional override hint; `down`
      passes the `-f/--force` hint, `switch` keeps its current text.
- [ ] Update the module docstring (`down` line, `bin/browser.py:34`) and the
      `cmd_down` docstring (fail-closed-for-registered + force semantics + stale
      path); README `browser.py down` line (`README.md:78`) and the
      "Consumer contract" section (`README.md:140`) with `down -f`.
- [ ] New `tests/test_down.py` (same import pattern as
      `tests/test_switch_site.py`; monkeypatch `CACHE_DIR`, `PROFILE_DIR`,
      `PID_FILE`, `LIFECYCLE_FILE`, `CLIENTS_DIR`, `REGISTRY_GATE` to `tmp_path`,
      shrink `REGISTRY_EX_WAIT_S`/`REGISTRY_UP_WAIT_S`, stub `_is_up`,
      `_find_root_pids`, `_shutdown_browser`, `_unknown_clients_verdict`; hold a
      registration via `_registry_register`):
      1. stale `running` record + registered client, no CDP/roots → rc 0, record
         and PID file gone, returns without waiting for the gate (<1 s).
      2. fresh `starting` record + no CDP → record NOT cleared by the early path.
      3. dead (age > 120 s) `switching` record + registered client → cleared.
      4. live browser + registered client, no force → rc 1, message contains
         `--force`, `_shutdown_browser` not called, record unchanged.
      5. live browser + registered client, `force=True` → `_shutdown_browser`
         called, record cleared, stderr names the client.
      6. `force=True` + fresh `switching` record → rc 1, nothing shut down.
      7. no record, nothing running → unchanged `Stopped (or was not running).`
- [ ] Lint + tests (Verification below), `bin/browser.py down -h` shows `-f`.
- [ ] Commit via `ai.py push` (subagents never commit); tick boxes; on completion
      `tp tidy` archives this plan.

NOTE (Albert, optional): a live check on the real shared browser — `browser.py
down -f` with a Claude session's Playwright MCP attached — stops a live
browser with real sessions, so it is not part of the automated verification.

## Verification

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login
uv sync
uv run pytest -q tests/
ruff format --check bin/ tests/test_down.py
ruff check bin/ tests/test_down.py
mypy bin/browser.py
uv run pylint bin/browser.py
bin/browser.py down -h | grep -- '-f, --force'
bin/browser.py -h >/dev/null
```
