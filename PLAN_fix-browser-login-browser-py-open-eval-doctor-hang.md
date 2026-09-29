# fix(browser-login): browser.py open / eval / doctor hang while status works (tp#693)

## Session

Resume: `c --resume e1ce9120-0ef0-4a6d-922c-85cf4dd84e23`

## Context

**Classification: DEFECT** — reproduced 2026-09-29 against the live shared Chromium (read-only).

**Symptom.** `browser.py open <url>`, `eval` and `doctor` block forever while `status` answers in
0.4 s. Found by the nixos deploy agent, which fell back to raw CDP.

**Evidence (reproduction, 2026-09-29).**

- `browser.py status` → 7 tabs, answers in 0.4 s. It only uses the CDP HTTP endpoints
  (`/json/version`, `/json/list` via `_cdp_get`, `bin/browser.py:474`), which the browser process
  serves itself.
- `PYTHONFAULTHANDLER=1 timeout -s ABRT 45 bin/browser.py eval '1+1' --url 192.168.178.156` hung
  for the full 45 s inside Playwright's event loop.
- `DEBUG=pw:protocol` run: 171 CDP commands sent, 161 answered. All 10 unanswered commands belong to
  ONE page session: `Page.enable`, `Page.getFrameTree`, `Runtime.enable`, … up to
  `Runtime.runIfWaitingForDebugger`. That session belongs to the tab `Sign in ・ Cloudflare Access`
  (`https://albertha.cloudflareaccess.com`, target `EEE09E93…`). Every other page, iframe, worker
  and service worker answered.
- A raw websocket probe on that target's `webSocketDebuggerUrl`: `Runtime.evaluate 1+1`,
  `Page.getFrameTree` and `Page.enable` each timed out after 5 s. The only thing the target emitted
  was `Page.frameStartedNavigating`, so the renderer is stuck mid-navigation and answers no CDP
  commands at all.
- A standalone Playwright 1.62.0 script: `connect_over_cdp("http://127.0.0.1:9222")` with no timeout
  was still blocked after 50 s. With `timeout=5000` it raised `TimeoutError: … Timeout 5000ms
  exceeded` after 5.5 s. In practice, then, the unset `timeout` does not bound the page-attach phase.

**Root cause (confidence: high).** `_connect` (`bin/browser.py:2124`) calls
`pw.chromium.connect_over_cdp(...)` without a `timeout`. Playwright attaches to every existing page
target and waits until each one answers its initialisation commands. A single tab whose renderer
does not answer CDP therefore blocks `connect_over_cdp` forever. Every `_connect` caller hangs (19
call sites: `open` `bin/browser.py:2273`, `eval` `:2300`, `doctor` via `_doctor_open_probe` `:2836`
and `_doctor_probe` `:2890`, `token`, every `login`/`logged-in` flow). So does the private
`connect_over_cdp` in `_cdp_browser_close` (`:997`), which `down`/`switch` use for a graceful quit.
`status` escapes because it never uses Playwright. What wedged that renderer is Chrome-internal and
outside this repo; any tab can get into this state, and browser.py has to survive it.

**Secondary unbounded wait, same class (not observed, found while reading).** `cmd_eval` runs
`page.evaluate` (`bin/browser.py:2372`), and Playwright's `evaluate` has no timeout. An expression
that returns a promise that never settles hangs `eval` in the same way, even after a successful
connect.

**Constraints.**

- The shared browser is live infrastructure with Albert's real sessions. The fix must NEVER close,
  reload or navigate a real tab automatically. It detects and reports the problem. Removing a hung
  tab is an explicit, separate action.
- Output about tabs stays origin-only, through `_tab_hint`/`_tab_title` (AGENTS.md; tp#337, tp#365).
- The CDP endpoint is always `127.0.0.1`, never `localhost`.
- `bin/browser.py` is executed live by consumers. The WORK session edits it in a git worktree, never
  in place (AGENTS.md; memory "worktree isolation").
- Tests must not touch the real browser on :9222. They use a fake CDP server on an ephemeral port.
- Every new flag has a short and a long form; `-h` exits 0.

**Settled defaults** (recorded with `tp question -d`; Albert can overrule them):

1. Connect bound: `timeout=` on every `connect_over_cdp`. Default 30 s, overridable with the env var
   `CLAUDE_BROWSER_CONNECT_TIMEOUT_S`, documented in `.env.example`.
2. The per-target probe uses the `websockets` package. It goes into the self-bootstrapped venv deps
   (`ensure_deps`, which self-heals a missing dep) and into `pyproject.toml`. Alternative rejected:
   a hand-rolled stdlib RFC 6455 client (more code to own for a diagnostic path).
3. Remediation is an explicit `close-hung` subcommand. It closes only targets that fail two
   consecutive probes, through the browser-level `Target.closeTarget`. It asks for confirmation
   unless `-y/--yes` is given, and it holds the interaction lease. Never automatic.
4. `eval` gains `-t/--timeout SECONDS` (default 30). The expression is wrapped in `Promise.race`
   with a rejecting timer, so a never-settling promise fails with a clear message.

**Blocked on Albert:** no.

**Why the Verification block is not strict-eligible:** it runs `uv run pytest`, `mypy` and
`uv run pylint` beyond the allowlisted read-only checks. The fix changes runtime behaviour that
only the tests exercise (the hang comes from a fake CDP server with an unresponsive target).

## Steps

- [ ] 1. Work in a git worktree of `home/browser-login` (never edit the live `bin/browser.py` in
  place). Add a module constant `CONNECT_TIMEOUT_S` (env `CLAUDE_BROWSER_CONNECT_TIMEOUT_S`,
  default 30, invalid or non-positive values fall back to 30) next to `DEFAULT_CDP_PORT`
  (`bin/browser.py:109`), and document it in `.env.example` under "shared browser".
- [ ] 2. `_connect` (`bin/browser.py:2101`): pass `timeout=CONNECT_TIMEOUT_S * 1000` to
  `connect_over_cdp`. On Playwright `TimeoutError`, stop Playwright cleanly, run the per-target
  probe from step 3 and exit non-zero with a `❌` message. The message names each unresponsive tab
  by `_tab_title` + `_tab_hint` origin and short target id, and gives the remedy (`browser.py
  close-hung`, or reload/close that tab by hand). With no unresponsive target found, it says that
  the connect timed out and prints the plain timeout. Same bound in `_cdp_browser_close`
  (`bin/browser.py:997`), where a timeout counts as "not sent" so `down` falls through to its
  existing signal path.
- [ ] 3. New helper `_unresponsive_targets(port, probe_timeout_s=5.0) -> list[dict]`: for every
  `type == "page"` target from `/json/list`, open its `webSocketDebuggerUrl` with
  `websockets.sync.client.connect` (`open_timeout` bounded) and send `Runtime.evaluate
  {"expression": "1"}`. A target that gives no reply within `probe_timeout_s` counts as
  unresponsive. Probes run concurrently (a thread pool), so N tabs cost about one probe timeout.
  Read-only: nothing but `Runtime.evaluate("1")` is sent. Add `websockets` to `ensure_deps` (import
  check + `deps` list + the two "creating venv" messages) and to `pyproject.toml`
  `dependencies`, then `uv lock`.
- [ ] 4. `status`: new flag `-p/--probe` that appends `⚠ unresponsive` to each tab line of a tab
  the probe from step 3 flags. Without the flag, output is unchanged (it stays fast and
  HTTP-only).
- [ ] 5. New subcommand `close-hung` with flag `-y/--yes`. Under the interaction lease: probe, and
  re-probe every flagged target once more. Only targets that fail BOTH probes are listed
  (origin-only). After confirmation (or with `-y`), each one is closed with `Target.closeTarget`
  over the browser-level websocket (`/json/version` → `webSocketDebuggerUrl`), which works even
  when the renderer is hung. Prints what it closed. Exit 0 when nothing is hung or everything was
  closed, 1 otherwise. Never touches a responsive tab.
- [ ] 6. `doctor`: before `_doctor_probe`, add a check `tab responsiveness`: ✅ when every page
  target answers, ❌ naming the hung tab(s) and the `close-hung` remedy otherwise, and skip the
  Playwright probe (it would only time out). The bounded `_connect` from step 2 still covers any
  other path.
- [ ] 7. `eval`: add `-t/--timeout SECONDS` (default 30). Evaluate
  `() => Promise.race([Promise.resolve((<js>)), new Promise((_, rej) => setTimeout(() => rej(new
  Error("browser.py eval: timed out after Ns")), N*1000))])`. On that error: print `❌ eval timed
  out after Ns` and exit 1. Synchronous expressions behave exactly as before.
- [ ] 8. Tests `tests/test_connect_hang.py`, with no real browser. A fake CDP server on an
  ephemeral `127.0.0.1` port (stdlib `http.server` for `/json/list` + `/json/version`, and a
  `websockets` server for the target and browser sockets). One target answers `Runtime.evaluate`,
  one never answers. Assert that:
  - `_unresponsive_targets` returns exactly the silent one within ~probe timeout + slack;
  - the `_connect` timeout path (Playwright monkeypatched to raise `TimeoutError`) exits non-zero
    within the bound, and its message has the origin but no path/query of the hung tab's URL;
  - `close-hung -y` sends `Target.closeTarget` only for the silent target;
  - `status -p` marks only the silent tab;
  - the `eval` wrapper string is well-formed for a sync expression and a never-settling one
    (unit test of the wrapper builder).
- [ ] 9. Docs: README (subcommand list, the "Consumer contract"/troubleshooting section: "one hung
  tab blocks every Playwright attach → `status -p` / `close-hung`"), the module docstring
  subcommand list, AGENTS.md if a convention changed, and `.env.example`.
- [ ] 10. Lint + tests green (Verification block). Live read-only smoke against the shared browser:
  `timeout 120 bin/browser.py eval '1+1' --url 192.168.178.156` must end within about
  `CONNECT_TIMEOUT_S` + 10 s, either with `2` or with the hung-tab diagnosis. Also run `bin/browser.py
  status -p`. Do NOT run `close-hung` against the shared browser (Albert's tabs; see NOTE).
  Commit via `ai.py push <files>` from the main checkout after merging the worktree.

NOTE (albert, optional): once this lands, run `browser.py status -p` and then `browser.py
close-hung` yourself if the Cloudflare Access tab is still wedged. Closing a real tab of the shared
browser is your call, not an agent's.

NOTE: Playwright MCP (`browser_*` tools) also uses `connect_over_cdp` and will hang on the same
wedged tab. That is outside this repo; `close-hung` is the shared remedy.

## Verification

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff check bin/ tests/
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff format --check bin/ tests/
cd /Users/albert/obsidian/42-Git/home/browser-login && git status --short
cd /Users/albert/obsidian/42-Git/home/browser-login && bin/browser.py -h
cd /Users/albert/obsidian/42-Git/home/browser-login && bin/browser.py close-hung -h
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests/test_connect_hang.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q
cd /Users/albert/obsidian/42-Git/home/browser-login && mypy bin/browser.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pylint bin/browser.py
```
