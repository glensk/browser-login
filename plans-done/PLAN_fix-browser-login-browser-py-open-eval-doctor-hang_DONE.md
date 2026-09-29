# fix(browser-login): browser.py open / eval / doctor hang while status works (tp#693)

## Session

Resume: `c --resume e1ce9120-0ef0-4a6d-922c-85cf4dd84e23`

## Context

**Classification: DEFECT**, reproduced on 2026-09-29 against the live shared Chromium, read-only.

**Symptom.** `browser.py open <url>`, `eval` and `doctor` block, while `status` answers in 0.4 s.
The nixos deploy agent found this and fell back to raw CDP.

**Evidence (reproduction, 2026-09-29).**

- `browser.py status` lists 7 tabs and answers in 0.4 s. It only uses the CDP HTTP endpoints
  (`/json/version`, `/json/list` via `_cdp_get`, `bin/browser.py:474`), which the browser process
  serves itself.
- `PYTHONFAULTHANDLER=1 timeout -s ABRT 45 bin/browser.py eval '1+1' --url 192.168.178.156` blocked
  for the full 45 s inside Playwright's event loop.
- A `DEBUG=pw:protocol` run sent 171 CDP commands and got 161 answers. All 10 unanswered commands
  belong to ONE page session: `Page.enable`, `Page.getFrameTree`, `Runtime.enable` …
  `Runtime.runIfWaitingForDebugger`. That session is the tab `Sign in ・ Cloudflare Access`
  (`https://albertha.cloudflareaccess.com`, target `EEE09E93…`). Every other page, iframe, worker
  and service worker answered.
- A raw websocket probe on that target's `webSocketDebuggerUrl`: `Runtime.evaluate 1+1`,
  `Page.getFrameTree` and `Page.enable` each timed out after 5 s. The target only emitted
  `Page.frameStartedNavigating`. The renderer is stuck mid-navigation and answers no CDP command.
- Standalone Playwright 1.62.0: `connect_over_cdp("http://127.0.0.1:9222")` with no `timeout` was
  still blocked after 50 s. With `timeout=5000` it raised `TimeoutError … Timeout 5000ms exceeded`
  after 5.5 s. Playwright's unset timeout for `connectOverCDP` is `launch_timeout` = **180 000 ms**
  (`playwright/_impl/_helper.py` `DEFAULT_PLAYWRIGHT_LAUNCH_TIMEOUT_IN_MILLISECONDS`, used by
  `_browser_type.py` `connect_over_cdp`).

**Root cause (confidence: high).** `_connect` (`bin/browser.py:2124`) calls
`pw.chromium.connect_over_cdp(...)` without a `timeout`. Playwright attaches to every existing page
target and waits until each one answers its initialisation commands. So one tab whose renderer does
not answer CDP blocks the attach for Playwright's 180 s launch default. Agents calling with a
120 s Bash timeout, and humans, see that as a hang. The wait is not infinite; that was corrected in
the debate (O1). Every `_connect` caller is affected (19 call sites: `open` `bin/browser.py:2273`,
`eval` `:2300`, `doctor` via `_doctor_open_probe` `:2836` and `_doctor_probe` `:2890`, `token`,
every `login`/`logged-in` flow). So is `_cdp_browser_close` (`:997`), which `down`/`switch` use to
quit gracefully. It attaches Playwright only to send `Browser.close`, and the wait eats
`_shutdown_browser`'s 10 s escalation budget (`:1075`). `status` escapes because it never uses
Playwright. Whatever wedged the renderer is Chrome-internal and outside this repo; any tab can reach
this state, and browser.py must survive it.

**Second unbounded wait of the same class** (not observed, found while reading): `cmd_eval`'s
`page.evaluate` (`bin/browser.py:2323`) has no timeout. A never-settling promise or a busy renderer
blocks `eval` even after a successful attach. A timer inside the page cannot bound this, because it
runs in the blocked renderer (debate O2). Only a deadline in the Python process can.

**Constraints.**

- The shared browser is live infrastructure with Albert's real sessions. The fix detects and
  reports. It NEVER closes, reloads or navigates a real tab automatically. Removing a hung tab is an
  explicit, separate, confirmed action.
- Tab output stays origin-only through `_tab_hint`/`_tab_title` (AGENTS.md; tp#337, tp#365).
- CDP endpoint is always `127.0.0.1`, never `localhost`.
- The lock order is registry gate, then interaction lease (`bin/browser.py:1681`, README "Consumer
  contract"). Every new command that talks to the browser registers as a client. Low-level
  websocket helpers stay registration-free, so shutdown can call them while it holds the gate
  exclusively.
- `bin/browser.py` is executed live by consumers. The WORK session edits it in a git worktree,
  never in place (AGENTS.md).
- Tests never touch the real browser on :9222 or the real `~/.cache/claude-browser` coordination
  files. They use a fake CDP endpoint on an ephemeral port, with the cache/registry directories
  redirected to `tmp_path`.
- Every new flag has a short and a long form, and `-h` exits 0.

**Settled defaults** (recorded with `tp question -d`; Albert can overrule them):

1. Connect bound: `timeout=` on `connect_over_cdp`, default 30 s. Overridable with the env var
   `CLAUDE_BROWSER_CONNECT_TIMEOUT_S`, documented in `.env.example`.
2. The raw CDP probe/close client is the `websockets` package (sync client). It is added to the
   self-bootstrapped venv deps (`ensure_deps` self-heals a missing dep) and to `pyproject.toml`.
   Rejected alternative: a hand-rolled stdlib RFC 6455 client (more code to own).
3. Remediation is an explicit `close-hung` subcommand with confirmation unless `-y/--yes`. It is
   never automatic.
4. `eval` gets a Python-side hard deadline `-t/--timeout SECONDS` (default 60). On expiry it prints a
   ❌ line and calls `os._exit(1)`. An abandoned expression may keep running in the page, and the
   docs say so.

**Debate.** Codex gpt-6-astra, round 1, judge converged. All 10 objections were accepted (O9
partially): 180 s rather than infinite, a Python-side eval deadline, structured probe outcomes with
re-validation after confirmation, client registration, raw-CDP shutdown, a total probe budget, a
real Playwright-attach test against a stalling fake endpoint, doctor cleanup, a narrower live smoke,
and worktree-root verification. On O9: Albert's item rule allows `status` and `open` of a harmless
URL against the live browser, so the live smoke uses those and never `eval` or `close-hung`.

**Blocked on Albert:** no.

**Why the Verification block is not strict-eligible:** it runs `uv run pytest`, `mypy` and
`uv run pylint` beyond the allowlisted read-only checks. The fix changes runtime behaviour that only
the tests exercise, against a fake CDP endpoint whose page target never answers.

## Steps

- [x] 1. Create a git worktree of `home/browser-login` and do all edits there (never the live
  `bin/browser.py`). Add a module constant `CONNECT_TIMEOUT_S`, read from the env var
  `CLAUDE_BROWSER_CONNECT_TIMEOUT_S`, default 30. Invalid or non-positive values fall back to 30.
  Put it next to `DEFAULT_CDP_PORT` (`bin/browser.py:109`) and document it in `.env.example` under
  "shared browser".
- [x] 2. Raw CDP layer, registration-free. Add `websockets` to `ensure_deps` (import check, `deps`
  list, both "creating venv" messages) and to `pyproject.toml` `dependencies`, then `uv lock`.
  Add helpers:
  - `_cdp_ws_call(ws_url, method, params, budget_s)`: one monotonic deadline over the whole call.
    `open_timeout` and `close_timeout` are each ≤ 1 s and capped by what is left of the budget. The
    reply is matched by CDP `id`. Events are ignored and never extend the deadline. It returns a
    tagged result: ok / timeout / transport-error.
  - `_browser_ws_url(port)` reads the browser-level `webSocketDebuggerUrl` from `/json/version`.
- [x] 3. `_probe_targets(port, budget_s=6.0) -> ProbeReport`: enumerate `type == "page"` targets
  from `/json/list`, with its own `_cdp_get`, NOT `_page_targets` (that one maps a failure to `[]`).
  A failed enumeration makes the report `indeterminate` as a whole. Otherwise probe each target
  concurrently with `Runtime.evaluate {"expression": "1"}` over its `webSocketDebuggerUrl`: one
  thread per target, at most 32. Targets beyond the cap count as `indeterminate`. The whole probe
  shares one monotonic budget. Per-target outcome: `responsive` (reply received), `unresponsive`
  (websocket opened but no reply within the budget), `gone` (target vanished or the socket was
  refused because the target closed), `indeterminate` (any other transport error). Read-only: the
  only command sent is `Runtime.evaluate("1")`.
- [x] 4. `_connect` (`bin/browser.py:2101`) passes `timeout=CONNECT_TIMEOUT_S * 1000` to
  `connect_over_cdp`. On Playwright `TimeoutError` it stops Playwright (bounded, errors suppressed),
  runs `_probe_targets`, and raises a new `BrowserAttachTimeout` whose message names each
  `unresponsive` tab by `_tab_title` + `_tab_hint` origin + 8-char target id, plus the remedy
  (`browser.py close-hung`, or reload/close that tab by hand). If no tab is unresponsive, the message
  says so and reports the indeterminate count. `main()` turns `BrowserAttachTimeout` into
  `_fail(...)` (exit 1). `doctor` catches it itself (step 8). The ~19 other callers need no change.
- [x] 5. `_cdp_browser_close` (`bin/browser.py:973`) sends `Browser.close` through `_cdp_ws_call`
  on the browser-level websocket with a 5 s budget, and no longer uses Playwright. A connection
  dropped mid-command counts as sent, as it does today. A timeout counts as "not sent", so
  `_shutdown_browser` escalates with its budget intact.
- [x] 6. `status -p/--probe` registers a client (`_registry_register`) for the probe's lifetime,
  then appends a marker to each tab line: `⚠ unresponsive`, `? indeterminate` or nothing.
  Enumeration failure prints `probe indeterminate: <reason>` and exits 1. Without `-p`, output and
  speed are unchanged (HTTP only).
- [x] 7. New subcommand `close-hung` with `-y/--yes`, in this order: register a client, take the
  interaction lease, run probe #1, re-probe the `unresponsive` ones (probe #2), then list the
  candidates (origin-only, id8). Ask for confirmation (skipped with `-y`; a declined prompt or no TTY
  without `-y` exits 1 and closes nothing). AFTER confirmation, re-probe exactly the approved target
  ids (probe #3) and close only those that are still `unresponsive` with an unchanged `url`, using
  `Target.closeTarget` over the browser-level websocket. Print what was closed and what was skipped
  as recovered or changed. Exit 0 when nothing was hung or every approved candidate was closed or
  had recovered, 1 on an indeterminate probe or a failed close. Contract in help and README: "closes
  only tabs that failed three consecutive CDP probes; a responsive tab is never a candidate".
- [x] 8. `doctor`:
  - (a) Before the probe, add a check `tab responsiveness` via `_probe_targets`: ✅ when every tab
    answers; ❌ naming the unresponsive tab(s) and the `close-hung` remedy, and skip the Playwright
    probe; ⚠ when the result is indeterminate.
  - (b) Restructure `_doctor_open_probe`/`_doctor_probe` (`bin/browser.py:2828`, `:2878`) so that
    probe-tab creation and the reconnect run inside ONE `try/finally`. `_open_background_tab` must
    return the created target id. When Playwright never got the page, cleanup closes that id via
    browser-level `Target.closeTarget` (bounded). A `BrowserAttachTimeout` there becomes a ❌ line,
    and `_doctor_windows_after` still runs.
- [x] 9. `eval -t/--timeout SECONDS` (default 60; must be > 0): arm a daemon `threading.Timer`
  BEFORE `_connect`. On expiry it writes `❌ eval: no result after Ns (tab unresponsive or
  expression never settled)` to stderr and calls `os._exit(1)`. The registry flock goes away with
  the process, and `_registry_live_clients` already drops records whose PID is dead. Check that
  last point and fix it if not. Help and README note that JS already running in the page is not
  stopped.
- [x] 10. Tests in `tests/test_connect_hang.py`. No real browser. Coordination dirs are redirected
  to `tmp_path` (monkeypatch `CACHE_DIR`/`CLIENTS_DIR` in-process; for subprocess tests, add a
  test-only env override `CLAUDE_BROWSER_CACHE_DIR`, documented in `.env.example`). Fake CDP
  endpoint on an ephemeral `127.0.0.1` port: stdlib HTTP for `/json/version` and `/json/list`, and a
  `websockets` server for the browser and page sockets. It answers Playwright's connectOverCDP
  handshake (`Browser.getVersion`, `Target.setAutoAttach` → `Target.attachedToTarget` for one page,
  `Browser.setDownloadBehavior`, …) and then never answers the stalled page session. Cases:
  - the REAL `_connect` in a subprocess with `CLAUDE_BROWSER_CONNECT_TIMEOUT_S=2` and an outer
    deadline exits 1 within about 2 s + probe budget + slack. The message contains the hung tab's
    origin and none of its path or query;
  - `_probe_targets`: responsive vs silent vs a target spamming events (no deadline extension) vs a
    stalled handshake vs a stalled close vs 33 targets (the cap) vs a failed `/json/list`
    (indeterminate);
  - `close-hung -y` closes only the silent target; a target that recovers before probe #3 is
    skipped; a declined confirmation closes nothing;
  - `status -p` marks only the silent tab;
  - the `eval -t 2` watchdog, run in a subprocess against a page whose `Runtime.evaluate` never
    answers, exits 1 within the deadline + slack;
  - `_cdp_browser_close` against a silent browser socket returns False within its 5 s budget;
  - doctor with a stalled attach: the ❌ line is printed, the probe target is closed by id, and
    windows-after still runs (Quartz/osascript mocked).

  NOTE: the project venv locks Playwright 1.60 (`uv.lock`) while the bootstrap venv runs 1.62. Both
  use `launch_timeout` for `connectOverCDP`. Bump the lock only if a test shows the two differ.
- [x] 11. Docs: README (subcommand list; a troubleshooting entry "one hung tab blocks every
  Playwright attach, so run `status -p` / `close-hung`"; the new env vars; the eval deadline caveat),
  the module docstring's subcommand list, AGENTS.md (the raw-CDP helper and registration rule), and
  `.env.example`.
- [x] 12. From the WORKTREE root, run every Verification command below (same argv, worktree path)
  until green. Then do the live read-only smoke against the shared browser, as Albert's item rule
  allows: `bin/browser.py status -p` and `timeout 120 bin/browser.py open https://example.com`.
  Each must end within `CONNECT_TIMEOUT_S` + 10 s, either with success or with the named hung-tab
  diagnosis. Never run `eval` in a real tab or `close-hung` against the shared browser. Merge the
  worktree into main, re-run the Verification block on the main checkout, and commit with
  `ai.py push <files>`.

Status 2026-09-29: steps 1–12 done. Live smoke against the shared browser: `status -p` (7 s) marked
exactly the `Sign in ・ Cloudflare Access` tab `⚠ unresponsive`; `open https://example.com` ended in
37 s with the named hung-tab diagnosis (`[id EEE09E93]`) instead of hanging for 180 s. The bootstrap
venv self-healed `websockets` on that first run. `uv.lock` resolves websockets 16.1.1 (Python 3.10)
and 17.1 (≥ 3.11); `_cdp_ws_call` uses the `with connect(...)` form, which both support.

NOTE (albert, optional): once this lands, run `browser.py status -p`, then `browser.py close-hung`
if the Cloudflare Access tab is still wedged. Closing a real tab of the shared browser is your call,
not an agent's.

NOTE: Playwright MCP (the `browser_*` tools) also uses `connect_over_cdp` and will stall on the same
wedged tab. That is outside this repo; `close-hung` is the shared remedy.

## Verification

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff check bin/ tests/
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff format --check bin/ tests/
cd /Users/albert/obsidian/42-Git/home/browser-login && git status --short
cd /Users/albert/obsidian/42-Git/home/browser-login && bin/browser.py -h
cd /Users/albert/obsidian/42-Git/home/browser-login && bin/browser.py close-hung -h
cd /Users/albert/obsidian/42-Git/home/browser-login && bin/browser.py status -h
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests/test_connect_hang.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q
cd /Users/albert/obsidian/42-Git/home/browser-login && mypy bin/browser.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pylint bin/browser.py
```
