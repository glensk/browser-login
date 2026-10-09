# Plan: tp#871 — keep headed-mode check tabs from freezing, without showing a window

## Session

Resume: `c --resume 7d725bed-5c4e-4909-82fc-dd9a58934d10`

## Context

**Problem.** The shared browser is headed only during a mode-A guided login or after
a failed revert. Then background tabs are created in the shared visible window with
`{url, background: true}` and can freeze. A frozen tab answers no CDP command, and
since `connect_over_cdp` waits for every page target, one frozen tab blocks every
Playwright attach (tp#693). Affected:

- owned check tabs (`_owned_background_page` → `_create_owned_target` →
  `_cdp_create_background_target`);
- `_guided_a_tab`'s `logged-in` every 5 s via `_guided_probe`;
- doctor's probe tab (`_open_background_tab`: a Playwright session, `background: true`,
  no `newWindow` — even in headless).

**Evidence.**

- `bin/browser.py:1211-1236`: headless adds `newWindow: true`; headed deliberately does
  not (a window would appear). `plans-done/PLAN_owned-tabs_DONE.md:252`: a background
  tab is `visibilityState: hidden`; CfT 153 froze such tabs.
- `PLAN_focus-free-browser.md` acceptance matrix: doctor on a headed browser timed out on
  its own probe tab.
- Option (d) is already in place: `_launch_and_record` (`browser.py:2810-2812`) passes
  `--disable-backgrounding-occluded-windows`, `--disable-renderer-backgrounding`,
  `--disable-background-timer-throttling` in both modes, and the freeze still happened.
  None of them makes a non-active tab visible or disables page freezing.
- Traps: `_cdp_create_background_target` also creates the human's own login tab
  (`open -N` → `_guided_open_owned` → `_activate_owned`) and keep-alive tabs; the
  `cmd_*_login` flows drive the page the human types into through a direct
  `_owned_background_page` and raise it with `_bring_to_front`. Only CHECK tabs may
  move: `_background_page_run` callers (`_logged_in_page_check`, `_switch_probe`,
  `cmd_eval_fresh`, `cmd_token`, `cmd_slack_session`) and doctor's probe. Human-facing
  tabs stay in the shared window.

**CDP facts (devtools-protocol, tot).**

- `Target.createTarget` accepts `left`/`top`/`width`/`height`/`windowState` ("requires
  newWindow to be true"): a window can be born off-screen or minimized in one call.
- `focus` (experimental): `background: false, focus: false` opens "without changing the
  window's focus"; `focus: true` with `background: true` is an error.
- `hidden: true` ties the tab's lifetime to the CDP session and cannot be combined with
  `newWindow`; our one-websocket-per-command `_cdp_ws_call` would kill it at once.
  Rejected.
- `Browser.getWindowForTarget` → `{windowId, bounds}`; `Browser.setWindowBounds` cannot
  combine `minimized` with geometry.
- `Page.setWebLifecycleState` is one-shot; `Emulation.setFocusEmulationEnabled` only
  simulates focus. No CDP command sets `visibilityState`.

**focus_watch caveat.** `on_screen` is `kCGWindowIsOnscreen`, also true for a window
placed off every display. The gate counts a window as visible only if `on_screen` is
true AND its bounds intersect a display, and reads the JSONL directly (`-s` exits 1 on
any on-screen Chrome `window_new`).

**Options**

| Option                                                         | Pros                                                                                         | Cons                                                                                              | Risk |
| :------------------------------------------------------------- | :------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------ | :--- |
| (a1) new window OFF-SCREEN, check tabs only                    | active in its own window → `visible`; occluded-window flag keeps it rendering; one call, no flash; same model as the headless fix | a real NSWindow (Window menu, App Exposé); macOS/WindowSizer may clamp it on screen; activation unmeasured | medium |
| (a2) new window MINIMIZED                                      | never at a usable position                                                                   | minimized pages likely `hidden` (same freeze class); Dock tile + genie animation                 | high |
| (b) background tab + `setWebLifecycleState active`             | no new window                                                                                | one-shot, needs a page session a frozen tab does not answer; stays `hidden` (no rAF)              | high |
| (c) no check tabs while headed (raw-CDP URL/cookie trigger, then `logged-in` after `_ensure_headless`) | no window at all                                                     | cookies are not a DOM sentinel (trigger only); false triggers cost ~13 s mode flips; does not cover doctor / failed revert | medium, partial |
| (d) launch flags                                               | already passed                                                                               | proven insufficient                                                                               | n/a  |

**Recommendation: (a1) behind a measurement gate.** It is the only option that keeps
the check tab `visible` without touching the human's window, and reuses the mechanism
proven in headless. If neither a1 variant passes the gate: (c) for mode A, and doctor
prints ⚠ "probe skipped: headed" instead of attaching.

**Why Verification runs tests, mypy, pylint:** the change moves the `createTarget`
payload that fake-CDP tests pin (`tests/test_owned_tabs_tp845.py:441`) and must keep
`open -N`/login tabs in the shared window; ruff/mypy/pylint are the AGENTS gates.

## Steps

- [ ] **0. Measurement gate** on a disposable HEADED instance only
      (`CLAUDE_BROWSER_CACHE_DIR=<scratchpad>/h871`, port 9371 — never 9222/9223;
      `CLAUDE_BROWSER_TEST_NO_LAUNCH` unset). Launch in-process (`up` is always
      headless): `uv run python -c 'import sys; sys.path.insert(0,"bin"); import
      browser; sys.exit(browser._launch_and_record(9371, False))'`. Wait 10 s; put the
      initial "human" tab on a `data:` page with a rAF counter and a textarea; start
      `bin/focus_watch.py -l <scratchpad>/h871/fw.jsonl -d 1200`.
  - 0a. Control: `browser.py --cdp-port 9371 doctor` (never reverts) → expect the tp#871
    attach failure; then V0 `{url, background: true}` in the probe script.
  - 0b. Probe script (`<scratchpad>/h871/probe871.py`, raw `websockets`, `origin=None`),
    variants:
    - V1 `{newWindow: true, background: true, left: -32000, top: -32000, width: 1280,
      height: 900}`;
    - V2 as V1 but `background: false, focus: false`;
    - V3 `{newWindow: true, background: true, windowState: "minimized"}`.

    Per variant: one long-lived tab on a `data:` page logging
    `freeze`/`resume`/`visibilitychange`; for 60 s a `Runtime.evaluate` every 1 s (1 s
    budget) for `{visibilityState, hasFocus, events}`; in parallel create+close a fresh
    tab every 5 s (like `_guided_probe`); every second record `Browser.getWindowForTarget`
    bounds/state and the human tab's `visibilityState`, rAF progress and `hasFocus`.
  - 0c. Repeat V1 and V2 while the human tab receives simulated typing
    (`Input.insertText` / `Input.dispatchKeyEvent` into the textarea every 200 ms) with
    Chrome for Testing frontmost (activate it once via `osascript` at the start of 0c —
    disposable instance only): the human tab keeps `hasFocus` and loses no character.
  - 0d. Verdict, recorded here. A variant passes when: every evaluate answers < 1 s for
    60 s and reports `visible`; no `freeze`; the human tab stays `visible` with rAF
    running; zero Chrome `activate`/`window_raise` during the variant (outside 0c's own
    activation); no new window whose bounds intersect a display (`NSScreen` frames);
    `getWindowForTarget` reports the requested bounds (not clamped). Pick V1 if it
    passes, else V2; if neither, implement the (c) fallback instead. Tear down with
    `browser.py --cdp-port 9371 down` (same env).
- [ ] **1.** `_cdp_create_background_target(ws_url, url, budget_s, *, check: bool =
      False)`: headless unchanged; headed + `check=True` → the winning payload, built in a
      pure `_background_target_params(mode, url, check)` with a `HEADED_CHECK_WINDOW`
      constant; headed + `check=False` (`open -N`, keep-alives, login pages) unchanged
      `{url, background}`.
- [ ] **2.** After a headed check-tab create: `Browser.getWindowForTarget`; if clamped on
      screen, one `Browser.setWindowBounds` back off-screen + journal
      `check_window_clamped`; any failure closes the target by id.
- [ ] **3.** Thread the flag: `_owned_background_page(..., check=False)` →
      `_create_owned_target(..., check)`; `_background_page_run` passes `check=True`.
      Audit every `fn` given to it (and to `_with_background_page`) for `_bring_to_front`
      or human interaction — none may stay `check=True`.
- [ ] **4.** Doctor: `_doctor_open_probe` creates its probe through
      `_cdp_create_background_target(ws, DOCTOR_PROBE_URL, check=True)` +
      `_await_target_load` instead of `_open_background_tab` (keep the `created`
      bookkeeping); skip the rAF `bring_to_front` escalation for an off-screen probe and
      journal the skip.
- [ ] **5. Tests (fakes).** `fake_cdp.py` answers `Browser.getWindowForTarget` /
      `setWindowBounds` (incl. a clamped variant). Payload test parametrized: headless;
      headed check; headed `open -N` / direct `_owned_background_page` stay `{url,
      background}`. Tests: clamped → `setWindowBounds` + journal; doctor probe uses raw
      create with the check payload; `_guided_a_tab`'s login tab payload unchanged.
- [ ] **6.** Re-run step 0 against the implementation: doctor on the headed disposable
      passes attach; focus_watch gives the same verdict.
- [ ] **7. Docs:** `_cdp_create_background_target` docstring; AGENTS.md "Owned-tab
      ledger" (payload per mode and kind); README "Why you never see the window"
      (headed check tabs live in an off-screen window, and why); plan results; tp#871
      note.

## Verification

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests/test_owned_tabs_tp845.py tests/test_guided_login.py tests/test_headless_default.py tests/test_tab_selection.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests/
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff format --check bin/ && ruff check bin/ && uv run mypy bin/browser.py && uv run pylint bin/browser.py
cd /Users/albert/obsidian/42-Git/home/browser-login && bin/browser.py -h && bin/focus_watch.py -h
```
