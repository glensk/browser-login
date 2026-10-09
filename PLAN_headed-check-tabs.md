# Plan: tp#871 — keep headed-mode check tabs from freezing, without showing a window (reconciled)

## Session

Resume: `c --resume 7d725bed-5c4e-4909-82fc-dd9a58934d10`

## Context

**Problem.** The shared browser is headed only during a mode-A guided login or after a
failed revert. Then background tabs are created in the shared visible window with
`{url, background: true}` and can freeze; a frozen tab answers no CDP command and one
such tab blocks every Playwright attach (tp#693). Affected:

- owned check tabs (`_owned_background_page` → `_create_owned_target` →
  `_cdp_create_background_target`);
- `_guided_a_tab`'s `logged-in` every 5 s (`_guided_probe`);
- doctor's probe tab.

**Evidence.**

- `browser.py:1211-1236`: headless adds `newWindow: true`; headed deliberately does not.
- `plans-done/PLAN_owned-tabs_DONE.md:252`: a background tab is
  `visibilityState: hidden`; CfT 153 froze such tabs. `PLAN_focus-free-browser.md`
  matrix: a headed doctor timed out on its own probe tab.
- Option (d) is already in place: `_launch_and_record` (`browser.py:2810-2812`) passes
  `--disable-backgrounding-occluded-windows`, `--disable-renderer-backgrounding`,
  `--disable-background-timer-throttling` in both modes, and the freeze still happened.

**Traps.**

- `_cdp_create_background_target` also creates the human's login tab (`open -N` →
  `_guided_open_owned` → `_activate_owned`) and keep-alive tabs.
- The `cmd_*_login` flows (7057, 7928, 8189, 8378, 9018, 11119) drive the page the
  human types into through a direct `_owned_background_page` and raise it with
  `_bring_to_front`.
- So only CHECK tabs may move — the `_background_page_run` callers. Full audit list:
  - direct: `cmd_eval_fresh` (5376), `cmd_token` (6282), `_logged_in_page_check`
    (8106; claude, chatgpt, slack, biopolwifi checks), `cmd_slack_session` (8454),
    `_switch_probe` (8792);
  - via `_with_background_page`: `_switch_sso_click_background` (8903, under the
    interaction lease), `_notion_probe` (11096), `_test_site_logged_in` (11297);
  - via `_with_prepared_background_page`: `_broker_check_entry` (10580),
    `_broker_write_storage` (10663).

**CDP facts (devtools-protocol, tot).**

- `Target.createTarget`: `url`, `left`/`top`/`width`/`height`/`windowState` (all
  "require newWindow"), `browserContextId`, `newWindow`, `background`, `forTab`,
  `hidden`, `focus`.
- There is no windowId, and the default `browserContextId` spans every window, so CDP
  cannot put a tab into a chosen existing window; the only explicit window choice is
  `newWindow: true` with bounds.
- `background: false, focus: false` opens "without changing the window's focus";
  `focus: true` with `background: true` is an error.
- `hidden: true` ties the tab's lifetime to the CDP session (our one-shot
  `_cdp_ws_call` would kill it at once) — rejected.
- `Browser.getWindowForTarget` → `{windowId, bounds}`; `Page.setWebLifecycleState` is
  one-shot; `Emulation.setFocusEmulationEnabled` only simulates focus; no CDP command
  sets `visibilityState`.

**Doctor reachability.** `cmd_doctor` registers (`browser.py:6130`);
`_registry_register` exits `BUSY_RC` (`browser.py:3127`) while a maintenance record is
live and the caller is not its owner. A headed doctor is therefore reachable only after
a failed revert.

**focus_watch.** `on_screen` is `kCGWindowIsOnscreen`, also true for a window placed
off every display. Today `summarize` downgrades only `on_screen: false`
(`focus_watch.py:583`) and counts every other Chrome `window_new`
(`COUNTED_CHROME_EVENTS`, `:130`); Step 1 teaches it the off-display rule.

**Options**

| Option                                          | Pros                                                                                         | Cons                                                                                         | Risk            |
| :---------------------------------------------- | :------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------- | :-------------- |
| (a1) new window OFF-SCREEN, check tabs only     | active in its own window → `visible`; occluded-window flag keeps it rendering; one call, no flash; same model as the headless fix | real NSWindow (Window menu, App Exposé, Cmd-`); may be clamped; popups may land on screen | medium          |
| (a2) new window MINIMIZED                       | never at a usable position                                                                   | minimized page likely `hidden` (same freeze class); Dock tile + genie                         | high            |
| (b) `setWebLifecycleState active` / focus emul. | no window                                                                                    | one-shot, needs a session a frozen tab does not answer; stays `hidden`                        | high            |
| (F1) read-only sentinel in the owned login tab  | no new tab; owned id (tp#786-compliant)                                                      | only CSS-sentinel sites; authoritative check needed after the revert                          | medium          |
| (c) no check tabs while headed (trigger, check after headless) | no window                                                                     | trigger only, mode flips; not the failed-revert path                                          | medium, partial |
| (d) launch flags                                | already passed                                                                               | proven insufficient                                                                           | n/a             |

**Recommendation: (a1), only if the gate proves both the freeze and the fix.** It is
the only option that keeps a check tab `visible` without touching the human's window.

**Desktop constraint.** Every Step-0 and Step-8 run puts a headed disposable Chrome
window on Albert's screen (~1 h in total). They run only while the Mac is idle
(`ioreg -c IOHIDSystem` `HIDIdleTime` > 600 s, checked before each variant and every
30 s during it); on activity the run aborts that variant, tears the disposable browser
down and resumes at the next idle period.

**Why Verification runs tests, mypy, pylint:** the change alters the `createTarget`
payload that fake-CDP tests pin (`tests/test_owned_tabs_tp845.py:441`) and must prove
human tabs stay in the human's window; ruff/mypy/pylint are the AGENTS gates.

## Debate outcome (Opus adversary)

Critic: fresh Opus subagent, 2026-10-09, 1 round (Codex seats capped).

1. Repositioning a clamped window is unsafe — accepted: close at once, journal
   `check_window_clamped`, headed checks unusable for the process; old Step 2 dropped.
2. A rejected create would trigger marker recovery — accepted: distinct `rejected`
   outcome; `_create_owned_target` skips `_marker_target` for it.
3. The gate cannot use `focus_watch -s` as is — accepted: Step 1 adds the off-display
   rule to `summarize` + a test.
4. Human tabs may land in the check window — accepted: gate cases for `open -N` and for
   a closed/minimized login window + Cmd-`; windowId is a pass criterion; Step 4 adds an
   explicit-window fallback.
5. The gate may not reproduce the freeze — accepted: V0 must freeze in the same harness;
   Playwright connects every 5 s; 15-min runs; if V0 never freezes, stop.
6. Doctor scope too wide — accepted: a headed doctor skips the probe with ⚠ (line
   cited); the headless probe is unchanged.
7. Caller audit incomplete, popups ignored — accepted: all ten callers listed; a popup
   gate case; any on-display popup is closed at once.
8. 0c activation unscoped — accepted: activate the disposable's PID only, filter the
   JSONL by PID, 0c only while Albert is away; what stays unproven without 0c is stated.
9. Verification vague — accepted: explicit pytest node ids; verdict file paths recorded.
10. Fallback order unclear — accepted: F1 (owned-login-tab sentinel) first, then (c).

## Steps

- [ ] **0. Measurement gate** (idle-only, see Desktop constraint).
  - `S=/Users/albert/.local/state/tp871`; disposable `CLAUDE_BROWSER_CACHE_DIR=$S/cache`,
    port 9371 (never 9222/9223), `CLAUDE_BROWSER_TEST_NO_LAUNCH` unset.
  - Launch headed in-process: `uv run python -c 'import sys; sys.path.insert(0,"bin");
    import browser; sys.exit(browser._launch_and_record(9371, False))'`.
  - The human tab gets a `data:` page with a rAF counter and a textarea; record its
    `windowId` as `H`. Start `bin/focus_watch.py -l $S/fw-step0.jsonl -d 7200`.
  - The probe script (implementer's scratchpad; raw `websockets`, `origin=None`,
    `127.0.0.1`) writes `$S/gate-step0.json`. No connecting CLI command except doctor
    (a connecting command would revert the headed instance); `open -N` is exercised
    in-process via `browser._open_new_raw(9371, url)`.
  - 0a. **Control V0** `{url, background: true}`, 15 min: one long-lived tab on a
    `data:` page logging `freeze`/`resume`/`visibilitychange`; `Runtime.evaluate` every
    1 s (1 s budget); a fresh tab created+closed every 5 s; a real Playwright
    `connect_over_cdp("http://127.0.0.1:9371", timeout=CONNECT_TIMEOUT_S)` + close every
    5 s; also `browser.py --cdp-port 9371 doctor`. Reproduced = an evaluate unanswered
    within 5 s, a `freeze` event, or a failed connect. **If V0 never reproduces: verdict
    "freeze not reproduced" — record it here and in tp#871, tear down, stop; no code
    ships.**
  - 0b. Same harness, 15 min each: **V1** `{newWindow: true, background: true, left:
    -32000, top: -32000, width: 1280, height: 900}`; **V2** as V1 but `background:
    false, focus: false`; **V3** minimized (5 min, evidence only, never selectable).
    Every second: `getWindowForTarget` per tab; the human tab's `visibilityState`, rAF
    progress, `hasFocus`. Extra cases per variant:
    - (i) a check window alive → `_open_new_raw`: the new tab's `windowId` must be `H`;
    - (ii) minimize `H` → `_open_new_raw`: `windowId` must be `H`;
    - (iii) close every tab in `H` → `_open_new_raw`: record where it lands (expected:
      the check window — why Step 4 exists);
    - (iv) popup: a check tab runs `window.open("data:…", "_blank",
      "popup,width=500,height=400")` — record the popup's bounds and whether they
      intersect a display.
  - 0c. **Takes desktop focus — only while Albert is away.** Activate the DISPOSABLE
    instance by PID (`NSRunningApplication.runningApplicationWithProcessIdentifier_(pid)
    .activateWithOptions_`; pid from `$S/cache/browser.pid`); re-run V1 and V2 for 5 min
    each with simulated typing into the human textarea (`Input.insertText` every
    200 ms), then Cmd-` via a Quartz `CGEvent`; filter the focus JSONL to that pid. Pass:
    the human tab keeps`hasFocus`and loses no character; after Cmd-` record whether a
    check tab gained `hasFocus` (residual-risk fact). If 0c is skipped: key-focus theft
    while typing and Cmd-` landing in a check window stay unproven; V2 cannot be chosen
    and shipping V1 needs Albert's explicit OK on that residual.
  - 0d. **Verdict** → `$S/gate-step0.json` + a summary here; valid only if 0a
    reproduced. A variant passes when: every evaluate answers < 1 s for 15 min and
    reports `visible`; no `freeze`, no failed connect; the human tab stays `visible`
    with rAF running; `getWindowForTarget` returns exactly the requested bounds; cases
    (i) and (ii) land in `H`; `focus_watch -s $S/fw-step0.jsonl` (after Step 1) shows
    zero activations, `window_raise` or on-display windows for the disposable pid
    (popup segment excluded). Pick V1, else V2; if neither passes, ship F1 → (c)
    (Step 7) instead of Steps 2–4. Tear down: `browser.py --cdp-port 9371 down` (same
    env).
- [ ] **1. focus_watch.** Record `on_display` at capture time (bounds intersect an
      `NSScreen` frame, converted to CG coordinates). In `summarize`, a Chrome
      `window_new` with `on_screen: true, on_display: false` is treated like the
      `on_screen: false` downgrade (`:583`) — informational until a `window_shown`. Old
      records without `on_display` keep today's rule. Test
      `test_summary_off_display_window_is_not_counted`.
- [ ] **2. Check-tab creation.** New `_cdp_create_check_target(ws_url, url, budget_s)
      -> CheckCreate(tid, rejected)`: headless → today's `{url, background,
      newWindow}`; headed → the winning payload from a pure
      `_background_target_params(mode, url, check=True)` with a `HEADED_CHECK_WINDOW`
      constant, then `Browser.getWindowForTarget`. Off-display = wholly in the
      off-screen band (`left + width <= -16000` or `top + height <= -16000`; secondary
      displays may sit at negative coordinates but never that far out). Bounds not as
      requested, or a failed read: close the target by id at once, journal
      `check_window_clamped`, set the process flag `_HEADED_CHECKS_UNUSABLE`, return
      `rejected=True`. No repositioning. `_cdp_create_background_target` stays as is for
      handoffs and keep-alives.
- [ ] **3. Thread it through.**
  - `_owned_background_page(..., check=False)` → `_create_owned_target(..., check)`; a
    `rejected` result raises `HeadedCheckUnavailable` WITHOUT `_marker_target` recovery
    (`browser.py:~10164-10171`); the ledger entry is dropped only once the target is
    confirmed gone.
  - `_background_page_run` passes `check=True` and re-raises `HeadedCheckUnavailable`
    like `BrowserAttachTimeout`, so `main` reports "cannot tell" (exit 1), never "logged
    out"; while the flag is set, further check-tab creation raises immediately.
  - Audit all ten callers: none may call `_bring_to_front` or wait for the human; if
    `_switch_sso_click_background` proves human-facing it becomes `check=False`.
  - Popups: for a headed check tab a poll thread (raw `_target_snapshot` every 250 ms)
    finds page descendants via `openerId`; any whose window is not off-display is closed
    at once and journaled `check_popup_closed`.
- [ ] **4. Human tabs.** `_guided_a` records `H` (`getWindowForTarget` of its first page)
      in the transaction. `_guided_open_owned` and the headed `cmd_*_login` owned pages
      verify `windowId == H` after creation; on a mismatch or when `H` is gone: close the
      tab and recreate it with `newWindow: true` at `H`'s last bounds (default bounds if
      unknown), then `_activate_owned` — a visible window under the lease is allowed.
- [ ] **5. Doctor.** If `_browser_mode(port) == "headed"`, `cmd_doctor` adds ⚠ "probe
      skipped: headed" and skips `_doctor_probe`; responsiveness and window checks still
      run. The headless `_doctor_open_probe` is unchanged.
- [ ] **6. Tests (fakes).** `fake_cdp.py` answers `Browser.getWindowForTarget`
      (configurable bounds/windowId). New:
  - `tests/test_owned_tabs_tp845.py::test_created_target_payload_per_mode_and_kind`
    (headless / headed-check / headed `open -N` / headed direct `_owned_background_page`);
  - `…::test_headed_check_window_clamped_is_closed_and_disables_checks`;
  - `…::test_rejected_check_target_skips_marker_recovery`;
  - `…::test_check_popup_on_display_is_closed`;
  - `tests/test_guided_login.py::test_human_tab_outside_human_window_is_recreated_in_new_window`;
  - `tests/test_connect_hang.py::test_doctor_headed_skips_the_probe_with_a_warning`;
  - Step 1's focus_watch test.
- [ ] **7. Fallback — only if V1 and V2 fail.** F1: in `_guided_a_tab` the 5 s probe
      becomes a read-only raw-CDP `Runtime.evaluate` on the owned login tab's page
      websocket (never navigates): `try { [...document.querySelectorAll(SEL)]
      .some(visible) } catch { null }`, `SEL` = the site's broker `logged_in_selector`
      or `DEFAULT_LOGGED_IN_SELECTORS`. True → `_ensure_headless`, then the
      authoritative `_guided_probe` (headless `newWindow` path). `null` (Playwright-only
      selectors like `text=`/`:has-text`), no selector (check_url + fill-origin rule) or
      cscs (portal token) → (c): trigger on the login tab's origin leaving the fill
      origins (`/json/list`) or Enter on `/dev/tty`, then the check after headless. The
      built-in window flows also move their final `_guided_probe` after
      `_ensure_headless`. Residual: check tabs during a failed revert stay unfixed; the
      doctor skip still applies.
- [ ] **8. Re-measure** (idle-only): Step 0 against the implementation, the gate script
      driving the real helpers → `$S/gate-step6.json` + `$S/fw-step6.jsonl` (the Step-6
      verdict of record); doctor on the headed disposable: ⚠ skipped, no ❌.
- [ ] **9. Docs:** docstrings; AGENTS.md "Owned-tab ledger" (payload per mode and kind,
      the rejected rule); README "Why you never see the window"; plan results; a tp#871
      note with both verdict files.

## Verification

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests/test_owned_tabs_tp845.py::test_created_target_payload_per_mode_and_kind tests/test_owned_tabs_tp845.py::test_headed_check_window_clamped_is_closed_and_disables_checks tests/test_owned_tabs_tp845.py::test_rejected_check_target_skips_marker_recovery tests/test_owned_tabs_tp845.py::test_check_popup_on_display_is_closed
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests/test_focus_watch.py::test_summary_off_display_window_is_not_counted tests/test_connect_hang.py::test_doctor_headed_skips_the_probe_with_a_warning tests/test_guided_login.py::test_human_tab_outside_human_window_is_recreated_in_new_window
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests/
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff format --check bin/ && ruff check bin/ && uv run mypy bin/browser.py && uv run pylint bin/browser.py bin/focus_watch.py
cd /Users/albert/obsidian/42-Git/home/browser-login && bin/browser.py -h && bin/focus_watch.py -h
cd /Users/albert/obsidian/42-Git/home/browser-login && test -s /Users/albert/.local/state/tp871/gate-step0.json && test -s /Users/albert/.local/state/tp871/gate-step6.json
cd /Users/albert/obsidian/42-Git/home/browser-login && bin/focus_watch.py -s /Users/albert/.local/state/tp871/fw-step6.jsonl
```
