# PLAN: fully non-interfering background browser for automation

Reconciled through a judged Claude↔Codex debate (gpt-5.6-sol, 3 rounds,
2026-08-20). Future work — not implemented in that session.

## Session

Resume: `c --resume 44e9d484-4ec0-4ce4-8635-b8ee209fb5a2`

## Problem

The shared automation Chromium (browser.py, CDP :9222) must never interfere
with Albert's desktop work: no focus steal, no window raising, ideally no
visible window — while remaining fully drivable (clicks, keystrokes,
screenshots) by anthropic-api.py / openai-team.py / MCP browser tools.

## Contract (define first)

Normal automation must never activate the app, raise the window, or change
macOS focus/z-order. The ONE exception: an explicitly requested assisted login
(`browser.py login SITE` / `--headed`), which may raise the window because a
human asked for it.

## Facts established 2026-08-19/20

1. Window launches behind everything (`open -g -n`), never takes focus.
2. macOS pauses rendering of the occluded window: rAF freezes → Playwright
   actionability ("stable" needs 2 rAF frames) and screenshots stall. The
   `--disable-backgrounding-*` launch flags did NOT unfreeze rAF.
3. `page.bring_to_front()` (CDP, tab-level) unfreezes rAF WITHOUT raising the
   macOS window (verified via `CGWindowListCopyWindowInfo`: Chrome for Testing
   stayed behind Brave/iTerm) and without focus change.
4. Consumers additionally use robust clicks (force-fallback on NON-final
   controls only) and bounded screenshot timeouts.
5. Interim mitigation shipped with the invite-flow work: both team CLIs hold
   an exclusive advisory flock (`~/.cache/claude-browser/interaction.lock`)
   around their browser-driving sections (bounded wait, loud failure naming
   the holder).

## Steps (in order)

- [ ] **Spike A: headless-by-default.** `browser.py up --headless`
      (`--headless=new`, same profile). Validation matrix = FULL workflows
      across ALL consumers, not just login sentinels: claude.ai admin DOM read
      + `-ta` dry-run; chatgpt.com admin read + `-ta` dry-run; CSCS login +
      token read; Slack session extraction; biopolwifi; file downloads;
      screenshots; assisted-login handoff. Anti-bot risk (Cloudflare) is the
      thing being tested. Headless stays opt-in behind a soak period before
      any default flip.
- [ ] **Spike B (independent): hidden launch `open -g -j`.** Do NOT infer from
      occluded-window results — a hidden window is a different macOS state.
      Own pass: rAF alive after `bring_to_front()`, click, screenshot, focus
      and z-order unchanged. Until it passes, keep `open -g`.
- [ ] **Lifecycle record + transactional mode switching.** Atomic
      `.browser-lifecycle.json` `{state: starting|running|stopping|switching,
      mode, pid, process_start_time, nonce}`. Acceptance: at most ONE
      validated root browser process (executable + process start time + debug
      port + profile dir all match the record); zero processes allowed only
      while a recorded transition state is active; exactly one healthy CDP
      root afterwards. Signals go only to a validated PID (never bare-PID
      kill — PID reuse). Shutdown = CDP `Browser.close` → SIGTERM after 5 s →
      pkill after 10 s; relaunch aborts while the old root or the profile
      `SingletonLock` persists. Record agreement is required only in state
      `running`; `doctor` flags stale transitional/crash states.
- [ ] **Two-layer client coordination.** Layer 1: shared lifecycle
      REGISTRATION for every supported CDP connection (read-only evals and our
      MCP tools included); mode switch/down requires exclusive acquisition
      over the registration set. Layer 2: exclusive INTERACTION lease for
      focus/input/screenshot flows (supersedes the interim interaction.lock).
      Both via flock/O_EXCL, owner nonce + PID start time, bounded heartbeat,
      compare-before-release; crash/stale-owner tests. Unknown/unregistered
      CDP clients (detected: established connections on :9222 vs
      registrations) make automatic mode switching FAIL CLOSED.
- [ ] **`browser.py doctor`.** Uses a disposable `data:` page; acquires the
      interaction lease; bounded rAF/click/screenshot checks; records
      frontmost app + window z-order before/after and asserts them unchanged;
      closes its target; non-macOS → explicit skip. Also validates the
      lifecycle record against the live process.
- [ ] Docs: README "Why you never see the window" + the consumer contract
      (tab-level bring_to_front only; no app activation; force-click never on
      final mutating controls; bounded screenshots; lease usage).
