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

- [x] **Spike A: headless-by-default.** `browser.py up --headless`
      (`--headless=new`, same profile). Validation matrix = FULL workflows
      across ALL consumers, not just login sentinels: claude.ai admin DOM read
      + `-ta` dry-run; chatgpt.com admin read + `-ta` dry-run; CSCS login +
      token read; Slack session extraction; biopolwifi; file downloads;
      screenshots; assisted-login handoff. Anti-bot risk (Cloudflare) is the
      thing being tested. Headless stays opt-in behind a soak period before
      any default flip.

      **Result 2026-08-20 — headless is a NO-GO for the admin surfaces;
      stays opt-in permanently (`up -H/--headless`, env
      `CLAUDE_BROWSER_HEADLESS=1`); default flip is off the table.**
      Matrix (Chrome for Testing 151, `--headless=new`, shared profile):

      | Workflow                          | Headless result |
      | :-------------------------------- | :--------------- |
      | claude.ai DOM read (`logged-in`)  | ❌ Cloudflare "Just a moment…" interstitial persists >20 s, sentinel never appears |
      | `anthropic-api.py -ta` dry-run    | ❌ clean gate abort (exit 1, correct remedy message) |
      | chatgpt.com admin read            | ❌ same Cloudflare interstitial |
      | `openai-team.py -ta` dry-run      | ❌ gate fails; full run NOT executed headless — its legacy own-profile fallback would spawn a second uncoordinated browser |
      | CSCS Keycloak login + token       | ✅ full unattended login, token cached + API-validated, 17 s |
      | Slack session extraction          | ✅ xoxc + d cookie + team_domain |
      | biopolwifi unattended login       | ✅ 6 s (also restored the cold session) |
      | rAF / screenshot / download       | ✅ 2 rAF frames in 28 ms (no occlusion throttling), shot 0.1 s, download OK |
      | assisted-login handoff            | ✅ new guard: exit 2 + remedy before any human-wait; himalaya auto path stays allowed |

      Root cause: `--headless=new` advertises `HeadlessChrome/151.0.0.0` in the
      User-Agent; Cloudflare (fronting claude.ai AND chatgpt.com — the two
      primary consumers) hard-challenges it. Sessions were NOT damaged: after
      restoring headed mode all five sites verified logged in, and both `-ta`
      dry-runs pass headed end-to-end (dialog filled, stopped before mutation).
      Detection gotcha shipped: CfT 151 reports a plain `Browser` field in
      `/json/version` — only the User-Agent carries the `HeadlessChrome`
      marker; `_browser_mode()` checks both. `up` now refuses a mode-mismatched
      request (exit 1) instead of silently ignoring it; `status` prints the
      mode. Headless remains useful for CSCS/Slack/biopolwifi + mechanical
      CDP work (screenshots, downloads, evals).
- [x] **Spike B (independent): hidden launch `open -g -j`.** Do NOT infer from
      occluded-window results — a hidden window is a different macOS state.
      Own pass: rAF alive after `bring_to_front()`, click, screenshot, focus
      and z-order unchanged. Until it passes, keep `open -g`.

      **Result 2026-08-20 — FAIL; `open -g` stays. No code change.**
      Own pass on CfT 151, isolated step by step (System Events `visible`
      probed between single CDP actions):

      1. `open -g -j` itself is ineffective: Chrome un-hides at window
         creation — end state identical to `open -g` (window on-screen,
         z-behind frontmost, `visible=true`, no focus steal).
      2. Post-launch hide (Cmd+H equivalent) establishes a true hidden state
         (0 on-screen windows), and while hidden the browser IS fully
         drivable: rAF alive on existing tabs (~16.5 ms frame delta — hidden
         is NOT occlusion-paused, with the anti-throttling flags present),
         click and bounded screenshot pass on a disposable `data:` tab.
      3. But the hidden state cannot be HELD under automation: BOTH
         `Target.createTarget` (even `background:true`) AND
         `Page.bringToFront` un-hide the app (window returns on-screen
         behind the frontmost app; focus still never stolen). Bare CDP
         connects and `Runtime.evaluate` on existing tabs do NOT un-hide.

      Net: every consumer workflow creates/navigates tabs and calls
      tab-level `bring_to_front`, so a hidden launch degrades to today's
      occluded `open -g` state on first action. Focus/z-order contract held
      in every state tested. Useful side-fact: if the user manually hides
      the window, read/eval-only automation keeps it hidden.
- [x] **Lifecycle record + transactional mode switching.** *(done 2026-08-20:
      `.browser-lifecycle.json` under `~/.cache/claude-browser/`, new
      `browser.py switch headed|headless`; `up` heals the record of an
      already-running browser; `status` prints the record + every invariant
      violation. Verified live: 4-s transactional round-trip switch with
      sessions intact; SIGKILL crash → status flags record/CDP/SingletonLock
      violations and `up` self-recovers by removing the provably-stale lock;
      clean `down` clears the record. The only direct signal target is a
      `_validated_root_pid` (pid + ps lstart + root command line + Playwright
      cache executable); pattern-scoped `pkill` is the final fallback. 53/53
      helper unit checks.)* Atomic
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
