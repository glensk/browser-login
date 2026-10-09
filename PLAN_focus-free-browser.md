## Session

Resume: `c --resume 7d725bed-5c4e-4909-82fc-dd9a58934d10`

# PLAN: the shared browser never disturbs Albert's desktop

## Context

Agents drive the shared logged-in Chrome for Testing (CDP `127.0.0.1:9222`, `bin/browser.py`,
Playwright MCP `browser_*`) all day, and it keeps stealing macOS focus / popping its window
while Albert works. Goal: it never does, except during a login Albert starts himself.

**Invariant this plan enforces:** the shared browser is headless unless a live,
human-started guided-login maintenance lease exists. Outside that lease Chrome never
becomes frontmost, never creates or raises a window, never triggers native UI.

Requirements (Albert, 2026-10-08):

| Item                    | Answer                                                                                    |
| :---------------------- | :---------------------------------------------------------------------------------------- |
| What steals focus today | All three: agents browsing (MCP/`browser.py`), login checks/logins, browser (re)start     |
| Visibility              | Only for logins he starts; otherwise never visible                                        |
| Off home network        | Must work everywhere: EPFL, travel, Cisco VPN, EPFL/ETH-internal sites                    |
| Placements              | Any (Mac headless, second macOS user, Linux VM, nixos) — chosen on the merits             |
| Human login path        | **B: remote view** of the headless login tab in his normal browser, no restart; **A: switch headed → login → headless** only as fallback (passkey/Touch ID/native UI, or B spike fails) |

Facts:

- Focus sources in our code: 8 `page.bring_to_front()` call sites, incl. non-login
  `token` (`bin/browser.py` ~4387) and `slack-session` (~6453); the rendering-freeze
  escalation in `doctor`; the headed cold launch. Playwright MCP calls `bringToFront()` on
  tab select. In a headless browser none of these has a window to act on.
- Headless vs Cloudflare: `--headless=new` announced `HeadlessChrome`; the 2026-08-20 matrix
  failed claude.ai/chatgpt.com (`PLAN_background-browser.md`). Commit `34c78ea` (2026-10-06)
  passes a plain UA and claude.ai then loaded — on a warm, already-cleared profile only.
  Cold-profile and challenge-renewal behaviour is unproven; Phase 1 gates on it.
- No history exists of who launched what: the lifecycle file is one current record, client
  metadata is deleted on unregister. Hence the journal in Phase 0.
- `register-exec` holds the registry gate shared for its child's lifetime; `switch` needs it
  exclusively — so a registered MCP makes a switch REFUSE, it does not drain. The pinned
  `@playwright/mcp@0.0.76` can stay stuck after a CDP drop (playwright-mcp#1588).
- `--remote-allow-origins=*` is set unconditionally today; it disables Chrome's WebSocket
  Origin check on CDP. The stock DevTools screencast forwards mouse/wheel/basic keys only —
  no paste, `insertText` or IME composition.
- The Verification block runs pytest, mypy, pylint, the `-h` smoke runs of `bin/browser.py`,
  `bin/focus_watch.py` and `agent-login.py`, and `pre-commit` — all of them execute
  repository code, so it is deliberately not strict-eligible.

Options:

| Option                                   | Verdict      | Why                                                                                                                         |
| :--------------------------------------- | :----------- | :-------------------------------------------------------------------------------------------------------------------------- |
| Mac, headless by default + B/A logins    | **Chosen**   | No window → no focus source; same network/VPN/Keychain/LAN grant as today                                                    |
| Second macOS user (headed, off-session)  | Fallback #1  | Real headed macOS fingerprint, host network stack; costs: own Keychain/TCC, FileVault reboot login, off-session rendering unproven |
| Linux VM on the Mac (headed on Xvfb)     | Fallback #2  | Never a macOS window; costs: profile not portable (full re-login), control boundary, Cisco split-tunnel/DNS via NAT unproven |
| nixos                                    | Rejected     | Fails "works everywhere" (off-LAN via WireGuard, EPFL-VPN/IP-restricted sites unreachable); sessions on a 2014 laptop         |

Debated with Codex (gpt-5.6-sol), 2 rounds, judge converged 2026-10-08: 18 objections, all
accepted and folded in below.

## Steps

### Phase 0 — instruments (acceptance tools, built first)

- [x] `bin/focus_watch.py` (`-h`, short flags, ✅/❌): pyobjc-framework-Cocoa + -Quartz in a
      `focus` dependency group; Cocoa run loop (`AppHelper.runConsoleEventLoop`) for
      NSWorkspace activation notifications, plus 500 ms polling of
      `frontmostApplication` and CGWindowList (Chrome-for-Testing window creation / z-order,
      reusing `doctor`'s Quartz logic) as a fallback; size-capped rotating log;
      LaunchAgent with `LimitLoadToSessionType=Aqua`. Logs activations of native-prompt
      processes (SecurityAgent, UserNotificationCenter, TCC) too.
- [x] Watcher self-test, recorded here: spawn a throwaway headed Chrome with a temp profile
      and activate TextEdit and back — both must be logged.
- [x] Append-only, redacted journal in `browser.py`: every up/switch/down/login/guided
      session/focus-capable action with caller pid, parent chain, argv, origins only.
- [x] Baseline soak: one working day on today's setup, steals tabulated by source.

### Status 2026-10-08 (handover)

- Phase 0 done: `bin/focus_watch.py` (`f93dcff`; 5 Hz poll, seen-set window tracking,
  `window_shown` separate from failures, self-test bracketing) — self-test ✅ chrome
  window_new + TextEdit activate. LaunchAgent `com.albert.focus-watch` installed from the
  main checkout 2026-10-08 13:53; log `~/.local/state/focus-watch/focus.jsonl`. Journal
  (`fd7398a`): `~/.cache/claude-browser/journal.jsonl`, `browser.py journal`; all 8
  `bring_to_front` calls go through `_bring_to_front(page, reason)`.
- Baseline soak running since 2026-10-08 13:53 (headed setup) → `focus_watch.py -s` on
  2026-10-09.
- Phase 1 cold column (disposable profile, home egress, CfT 153.0.8010.12): 12/12 ✅ —
  claude.ai, chatgpt.com, platform.openai.com, Slack, Notion, CSCS, SWITCH, Smartsheet,
  Infomaniak, gitlab.datascience.ch, console.anthropic.com (→ platform.claude.com),
  vaultwarden.dom42.space (LAN, terminal-launched). No challenge anywhere.
  Diagnostics: the only explicit tell is `HeadlessChrome` in the UA, removed everywhere
  (page, worker, headers, `/json/version`) by the shipped `--user-agent`. Residual tells,
  harmless today: `--user-agent` empties high-entropy UA-CH (`fullVersionList`,
  `platformVersion`, `architecture`) — fix = `Emulation.setUserAgentOverride` with
  `userAgentMetadata` if a site starts failing; `screen` 800×600; no "Google Chrome" brand
  (CfT). Open: warm + renewal columns (need `switch headless` on the real profile), EPFL/ETH
  egress.
- Phase 3 B spike: stock DevTools screencast REJECTED — WebSocket 403 unless a narrow
  `--remote-allow-origins` is set, and its key events (`nativeVirtualKeyCode`) hang
  headless CfT 153 on macOS from the 2nd keystroke; no paste/IME. Own viewer
  `bin/login_viewer.py` (websockets only): every input item ✅ (scaled clicks, typing,
  Backspace/Tab/Enter, password paste, äöü€/日本, IME, dead key, Meta+A, wheel), popup
  reported with `openerId`; one-shot token bound to an HttpOnly cookie, Host/Origin
  checks, single viewer, owned target created by the relay (`-t` needs `-A`); input→frame
  p50 10 ms; idle CPU ≈ 0. Background-created tabs need
  `Emulation.setFocusEmulationEnabled` to render headless. Integration TODOs are listed
  at the top of the module.
- Removing `--remote-allow-origins=*`: Chrome then 403s every WebSocket that sends an
  Origin header (even same-origin); Playwright sends none — audit other consumers first.

- Phase 2 BUILT, reviewed, NOT merged: branch `worktree-agent-a14a355ac5d0f6712`
  (`d3a580d`, worktree `.claude/worktrees/agent-a14a355ac5d0f6712`). Headless-only `up`
  - `desired-mode.json`; headed lease (`headed-lease.json`, live = owner pid + start
  time, heartbeat only detects a hung owner >120 s); `_preflight` revert re-checks under
  the gate, writes to stderr only, never blocks a command (❌ warning + proceed), skipped
  for doctor/close/close-hung/status/journal/down/switch; `login` exits 4 `needs Albert`
  outside the lease; `_bring_to_front` only for the lease holder; token/slack-session
  raises removed; `--deny-permission-prompts` + Preferences (notifications/geo/cam/mic
  blocked, downloads to `<cache>/downloads`); `--remote-allow-origins=*` removed (all
  consumers send no Origin — verified py/node Playwright, websockets). Unit-tested; the
  headed paths are NOT live-tested yet.
- Merge + deploy sequence (after the baseline soak and the warm/renewal gate):
  1. `focus_watch.py -s` on the baseline (2026-10-08 13:53 → 2026-10-09 ~14:00).
  2. `browser.py switch headless` on the real profile; warm + renewal columns of the
     site matrix; record here.
  3. Merge the branch to main, `browser.py switch headless` once (deploy step), run
     `doctor`.
  4. Live-test the guided path once: `agent-login.py -g <site>` (lease → headed → back).
  5. Update `sdsc/openai-api/openai-team.py` (assumes a headed shared browser, waits 5 min
     for a human) — README "Known consumers to update".
  6. Wrap the Playwright MCP in `register-exec` (mydotfiles MCP config, also
     `localhost` → `127.0.0.1`).

- 2026-10-08 decisions/results: full-day baseline SKIPPED (Albert) — partial baseline
  13:53–15:53 (screen mostly locked): 0 on-screen Chrome windows, 0 activations, 0
  raises; 145 off-screen windows of other headless Chromes (now informational in `-s`,
  `787f769`); 2 Touch-ID (`coreautha`) prompts not from this browser.
  Warm + renewal gate on the real profile (headless since 15:53): every matrix site ✅
  logged in; claude.ai + chatgpt.com after deleting `cf_clearance`/`__cf_bm` (partitioned —
  `Storage.getCookies` needed): no challenge, new clearance issued silently, still logged
  in; anthropic-api roster read ✅, Slack xoxc ✅, LAN vaultwarden ✅, download ✅,
  `agent-login.py -c` no headed fallback, no headless regression (the 13 ❌ sites were ❌
  before). Non-headless failures filed: tp#843 (login cscs hang, no timeout), tp#844
  (openai-team selector + headed assumption), tp#845 (logged-in hijacks tabs by URL).
  Phase 2 merged `4cda030`, `doctor` all ✅ on the live browser. Playwright MCP wrapped in
  `register-exec` (mydotfiles `dotfiles/claude/.claude/mcp/playwright.json`,
  `link_all_using_stow.sh`; cpriv local-scope entries re-registered; cwork entries need
  `claude-config-sync.py -a` with no Claude session open).

### Phase 1 — headless gate (site outcomes, not fingerprint spoofing)

- [x] Diagnostic dump in headless + plain UA: `userAgent`, `userAgentData.brands`, request
      `Sec-CH-UA`, `webdriver`, WebGL vendor, `outerWidth` (informational only).
- [x] Site matrix, each a real logged-in read, three ways — warm (persisted profile),
      cold (disposable headless profile, no `cf_clearance`), renewal (delete `cf_clearance`
      in the real profile, reload): claude.ai work (`anthropic-api.py` team read),
      chatgpt.com (`openai-team.py -ta` dry-run), Slack, Notion, CSCS, SWITCH Cloud,
      Vaultwarden, Smartsheet, Infomaniak, GitLab admin, a `*.dom42.space` LAN site
      (launched from a terminal AND from launchd), downloads, screenshots, a full
      `agent-login.py` run. ✅/❌ per cell recorded here.
- [x] Gate: all ✅ → Phase 2. A ❌ that only headed fixes → Fallback phase.

### Phase 2 — enforce headless

- [x] Persisted `desired_mode=headless`; `up` always headless; `up --headed` and
      `CLAUDE_BROWSER_HEADLESS=0` removed. Headed only inside a live maintenance lease.
- [x] Every `browser.py` command preflight: headed without a live lease → revert to
      headless before doing work. `agent_login_jobs.py` ~284–290: a failed switch back is a
      loud ❌ + retry, never silently ignored.
- [x] `browser.py login` never opens a human flow: unattended or exit with
      `needs Albert: agent-login.py -g <site>`. No TTY/env heuristics.
- [x] Remove all non-guided `bring_to_front` calls (inventory of the 8 sites in this file).
- [x] Native UI suppression, fault-tested to fail closed: notification/permission prompts
      denied (profile prefs + launch flags), downloads via `Browser.setDownloadBehavior` to a
      fixed dir, `op`/Touch-ID fallback disabled in unattended paths, broker keychain
      `security` ACL prompts listed and pre-authorised or failed closed. Chrome-for-Testing
      auto-update documented as not applicable (Playwright-cache managed).
- [x] Register the Playwright MCP: `browser.py register-exec -t playwright-mcp -- npx -y
      @playwright/mcp@0.0.76 --cdp-endpoint http://127.0.0.1:9222` in mydotfiles' MCP
      configs (also `localhost` → `127.0.0.1`). `register-exec` refuses to spawn while the
      browser is headed without a live maintenance owner.
- [x] Remove `--remote-allow-origins=*`: first audit every consumer's WebSocket Origin
      (Playwright py/node send none; `websocket-client` sends the same origin), then retest
      all consumers.
- [x] `doctor`: certify `mode=headless`, frontmost unchanged, no unregistered CDP peers.

### Phase 3 — guided login (B primary, A fallback)

Status 2026-10-09 — first live B run (Notion, cookies deleted first,
`browser.py assisted-login notion -f` because another session's bare-npx MCP was attached):
✅ result 0 in 5 min 40 s; record, heartbeat, watchdog, owned target (closed=1 owned=1),
`maintenance/end result=ok problems=0`, record file gone, `logged-in notion` ✅, `doctor`
all ✅. focus_watch over the session: zero Chrome activations; 3 Chrome `window_new`, all
`on_screen: false`, never shown. Typing, email-code paste and clicks through the viewer
worked. Notion dropped the fresh login on `/onboarding` ("Join teammates…"); "‹" →
"Back to previous workspace" reached the sidebar. Defects found → fixed in the follow-up
commit: no `-F` pass-through on `agent-login.py -g`; the relay's `opener=unknown` note
(our own `logged-in` probe tabs) overwrote the viewer banner; the viewer said "reload to
reconnect" after success instead of ✅; a ⚠ for the normal no-Brave path. Deviation: Brave
is not installed, so the viewer opens in the DEFAULT browser (Safari, Albert's daily
profile) — accepted for now: loopback-only, one-shot token bound to an HttpOnly cookie,
relay exposes only owned targets.

- [x] Single entry: `agent-login.py -g <site>` → `browser.py assisted-login <site>`,
      confirmation typed on `/dev/tty`.
      2026-10-09: done; `agent-login.py -g SITE -F` passes `-f` through (13ae308).
- [x] Maintenance transaction (B and A): take the client gate exclusively; pause registered
      long-lived clients (the `register-exec` wrapper SIGSTOPs its child's process group,
      SIGCONTs on clear); refuse if unregistered CDP peers exist (`-f` overrides); write the
      maintenance record (owner nonce, 10 s heartbeat) while holding the gate; new
      registrations without the owner token refuse; interaction lease held throughout;
      clear, then SIGCONT.
- [ ] Test SIGSTOP/SIGCONT on `@playwright/mcp@0.0.76` mid-session (pending calls, socket
      survival). If it breaks MCP: documented manual `browser_close`/reconnect instead.
- [ ] Watchdog: detached process spawned by the transaction (plus a check in the
      LaunchAgent watcher) reverts headed → headless and closes owned targets within 30 s of
      a stale heartbeat. Residual, stated: an already-running MCP reconnecting inside that
      window after a SIGKILL could reach a headed browser — covered by the SIGKILL fault test.
- [x] B spike on the pinned CfT 153, pass criteria: typing, Tab/Enter/modifiers/dead keys,
      clipboard paste of a password, non-ASCII + IME composition, scrolling, scaled-coordinate
      clicks. Stock DevTools screencast first (same-origin from `127.0.0.1:9222`); expected
      result: own minimal viewer — screencast frames + hidden textarea,
      `beforeinput`/paste/composition → `Input.insertText` / `Input.imeSetComposition`,
      mouse/wheel → `Input.dispatchMouseEvent` — served by a tokenized loopback relay that
      exposes only that CDP subset for owned targets, with exactly its origin allowed.
      2026-10-08: all criteria ✅ (results: stock screencast rejected, own viewer `bin/login_viewer.py`); 2026-10-09 live Notion login through it.
- [x] Viewer opens in a dedicated extension-free Brave profile (or a CfT app-mode window
      with its own throwaway profile) — never Albert's daily profile.
      Deviation accepted 2026-10-09: no Brave on this Mac → default browser (Safari); loopback only, one-shot cookie-bound token, owned targets only.
- [x] Owned targets: B always creates a dedicated login target (never reuses a site tab);
      a target supervisor follows new targets whose `openerId` is owned (OAuth popups),
      switches the viewer to them, handles popup close + opener redirect, never selects a
      non-owned tab. Owned ids live in the maintenance record and are closed on success,
      timeout, cancel and stale-heartbeat recovery.
- [x] Unsupported surfaces end B within seconds with a named reason: JS dialogs handled in
      the viewer; WebAuthn/passkey, permission requests, client-cert and external-protocol
      prompts → close owned targets, offer fallback A in the same transaction. B idle
      timeout 5 min.
      Implemented and unit-tested (df04a95); live passkey/permission cases stay in the acceptance matrix below.
- [ ] Fallback A: transactional `switch headed` → login with the window shown →
      `switch headless`, inside the same maintenance lease; the only path allowed to show or
      raise a window.

### Phase 4 — docs and acceptance

- [x] Docs: README "Why you never see the window" (headless default, why the old NO-GO
      changed, guided login B/A, invariant), AGENTS.md conventions, `README_AUTOLOGIN.md`.
      2026-10-09: README §"Why you never see the window", AGENTS.md conventions, README_AUTOLOGIN.md paragraph.
- [ ] Live acceptance matrix, ✅/❌ recorded here: SIGKILL during guided login, failed
      switch back, active MCP work during B, browser restart, sleep/wake, OAuth popup in B,
      download, permission prompt, passkey site (B → A handoff), launchd cold start, LAN,
      Cisco VPN, cold Cloudflare challenge, leftover viewer tab after cancel.
- [x] Soak: one working day with `focus_watch.py`. Pass = ZERO Chrome-for-Testing
      activations or window creations outside a live guided-login lease, fault tests
      included. On the first unexplained event: put a logging CDP proxy in front of MCP;
      if still unexplained, make the proxy the only 9222 endpoint (Chrome on an internal
      port).
      2026-10-09 PASS: focus log 2026-10-08 15:53 → 2026-10-09 14:02 (22 h incl. a working day, a guided login, 2 browser restarts by another session): 0 Chrome activations, 730 `window_new` all off-screen, 0 shown.

### Fallback phase — only if Phase 1's gate fails

- [x] Spike a second macOS GUI user first: off-session rAF/input/screenshots, cross-user
      loopback CDP, fast user switching, reboot + FileVault recovery, Local Network TCC,
      Cisco VPN.
      Not needed: Phase 1's gate passed (headless works for every site).
- [x] Then a Linux VM (OrbStack/Lima, headed on Xvfb): decide where lifecycle/login code
      runs and how control crosses the boundary; expect full re-login; test Cisco
      split-tunnel routing and internal DNS from inside the VM.
      Not needed: Phase 1's gate passed (headless works for every site).
- [x] Pick by that matrix; nixos stays rejected.
      Not needed: Phase 1's gate passed (headless works for every site).

## Verification

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && git diff --no-ext-diff --no-textconv --check && ruff format --check bin/ tests/ agent-login.py agent_login_jobs.py && ruff check bin/ tests/ agent-login.py agent_login_jobs.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run --no-sync pytest -q
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run --no-sync mypy bin/browser.py agent-login.py agent_login_jobs.py && uv run --no-sync pylint bin/browser.py agent-login.py agent_login_jobs.py
cd /Users/albert/obsidian/42-Git/home/browser-login && bin/browser.py -h && bin/browser.py up -h && bin/browser.py switch -h && bin/focus_watch.py -h && ./agent-login.py -h
cd /Users/albert/obsidian/42-Git/home/browser-login && pre-commit run --all-files
```

The live acceptance matrix and the soak (Phase 4) are acceptance evidence on the real
browser, recorded in this file — not part of the reproducible block above.
