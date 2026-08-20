# PLAN: fully non-interfering background browser for automation

## Session

Resume: `c --resume 44e9d484-4ec0-4ce4-8635-b8ee209fb5a2`

## Problem

The shared automation Chromium (browser.py, CDP :9222) must never interfere
with Albert's desktop work: no focus steal, no window raising, ideally no
visible window at all — while remaining fully drivable (clicks, keystrokes,
screenshots) by anthropic-api.py / openai-team.py / MCP browser tools.

## Facts established 2026-08-19/20 (this session)

1. The window launches behind everything (`open -g -n`) and never takes focus.
2. An occluded/background window has **rendering paused by macOS**:
   `requestAnimationFrame` freezes → Playwright's actionability wait ("stable"
   = 2 consecutive rAF frames) times out on every normal click; screenshots
   stall. The launch flags `--disable-backgrounding-occluded-windows`,
   `--disable-renderer-backgrounding`, `--disable-background-timer-throttling`
   did NOT unfreeze rAF on macOS.
3. `page.bring_to_front()` (CDP, tab-level) unfreezes rAF **without raising the
   macOS window**: verified via the window-server z-order
   (`CGWindowListCopyWindowInfo` — Chrome for Testing stayed behind Brave and
   iTerm after the call) and without focus change. So the current mechanism is
   already non-interfering; the window is merely present on the desktop /
   in Mission Control.
4. Downstream flows additionally use robust clicks (normal → `force=True`
   fallback) and bounded screenshot timeouts, so they survive even a frozen
   window.

## Plan (future work, in order)

- [ ] **Spike: headless-by-default.** Add `browser.py up --headless` (new
      headless mode, `--headless=new`), same profile dir. Validate the two
      critical sessions survive: `logged-in anthropic` + a claude.ai
      admin-page DOM read, `logged-in openai` + a chatgpt.com admin read.
      Risk to test: Cloudflare/anti-bot heuristics on claude.ai and
      chatgpt.com may treat headless differently; sessions may be flagged.
- [ ] **Dual-mode lifecycle.** If the spike passes: make headless the default
      for `up`; `browser.py up --headed` (and `login SITE`, which needs a human)
      auto-restarts the browser in headed mode and back. Guard: refuse
      mode-switch while another CDP client is connected.
- [ ] **Fallback if headless is flagged:** keep today's headed-behind-windows
      launch and codify the non-interference contract instead:
      `open -g -j` (launch hidden), never call app-level activation,
      tab-level `bring_to_front()` only (documented as z-order-safe), robust
      click + bounded screenshot patterns in every consumer (already done for
      anthropic-api.py; port to openai-team.py).
- [ ] **Regression check script.** `browser.py doctor`: asserts (a) CDP up,
      (b) rAF alive on the active tab after `bring_to_front()`, (c) frontmost
      app unchanged and Chromium window not top-of-z-order after a full
      open→click→screenshot cycle (via CGWindowList), so interference
      regressions are caught mechanically.
- [ ] Docs: README section "Why you never see the window" + consumer contract.
