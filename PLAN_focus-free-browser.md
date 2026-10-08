## Session

Resume: `c --resume 7d725bed-5c4e-4909-82fc-dd9a58934d10`

# PLAN: the shared browser never disturbs Albert's desktop

## Goal

Agents keep using the shared logged-in browser (CDP `127.0.0.1:9222`, `browser.py`,
Playwright MCP `browser_*`) all day, and Albert never loses keyboard focus or sees a
window pop up because of it. The one exception is a login that Albert himself starts.

## Requirements (Albert, 2026-10-08)

| Item                    | Answer                                                                                   |
| :---------------------- | :--------------------------------------------------------------------------------------- |
| What steals focus today | All three: agents browsing (MCP/`browser.py`), login checks/logins, browser (re)start    |
| Visibility              | Only for logins, on demand; otherwise never visible                                      |
| Off home network        | Must work everywhere: EPFL, travel, Cisco VPN, EPFL/ETH-internal sites                   |
| Acceptable placements   | Any (Mac headless, Linux VM on the Mac, nixos, second macOS user) — pick on the merits    |

## Facts this plan builds on

- Focus steals have three sources in our code: ~7 login paths call `page.bring_to_front()`
  on purpose (`bin/browser.py`, login flows), the rendering-freeze escalation in `doctor`,
  and the headed cold launch. Playwright MCP calls `page.bringToFront()` on tab
  select/new tab. On Chrome for Testing 151+ any of these can make Chrome frontmost
  (`PLAN_background-browser.md`, measured 2026-08-20).
- A headless browser has no window: nothing can be raised, nothing can take focus, and
  the occlusion rendering freeze cannot happen.
- The old blocker against headless is gone: `--headless=new` announced `HeadlessChrome`
  in the User-Agent and Cloudflare blocked claude.ai/chatgpt.com. Commit `34c78ea`
  (2026-10-06) passes a plain Chrome UA on headless launches; claude.ai loads with it
  (the private instance on 9223 already runs headless). The README section "Why you never
  see the window" still says "NO-GO" — stale.
- Unverified: whether other headless traits leak (UA Client Hints `Sec-CH-UA` /
  `navigator.userAgentData.brands` may still name `HeadlessChrome`; WebGL vendor;
  `window.outerWidth` = 0). Phase 1 tests exactly that.
- The Playwright MCP config (`~/.claude/mcp/playwright.json`) runs `npx @playwright/mcp`
  directly, NOT through `browser.py register-exec` — so `switch` cannot see or drain it.

## Options considered

| Option                                  | Verdict      | Why                                                                                                                                                      |
| :-------------------------------------- | :----------- | :------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Mac, headless by default                | **Chosen**   | Removes the window, hence every focus source, at once; same network/VPN/Keychain/LAN grant as today; mostly a default flip + login handling              |
| Linux VM on the Mac (OrbStack, Xvfb)    | Fallback     | Never a macOS window, real headed fingerprint, same network via NAT. Costs: Mac cookies are Keychain-encrypted (profile not portable → CDP cookie transfer or re-login), Linux UA, VNC for logins, one more VM to keep alive |
| nixos (headed on Xvfb, CDP via SSH)     | Rejected     | Fails "works everywhere": off-LAN everything rides WireGuard, EPFL-VPN/EPFL-IP-restricted sites unreachable, downloads/uploads cross-host; also puts Vaultwarden/Slack/Anthropic-admin sessions on a 2014 laptop |
| Second macOS user (fast user switching) | Rejected     | Separate Keychain + Local Network grant, needs a background GUI login that survives reboots (FileVault), rendering in an inactive session unverified — more moving parts than headless for the same result |

## Steps

### Phase 0 — find out who steals focus (evidence first)

- [ ] `bin/focus_watch.py` (`-h`, short flags, ✅/❌ markers): logs every frontmost-app
      change (NSWorkspace activation notification via pyobjc, or `lsappinfo` polling as a
      fallback) with timestamp, previous app, new app; on a change TO Chrome for Testing
      it also records the lifecycle record, registered clients (`clients/`), the
      interaction-lease holder and `lsof` CDP peers, so each steal names its caller.
- [ ] Run it for one normal working day (LaunchAgent or a background shell), then
      tabulate steals by caller. Expected: MCP tab select, assisted/unattended login
      fallbacks, headed (re)starts. Anything else becomes a step below.
- [ ] Find who started the headed browser at 2026-10-08 11:41 (lifecycle log /
      client registry) — an unattended path that starts headed is a bug on its own.

### Phase 1 — headless by default on the Mac

- [ ] **Fingerprint check, headless + plain UA, on the real profile** (`switch headless`):
      `navigator.userAgent`, `navigator.userAgentData.brands`, request header `Sec-CH-UA`
      (via a CDP `Network.requestWillBeSent` capture), `navigator.webdriver`, WebGL
      vendor/renderer, `outerWidth/outerHeight`. Fix every `HeadlessChrome` leak (e.g. CDP
      `Emulation.setUserAgentOverride` with `userAgentMetadata` on each new target, or the
      matching launch switch) before the site matrix.
- [ ] **Site matrix headless** — each with a real logged-in read, never the sentinel
      alone: claude.ai work (`anthropic-api.py` team read), chatgpt.com
      (`openai-team.py -ta` dry-run), Slack, Notion, CSCS, SWITCH Cloud, Vaultwarden,
      Smartsheet, Infomaniak, GitLab admin, one `*.dom42.space` LAN site (Local Network
      grant when launched from launchd vs a terminal), downloads, screenshots,
      `agent-login.py` full run. Record ✅/❌ per site in this file.
- [ ] Decision gate: all ✅ → continue Phase 1. A site that only works headed → Phase 2
      for the whole browser (one profile cannot be in two modes) unless that site is
      rare enough to live with the on-demand headed switch below.
- [ ] Flip the default: `up` starts headless; `-W/--headed` (and
      `CLAUDE_BROWSER_HEADLESS=0`) opts into a window. `agent-login.py` already starts
      headless — keep it.
- [ ] **No unattended path ever goes headed.** `browser.py login <site>` in a
      non-interactive context (no TTY, `$CI`, launchd, `CLAUDE_BROWSER_UNATTENDED=1`, any
      agent session) never falls back to the window flow: it exits with a distinct code and
      the message `needs Albert: agent-login.py -g <site>`. Covers the daily check.
- [ ] **On-demand login window.** `agent-login.py -g <site>` / interactive
      `browser.py login <site>`: transactional `switch headed` (drains registered clients,
      refuses with names while one is busy) → login with the window shown → `switch
      headless` back in a `finally`, also on Ctrl-C/timeout. This is the only path allowed
      to show or raise the window.
- [ ] `bring_to_front` calls: skip them when the running mode is headless (no-op there,
      but keep the contract explicit); keep them only inside the on-demand login window.
- [ ] Register the Playwright MCP: wrap it in `browser.py register-exec -t playwright-mcp --
      npx -y @playwright/mcp@0.0.76 --cdp-endpoint http://127.0.0.1:9222` (also fixes
      `localhost` → `127.0.0.1`, AGENTS.md rule) in mydotfiles' MCP configs, so `switch`
      drains it instead of failing closed or cutting it.
- [ ] `doctor`: certify `mode=headless` and frontmost app unchanged; warn when the browser
      is headed with no login lease held (a window left over from a login).
- [ ] Docs: README "Why you never see the window" (headless is the default, why the old
      NO-GO no longer holds, the on-demand login window), AGENTS.md conventions,
      `README_AUTOLOGIN.md` if consumers are affected.
- [ ] Verify: re-run `focus_watch.py` for one working day with the new default — zero
      steals outside Albert-started logins. Then this plan is done.

### Phase 2 — only if Phase 1's gate fails: Linux VM on the Mac

Spec only; build nothing unless the gate above sends us here.

- [ ] OrbStack (or Lima) Linux VM; headed Chrome for Testing on Xvfb; CDP bound to the VM
      and forwarded to `127.0.0.1:9222` on the Mac only (never the LAN).
- [ ] Logins: VNC/noVNC viewer opened by `agent-login.py -g` only.
- [ ] Migrate sessions: export cookies from the Mac profile over CDP
      (`Storage.getCookies`) → import into the VM (`Storage.setCookies`); re-login what
      does not survive (UA/platform change).
- [ ] Downloads: a shared folder Mac↔VM; check VPN routes and `*.dom42.space` from the VM.

## Open decisions

- Accept that a login Albert starts restarts the browser twice (headless → headed →
  headless, ~5–10 s each) and refuses while an agent is mid-task? Recommended: yes — the
  alternative (a headed window that stays up) is today's problem.
