# Chromium build bump (Keychain grant + pin move)

Why (tp#2537): Chromium encrypts its cookies with a key from the login Keychain
item **"Chromium Safe Storage"** (account `Chromium`). macOS hands that key only to
the apps on the item's ACL application list. Every Playwright build is a new `.app`
path (`~/Library/Caches/ms-playwright/chromium-<rev>/chrome-mac-arm64/Google Chrome
for Testing.app`), so a new build is NOT on the list: it gets no key, and the profile
writes no cookies to disk — logins work until the next restart, then all are gone.
Never work around it with `--use-mock-keychain` (Albert, 2026-11-21).

Guards in `bin/browser.py`:

- `PINNED_CHROMIUM_REVISION`: every instance launches only this build.
- Pre-launch Keychain check (`_keychain_grant_gate`): the pinned build's `.app` must be
  on the item's decrypt ACL (read-only `security dump-keychain -a`, cached per revision
  in `~/.local/share/claude-browser/playwright-pin/keychain-acl.json`; a miss is
  re-checked after 10 min). Missing → an unattended launch (`AGENT_LOGIN_SCHEDULED=1`)
  is refused with "grant needed: <this file>", an attended one warns.
- Cookie canary in `browser.py doctor`: persistent cookies in memory (CDP) vs rows in
  `Default/Network/Cookies` (read-only, immutable open), judged after 60 s uptime;
  ❌ when memory > 0 and the db is missing or empty.

## Steps (attended: Albert at the unlocked Mac)

1. Install the new build next to the pinned one (`uv run --with playwright==<ver>
   playwright install chromium`) and note its revision `<new>`.
2. Disposable instance on the new build (never the live 9222-9225 instances):

   ```
   env CLAUDE_BROWSER_CACHE_DIR=/tmp/cb-bump CLAUDE_BROWSER_CHROMIUM_REVISION=<new> \
     bin/browser.py --cdp-port 9333 up
   ```

   The launch warns "grant needed" (attended). Load any page that sets a persistent
   cookie (`… browser.py --cdp-port 9333 open -N https://example.com/`).
3. macOS asks: "Google Chrome for Testing wants to use your confidential information
   stored in 'Chromium Safe Storage' in your keychain." Albert types his login password
   and clicks **Always Allow** (not "Allow": that grants one read only). If the prompt
   names another item, that build asks for a different item: stop, update
   `KEYCHAIN_SAFE_STORAGE_SERVICE` first.
4. Prove it on the disposable instance: wait 60 s, then `… browser.py --cdp-port 9333
   doctor` shows `✅ cookie canary`; `down`, `up` again, the cookie is still there and
   the canary is still green. Then `down` and remove `/tmp/cb-bump`.
5. Pin move, in this order:
   1. The grant is proven (step 4).
   2. Back up each profile's `Default/Network/Cookies` and `Local State`
      (`~/.cache/claude-browser[-<instance>]/profile/`), set
      `PINNED_CHROMIUM_REVISION = <new>`, land it, restart the PRIVATE instance only:
      canary green and `agent-login.py -L console-private` / `logged-in` ✅.
   3. default/admin/alt move at their natural next restart — an agent never restarts
      them. Keep the old build's `.links` entry (`_ensure_chromium_pin_link`) until
      every instance passed the canary on the new revision.
