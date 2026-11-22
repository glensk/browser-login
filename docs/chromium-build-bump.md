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
- Pre-launch Keychain check (`_keychain_grant_gate`, read-only `security dump-keychain
  -a`; the password is never read, `security … -w` is forbidden). Granted means: the
  pinned build's `.app` is on the item's decrypt ACL with a verified entry (see "ACL
  status codes" below) AND the binary's CDHash (`codesign -dvvv <app>`, line
  `CDHash=`) is on the item's `partition_id` list (`cdhash:<hex>`). Cached per revision
  - `.app` + CDHash in `~/.local/share/claude-browser/playwright-pin/keychain-acl.json`
  (granted for good, a miss re-checked after 10 min). States: `missing` (not listed),
  `unknown` (listed but the entry is unverified, the CDHash is not partitioned, or
  `codesign` gave no CDHash) → an unattended launch (`AGENT_LOGIN_SCHEDULED=1`) is
  refused with "grant needed: <this file>", an attended one warns; `absent` (no item
  yet) and `error` (the dump failed) only warn.
- Cookie canary in `browser.py doctor`: persistent cookies in memory (CDP) vs rows in
  `Default/Network/Cookies` (read-only, immutable open), judged after 60 s uptime.
  ❌ when memory > 0 and the db is missing or empty; when memory is 0 but the db has
  rows (the jar is unreadable); and when the db's rows dropped by more than 50 % and
  more than 10 rows against the count `_launch_and_record` recorded right before the
  spawn (`~/.cache/claude-browser[-<instance>]/cookie-baseline.json`; a build that
  wipes the jar at startup reads 0/0, which alone looks green).

## ACL status codes

`security dump-keychain -a` prints each ACL application as `<path> (OK)` or `<path>
(status N)`, followed by its stored requirement. Decode a code with `security error N`.

- `status -2147415734` = `0x8001094A` `CSSMERR_CSP_VERIFY_FAILED`. `security`
  re-validates the app on disk against the stored requirement as a full bundle; the
  Playwright "Google Chrome for Testing" builds are linker-signed ad hoc with no sealed
  resources, so that validation fails (`codesign --verify --strict` says "code has no
  resources but signature indicates they must be present") for EVERY listed build,
  granted ones included (seen 2026-11-22 on 1223, 1243, 1248, 1254; 1254 provably read
  the key and kept its cookies). The stored requirement is `cdhash H"<hex>"`, the
  binary's exact CDHash, and that is what macOS matches at run time together with the
  `partition_id` list. So the check accepts this status only when the requirement's hex
  equals the binary's CDHash; otherwise the entry is `unknown`.
- `status -67068` = `errSecCSStaticCodeNotFound` ("cannot find code object on disk"):
  the build was deleted. `unknown`.
- Any other non-OK status: `unknown` until its meaning is documented here.

## Steps (attended: Albert at the unlocked Mac)

1. Install the new build next to the pinned one (`uv run --with playwright==<ver>
   playwright install chromium`) and note its revision `<new>`.
2. Disposable instance on the new build (never the live 9222-9225 instances):

   ```
   env CLAUDE_BROWSER_CACHE_DIR=/tmp/cb-bump CLAUDE_BROWSER_CHROMIUM_REVISION=<new> \
     bin/browser.py --cdp-port 9333 up
   ```

   The launch warns "grant needed" (attended). Load any page that sets a persistent
   cookie (`… browser.py --cdp-port 9333 open -N https://www.google.com/`;
   example.com sets none, so it neither triggers the prompt nor tests the canary).
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
