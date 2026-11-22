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
  `CDHash=`) is on the item's `partition_id` list (`cdhash:<hex>`). Cached per
  revision, `.app` and CDHash in `~/.local/share/claude-browser/playwright-pin/keychain-acl.json`
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
5. Pin move, in this order (tp#2537 B2b):
   1. The grant is proven (step 4).
   2. Prove the migration on a disposable COPY of the default profile first: copy
      `Default/Cookies` (or `Default/Network/`), `Local State`, `Last Version` and
      `Default/Preferences` into `/tmp/cb-mig/profile/`, then
      `env CLAUDE_BROWSER_CACHE_DIR=/tmp/cb-mig CLAUDE_BROWSER_CHROMIUM_REVISION=<new>
      bin/browser.py --cdp-port 9333 up` (attended): it prints the backup, "✓ cookies
      migrated … N exported, N written", and after 60 s `doctor` shows the canary green
      with about the exported count. `down`, `up` again (no second migration), `down`,
      remove `/tmp/cb-mig`.
   3. Set `PINNED_CHROMIUM_REVISION = <new>`, land it. Keep the old build installed:
      the migration exports through it.
   4. Restart the PRIVATE instance attended (`env CLAUDE_BROWSER_INSTANCE=private
      browser.py down`, then `… up` from a terminal): the `Last Version` guard backs the
      profile up and migrates the cookies; canary green and `agent-login.py -L
      console-private` / `logged-in` ✅.
   5. default/admin/alt move at their natural next restart — an agent never restarts
      them. An attended `up` migrates them the same way; an unattended launch
      (`AGENT_LOGIN_SCHEDULED=1`) refuses. Keep the old build and its `.links` entry
      (`_ensure_chromium_pin_link`) until every instance passed the canary on the new
      revision.

## Why a new Chrome major can wipe the jar (Last Version guard, migration)

Measured 2026-11-22 on disposable copies (tp#2537 B2b): Chrome 158 (chromium-1254)
enables the feature `KeychainKeyProviderUserDataDirProtection` and encrypts its
cookies with a NEW key (rows start with `v11`); Chrome 156 (chromium-1248) uses the
legacy `v10` key from the same "Chromium Safe Storage" password. Each build deletes
every row it cannot decrypt at startup: 1254 wipes a 1248 jar (1555 rows → 0), 1248
wipes a 1254 jar. Not the cause: the Keychain item (only one exists, both builds read
it; with the feature disabled 1254 reads the `v10` rows), `Local State` (no `os_crypt`
key on macOS), the Cookies schema (24 on both) or the move of `Default/Cookies` into
`Default/Network/`.

So `_launch_and_record` compares the profile's `Last Version` major with the pinned
build's. When the pinned build is newer: unattended → refuse naming this file;
attended → (1) a full backup into `~/.cache/claude-browser[-<instance>]/profile-backups/
<time>-chrome<old>-to-<new>/` (`Default/Network/`, `Default/Cookies`, `Default/Preferences`,
`Local State`, `Last Version`; `manifest.json` records each cookie db's row count and
the backup is checked against the source), (2) the old build (an installed revision
of the profile's major) starts headless on the profile, its persistent cookies are read
over raw CDP (`Storage.getCookies`, in memory only), it is closed, (3) the pinned build
starts and they are written back (`Storage.setCookies`; never a cloudflareaccess.com
cookie, the Access team sweep in a `finally`). Fewer than 90 % in memory afterwards
→ ❌ with the rollback command. A downgrade (profile newer than the pin) only warns:
the old build deletes the `v11` rows too.

Rollback (browser down): `browser.py cookie-rollback -l` lists the backups;
`browser.py cookie-rollback [-b <backup dir>]` moves the current items aside into
`<backup>/replaced-<time>/` (nothing is deleted), restores the backup and fails unless
each restored cookie db's row count equals the recorded one. Then pin the old build
again before the next start (a start on the new build would migrate again).
