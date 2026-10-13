## Session

Resume: `c --resume 3871ad21-0f16-4b68-828e-f9eb1f7a6847`

## Status

WON'T DO (Albert, 2026-10-13): little gain today — the Safari vault locked twice in one day (one of them self-inflicted), and no recipe hit an SMS code. Cost: the agent-vault master password would be readable by any agent (breaks the vault-touchid promise), and adb SMS access is fragile. Plan and Codex round 1 are kept in browser-login/PLAN_ws1b-agent-vault-sms.md for a later revisit. Previously: PARKED (Albert, 2026-10-13): resumes after plans-done/PLAN_ws1b-durability_DONE.md is done. Parent: plans-done/PLAN_ws1b-durability_DONE.md (tp#949) → plans-done/PLAN_agent-login-repair_DONE.md (tp#880). Codex debate round 1 ran (below, unreconciled); next: write the round-1 ledger, judge, rounds 2-3, then Albert's open questions.

# WS1b follow-up (tp#955): agents unlock the agent vault and read SMS codes themselves

## Context

`plans-done/PLAN_ws1b-durability_DONE.md` (D3, closure matrix) and AGENTS.md's WS1b section keep five stops
for Albert: `needs_albert_captcha|sms|push|hardware_key|vault_locked`. Albert, 2026-10-13,
narrowed that list:

1. **The Vaultwarden account `albert.glensk@gmail.com`** (`https://vaultwarden.dom42.space`)
   is the AGENTS' account. `albert.glensk+vault@gmail.com` is Albert's personal one. Agents
   may unlock the agent account's web-vault tab in Albert's Safari themselves. They never
   touch the personal account.
2. **SMS codes:** agents read them from Albert's Pixel 9a (GrapheneOS) themselves.

After this plan, `needs_albert_vault_locked` no longer exists for the agent account.
`needs_albert_sms` stays only for a phone the agent cannot reach.

### What exists today (read-only evidence, 2026-10-13)

- **safari.py** (mydotfiles `bin/safari.py`) finds the vault tab by URL substring
  (`$SAFARI_VAULT_URL`, default `vaultwarden.dom42.space`). Its `VAULT_FN` detects the
  lock screen (route `#/lock|login|sso|2fa` or a master-password input) and exits 3:
  "agents never unlock it". `agent_login_safari.error_code` maps that exit to
  `needs_albert_vault_locked`. `-L/-O` take the flock `~/.cache/safari-py/vault.lock`.
  `run_js` already passes JavaScript to osascript through a private 0600 temp file, never argv.
- **vault-touchid** (mydotfiles `tools/vault-touchid`): its `main` account IS
  `albert.glensk@gmail.com`. The master password sits in a Secure-Enclave envelope that
  opens only with Touch ID. Its README promises "no documented tool path hands the main
  account's master password … to the requester". A Keychain copy that agents can read
  breaks that promise. See Open question 1.
- **Beeper Desktop API** (`/v1/accounts`): the networks are Beeper (matrix), Signal, Slack
  and WhatsApp. **No SMS / Google Messages bridge.** Beeper cannot read SMS today.
- **adb**: `/opt/homebrew/bin/adb` (1.0.41) is installed. The Mac's key is authorised on the
  phone. The repo `home/pixel_9a_graphen_os` has `scripts/adb_pick.py` (picks the serial),
  `scripts/pixel-connect-adb.py` (USB → fixed port 5555 → mDNS → off-LAN WireGuard relay
  via `nixw`) and `scripts/pixel_ssh.py` (Termux sshd). `adb devices` was empty at 09:50, so
  the phone is not always reachable. Port 5555 dies on every phone reboot.
- **KDE Connect:** not installed on the Mac (`kdeconnect-cli` missing), and not on the phone
  (it is not in `apps.yaml`).
- **Termux:API:** not installed (only Termux is). `termux-sms-list` would need it plus a
  READ_SMS grant, which is a phone change.
- **The SMS app** is GrapheneOS's default SMS app. Messages land in the system
  `content://sms` provider, whichever app holds the role.

**Chosen SMS source:** `adb shell content query --uri content://sms/inbox …` over the
existing adb channel. It needs no phone change. Whether the adb shell uid may read
`content://sms` on GrapheneOS (Android 16) is UNVERIFIED and is spike L-S1. The fallback,
`dumpsys notification --noredact`, is decided there too.

**Debate needed:** this plan handles a master password and SMS 2FA, so it is
security-sensitive.

**Verification block:** it is not strict-eligible. It runs pytest, mypy and pylint, which
execute repository code. Every Safari, Keychain and phone step is a manual live-acceptance
step for the main session (L-V*, L-S*). Tests fake `safari.py`, `security`, `adb` and the
clock; no test touches the real Safari, Keychain or phone.

## Design

### V1 — where the agent vault's master password lives

- **Keychain item:** one generic password in the default (login) keychain.
  - service `agent-login-vault-master`;
  - account `albert.glensk@gmail.com`;
  - label "agent-login: Vaultwarden agent account master password".
  - It is never in `.env`, a file, argv, an environment variable, the transcript or the
    journal.
- **Enrolment:** `agent-login.py -K/--vault-enroll` is TTY-only and refuses without
  `/dev/tty` (exit 2).
  - Albert types the password twice with `getpass`.
  - It is written delete-then-add through `security -i`, with the command on STDIN (the
    pattern of `browser.py` ~6997), never `add-generic-password -w VALUE` in argv and never
    `-U`.
  - Enrolment does not prove the password. The first live unlock (L-V3) proves it.
- **Reading it:** a new stdlib module `agent_login_vault.py` has one function
  `read_master()` with the `_security_run` rules (AGENTS.md):
  - a new session;
  - no timeout, never `kill`/`terminate`;
  - it waits on a locked keychain;
  - argv is `security find-generic-password -s SVC -a ACCT -w <default keychain>`;
  - the value comes back on the pipe into a `bytearray`, is used once and is overwritten
    in `finally`.

  agent-login is stdlib-only and does not import `browser.py`. The function is therefore a
  small copy with the same contract, pinned by a test that mirrors
  `tests/test_credentials.py`'s `_security_run` tests. An AST test asserts that it is the
  module's only `security` caller.
- **`agent_login_keychain.py`'s listing** will show the item as agent-readable (its decrypt
  ACL trusts `/usr/bin/security`). That is intended. The listing names it, never its value.

### V2 — the unlock (mydotfiles safari.py feature `vault_unlock`, spec M7)

The unlock lives in safari.py, because safari.py owns the vault tab, its flock and
`VAULT_FN`. `agent_login_vault.unlock()` drives it.

- **The call:** `safari.py --unlock-vault --expect-email albert.glensk@gmail.com -j`. The
  password arrives on STDIN (a pipe from agent-login), never argv or env. safari.py refuses
  a TTY stdin.
- **Under the vault flock (`-W` wait), in order:**
  1. **Exactly ONE tab** matches `$SAFARI_VAULT_URL`. Its full origin must equal
     `https://vaultwarden.dom42.space` (`pin_origin`; the host is pinned, not
     substring-matched). 0 tabs → `vault_tab_missing`; more than one → `vault_tab_ambiguous`.
  2. **The state read** is one JS call that returns only an enum and booleans:
     - `state`: `unlocked` / `lock` / `login` / `other`;
     - `email_match`: the lock screen's "logged in as …" e-mail, exactly the e-mail
       sent with the call (lowercased, trimmed, whole-token match; the expected e-mail goes
       into the JS file, never back out);
     - `personal`: the e-mail shown contains `+vault`, or any `+` tag.

     Only booleans leave the page; the e-mail shown is never printed.
  3. **The checks:**
     - `unlocked` → exit 0, `already_unlocked`, no typing;
     - `personal` or `!email_match` → exit 2 `vault_wrong_account`, with NOTHING typed (the
       `+vault` account is refused by name and by mismatch);
     - `login` / `other` → exit 3 `vault_logged_out`, nothing typed (Open question 2).
  4. **Typing.** The password is written into the private 0600 JS file (native setter +
     `input`/`change` events on the ONE `input[type=password]` whose `formcontrolname`/`id`
     contains `master`). The exactly-one "Unlock" button is clicked
     (`read_submit_buttons`-style; none or more than one → `submit_unidentified`, nothing
     sent). The file is deleted in `finally`, and the password variable is overwritten.
  5. **Proof** (polled ≤ 15 s): the route left `#/lock`, the vault list rendered, and the
     account e-mail in the web vault's state is still the expected one (`email_match`
     again). Otherwise: `unlock_failed` (a wrong password shows Bitwarden's
     "invalid master password" toast → `unlock_rejected`).
- **What leaves safari.py:** `{ok, code, state}` only. No page text, no e-mail, no value.
- **One attempt per `-L` run.** `unlock_rejected` writes a client quarantine on the
  pseudo-site `vault`, so no agent retries a wrong master password into Vaultwarden's
  rate limiter. `agent-login.py -Q vault` releases it.
- **Where `-L` uses it:**
  - (a) **as a preflight** before the first clipboard step of a recipe (`user|login|otp`):
    `safari.py --vault-status -j` (new, read-only, feature `vault_status`) → if
    `lock` + `email_match` → unlock;
  - (b) **reactively, once**, when a clipboard step fails with the lock class. That failure
    is proven pre-credential, because safari.py checks `locked()` before any copy click.
    Unlock, then re-run that step once.

  Anything else from the unlock maps to its own code (V4). Nothing falls back to Albert
  except a missing Keychain item (`vault_master_missing` → "needs Albert: run
  `agent-login.py -K`").
- **After the run:** the vault stays unlocked. Albert's web vault timeout governs it (Open
  question 3).
- **Interactive gate:** the unlock runs only inside `-L`, so it inherits `-L`'s gates.
  These are `AGENT_LOGIN_SCHEDULED` refusal, `alsafari.interactive_gate` (console unlocked,
  Albert on console, idle < 15 min) and the `safari-login.lock` flock. No LaunchAgent ever
  unlocks the vault.

### V3 — vault-touchid / broker-add: unchanged

- The Touch-ID flows are untouched. That covers `broker-add.py` and `credctl.py`'s vault
  modes through `vault-touchid` (envelope, two touches, pinned child). They neither read
  nor use the new Keychain item. The new item is never added to vault-touchid's
  enrolment.
- **The promise changes:** the vault-touchid README's "What it guarantees" gains one line
  (mydotfiles spec M8, after Open question 1). The agent account's master password IS
  readable by same-user processes through the `agent-login-vault-master` Keychain item.
  The two-touch approval protects only the broker-add / credctl write path, not the
  account as a whole.

### S — SMS codes from the phone (`agent_login_sms.py`, stdlib)

- **Source:** adb only (Beeper has no SMS bridge; KDE Connect and Termux:API are not
  installed).
  - The serial comes from `pixel_9a_graphen_os/scripts/adb_pick.py`, resolved like
    safari.py: env override `AGENT_LOGIN_PIXEL_ROOT`, then the conventional sibling
    `~/obsidian/42-Git/home/pixel_9a_graphen_os`.
  - **Reachability:** `adb_pick.py` must give a serial with state `device`. If not, ONE
    `pixel-connect-adb.py -W -F --no-storage --no-syncthing` runs with a 60 s deadline
    (connect only: `-W` never arms `adb tcpip`, and storage and syncthing are skipped, so
    nothing on the phone changes). Still nothing → `sms_source_unreachable`.
- **Phone clock baseline:** at `-L`'s step 3 start (before any step that can trigger an
  SMS), read `adb -s S shell date +%s%3N` → `t0_phone_ms`. Freshness uses the PHONE's clock,
  so Mac/phone skew cannot matter. Also take a baseline of process-local HMAC digests
  (random per-run key, memory only) of the codes in every inbox SMS from the pinned senders
  dated in the last 15 min. This is the D2b rule: an old code never counts.
- **Query** (per poll):
  `adb -s S shell content query --uri content://sms/inbox --projection _id:address:date:date_sent:body --where "date>=T0"`.
  - The output is parsed in memory.
  - argv carries only the timestamp. Senders are filtered in Python, so no sender string
    goes through the remote shell's quoting.
  - The body never leaves the process: no log, no journal, no exception text. Parse
    errors map to fixed codes.
- **Pinning:**
  - **Sender:** `address` exactly equal (after removing spaces and a leading `+`) to one
    of the step's `sms_senders`, a per-site tuple in the recipe. The default for Google is
    `("Google",)`. It may be overridden in `safari-logins.json` key `sms_senders`, which
    joins the closed key set. An unknown sender is ignored.
  - **Body:** the step's `sms_pattern` (Google: `\bG-(\d{6})\b`) must match exactly once.
  - **Freshness:** `date >= t0_phone_ms` AND `date_sent >= t0_phone_ms - 120000` (a delayed
    old SMS is refused). It is also not in the baseline.
- **Two polls agree:** polls run every 3 s, for ≤ 90 s. A code is taken only when two
  consecutive polls return the same candidate set: the same `_id` and the same code digest,
  with exactly ONE distinct code. Two different fresh codes → `sms_code_ambiguous`, nothing
  typed. Duplicates of one code are fine.
- **Typing:** the D2b path for mail codes. A 0600 JS file (native setter + events), the
  exactly-one submit button and `SubmitTripwire` semantics as for `mail_code`. It is
  deleted in `finally`. It is a credential step (`CREDENTIAL_KINDS`), so a failure after it
  quarantines the site.
- **Step machine:** a new step kind `sms_code`, appended to the Google sub-recipe (`_google`)
  for notion, slack and openai. When the detector reports `sms` (a visible code field + the
  SMS text):
  - a recipe with an `sms_code` step and a reachable source runs that step once;
  - no `sms_code` step or an unreachable source → `needs_albert_sms` (exit 4);
  - a source that is reachable but finds no code within 90 s → `sms_code_timeout`
    (exit 2, agent's; re-run `-L` later).

  An SMS that Google sends only after a "Send code" / "Try another way" choice is a
  `click` step with `optional=True` before `sms_code`. Its labels are UNVERIFIED until L-S3.
- **Never:** no SMS is sent, deleted or marked read, and nothing is written on the phone.

### V4 — the stop list after this plan

| code                        | owner  | when                                                             |
| :-------------------------- | :----- | :--------------------------------------------------------------- |
| `needs_albert_captcha`      | Albert | unchanged                                                        |
| `needs_albert_push`         | Albert | unchanged                                                        |
| `needs_albert_hardware_key` | Albert | unchanged                                                        |
| `needs_albert_sms`          | Albert | ONLY `sms_source_unreachable`, or a recipe without `sms_code`     |
| `needs_albert_vault_locked` | —      | REMOVED for the agent account                                    |
| `needs_albert_vault_master` | Albert | the Keychain item is missing → `agent-login.py -K` (secret only he holds) |
| `vault_wrong_account`       | agent  | the Safari vault tab is on another account (e.g. `+vault`): stop, never typed |
| `vault_logged_out`          | agent→Albert per Open question 2 | the web vault shows the login page, not the lock screen |
| `vault_tab_missing` / `vault_tab_ambiguous` | agent | open exactly one vault tab (`safari.py -o https://vaultwarden.dom42.space`) and re-run |
| `unlock_rejected`           | agent  | quarantined (`-Q vault`), never retried                           |
| `unlock_failed`, `submit_unidentified` | agent | re-run `-L` once; then report               |
| `sms_code_timeout`, `sms_code_ambiguous` | agent | re-run `-L` later                      |

- **`vault_wrong_account`:** the tab is on Albert's personal vault. Agents never log out or
  switch his account. It is reported as agent-visible "Safari vault is on another
  account", not a `needs_albert_*` code. Open question 4 asks whether it should be his.
- **Other changes:** `broker/phases.py` texts, the `-L` exit map, agents.md's header line
  ("only CAPTCHA / push / security key are his; an SMS code only when his phone is
  unreachable") and `ALBERT_STOPS` are updated to match.

## Steps

- [ ] L-V1 (live, read-only spike, main session) — on the locked web vault in Safari:
      confirm the lock route (`#/lock`), the element that holds "logged in as <e-mail>", the
      master-password input attributes, the "Unlock" button label, the wrong-password toast,
      and where the unlocked vault exposes the account e-mail. Record selectors only, never
      the e-mail text, in this plan.
- [ ] L-S1 (live, read-only spike, main session) — with the phone reachable over adb, run
      the content query with `--projection _id:date` and a `--where` on the last hour.
      Record ONLY whether it is permitted and the row count, never bodies or senders. If it
      is denied, test `dumpsys notification --noredact` (presence of the SMS app's
      notification keys only) and update S's Source accordingly.
- [ ] L-S2 (live, read-only) — confirm the sender string Google's SMS 2FA arrives under
      (`address`, count of matching rows only), then set the Google default `sms_senders`.
- [ ] M7 (mydotfiles spec, built in mydotfiles by its own builder, isolated worktree because
      safari.py is live) — `safari.py --vault-status -j` (feature `vault_status`) and
      `--unlock-vault --expect-email E` with the password on stdin (feature
      `vault_unlock`). Includes the flock, the origin pin, the exactly-one tab, the
      enum/boolean-only JS, the `+`-tag refusal, the exactly-one Unlock button, the 0600
      file, the post-unlock e-mail re-check and fixed exit codes. Tests: a fake osascript
      (wrong account, `+vault`, two vault tabs, foreign origin, login page, TTY stdin
      refused, argv/env never carrying the value, file removed after a raise).
- [ ] M8 (mydotfiles doc) — vault-touchid README "What it guarantees": the agent account's
      master is in the login keychain for `agent-login.py -L` (after Open question 1).
- [ ] B1 `agent_login_vault.py`: `read_master` (the `_security_run` contract), `enroll`
      (`-K`, TTY-only, `security -i` on stdin, delete-then-add), `vault_status`, `unlock`
      (stdin pipe to safari.py, value overwritten in `finally`), the `vault` pseudo-site
      quarantine on `unlock_rejected`.
- [ ] B2 `agent_login_safari.py`: the preflight unlock before the first clipboard step; the
      one reactive unlock plus a single step re-run on the lock class; `error_code` maps the
      lock class to "unlock" instead of `needs_albert_vault_locked`; `needed_features`
      adds `vault_status` + `vault_unlock` for recipes with clipboard steps (missing →
      `safari_py_outdated`, nothing driven); the new step kind `sms_code` in
      `CREDENTIAL_KINDS`; `ALBERT_STOPS` handling for `sms` as in V4; the `sms_senders`
      key in the override file's closed key set.
- [ ] B3 `agent_login_sms.py`: source resolution (`AGENT_LOGIN_PIXEL_ROOT`, sibling),
      reachability with one bounded `pixel-connect-adb.py -W -F --no-storage
      --no-syncthing`, the phone-clock `t0`, the HMAC baseline, the query, sender/pattern/
      freshness pinning, two-polls-agree, ambiguity, fixed error codes, no body in any
      output or exception.
- [ ] B4 `agent-login.py`: `-K/--vault-enroll` (exclusive with every other mode; refused
      under `AGENT_LOGIN_SCHEDULED`), `-Q vault`, the new codes in the `-L` exit map, and
      the agents.md header text.
- [ ] B5 `broker/phases.py`: add `needs_albert_vault_master`, `vault_wrong_account`,
      `vault_logged_out`, `vault_tab_missing`, `vault_tab_ambiguous`, `unlock_rejected`,
      `unlock_failed`, `sms_source_unreachable`, `sms_code_timeout`,
      `sms_code_ambiguous`; drop `needs_albert_vault_locked`; reword `needs_albert_sms`.
- [ ] T1 `tests/test_ws1b_vault_unlock.py` with a fake `security` and a fake safari.py.
      Cases:
      - the master reaches safari.py only on stdin (asserted on recorded argv and env);
      - `+vault` / mismatch → nothing typed and no `security` read at all (the status
        check runs BEFORE the Keychain read);
      - already unlocked → no read;
      - `unlock_rejected` → quarantine, and a second `-L` is refused until `-Q vault`;
      - a missing item → `needs_albert_vault_master`;
      - a lock mid-run → exactly one unlock + one step re-run;
      - a scheduled run → refused;
      - `read_master` has no timeout and never kills (fake Popen asserts);
      - `-K` without a TTY → exit 2;
      - an AST check: `security` is called only from `read_master`/`enroll`.
- [ ] T2 `tests/test_ws1b_sms.py` with a fake adb and a fake phone clock. Adversarial
      cases:
      - a foreign sender;
      - an SMS dated before `t0`;
      - an old code re-delivered under a new `_id`;
      - an old `date_sent` with a fresh `date`;
      - two different fresh codes;
      - a code appearing in one poll only;
      - the phone unreachable → `needs_albert_sms`;
      - reachable with no SMS → `sms_code_timeout`;
      - the body never in stdout, stderr, the journal or exception text (canary string);
      - `pixel-connect-adb.py` invoked only with `-W -F --no-storage --no-syncthing` and
        a deadline.
- [ ] T3 update `tests/test_ws1b_safari.py` / `test_ws1b_agent_login.py` for the removed
      `needs_albert_vault_locked` and the new codes. Run the full suite.
- [ ] D1 docs:
      - AGENTS.md WS1b "Albert's stops" bullet → `captcha|push|hardware_key`, `sms` only
        when the phone is unreachable, plus a new "Vault unlock" bullet (Keychain item,
        stdin-only, account check before typing, `+vault` refused, one attempt,
        quarantine) and an "SMS codes" bullet (adb source, sender + phone-clock
        freshness + two polls, value never logged);
      - README (`-L`, `-K`, `-Q vault`, the stop list ~line 819);
      - `plans-done/PLAN_ws1b-durability_DONE.md` D3 + closure matrix + line 11, with a pointer to this
        plan.
- [ ] D2 lint (ruff format/check, mypy, pylint, shellcheck n/a) + full suite + `lint-gate.py
      -c -M -b HEAD <files>`.
- [ ] L-V2 (live, main session, after B1/M7) — Albert runs `agent-login.py -K` (`You
      [secret]`).
- [ ] L-V3 (live) — lock the agent vault in Safari; then `agent-login.py -L galaxus`
      (clipboard recipe). Expect the preflight unlock, the login and the import ✅.
- [ ] L-V4 (live) — negative check: with the Safari vault tab on the `+vault` account (only
      if Albert switches it himself; never switched by an agent), `--vault-status` must say
      `vault_wrong_account`, and nothing is typed.
- [ ] L-S3 (live) — a Google SSO that asks for an SMS (notion or openai `-L`). Expect the
      code read, typed and the site ✅; or record the "Try another way" labels and re-run.

## Open questions

1. **Where does the master password live, and is the vault-touchid promise allowed to
   change?** A Keychain item readable through `/usr/bin/security` lets any same-user agent
   `bw unlock` the agent account, which bypasses broker-add's two-touch approval for writes.
   - **Recommendation (moderate confidence):** accept it, for two reasons.
     - vault-touchid's boundary already excludes a malicious same-user agent.
     - An unlocked Safari web vault, which is what Albert asked for, is already fully
       drivable by agents through safari.py.
   - Store it as V1 says and update the vault-touchid README (M8).
   - The alternative: an item whose ACL trusts only a pinned vault-touchid subcommand that
     types the password itself. This keeps the master out of agent processes, but it breaks
     on every helper rebuild (ad-hoc cdhash) and buys little while the web vault is
     agent-drivable.
2. **Login page (not lock screen):** after a Vaultwarden logout or token expiry, Safari
   shows the login form (e-mail + master, maybe 2FA). Should agents log the agent account in
   there too?
   - **Recommendation:** yes, in the same safari.py call, when the e-mail field is typed
     with exactly `albert.glensk@gmail.com` and the next page is the master-password
     page.
   - A 2FA step there stops as `needs_albert_vault_2fa`.
   - Until Albert agrees, `vault_logged_out` is an Albert stop.
3. **Re-lock after the run?**
   - **Recommendation:** no. Leave the vault as `-L` found it unlocked; Vaultwarden's own
     timeout locks it. Re-locking after each run would force an unlock (a Keychain read +
     typing) on every `-L`.
   - Albert may prefer "re-lock only if the agent unlocked it" for a smaller exposure
     window.
4. **The Safari vault tab on the personal `+vault` account:** whose stop is it?
   - **Recommendation:** Albert's, as `needs_albert_vault_account` ("Safari's Vaultwarden
     tab is on your personal account"). Agents must never log his personal account out to
     switch.
   - Alternative: a SECOND vault tab of the agent account in a separate Safari profile.
     That needs safari.py profile support; defer.
5. **May Beeper bridge SMS (Google Messages)?**
   - **Recommendation: no.** Beeper's Google Messages bridge needs Google Messages as the
     default SMS app (Play-services-dependent on GrapheneOS). It would also route every SMS,
     2FA codes included, through Beeper's servers.
   - adb keeps the codes on the LAN/WireGuard path with no phone change. Revisit only if
     L-S1 shows adb cannot read `content://sms`.
6. **Off-LAN reachability:** adb dies after a phone reboot until a USB cable or Wireless
   debugging re-arms it, and `pixel-connect`'s relay needs `nixw`. Is
   `needs_albert_sms` on an unreachable phone acceptable, or should agents also toggle
   Wireless debugging (the `wdtoggle` app needs a tap)?
   - **Recommendation:** accept it. A tap on the phone is physical and stays Albert's.

## Verification

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff check agent_login_vault.py agent_login_sms.py agent_login_safari.py agent-login.py broker/phases.py tests/test_ws1b_vault_unlock.py tests/test_ws1b_sms.py
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff format --check agent_login_vault.py agent_login_sms.py agent_login_safari.py agent-login.py broker/phases.py tests/test_ws1b_vault_unlock.py tests/test_ws1b_sms.py
cd /Users/albert/obsidian/42-Git/home/browser-login && git diff --no-ext-diff --no-textconv --stat HEAD
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run mypy agent_login_vault.py agent_login_sms.py agent_login_safari.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pylint agent_login_vault.py agent_login_sms.py agent_login_safari.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests/test_ws1b_vault_unlock.py tests/test_ws1b_sms.py tests/test_ws1b_safari.py tests/test_ws1b_agent_login.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests
```


## Codex round 1 (2026-10-13, unreconciled)

### Codex's independent plan

1. Resolve the security contract first: Keychain exposure, unlock-only scope, re-lock policy, and ownership of wrong-account/logged-out failures.
2. Complete two blocking spikes before implementation:
   - Prove account identity on both locked and unlocked Vaultwarden pages.
   - Prove `content://sms` access, timestamp behavior, sender representation, and output format on the Pixel.
3. Implement a narrowly scoped vault helper with hardcoded agent account/origin, pinned executables, robust Keychain enrollment/readback, and no generic personal-account capability.
4. Make unlock one guarded transaction: verify account immediately before typing, validate all controls before filling, submit once, prove the same account afterward, then quarantine every uncertain failure.
5. Implement SMS reading only against a verified Pixel identity, using a non-mutating connection path, bounded ADB calls, robust parsing, sender/freshness pinning, and no diagnostic leakage.
6. Integrate SMS into the Safari state machine before the generic `sms` stop, with explicit Google-account/challenge verification and a limiter for code-generation attempts.
7. Add adversarial tests for wrong accounts, races, signals, stale files, wrong devices, malformed ADB output, timestamps, concurrency, and all failure classifications.
8. Verify browser-login, mydotfiles, and any Pixel tooling changes independently, including their native test suites and secret scanning, before live acceptance.

### Objections to Claude's plan

O1: The `unlocked` branch does not verify the account. The state description defines `email_match` from the lock screen, but the checks return `already_unlocked` before requiring it. An already-unlocked personal `+vault` account would therefore be accepted, after which existing `safari.py` could search and copy from the personal vault. Require a positive account proof for every state, especially `unlocked`, and test an unlocked personal account explicitly.

O2: The account check and password submission are vulnerable to a same-origin TOCTOU. A flock serializes cooperating tools, not Albert or another Safari action. The plan reads state in one JS call and types later; the tab can change accounts while remaining on the same Vaultwarden origin. The action call itself must atomically revalidate origin, route, unique visible account identity, password field, and submit button before setting the value and clicking.

O3: Four material requirements remain “open questions,” so this is not implementation-ready. They determine the security boundary, supported states, exposure window, and who can recover. The current plan is internally inconsistent: `vault_wrong_account` is called an agent stop although only Albert can switch away from his personal account; `vault_logged_out` has no settled owner; and the docs promise only CAPTCHA/push/hardware-key stops while other Albert-only conditions remain. Adopt safe defaults now: unlock only, never log in or switch accounts, re-lock if the agent unlocked it, and classify personal-account/logged-out states as Albert-owned.

O4: The Keychain design cites `browser.py`’s pattern without specifying the parts that make it safe. It omits explicit default-keychain resolution, control-character and length rejection, correct `security -i` quoting, `-T /usr/bin/security`, delete/add outcome classification, byte-exact readback, interruption handling, and recovery when delete succeeds but add fails. `find-generic-password -w` also adds output framing that must not be handled with a generic `.strip()`. Copy the complete tested contract or extract a shared helper; do not implement a simplified imitation.

O5: The claim that the password lives in a `bytearray` and is overwritten is misleading. `getpass`, decoding, JSON construction, JavaScript construction, subprocess input, and exception machinery create immutable copies Python cannot reliably erase. State this as best-effort memory hygiene, minimize copies, and test that the canary never reaches output, errors, journals, argv, environment, or surviving files.

O6: The plan would send the master password to an executable selected by the existing `SAFARI_PY_BIN` environment override. It also names `security` through `PATH`, and the SMS design executes/imports tools from `AGENT_LOGIN_PIXEL_ROOT`. Those are secret-exfiltration paths under accidental environment poisoning. Pin `/usr/bin/security` and the production Safari/Pixel tool paths; allow overrides only in an explicit test mode. The unlock command should also hardcode the one permitted account rather than accept an arbitrary `--expect-email`.

O7: The unlock retry policy violates the existing “credential may have been submitted” rule. `unlock_failed` is told to “re-run once,” even though the click may have sent the master password and the result may merely be unobservable. Quarantine the global `vault` pseudo-site after every unsuccessful or interrupted post-fill attempt, not only a recognized rejection. Permit observation-only status checks while quarantined, but no second submission until audited release. Explicitly gate every `-L` on that global quarantine.

O8: The SMS source is a prerequisite, not an implementation detail to decide later. If GrapheneOS denies `content://sms`, `dumpsys notification --noredact` has a different trust model, schema, freshness data, spoofing surface, and disappearance behavior. L-S1 must gate the SMS design. If it fails, stop and produce a separate concrete notification-source design; do not silently “update S’s Source.”

O9: The phone itself is not pinned. `adb_pick.py` chooses the only connected authorized device even if it is not Albert’s Pixel 9a, and `ANDROID_SERIAL` can redirect it. Verify a pinned device identity—at least the expected product/model/device fingerprint and an approved serial policy—before querying messages. Test one wrong device, several devices, duplicate transports to the same Pixel, and a poisoned `ANDROID_SERIAL`.

O10: The claimed non-mutating reconnect is false. `pixel-connect-adb.py` calls `rearm_shizuku()` unconditionally after a successful connection; `-W` only disables fixed-port Wi-Fi bootstrap, while `--no-syncthing` and `--no-storage` do not disable Shizuku. It also prunes ADB endpoints and may create relay state. Add and verify a genuine connect-only mode, or use a smaller read-only reachability path. Until then, “nothing is written on the phone” is incorrect.

O11: The ADB query protocol is underspecified and unsafe to parse casually. The remote-shell quoting for `date>=T0` is not defined, despite `>` being shell syntax, and `content query` emits text records whose `body` can contain delimiters, newlines, or row-looking content. The plan also assumes inbox `date_sent` is populated and meaningful. The spike must establish the exact raw format and timestamp semantics; implementation needs a fail-closed parser, bounded output, fixed errors, and tests for hostile/malformed bodies and missing/zero `date_sent`.

O12: The current state-machine order defeats the proposed SMS step. `Machine._loop()` checks `ALBERT_STOPS`, including `sms`, before `_next_step()`, so an SMS page exits before `sms_code` can run. Specify and test the new precedence: CAPTCHA/push/hardware-key remain immediate stops; an SMS indication first resolves one eligible SMS step, then falls back to `needs_albert_sms`.

O13: The recipe plan is factually wrong for Notion. Its current recipe is mail-code-only, does not use `_google`, and does not allow `accounts.google.com`. “Append to the Google sub-recipe for notion” cannot work without redesigning Notion’s hosts, trigger, account selection, and preferred login route. Do not replace the working mail-code route merely to exercise SMS; add Google only after a live, explicit recipe spike.

O14: “SubmitTripwire semantics as for `mail_code`” refers to a mechanism that does not exist in the Safari path. `SubmitTripwire` is a Playwright broker feature; Safari’s `CODE_FILL_JS` only checks a button, fills, and clicks. Define the real Safari guarantee: unique visible OTP field, unique non-destructive submit control validated before filling, origin/handle pin in the same evaluation, and conservative handling of auto-submit pages.

O15: Freshness does not bind the SMS to this login transaction. A `t0` taken at run start plus two stable polls can accept an unrelated Google code that arrives afterward. Verify the expected Google account before any action that may trigger 2FA, verify the displayed phone target where available, take the baseline immediately before the earliest triggering action, and serialize the trigger/read interval. A “Send code” click must count as a rate-limited side effect; `sms_code_timeout → rerun later` currently permits repeated code generation with no cooldown or quarantine.

O16: The live steps are mislabeled and can violate the one-attempt rule. L-S2 cannot discover a fresh Google sender without potentially generating an SMS, so it is not necessarily read-only. L-S3’s “record labels and re-run” may request another code. Separate passive inspection from authorized code generation, and give each generated-code attempt an explicit budget and recovery rule.

O17: The proposed tests miss the highest-risk cases: already-unlocked personal vault, account change between status and action, hidden/duplicate identity elements, arbitrary `SAFARI_PY_BIN`, SIGTERM/SIGKILL with a secret temp file present, wrong Pixel identity, remote-shell quoting, malicious `content query` framing, missing `date_sent`, Google account mismatch, and repeated SMS-trigger limiting. Add these before live acceptance.

O18: The Verification block is syntactically valid—I ran `tp verify 955 -n -f …`; it exited 0 and reported `exec-eligible: yes`. Its coverage is still inadequate. M7/M8 change security-critical mydotfiles code, but the block runs neither `bin/test_safari.py` nor mydotfiles linting; it also omits the repository’s pre-commit/gitleaks check. Split mydotfiles and any Pixel-tool change into verified prerequisite work items, or provide an accepted cross-repository verification arrangement before linking this plan.
