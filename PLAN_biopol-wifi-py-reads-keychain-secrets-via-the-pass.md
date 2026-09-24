# tp#511 — biopol-wifi.py reads keychain secrets with `-w`, which returns non-ASCII as hex

## Session

Resume: `c --resume 4cb9fd31-0bce-4f4c-8311-fb7172eb92eb`

## Context

Classification: **DEFECT**. A stored secret is read back in a different form than it was
written. The code lives in `sdsc/biopol-wifi` (`~/obsidian/42-Git/sdsc/biopol-wifi`). The ticket
and this plan live in `home/browser-login`, because tp#498 fixed the same bug there.

**Symptom.** `_keychain_get` (`sdsc/biopol-wifi/biopol-wifi.py:365-389`) runs
`security find-generic-password -a <acct> -s <svc> -w` and returns stdout without the trailing
newline. For a value that `security` treats as non-printable, `-w` prints its UTF-8 bytes as
lowercase hex, with no marker.

biopol-wifi's own `--store-creds` hides this in two ways:

- It refuses values that are not printable ASCII (`biopol-wifi.py:553-562`).
- Its read-back check *expects* hex for such values (`biopol-wifi.py:469-470`).

But `browser.py store-creds biopolwifi` (`home/browser-login/bin/browser.py:5384-5420`) writes
the **same two items** without that refusal (`bin/browser.py:184-196`). So if a portal password
containing `ä` was stored through browser.py, biopol-wifi reads it back as hex and sends the hex
to the Cloudpath token endpoint. The login fails, and repeated failures risk locking the portal
admin account.

**Reproduced 2026-09-24 in this plan session.** I used a throw-away keychain created with
`security create-keychain` under a `mktemp -d` directory. It was named on every call, checked to
be off the user search list, and deleted afterwards. I stored the dummy value `päss` and read it
with biopol-wifi's read argv plus the temp keychain path. In this plan `PW:` stands for the
literal lowercase `password` label plus colon and space that `-g` prints; it is abbreviated so
the repo's secret-scan hook does not flag the example lines.

| flag | output                                         |
| ---- | ---------------------------------------------- |
| `-w` | stdout `70c3a47373`                            |
| `-g` | stderr `PW: 0x70C3A47373  "p\303\244ss"` |

The full table is in tp#498's plan
(`plans-done/PLAN_browser-py-keychain-get-returns-hex-for-non-ascii_DONE.md`). It covers
hex-looking ASCII values (`cafe`, `c3a4`), `a\b`, `ä"x`, and the hex-only and empty shapes of
Apple's formatter.

**Root cause (confidence: high, measured).** `-w` switches between the literal value and bare
hex, and gives no sign of which one it used. So `cafe` and the hex of a UTF-8 password cannot be
told apart. `-g` labels the form on stderr: a quoted value is printed verbatim; otherwise it
prints `0x<HEX>`, optionally followed by a rendering. The browser.py fix is:

- `_kc_parse_password` (`bin/browser.py:3145-3183`);
- the `-g` read in `_keychain_get` (`bin/browser.py:3273-3300`);
- the never-kill runner `_security_run` (`bin/browser.py:3185-3257`).

A live temp-keychain test proves it.

**Decisions** (settled by the evidence; recorded with `tp question 511 -d`, non-blocking):

1. **Copy, don't import.**
   - biopol-wifi is a standalone script with its own venv. `browser.py` is a provider CLI, not
     an importable library. A cross-repo import would be a hidden dependency.
   - The parser and the runner are copied, with a comment naming
     `home/browser-login/bin/browser.py` as their origin.
2. **Lift the non-ASCII refusal in `--store-creds`.**
   - The refusal existed only because of this read bug; its own error text cites tp#498.
   - Once the read is exact, the refusal just blocks legitimate passwords. It never covered
     values that browser.py writes.
   - Control characters, unencodable values and overlong values stay refused, by `_kc_add_line`.
3. **Every biopol `security` call goes through a ported never-kill `_security_run`.**
   - The runner uses `Popen` and `start_new_session=True`. It has no timeout, never calls
     `kill`/`terminate`, and defers `KeyboardInterrupt` until the child has exited and been
     reaped.
   - Dropping `timeout=` alone would not be enough, because `subprocess.run` kills the child on
     Ctrl-C. On 2026-09-24 a kill in the middle of a dialog crashed `securityd` (tp#504).
     Albert's standing order also forbids a timeout wrapper around `security`.
   - This covers the read, the `-i` write and the delete. They have one hazard and one helper,
     and it is a bounded change.
   - A locked keychain now makes a call wait for the user's unlock, as in browser.py.
4. **Add an opt-in live test against a temporary keychain.** It runs only when
   `BIOPOL_LIVE_KEYCHAIN=1` is set on macOS. It proves the copied parser, and biopol's real
   `_keychain_get`, against the real `security -g` formatter:
   - A router is patched in place of `biopol._security_run`. It appends the temp keychain path
     to `find-generic-password` and refuses every other shape.
   - Writes in the live test are the test's own `security -i` lines, which name the temp path.
     biopol's `_keychain_write`, `_keychain_delete`, `store_creds` and `forget_creds` are never
     called live: they name no keychain, so they would reach the login keychain.

**Alternatives rejected.**

- *Decoding `-w` hex by guessing:* this corrupts all-hex ASCII passwords (tp#498).
- *`SecItemCopyMatching` through `ctypes`:* the items trust only `/usr/bin/security`
  (`-T /usr/bin/security`), so a read from the Python process would raise an access prompt.
- *Keeping the refusal and only fixing the read:* the read fix is needed anyway, because
  browser.py writes these items. A refusal that outlives the bug it guarded against is dead
  policy.

**Constraints.**

- Secrets never go on argv, so tp#497 stays fixed.
- The captured `-g` stderr is never printed.
- The secret is never printed or logged in any form: plain, hex or octal-escaped. That includes
  pytest assertion diffs.
- There is no new runtime dependency.
- Env-var credentials (`BIOPOLWIFI_EMAIL`/`_PASSWORD`) still skip `security` entirely.
- The mocked suite gets an autouse default-deny guard, so no test can reach the real `security`.
- The only live execution is the opt-in test against its own temporary keychain file:
  - It is created with a random password under `mktemp`.
  - It has its lock timeout disabled.
  - It is named explicitly on every `security` call.
  - It is never added to the search list.
  - It is deleted afterwards, and the deletion is verified.
- No session touches the login keychain or the real items.

**Blocked on Albert: no.** No step touches real keychain items or the portal.

**Verification strictness.** The biopol-wifi block runs pytest, mypy, pylint and
`biopol-wifi.py -h`, all of which execute repo code, so it is not strict-eligible. The live
pytest line is macOS-local only. CI (`.github/workflows/ci.yml`, a shared Linux workflow) skips
it. The browser-login block holds only read-only git checks.

## Steps

Steps 1-4 (the code) and 6-9 (the tests) must land as **one** change. The current
`FakeSecurity` calls `biopol._printable_ascii` (`tests/test_biopol_wifi.py:395-396`), which step 4
deletes. Split up, the change leaves a broken suite.

- [ ] 1. `sdsc/biopol-wifi/biopol-wifi.py`: port the runner.
      - Add `SecurityResult`, `SecurityInterrupted` and `_security_run(argv, *, data=None)`,
        copied from `home/browser-login/bin/browser.py:3185-3257` with an origin comment. The
        runner:
        - uses `Popen` with `start_new_session=True`, `stdout`/`stderr` as `PIPE`, and `stdin`
          as `PIPE` when `data` is given, else `DEVNULL`;
        - runs a `communicate` loop that defers `KeyboardInterrupt` and still reaps the child
          after any other exception;
        - never kills and has no timeout.
      - Its states are:
        - `not_started`: `OSError`;
        - `done`: the child exited normally, with its `rc`;
        - `unknown`: a broken run, a missing `rc`, or a negative (signal) `rc`.
      - A deferred Ctrl-C raises `SecurityInterrupted(result)`, a subclass of
        `KeyboardInterrupt`.
      - `argv[0]` stays `_security_bin()`.
- [ ] 2. `biopol-wifi.py`: port the parser and rewrite `_keychain_get` (`:365-389`).
      - Add `_KC_PW_PREFIX`, `_KC_HEX_RE` and `_kc_parse_password(stderr: str) -> str | None`,
        copied from `bin/browser.py:3145-3183` with an origin comment naming tp#498/tp#511.
        `re` is already imported. The parser works like this:
        - The last `password:` line wins.
        - `0x<hex>` is decoded as strict UTF-8, and any rendering after the first space is
          ignored. An odd-length, empty or invalid-UTF-8 payload gives `None`.
        - A quoted value is the text between the first and the last quote, verbatim. An empty
          one gives `None`.
        - Anything else gives `None`.
        - It never logs.
      - `_keychain_get` runs
        `_security_run([_security_bin(), "find-generic-password", "-a", acct, "-s", svc, "-g"])`.
        - If the state is not `done` or the rc is not 0, it returns `None` silently.
        - Otherwise it discards stdout and parses
          `_kc_parse_password(r.stderr.decode("utf-8", errors="replace"))`. Decoding is explicit
          UTF-8, not the locale.
        - If the parser returns `None`, it prints exactly one stderr line,
          `Keychain item <service> has an unreadable value — ignoring it.`, and returns `None`.
          That includes an empty stored value, as in browser.py.
      - Update the docstring: why `-g` (tp#498), why there is no timeout and no kill (tp#504),
        and that the captured output is never printed.
- [ ] 3. `biopol-wifi.py`: move the other calls to the runner, and make the read-back exact.
      - `_keychain_write` sends its `-i` line through `_security_run([sec, "-i"], data=line)`.
        - `"failed"` stays the word for: not started, unknown, or done with a non-zero rc.
        - A `SecurityInterrupted` propagates, so `store_creds`' `except BaseException` cleanup
          still runs.
        - The read-back must be exact, `_keychain_get(service) == value`. Delete the hex
          `expected` branch.
        - Rewrite the docstring paragraph that says "not proof of byte-exact storage": it is now
          a byte-exact round-trip check.
      - `_keychain_delete` uses `_security_run` too. It returns `True` only for `done` with rc
        0 or 44.
- [ ] 4. `store_creds`: delete the non-printable-ASCII refusal loop (`biopol-wifi.py:553-562`)
      and `_printable_ascii`, which has no other user. Keep the `_kc_add_line` pre-validation
      loop: control characters are still refused there, before any write, with "nothing
      stored".
- [ ] 5. `sdsc/biopol-wifi/README.md` § Credentials, lines 42-50: drop the "must be printable
      ASCII" bullet. Write instead:
      - non-ASCII values round-trip exactly, because the read uses `security`'s labelled `-g`
        dump (tp#498/tp#511);
      - control characters are refused;
      - the read-back is byte-exact;
      - `security` is never timed out or killed, so a locked keychain waits for the unlock.
      Do **not** claim the write path is otherwise hardened: `-U` remains (see NOTE).
- [ ] 6. New `sdsc/biopol-wifi/tests/conftest.py`, and the fake.
      - **Default-deny guard.** Add an autouse fixture that replaces `subprocess.run` and
        `subprocess.Popen`, as seen by `biopol`, with a raiser. `fake_security` and the runner
        unit tests override it. The live test opts out through a marker or a fixture override.
      - **`_security_g(value: str) -> str` helper.** Copy it from
        `home/browser-login/tests/conftest.py`. It has three shapes:
        - **Quoted:** every byte is printable ASCII and not `\` → `PW: "<v>"`.
        - **Mixed:** at least one byte is printable and not `\` →
          `PW: 0x<UPPER>  "<octal>"`.
        - **Hex-only:** otherwise → `PW: 0x<UPPER>`, with the trailing space.
      - **`FakeSecurity`** becomes a stand-in for `biopol._security_run(argv, *, data=None)`,
        returning `SecurityResult`s. Its `write_rc`/`delete_rc` values can be an int, a `state`
        string, or an exception to raise.
      - **Its reads:**
        - A read must be exactly `[SECURITY, "find-generic-password", "-a", "tester", "-s", svc,
          "-g"]`.
        - A hit answers `("done", 0, b"", _security_g(v).encode() + b"\n")`.
        - A miss answers rc 44.
- [ ] 7. Tests in `tests/test_biopol_wifi.py`, part 1: the runner, the reads and the read-back.
      - **Runner unit tests**, with a fake `Popen`:
        - `start_new_session=True` is passed.
        - `stdin` is `DEVNULL` without data.
        - A `KeyboardInterrupt` in `communicate` raises `SecurityInterrupted` after the child is
          reaped, and `kill`/`terminate` are never called.
        - `OSError` gives `not_started`.
        - A negative rc gives `unknown`.
      - **Read argv test:** pin the exact read argv. No `-w`, and no keychain path.
      - **Replace `test_keychain_set_non_ascii_expects_hex_readback`** with three tests:
        (a) `päss` succeeds with the mixed read-back;
        (b) `päss` gives `"mismatch"` when the read-back is the quoted literal
        `PW: "70c3a47373"`;
        (c) the all-hex ASCII password `70c3a47373` succeeds with a quoted read-back.
      - **Parametrised `test_keychain_get_failures`.** These all return `None` silently:
        - rc 44;
        - rc 51;
        - `not_started`;
        - `unknown` (a signal).
        An exit-0 empty `password:` line also returns `None`, but prints exactly the one
        warning line.
- [ ] 8. Tests part 2: the parser and secrecy.
      - **Parser unit tests** for `_kc_parse_password`. Cover:
        - the quoted form, including `ab"` and `ä"x`;
        - the mixed form, in uppercase and lowercase hex;
        - the hex-only form with its trailing space (`0xC3A4` → `ä`, `0x5C` → `\`);
        - the empty form → `None`;
        - several `password:` lines, where the last one wins, and stray other lines;
        - an odd-length payload, `0xFF`, and a missing closing quote → `None`;
        - a quoted value with leading and trailing spaces, kept verbatim.
      - **Secrecy tests**, using `capsys`:
        - Case 1: an unparsable exit-0 stderr that holds a dummy secret in plain, hex and octal
          form. stdout stays empty, and stderr is exactly the warning line.
        - Case 2: a non-zero exit whose stderr holds the secret. Nothing is printed.
- [ ] 9. Tests part 3: the consumers.
      - **`load_credentials()` with non-ASCII items.**
        - First run `monkeypatch.delenv` for `ENV_EMAIL` and `ENV_PASSWORD`, so real exported
          credentials can never reach an assertion diff.
        - Compare with `assert got == expected, "mismatch"`. The message hides both values.
      - **`store_creds()` with non-ASCII values.** Use `mé@x.ch` / `pässwörd-XYZ`: it returns 0,
        and the fake's store holds both values exactly.
      - **`test_store_creds_refuses_non_printable_ascii`** is cut down to the control-character
        case. That case is still refused before any write.
      - **A `SecurityInterrupted` during the second write** still runs `_cleanup_pair` and
        re-raises.
- [ ] 10. New `sdsc/biopol-wifi/tests/test_keychain_live.py`. It is skipped unless
      `BIOPOL_LIVE_KEYCHAIN=1` and `sys.platform == "darwin"`. Every lifecycle call goes
      through `biopol._security_run`, called directly: it never kills, has no timeout, and runs
      each call in a new session.
      - **Fixture setup:**
        - Create a `tempfile.mkdtemp()` directory holding a `tp511-<hex>.keychain-db` path, and
          a `secrets.token_hex` password.
        - Run `create-keychain -p <pw> <path>`, then `set-keychain-settings <path>` with no
          `-l`/`-u`/`-t`, then `unlock-keychain -p <pw> <path>`.
        - Assert that `show-keychain-info <path>` reports `no-timeout`.
        - Compare paths with `os.path.realpath`, and assert that the path is **not** in
          `list-keychains -d user`. If it is, delete the keychain first, then fail.
        - Never run `list-keychains -s`.
      - **Verified teardown:**
        - `delete-keychain <path>` exits 0.
        - The file no longer exists.
        - The path is not in the search list.
        - Remove the directory.
        - On any failure, fail with the manual cleanup command. The command names the path
          only.
      - **Test A: the parser against real output.**
        - Each run uses its own unique service prefix `tp511-live-<hex>`.
        - Before each add, `os.lstat(path)` must show a regular file (not a symlink) owned by
          the current uid.
        - The add is one `security -i` stdin line built with `biopol._kc_quote`. The test
          asserts that the line ends with ` ` + `_kc_quote(str(path))` + `\n`.
        - The test then reads with `find-generic-password -a <acct> -s <svc> -g <path>`.
          - rc 44: fail hard, naming the service for manual cleanup. It never probes the login
            keychain.
          - Otherwise it asserts `biopol._kc_parse_password(stderr) == value, "<case id>"`.
      - **Test B: biopol's real reader.**
        - Patch `biopol._security_run` with a router. It appends the temp path to the exact
          `find-generic-password -a … -s … -g` shape and raises on every other shape.
        - Assert `biopol._keychain_get(svc) == value, "<case id>"` for every case.
      - **Cases:** a superset of browser-login's `CASES`:
        - `plain`;
        - `dummy with spaces`;
        - `dummy'quote`;
        - `dummy$;|&#` plus a backtick;
        - `dummy-trailing\`;
        - `dümmy-✓`;
        - `cafe`, `c3a4`, `0x41`;
        - `ab"`, `ä"x`, `ä`, `😀`;
        - `\`, `a\b`, `päss`;
        - `sp` (with a trailing space).
      - **Rules:**
        - Only dummy values.
        - Nothing is printed.
        - No `-U` loops.
        - Never call `_keychain_write`, `_keychain_set`, `_keychain_delete`, `store_creds` or
          `forget_creds`.
- [ ] 11. Run every `## Verification` line in the foreground. The opt-in live line runs once,
      with no loops. Fix every lint and type finding in the touched files.
      - Commit in biopol-wifi with
        `ai.py push -m "fix(keychain): read secrets via labelled dump, never kill security (tp#511)" biopol-wifi.py README.md tests/conftest.py tests/test_biopol_wifi.py tests/test_keychain_live.py`.
      - Then tick the boxes here, and commit this plan in browser-login with
        `ai.py push PLAN_biopol-wifi-py-reads-keychain-secrets-via-the-pass.md`.

NOTE: the biopol write still uses `add-generic-password -U` (`biopol-wifi.py:418-423`).
browser.py dropped `-U` under tp#504/tp#509: an update re-sets the access list and can raise a
prompt, so browser.py moved to delete-then-add, which needs the careful outcome handling from
tp#509. That is out of scope here. The work session lists it under `### Observations` (defect,
with file:line) for the overseer.

NOTE: after this lands, Albert can re-run `biopol-wifi.py -C` or
`browser.py store-creds biopolwifi` himself if he wants the byte-exact read-back to check his
real items. No session touches the login keychain.

## Verification

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && git status --short
cd /Users/albert/obsidian/42-Git/home/browser-login && git log --oneline -3
```

### Other repositories

```commands
cd /Users/albert/obsidian/42-Git/sdsc/biopol-wifi && ruff check biopol-wifi.py tests/
cd /Users/albert/obsidian/42-Git/sdsc/biopol-wifi && ruff format --check biopol-wifi.py tests/
cd /Users/albert/obsidian/42-Git/sdsc/biopol-wifi && git status --short
cd /Users/albert/obsidian/42-Git/sdsc/biopol-wifi && git diff --no-ext-diff --no-textconv --stat HEAD~1
cd /Users/albert/obsidian/42-Git/sdsc/biopol-wifi && git log --oneline -3
cd /Users/albert/obsidian/42-Git/sdsc/biopol-wifi && uv run mypy biopol-wifi.py tests/
cd /Users/albert/obsidian/42-Git/sdsc/biopol-wifi && uv run pylint biopol-wifi.py tests/conftest.py tests/test_biopol_wifi.py tests/test_keychain_live.py
cd /Users/albert/obsidian/42-Git/sdsc/biopol-wifi && env BIOPOL_LIVE_KEYCHAIN=0 uv run pytest -q
cd /Users/albert/obsidian/42-Git/sdsc/biopol-wifi && env BIOPOL_LIVE_KEYCHAIN=1 uv run pytest -q tests/test_keychain_live.py
cd /Users/albert/obsidian/42-Git/sdsc/biopol-wifi && ./biopol-wifi.py -h
```

## Debate outcome (Opus adversary)

Round 1 (2026-09-24, independent Opus reviewer, read-only). 14 objections: 13 accepted, 1 partly
accepted. No severe objection was rejected, so there was no round 2.

| #  | Severity    | Objection                                                                                   | Disposition                                                                                                                            |
| -- | ----------- | ------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| 1  | high        | Dropping `timeout=` leaves `subprocess.run`'s kill-on-Ctrl-C, the tp#504 crash path          | Accepted: port `_security_run` and use it for the read, write and delete (decision 3, steps 1-3); add runner tests (step 7)             |
| 2  | high        | The live add could fall back to the login keychain if the temp path is invalid               | Accepted: `lstat` check before each add, assert the line ends with the path, unique service prefix, rc 44 fails hard (step 10)         |
| 3  | medium-high | The temp keychain keeps its default idle lock, so a mid-run lock hangs the test              | Accepted: `set-keychain-settings` with no timeout, plus a `show-keychain-info` assertion (step 10)                                     |
| 4  | medium      | Teardown is not verified; the path compare breaks on `/private/var`                          | Accepted: verified teardown, `realpath` compare (step 10)                                                                              |
| 5  | medium      | No default-deny `subprocess` guard in the mocked suite                                       | Accepted: autouse guard in a new `tests/conftest.py` (step 6)                                                                          |
| 6  | medium      | The `load_credentials` test could echo real env credentials in a diff                        | Accepted: `delenv` both vars, assertion message hides the values (step 9)                                                              |
| 7  | medium      | Read failure modes and the empty value are not tested                                        | Accepted: parametrised `test_keychain_get_failures`; empty value warns once (step 7)                                                   |
| 8  | low-medium  | `FakeSecurity` uses `_printable_ascii`, so steps must land together                          | Accepted: atomic-change note above the Steps                                                                                           |
| 9  | low-medium  | `text=True` decodes with the locale encoding                                                 | Accepted: bytes from the runner, explicit UTF-8 decode (step 2)                                                                        |
| 10 | low         | Live cases drop browser-login's tokenizer edge cases                                         | Accepted: superset of `CASES` (step 10)                                                                                                |
| 11 | low         | The production read path never meets the real formatter                                      | Accepted: test B routes `biopol._keychain_get` through a find-only router (decision 4, step 10)                                        |
| 12 | low         | Read argv not pinned                                                                         | Accepted: exact-argv test (step 7)                                                                                                     |
| 13 | low         | Verification gaps: live line is macOS-only, no leftover check                                | Partly accepted: `git status --short` added, macOS-only stated in Context. A `$TMPDIR` scan line is rejected: the Verification grammar forbids `$`, and the verified teardown in step 10 asserts that nothing is left over |
| 14 | low         | The exact read-back could make the write path look fully hardened while `-U` remains         | Accepted: README must not claim this (step 5); `-U` stays a NOTE → Observation                                                         |
