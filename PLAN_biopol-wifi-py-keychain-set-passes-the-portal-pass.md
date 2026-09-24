# tp#497 — biopol-wifi.py `_keychain_set` passes the portal password on argv

## Session

Resume: `c --resume 9f3f1e66-c1c9-4680-aac7-5bfd9dcee2ef`

## Context

Classification: **DEFECT** (a secret is exposed to every same-user process).
The code lives in another repository — `~/obsidian/42-Git/sdsc/biopol-wifi` — the ticket is
filed under home/browser-login because it is a follow-up of tp#489 (the same defect in
`bin/browser.py`, fixed there). All code changes below are in **biopol-wifi**; this repo only
holds the plan.

- **Symptom**: `biopol-wifi.py --store-creds` runs
  `security add-generic-password -a <user> -s <svc> -w <PASSWORD> … -U`, so the Cloudpath
  portal password (a full admin secret for the property) sits in the process argv for the
  lifetime of the `security` call and is readable via `ps` / `sysctl KERN_PROCARGS2` by any
  process of the same user.
- **Evidence**: `sdsc/biopol-wifi/biopol-wifi.py:392-419` builds the argv with
  `"-w", value`. Reproduced 2026-09-24 without touching any keychain: loading the module,
  replacing `subprocess.run` with a recorder and calling `_keychain_set("svc", "DUMMY-…")`
  shows the dummy value in argv and `input=None` (1 call). tp#489 measured the race live
  (120 `ps` hits in 200 runs with a dummy value) for the byte-identical browser.py code.
- **Root cause**: `_keychain_set` passes the secret as a command-line argument; macOS
  `security` has no stdin/file flag for `add-generic-password -w` except its interactive
  mode `security -i`, which reads commands from stdin. Established — high confidence.
- **Secondary defects in the same path** (fixed together because the fix touches them):
  1. No read-back — a write that exits 0 but stores something different goes unnoticed.
  2. `store_creds` (`biopol-wifi.py:456-481`) writes email then password with no
     pre-validation and no cleanup; if the second write fails the keychain holds the NEW
     email with the OLD password — a mismatched pair `load_credentials` then submits.
  3. `_keychain_delete` (`biopol-wifi.py:422-435`) discards the return code and always
     returns `True`, so `--forget-creds` reports success even when an item survives
     (mocked exit 51 confirmed by Codex).
  4. `_keychain_get` (`biopol-wifi.py:365-389`) returns what `find-generic-password -w`
     prints — hex for a non-printable-ASCII value — and `load_credentials` passes that on.
     This ticket closes the write path (store-creds refuses such values); the general
     reader fix is tp#498's (same defect in browser.py). Values placed in the keychain by
     other means stay a tp#498 limitation.
- **Reference fix**: `home/browser-login/bin/browser.py` — `_KC_LINE_MAX`, `_kc_quote`,
  `_kc_add_line`, `_keychain_write`, `_keychain_set`, `_keychain_set_all`, `_keychain_delete`
  (`bin/browser.py:3178-3352`) and its tests `tests/test_credentials.py:107-210`. Measured
  facts it relies on: `security -i` reads one command per line into a 4096-byte buffer
  (longer lines split, the tail parsed as a new command); inside `"…"` only `\\` and `\"`
  are escapes; `find-generic-password -w` prints the value itself when it is printable
  ASCII, else its UTF-8 bytes as hex. The read-back is a consistency check, NOT proof of
  byte-exact storage.
- **Deliberate divergences from the reference** (Codex debate, astra, 2026-09-24): a failed
  ATTEMPTED write never counts as "nothing changed" — Apple's `keychain_add.c` modifies the
  item content before `SecKeychainItemSetAccess`, so a positive exit can follow a mutation,
  and a negative one (signal) can too; cleanup therefore runs after ANY attempted-write
  failure and after an interruption (Ctrl-C). Cleanup is best effort and the pair is NOT
  atomic: a concurrent `load_credentials` can still read a mixed pair in the window.
- **Constraints**: never touch the real login keychain or the live `biopol-wifi:` items in
  tests; never print the password; tests mock `subprocess.run` completely; keep the existing
  `timeout=15`; no new dependency; biopol-wifi must not import browser.py (separate repo,
  browser-login is a provider).
- **Confidence**: high. **Blocked on Albert**: no.
- **Verification note**: the main block (this repo) holds only an allowlisted `git status`.
  The biopol-wifi block runs `uv run pytest`, `mypy` and `pylint`, which execute repository
  code, so it is not strict-eligible; its allowlisted `ruff`/`git` checks come first.

## Steps

- [ ] 1. In `sdsc/biopol-wifi/biopol-wifi.py`, port the stdin write path from browser.py
      (copied, not imported — decision ba91cc): `_KC_LINE_MAX = 4000`, `_kc_quote(s)`,
      `_kc_add_line(service, value, description)` (returns `None` on any control char
      `< 0x20` or `0x7F` in account/service/value/description, on a UTF-8 encode error, or
      when the ENCODED line exceeds `_KC_LINE_MAX` bytes; the line is
      `add-generic-password -a "…" -s "…" -w "…" -D "…" -T /usr/bin/security -U\n`, no
      keychain path named), and `_keychain_write(service, value, description) -> str`
      returning `ok | invalid | failed | mismatch`. It runs `[_security_bin(), "-i"]` with
      `input=<line bytes>`, `capture_output=True`, `timeout=15`, `check=False`; any non-zero
      return code (either sign) or `OSError`/`SubprocessError` → `failed` (may have written).
      The value never appears in argv or in any message.
- [ ] 2. After exit 0, read the item back with the existing `_keychain_get` and compare it
      with the form `find-generic-password -w` prints (the value when printable ASCII, else
      `value.encode("utf-8").hex()`); a difference returns `mismatch`. The docstring says it
      is a consistency check, not proof of byte-exact storage (tp#498).
- [ ] 3. Rewrite `_keychain_set(service, value)` as a thin wrapper:
      `_keychain_write(service, value, "biopol-wifi credential") == "ok"` (same signature,
      same `bool` contract, same `-D` description as today).
- [ ] 4. Fix `_keychain_delete`: `True` only for return code 0 or 44
      (`errSecItemNotFound`, already gone), `False` for anything else and for
      `OSError`/`SubprocessError` (browser.py:3331-3352 parity). `forget_creds` attempts both
      deletes, prints the service names that survive (never values) and exits 1 when any
      delete failed, 0 otherwise.
- [ ] 5. Make `store_creds` write the pair as one best-effort set (decisions 5ab619 and
      c33030, from the debate):
      a) refuse an email or password that is not printable ASCII (0x20-0x7E) — exit 1,
         "nothing stored", the message names the field and says `security -w` would read it
         back hex-encoded (tp#498); the value is never echoed;
      b) validate BOTH items with `_kc_add_line` before the first write — a refusal makes
         no `security` call and exits 1 with "nothing stored";
      c) write email, then password; ANY failure of an attempted write (`failed`,
         `mismatch`) → attempt `_keychain_delete` of BOTH items, print which item failed and
         which services (if any) survived the cleanup, exit 1 (load then exits 3 with the
         `--store-creds` hint);
      d) wrap the mutation phase (just before the first `security -i` call until both
         read-backs succeed) in `try: … except BaseException:` that runs the same cleanup
         and then re-raises, so Ctrl-C still propagates but never leaves a half-written
         pair behind knowingly;
      e) the success message stays; no message claims atomicity.
- [ ] 6. Add mocked tests to `sdsc/biopol-wifi/tests/test_biopol_wifi.py` — a stateful
      `subprocess.run` fake via `monkeypatch` (an in-memory dict keyed by service that
      parses the `security -i` stdin line, answers `find-generic-password -w` and
      `delete-generic-password`, and fails the test on any other argv), `_security_bin`
      patched to `"/usr/bin/security"`; no real `security` call anywhere:
      a) the secret is never in any argv and is on stdin exactly once; argv is
         `[<security>, "-i"]`;
      b) quoting: a value with `"`, `\`, spaces and `$;|&#` produces the expected escaped
         line and round-trips through the fake;
      c) validation boundaries, each asserting ZERO subprocess calls: encoded line of
         exactly 4000 bytes accepted vs 4001 refused; overflow caused by escaping and by
         multibyte characters; a control char (`\n`, `\x00`, `\x7f`) in each of the four
         fields; a lone surrogate;
      d) non-zero exit (positive and negative) → `False`; `OSError`/`TimeoutExpired` →
         `False`; read-back mismatch → `False`; non-ASCII value expects the hex read-back;
      e) `_keychain_delete`: 0 and 44 → `True`, 51 and an exception → `False`;
         `forget_creds` exits 1 and names the surviving service when one delete fails;
      f) `store_creds` (input/getpass patched): non-printable-ASCII email and password
         (parameterized) → zero calls, exit 1, value absent from captured stdout/stderr;
         second write fails after the first succeeded → both deletes attempted, exit 1;
         first write MUTATES the fake then returns 1 → both deletes attempted, exit 1;
         a delete fails during cleanup → the surviving service is named, exit 1;
         `KeyboardInterrupt` during the first write's read-back and during the second write
         → both deletes attempted and the `KeyboardInterrupt` propagates;
         success → exit 0 and the password appears in no argv and no captured output.
- [ ] 7. Run the Verification blocks in the foreground; fix every lint/type finding in the
      touched code on the spot.
- [ ] 8. Update `sdsc/biopol-wifi/README.md` (credentials section): the password is written
      via `security -i` on stdin (never argv) and read back; store-creds refuses
      non-printable-ASCII values (tp#498); a failed store removes both items.
- [ ] 9. Commit in biopol-wifi with
      `ai.py push -m "fix: write keychain secrets via security -i stdin, not argv" biopol-wifi.py tests/test_biopol_wifi.py README.md`
      and tick the boxes of this plan in browser-login (`ai.py push` this file). In the
      work Summary, list under `### Observations` (defect) that browser.py's
      `_keychain_write` (`bin/browser.py:3250`) and `_keychain_set_all` still treat a
      non-zero exit of the first write as "nothing changed" and do not clean up on
      `KeyboardInterrupt` (O6/O7 of this debate) — overseer decides whether to file it.

NOTE: Albert re-runs `biopol-wifi.py --store-creds` himself after this lands if he wants the
items rewritten through the new path; the existing items stay valid either way (no rotation
needed — the password was only exposed transiently in argv on this single-user Mac).

## Verification

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && git status --short
```

### Other repositories

```commands
cd /Users/albert/obsidian/42-Git/sdsc/biopol-wifi && ruff check biopol-wifi.py tests
cd /Users/albert/obsidian/42-Git/sdsc/biopol-wifi && ruff format --check biopol-wifi.py tests
cd /Users/albert/obsidian/42-Git/sdsc/biopol-wifi && git status --short
cd /Users/albert/obsidian/42-Git/sdsc/biopol-wifi && uv run pytest -q tests
cd /Users/albert/obsidian/42-Git/sdsc/biopol-wifi && uv run mypy biopol-wifi.py
cd /Users/albert/obsidian/42-Git/sdsc/biopol-wifi && uv run pylint biopol-wifi.py
```
