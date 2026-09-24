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
     pre-validation and no cleanup; if the second write fails, the keychain holds the NEW
     email with the OLD password — a mismatched pair `load_credentials` then submits to the
     portal.
- **Reference fix**: `home/browser-login/bin/browser.py` — `_KC_LINE_MAX`, `_kc_quote`,
  `_kc_add_line`, `_keychain_write`, `_keychain_set`, `_keychain_set_all` (around
  `bin/browser.py:3178-3320`). Measured facts it relies on: `security -i` reads one command
  per line into a 4096-byte buffer (longer lines split, the tail parsed as a new command);
  inside `"…"` only `\\` and `\"` are escapes; `find-generic-password -w` prints the value
  itself when it is printable ASCII, else its UTF-8 bytes as hex.
- **Constraints**: never touch the real login keychain or the live `biopol-wifi:` items in
  tests; never print the password; tests mock `subprocess.run` completely; no timeout
  wrapper change around `security` (keep the existing `timeout=15`); no new dependency;
  biopol-wifi must not import browser.py (separate repo, browser-login is a provider).
- **Confidence**: high. **Blocked on Albert**: no.
- **Verification note**: the block below runs `uv run pytest`, `mypy` and `pylint` in
  biopol-wifi, which execute repository code, so it is not strict-eligible; the allowlisted
  `ruff`/`git` checks come first.

## Steps

- [ ] 1. In `sdsc/biopol-wifi/biopol-wifi.py`, port the stdin write path from browser.py
      (copied, not imported — decision recorded with `tp question 497 -d`):
      `_KC_LINE_MAX = 4000`, `_kc_quote(s)`, `_kc_add_line(service, value, description)`
      (returns `None` on any control char `< 0x20` or `0x7F` in account/service/value/
      description, on a UTF-8 encode error, or on a line `> _KC_LINE_MAX` bytes; the line is
      `add-generic-password -a "…" -s "…" -w "…" -D "…" -T /usr/bin/security -U\n`, no
      keychain path named), and `_keychain_write(service, value, description) -> str`
      returning `ok | invalid | rejected | uncertain | mismatch`. It runs
      `[_security_bin(), "-i"]` with `input=<line bytes>`, `capture_output=True`,
      `timeout=15`, `check=False`; the value never appears in argv or in any message.
- [ ] 2. After exit 0, read the item back with the existing `_keychain_get` and compare it
      with the form `find-generic-password -w` prints (the value when printable ASCII, else
      `value.encode("utf-8").hex()`); a difference returns `mismatch`.
- [ ] 3. Rewrite `_keychain_set(service, value)` as a thin wrapper:
      `_keychain_write(service, value, "biopol-wifi credential") == "ok"` (same signature,
      same `bool` contract, same `-D` description as today).
- [ ] 4. Make `store_creds` write the pair as one set (decision recorded with
      `tp question 497 -d`): validate BOTH items with `_kc_add_line` before the first write —
      an invalid field makes no `security` call and exits 1 with "nothing stored"; then
      write email, then password; if the FIRST write returns `rejected`/`invalid` nothing
      changed → exit 1 without cleanup; any other failure → `_keychain_delete` both items so
      the keychain never holds a mismatched pair (load then exits 3 with the
      `--store-creds` hint), print which item failed and whether the cleanup ran, exit 1.
      Messages name the service, never the value.
- [ ] 5. Add mocked tests to `sdsc/biopol-wifi/tests/test_biopol_wifi.py` (a `subprocess.run`
      recorder via `monkeypatch`, `_security_bin` patched to `"/usr/bin/security"` — no real
      `security` call anywhere):
      a) the secret is never in any argv and is on stdin exactly once, argv is
         `[<security>, "-i"]`;
      b) quoting: a value with `"`, `\`, spaces and `$;|&#` produces the expected escaped
         line;
      c) a newline / control char / `> 4000`-byte line makes no call and returns `False`;
      d) non-zero exit → `False`; `OSError`/`TimeoutExpired` → `False`;
      e) read-back mismatch → `False`; non-ASCII value expects the hex read-back;
      f) `store_creds`: invalid password → no call at all; password write fails after the
         email write → both items deleted, exit 1; first write rejected → no delete, exit 1;
         success → exit 0 and the password appears in no argv and no captured output.
- [ ] 6. Run the Verification block in the foreground; fix every lint/type finding in the
      touched code on the spot.
- [ ] 7. Update `sdsc/biopol-wifi/README.md` (credentials section) with one line: the
      password is written via `security -i` on stdin, never on argv, and read back.
- [ ] 8. Commit in biopol-wifi with
      `ai.py push -m "fix: write keychain secrets via security -i stdin, not argv" biopol-wifi.py tests/test_biopol_wifi.py README.md`
      and tick the boxes of this plan in browser-login (`ai.py push` this file).

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
cd /Users/albert/obsidian/42-Git/sdsc/biopol-wifi && git diff --no-ext-diff --no-textconv HEAD~1 -- biopol-wifi.py
cd /Users/albert/obsidian/42-Git/sdsc/biopol-wifi && uv run pytest -q tests
cd /Users/albert/obsidian/42-Git/sdsc/biopol-wifi && uv run mypy biopol-wifi.py
cd /Users/albert/obsidian/42-Git/sdsc/biopol-wifi && uv run pylint biopol-wifi.py
```
