# tp#506 — isolate tests/test_keychain_live.py in a temporary keychain file

## Session

Resume: `c --resume 35e910f8-c663-4966-8d71-33e98b6d6fc4`

## Context

Classification: **DEFECT**. The test is meant to be isolated but writes to the real login keychain.
Line numbers are from HEAD `65bc78b`.

Debated on 2026-09-24 with Codex (gpt-6-astra). The judge declared convergence in round 1. All ten
objections were accepted; O3 was accepted in part. They are folded into the steps below, and each
step cites the objection it comes from as `(O#)`.

- **Symptom.** When `BROWSER_LIVE_KEYCHAIN=1` is set, `tests/test_keychain_live.py` creates, reads,
  dumps and deletes throw-away `tp489-live-<hex>` items in Albert's **login keychain**. The standing
  rule says that a test needing a real keychain uses its own temporary keychain file. That file is
  passed explicitly to every `security` call, is never added to the search list, and is deleted
  afterwards.
- **Evidence (static, file:line).**
  - The module docstring promises exactly this: "Writes ONLY throw-away items … into the login
    keychain" (`tests/test_keychain_live.py:3-5`).
  - The test helpers pass no keychain argument. `_items_matching` runs a bare
    `security dump-keychain` (`tests/test_keychain_live.py:70-77`) and ignores its return code.
    `_delete` runs `security delete-generic-password -a … -s …` (`:84-90`).
  - The code under test has no keychain argument either:
    - `_keychain_get` builds `find-generic-password -a -s -w` (`bin/browser.py:3152-3166`).
    - `_kc_add_line` builds the `security -i` line
      `add-generic-password … -T /usr/bin/security -U` (`bin/browser.py:3204-3208`).
      `_keychain_write` runs it at `:3240-3247`.
    - `_keychain_delete` builds `delete-generic-password -a -s` (`:3334-3345`).

    Each of these goes to the default keychain or the search list, which is the login keychain.
  - `tests/conftest.py:62-68` exempts `live_keychain`-marked tests from the whole default-deny guard.
    That exemption covers `security`, and also `op`, `himalaya` and `Popen`.
- **Root cause (established).** tp#489 wrote the test to exercise `browser.py`'s real `security`
  argv and stdin line. Neither the test nor `browser.py` can aim `security` at another keychain, so
  the login keychain was the only possible target. tp#491 only added the marker.
- **Not reproduced on purpose.** Albert's standing order forbids running this file against the login
  keychain, even to reproduce the defect. The argv at the lines above is the evidence and needs no
  run.
- **Hazards the fix must handle.**
  - `_kc_add_line` records a measured fact: "an invalid path falls back to the login keychain
    anyway" (`bin/browser.py:3198-3199`). Codex traced this to the `-U` update branch of Apple's
    `keychain_add.c`: `do_update_generic_password` passes a possibly-NULL `keychain_open` result
    into the search, while the plain insert branch checks that the open succeeded. The live harness
    therefore writes insert-only, without `-U` (O3).
  - Python's `subprocess.run(timeout=…)` kills the child when the timeout expires. On 2026-09-24,
    killing `security` mid-prompt made securityd abort. The live harness therefore runs `security`
    with **no** timeout. Hangs are prevented instead by an explicit unlock, a no-auto-lock setting
    and `-T /usr/bin/security` trust (O1, O2).
- **Search list.** Apple's `StorageManager.cpp` (`shouldAddToSearchList`) automatically adds only
  login and System keychains, so `create-keychain` of a private file is expected NOT to add it. That
  is expected behaviour, not proven behaviour on this macOS. The fixture therefore checks membership
  of its own path in the parsed `list-keychains -d user` output. If the path is present, the fixture
  runs an exact-path `delete-keychain` and fails. This is **detection plus recovery, not
  prevention**. The work session's first live run establishes the behaviour here (O7).
- **Chosen design (test-only, no `bin/browser.py` change).**
  - A strictly validating router replaces `subprocess.run` only inside the live test body.
  - It rewrites the exact `security` shapes that `browser.py`'s keychain helpers produce so that
    they name the temp keychain.
  - It rejects everything else.
  - It delegates non-`security` programs to conftest's still-active default-deny guard.
- **Alternatives considered.**
  - (a) A `BROWSER_KEYCHAIN_PATH` override in `bin/browser.py`. Rejected: it adds a
    credential-redirect surface to a live tool that consumers inherit through the environment, and a
    bad value would fall back to the login keychain.
  - (b) Switching the default keychain or search list. Rejected: it mutates Albert's preferences.
  - (c) Deleting the live test. Rejected: it is the only real-tokenizer round-trip check of
    `_kc_quote`.
  - (d) Codex's suggestion to allow live runs only in a disposable VM or account. Rejected: the
    remaining lstat-to-exec race needs a hostile same-user process, which is outside this test's
    threat model, and without `-U` an unopenable path makes the add fail instead of falling back.
- **Confidence:** high.
- **Blocked on Albert:** no. Defaults are recorded as non-blocking assumptions: the live test stays
  opt-in, it has no `-U` update case, and the routing is test-only.
- **Why the Verification block is not strict-eligible.** It runs pytest (including the single opt-in
  live run against the temp keychain) and pylint. These execute repository code, so the allowlist
  runner skips them and the reviewer runs them in its own session.

## Steps

- [ ] 1. Rewrite the module docstring of `tests/test_keychain_live.py`. It must say that the test
      uses its own temporary keychain file and never the login keychain.
  - Move the `skipif` (`BROWSER_LIVE_KEYCHAIN=1` and macOS) and the `live_keychain` marker from
    module level onto the live test function, so that the offline tests from step 5 always run.
  - Capture `_REAL_RUN = subprocess.run` at module import.
  - Rename the account prefix to `tp506-live-<hex>` and the description to `"tp506 live test"`.
- [ ] 2. `tests/conftest.py` (O6): stop exempting `live_keychain` tests from the guard. The
      default-deny wrappers on `subprocess.run` and `subprocess.Popen` stay installed for every
      test.
  - Keep registering the marker, with its meaning rewritten: "may run the real `security` binary
    against its own temp keychain through the test's router".
  - Update the module docstring (lines 1-10) to match.
- [ ] 3. Keychain lifecycle as plain functions that take a `runner`, so that fakes can test them
      (O5, O8).
  - Every argv names the fixture path explicitly.
  - No call passes `timeout` (O1).
  - `_kc_lifecycle(runner, argv)` checks `rc == 0` and raises with the subcommand name. It never
    prints output or the password.

  **`_create_temp_keychain(runner)`:**
  - Build the path `Path(tempfile.gettempdir()).resolve() / f"tp506-{secrets.token_hex(6)}.keychain-db"`.
    The password is `secrets.token_urlsafe(24)`, held in memory only.
  - `try:`, so that everything from creation onwards is covered, and on any failure call
    `_destroy_temp_keychain` before re-raising:
    - Run `security create-keychain -p <pw> <path>`.
    - Record the identity: lstat → `(st_dev, st_ino)`. The path must be a regular file, not a
      symlink, and owned by `os.getuid()`.
    - Run `security unlock-keychain -p <pw> <path>`.
    - Run `security set-keychain-settings <path>`. Without `-l`, `-u` or `-t`, this means no lock
      on sleep and no timeout (O2).
    - Run `security show-keychain-info <path>` and assert rc 0 with `no-timeout` in its
      stdout+stderr (O2).
    - Parse `security list-keychains -d user` (one quoted path per line, realpath-normalised). If
      the fixture's own path is a member, fail (O7). The `finally` below then deletes the file.
  - Return `(path, identity)`.

  **`_destroy_temp_keychain(runner, path)`:**
  - Run an exact-path `security delete-keychain <path>`, check its rc, then assert
    `not path.exists()`.
  - No `unlink` fallback. A failed delete raises and names the path (O8).
  - Re-parse `list-keychains -d user` and assert that the path is not a member.

  **Wiring:**
  - A function-scoped fixture `temp_keychain` binds these to `_REAL_RUN`, yields, and destroys in
    `finally`.
- [ ] 4. The router `_make_router(keychain, identity, security_runner, fallback_run)` returns a
      `run`-compatible callable (O3, O4, O6).
  - **Identity check.** Before every `security` call, lstat the path and require all of these,
    otherwise raise: a regular file, not a symlink, owner `os.getuid()`, `(st_dev, st_ino) ==
    identity`, and a path equal to the fixture's resolved path.
  - **Program detection.** The program is `os.path.basename` of `argv[0]`, or of an `executable=`
    kwarg. An `executable=` override on a `security` call raises.
  - **`["security", "-i"]`.**
    - stdin must be exactly one `\n`-terminated line matching
      `^add-generic-password -a "…" -s "…" -w "…" -D "…" -T /usr/bin/security -U\n$`. Fields are
      `_kc_quote`-quoted and contain no control characters.
    - Rewrite the line: remove the single trailing `-U` (insert-only; O3), then append
      `" " + browser._kc_quote(str(keychain))` before the `\n`.
    - The final routed line must be at most `browser._KC_LINE_MAX` bytes (O4).
  - **Exact argv shapes.** The router appends `str(keychain)` to exactly
    `["security", "find-generic-password", "-a", A, "-s", S, "-w"]` and
    `["security", "delete-generic-password", "-a", A, "-s", S]`. Every other `security` argv
    raises: `delete-keychain`, `dump-keychain`, `list-keychains`, `default-keychain`, extra
    operands, `-w` missing (O4).
  - **Execution.** Drop any inherited `timeout` kwarg and call `security_runner` (O1). Non-`security`
    programs go to `fallback_run`, which is conftest's guarded run captured at install time, so
    `op` and `himalaya` stay denied (O6).
- [ ] 5. Add always-running offline tests. They use fake runners, never execute `security`, and the
      conftest guard stays active. The tests cover:
  - the `-i` rewrite: `-U` is removed, the quoted path is appended before `\n`, and a line that is
    too long after routing raises;
  - a multi-line `-i` stdin, a wrong `-i` command (`delete-keychain …`) and a missing `-U` each
    raise;
  - `find-` and `delete-` get the path as their last argument, and extra operands raise;
  - `dump-keychain`, `list-keychains`, `default-keychain` and an `executable=` override raise;
  - an identity mismatch, a symlink, a missing file and a wrong owner (the fake lstat is patched)
    each raise;
  - the fake runner never receives `timeout`, even when the caller passed `timeout=15`;
  - `op` and `himalaya` through the router are still denied by the guard (`DeniedSubprocess`);
  - an integration run of `browser._keychain_set`, `_keychain_get` and `_keychain_delete` with the
    router over a recording fake: every recorded `security` argv or stdin names the fixture path;
  - `_create_temp_keychain` and `_destroy_temp_keychain` with fakes that fail right after
    `create-keychain`, at unlock, at settings, at `show-keychain-info`, and on search-list
    membership: each case ends with exactly one `delete-keychain <path>` and raises. A failed
    `delete-keychain` raises and names the path;
  - `_items_matching` raises on a `dump-keychain` rc other than 0, and returns `[]` only for an rc 0
    empty dump (O9).
- [ ] 6. Rewrite `test_keychain_set_round_trips_through_security_stdin` (live, opt-in) to use the
      `temp_keychain` fixture.
  - Inside `with monkeypatch.context() as m:`, patch `_kc_account` and install the router on
    `subprocess.run`. The context exits before fixture teardown (O5).
  - Keep `CASES` and the invalid-newline case.
  - `_items_matching(prefix, keychain)` calls `security dump-keychain <keychain>` via
    `_kc_lifecycle` and checks the rc.
  - Clean up per item through the routed `browser._keychain_delete` and assert `True`. Then assert
    that `_items_matching` in the temp keychain is empty.
  - Drop the old `_delete` loop.
  - Keep **no** `-U` update case (assumption d24e57).
- [ ] 7. Find stale wording with `git grep -n "login keychain" -- tests/` and
      `git grep -n BROWSER_LIVE_KEYCHAIN`, and fix any doc outside `plans-done/` that still says
      that the live test uses the login keychain.
- [ ] 8. Run the full `## Verification` block in the foreground. It includes exactly one opt-in live
      run against the temp keychain: no loops, no re-runs of the live line within one pass. Then
      run `ai.py push -m "test(keychain-live): isolate live test in a temp keychain" tests/test_keychain_live.py tests/conftest.py PLAN_tests-test-keychain-live-py-writes-throwaway-items.md`.

NOTE: No step touches the login keychain, the browser profile or `bin/browser.py`. The search list
is only read. The single exception is the fixture's own exact-path `delete-keychain` recovery,
which cannot remove anything but the fixture's file.

## Verification

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff check bin/ tests/
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff format --check bin/ tests/
cd /Users/albert/obsidian/42-Git/home/browser-login && git diff --no-ext-diff --no-textconv --stat HEAD
cd /Users/albert/obsidian/42-Git/home/browser-login && git log --oneline -5
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pylint tests/test_keychain_live.py tests/conftest.py
cd /Users/albert/obsidian/42-Git/home/browser-login && env BROWSER_LIVE_KEYCHAIN=0 uv run pytest -q
cd /Users/albert/obsidian/42-Git/home/browser-login && env BROWSER_LIVE_KEYCHAIN=1 uv run pytest -q tests/test_keychain_live.py
```
