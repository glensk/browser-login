# tp#506 — isolate tests/test_keychain_live.py in a temporary keychain file

## Session

Resume: `c --resume 35e910f8-c663-4966-8d71-33e98b6d6fc4`

## Context

Classification: **DEFECT**. The test is meant to be isolated but writes to the real login
keychain. Line numbers are from HEAD `65bc78b`.

- **Symptom.** When `BROWSER_LIVE_KEYCHAIN=1` is set, `tests/test_keychain_live.py` creates,
  reads, dumps and deletes throw-away `tp489-live-<hex>` items in Albert's **login keychain**. The
  standing rule says that a test needing a real keychain must use its own temporary keychain file.
  That file is passed explicitly to every `security` call, is never added to the search list, and
  is deleted afterwards.
- **Evidence (static, file:line).**
  - The module docstring promises exactly this: "Writes ONLY throw-away items … into the login
    keychain" (`tests/test_keychain_live.py:3-5`).
  - The test's own helpers pass no keychain argument. `_items_matching` runs a bare
    `security dump-keychain` (`tests/test_keychain_live.py:70-77`). `_delete` runs
    `security delete-generic-password -a … -s …` (`:84-90`).
  - The code under test also has no keychain argument. `_keychain_get` builds
    `find-generic-password -a -s -w` (`bin/browser.py:3152-3166`). `_kc_add_line` builds the
    `security -i` line `add-generic-password … -T /usr/bin/security -U` (`bin/browser.py:3204-3208`),
    which `_keychain_write` runs at `:3240-3247`. `_keychain_delete` builds
    `delete-generic-password -a -s` (`:3334-3345`). Each of these goes to the default
    keychain / search list, which means the login keychain.
  - `tests/conftest.py:62-68` exempts `live_keychain`-marked tests from the default-deny
    `security` guard, so nothing stops these calls.
- **Root cause (established).** tp#489 wrote the test to exercise `browser.py`'s real
  `security` argv and stdin line. Neither the test nor `browser.py` has a way to aim `security` at a
  different keychain, so the only possible target was the login keychain. tp#491 added the
  `live_keychain` marker and left the target logic as it was.
- **Not reproduced on purpose.** Albert's standing order forbids running this file against the
  login keychain, even to reproduce the bug. The argv at the lines above is the evidence and needs
  no run.
- **Extra hazard for the fix.** `_kc_add_line`'s docstring records a measured fact from tp#489:
  "an invalid path falls back to the login keychain anyway" (`bin/browser.py:3198-3199`). A
  temp-keychain path that is wrong or already deleted would therefore silently send writes back to
  the login keychain. The rewrite must fail closed before every routed call.
- **Open empirical point.** The `security(1)` man page does not say whether `create-keychain`
  adds the new file to the user search list. CI recipes run `list-keychains -s` afterwards, which
  suggests it does not, but that is not proof. The fixture therefore measures this and fails
  closed (step 2).
- **Chosen design (test-only, no `bin/browser.py` change).** For the length of the live test, a
  routing wrapper replaces `subprocess.run`. It rewrites every `security` invocation that
  `browser.py` makes so that the invocation names the temp keychain:
  - For `find-generic-password`, `delete-generic-password` and `dump-keychain`, it appends the
    path as the trailing keychain operand.
  - For `security -i`, it appends `<_kc_quote(path)>` to the single stdin command line, before
    its newline.
  - Any other `security` shape raises. Non-`security` programs pass through.

  The test still exercises `browser.py`'s real quoting, stdin line and read-back against the real
  binary, but only inside the temp file.
- **Alternatives considered.**
  - (a) A `BROWSER_KEYCHAIN_PATH` override inside `bin/browser.py`. Rejected: it adds a
    credential-redirect surface to the live tool that every consumer inherits through the
    environment, and the fallback above would make a bad value land in the login keychain anyway.
  - (b) Temporarily switching the default keychain or search list (`default-keychain -s`,
    `list-keychains -s`). Rejected: it mutates Albert's user keychain preferences, and a crash
    would leave them mutated.
  - (c) Deleting the live test and relying on the mocked `test_keychain_batch.py`. Rejected: the
    live test is the only check that `_kc_quote` round-trips through the real `security -i`
    tokenizer, which was tp#489's point.
- **Confidence:** high on the root cause and the design. The one unknown is the search-list
  behaviour of `create-keychain`, and step 2 turns it into a hard precondition instead of an
  assumption.
- **Blocked on Albert:** no. Every decision is test-local and reversible. Defaults are recorded
  as non-blocking `tp question` assumptions.
- **Why the Verification block is not strict-eligible.** It runs pytest, including the opt-in
  live run against the temp keychain, and pylint. These execute repository code, so the allowlist
  runner skips them. The reviewer runs them in its own session.

## Steps

- [ ] 1. Rewrite the module docstring of `tests/test_keychain_live.py`. It must say that the test
      uses its own temporary keychain file and never the login keychain. Keep the
      `BROWSER_LIVE_KEYCHAIN=1` opt-in for the live test: it still starts the real `security`
      binary, so the default suite must not run it (assumption recorded:
      `tp question 506 -d "keep BROWSER_LIVE_KEYCHAIN=1 opt-in" …`). Move the `skipif` from module
      level onto the live test function so that the pure tests from step 4 always run. The
      `live_keychain` marker stays on the live test only.
- [ ] 2. Add a function-scoped fixture `temp_keychain` that does the following:
  - Snapshot the output of `security list-keychains -d user` (read-only).
  - Create `Path(tempfile.gettempdir()) / f"tp506-{secrets.token_hex(6)}.keychain-db"`. The
    password is `secrets.token_urlsafe(24)`, held in memory only and never printed. Run
    `security create-keychain -p <pw> <path>`.
  - Assert that the file exists and that `security show-keychain-info <path>` exits 0.
  - Re-read `list-keychains -d user` and assert that it equals the snapshot. If it differs,
    `create-keychain` added the file to the search list: run `security delete-keychain <path>`
    (this removes it from the list again) and fail with a clear message. Never call
    `list-keychains -s`.
  - Yield the path.
  - In `finally`, run `security delete-keychain <path>`, then `Path.unlink(missing_ok=True)` as a
    fallback. Assert that the search list still equals the snapshot.

  Every `security` call in the fixture names the temp path. No `timeout` kill is needed because no
  call touches the login keychain, but keep `timeout=60` as the existing helpers do.
- [ ] 3. Add a pure function `_route_security(argv, input_, keychain) -> (argv, input_)` and a
      wrapper that the live test installs with `monkeypatch.setattr(browser.subprocess, "run", …)`.
      The wrapper is built from the real `subprocess.run` that was captured before patching.
  - Before every `security` call, it re-checks that `keychain` exists as a file. Because of the
    fallback hazard, a missing file raises instead of running.
  - Routing:
    - `["security", "-i"]` with exactly one `\n`-terminated command line on stdin: append
      `b" " + browser._kc_quote(str(keychain)).encode()` before the newline.
    - `["security", "find-generic-password" | "delete-generic-password" | "dump-keychain", …]`:
      append `str(keychain)`.
    - Any other `security` argv, or an `-i` stdin with zero or more than one line: raise
      `AssertionError` (fail closed).
  - Program names are matched through `os.path.basename` of `argv[0]`, the same way as
    `conftest._executable`.
  - The wrapper counts the calls it routed. The test asserts that the count is greater than zero,
    which proves the routing was really in the path.
- [ ] 4. Add always-running pure unit tests for `_route_security`. They execute nothing, and the
      conftest guard stays active for them:
  - the `-i` line gets the quoted path appended before `\n`;
  - `find-`, `delete-` and `dump-` get the path appended as the last argument;
  - an unknown subcommand (for example `list-keychains` or `default-keychain`) raises;
  - a multi-line `-i` stdin raises;
  - a missing keychain file raises;
  - a non-`security` argv passes through unchanged.
- [ ] 5. Rewrite `test_keychain_set_round_trips_through_security_stdin` to use `temp_keychain`
      and the routing wrapper:
  - Keep `CASES`, the `_kc_account` monkeypatch and the invalid-newline case.
  - `_items_matching(prefix, keychain)` runs `security dump-keychain <keychain>`.
  - Clean up per item through `browser._keychain_delete` (routed), which exercises the delete
    path, and assert `True`. Then assert that `_items_matching` finds nothing for the account in
    the temp keychain.
  - Drop the test's own `_delete` loop: `delete-keychain` in the fixture removes everything.
  - Keep **no** `-U` update case (assumption recorded:
    `tp question 506 -d "no -U update case even in the temp keychain" …`). An update could still
    open a SecurityAgent prompt, and "no repeated live -U loops" is a standing rule.
  - Rename the account prefix to `tp506-live-<hex>` and the description to `"tp506 live test"`.
- [ ] 6. Update the docstring of `tests/conftest.py` (lines 1-10). Drop the words "Albert's
      real login keychain" as the thing the live test reaches. The `live_keychain` marker now
      means "may run the real `security` binary against its own temp keychain".
- [ ] 7. Find stale wording with `git grep -n "login keychain" -- tests/` and `git grep -n
      BROWSER_LIVE_KEYCHAIN`, and fix any doc that still says that the live test uses the login
      keychain. Leave `plans-done/` as it is, because it is the archived record.
- [ ] 8. Run the full `## Verification` block in the foreground, including the opt-in live run
      against the temp keychain (at most one live run per verification pass, no loops). Then run
      `ai.py push -m "test(keychain-live): isolate live test in a temp keychain" tests/test_keychain_live.py tests/conftest.py PLAN_tests-test-keychain-live-py-writes-throwaway-items.md`.

NOTE: No step touches the login keychain, the search list (it is read-only except for the fixture's
own `delete-keychain` of its temp file), the browser profile or `bin/browser.py`.

## Verification

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff check bin/ tests/
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff format --check bin/ tests/
cd /Users/albert/obsidian/42-Git/home/browser-login && git diff --no-ext-diff --no-textconv --stat HEAD
cd /Users/albert/obsidian/42-Git/home/browser-login && git log --oneline -5
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pylint tests/test_keychain_live.py tests/conftest.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q
cd /Users/albert/obsidian/42-Git/home/browser-login && env BROWSER_LIVE_KEYCHAIN=1 uv run pytest -q tests/test_keychain_live.py
```
