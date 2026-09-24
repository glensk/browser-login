# tp#504 — browser.py keychain writes: `-U` raises a SecurityAgent prompt, the 15 s timeout kills `security` mid-prompt

## Session

Resume: `c --resume d680a904-d489-4392-8c9f-f33b600b8bbe`

## Context

Classification: **DEFECT**. Updating an existing keychain item can open a GUI prompt. A fixed
timeout then kills the `security` process while that prompt is open. That crashed `securityd`
once.

**Symptom (2026-09-24, observed in the tp#489 work session).** A probe called `_keychain_set` 60
times on one throw-away login-keychain item: 1 create, then 59 `-U` updates. The FIRST update
opened a SecurityAgent prompt at 14:15:06. The 15 s `subprocess.run` timeout killed the
`security` client at about 14:15:21. At 14:15:21 launchd logged that `securityd` exited with
SIGABRT, and it did so again at 14:25:04. After that, every login-keychain read hung: more than
500 `security find-generic-password` calls from other tools got stuck. Source:
`plans-done/PLAN_browser-py-keychain-set-passes-password-and-totp-s_DONE.md`, "Execution notes".

**Code.**

- `_kc_add_line` always appends `-T /usr/bin/security -U` (`bin/browser.py:3253-3256`).
- `_keychain_write` runs `subprocess.run(["security", "-i"], input=line, timeout=15)`
  (`bin/browser.py:3286-3295`). `subprocess.run` kills the child when the timeout expires.
- `_keychain_get` (`bin/browser.py:3195-3211`) and `_keychain_delete`
  (`bin/browser.py:3377-3391`) use the same `timeout=15`.
- There are only three `security` call sites. Their callers are `_keychain_set_all`
  (`:3324-3353`), `cmd_cscs_store_creds` (`:3830`, `:3889`), the CSCS forget path (`:3914`),
  `cmd_biopolwifi_store_creds` (`:5201`, `:5219`), the biopol forget path (`:5242`), and the reads
  in `_keychain_creds` (`:3480-3482`) and the biopol login (`:5146-5147`).
- None of the three calls names a keychain. Apple's delete searches the whole search list for
  the first match. A create with a NULL keychain targets the default keychain. So today a delete
  and an add can address two different keychains.

**Root cause, part 1: why an update prompts.** Established from Apple's source; moderate-high
confidence. See apple-oss-distributions/Security, `SecurityTool/macOS/keychain_add.c:125-140`,
`do_update_generic_password`. With `-U`, when the item already exists, the tool calls
`SecKeychainItemModifyContent`. Because `-T` gave an access list, it then also calls
`SecKeychainItemCopyAccess` → `merge_access` → `SecKeychainItemSetAccess`, and Apple's source
comments that this call may prompt. Changing an item's Access Control List (ACL) needs the owner's
authorization, which is a SecurityAgent dialog.

The update path looks the item up through `keychain_open`. On an invalid path that yields NULL,
so the lookup falls back to the search list. `tests/test_keychain_live.py` works around this
quirk by stripping `-U`.

I did not capture which dialog appeared. The fix removes this ACL-update path. It does **not**
guarantee that nothing prompts: a create, a delete, or a read on a LOCKED keychain can still show
an unlock dialog, as Apple's documentation for creation says. Process safety therefore has to
hold whether or not a dialog appears.

**Root cause, part 2: why it became a crash.** Here the evidence is correlation. The client was
killed while its SecurityAgent request was pending, and `securityd` aborted 15 s after the prompt
opened. That timing fits exactly, and it happened once. That the kill *causes* the abort is not
proven. I will **not reproduce it**: doing so means crashing `securityd` on Albert's live machine
again, and Albert's standing order forbids killing `security`.

**Why a reproduction of part 1 is not run here either.** A single `-U` update, even in a temp
keychain, would pop a real GUI prompt in a headless session. Nobody could answer it, and killing
`security` is forbidden. The source reading is enough to choose a fix. After the fix, one live
overwrite runs in a private temp keychain. That keychain is unlocked and has no lock timeout.

**Two more ways the same kill can happen:**

- Pressing Ctrl-C during `store-creds` sends SIGINT to the whole foreground process group. That
  includes a `security` child that is showing a prompt.
- A read against a locked login keychain opens an unlock prompt, and the 15 s timeout then kills
  that client in the same way.

**Decisions** (settled from the evidence and recorded with `tp question -d`; Albert can overrule;
the Codex debate converged in round 1 with gpt-6-astra, and all 7 objections were accepted):

1. **Delete-then-add replaces `-U`.** Drop `-U` and keep `-T /usr/bin/security`.
   - A fresh add never calls `SetAccess`.
   - Delete and add both NAME the same target keychain. That target is resolved once per batch
     with `security default-keychain -d user`, and the write fails closed when it cannot be
     resolved.
   - The read-back stays unpinned. It reads what consumers read, so a shadowing copy earlier in
     the search list shows up as `"mismatch"`.
   - Rejected: `-U` without `-T`. It still calls `ModifyContent`, and whether that prompts is
     unmeasured.
   - Rejected: a longer timeout, because it still ends in a kill.
2. **Never kill `security`, and put no deadline on any `security` call, reads included.**
   - Everything goes through one `_security_run` runner. It starts the child with
     `start_new_session=True`, so Ctrl-C does not reach it.
   - The runner always drains and reaps the child. There is no abandonment and no
     SIGPIPE-by-design.
   - While a child is running, the runner defers `KeyboardInterrupt`: it keeps waiting without
     signalling the child, then re-raises.
   - Trade-off accepted: a headless login that reads a LOCKED login keychain waits until the user
     unlocks it. Before, it killed the client.
3. **Outcomes are structured, never guessed.**
   - The runner reports `not_started` (an `OSError` at `Popen`, so provably nothing mutated),
     `done(rc)`, or `unknown` (an exception after launch, or a negative return code).
   - Only a proven no-op counts as "nothing changed".
   - `unknown` never starts the next mutation, and it is reported as "changed".

**Blocked on Albert: no.** Nothing here is irreversible, external or costly. No step touches the
login keychain.

**Why the Verification block is not strict-eligible:** the change is to code, so the block runs
`mypy`, `pylint` and the test suite. It includes one opt-in live test, and that test uses only a
private temp keychain created by its fixture.

## Steps

- [x] 1. Record the revised timeout decision (non-blocking). Done in the plan session with
      `tp question 504 -d "no deadline on any security call (reads included); …"` (assumption
      `6e6be2`). The delete-then-add and scope decisions are `c1a62d`/`c42af6`. `6d14fe` (a 15 s
      read wait) is superseded by `6e6be2`.
- [ ] 2. In `bin/browser.py`, add the runner `_security_run(argv, *, input=None)` next to the
      keychain helpers. It returns a small result object (`SecurityResult`) with
      `state: "not_started" | "done" | "unknown"`, `rc`, `stdout: bytes` and `stderr: bytes`.
      - Launch: `subprocess.Popen(argv, stdin=PIPE if input is not None else DEVNULL, stdout=PIPE, stderr=PIPE, start_new_session=True)`.
        An `OSError` there → `not_started`.
      - Wait: `communicate(input)` with NO timeout. On `KeyboardInterrupt`, remember it and keep
        calling `communicate()`/`wait()` until the child exits. Never call `kill`, `terminate`
        or `send_signal`. Then re-raise the `KeyboardInterrupt`.
      - Any other exception after launch → wait for the child as above, then `unknown`. A
        negative return code → `unknown`.
      - Docstring: cite the 2026-09-24 securityd abort and state "never kill `security`, never
        time it out".
- [ ] 3. Add `_kc_target_keychain() -> str | None`. It runs
      `security default-keychain -d user` through the runner, strips quotes and whitespace, and
      returns the path only if it exists as a file. Otherwise it returns `None`.
- [ ] 4. Route the three existing helpers through `_security_run` and remove every `timeout=15`:
      - `_keychain_get` stays unpinned. It decodes stderr with `errors="replace"` itself, and any
        state other than `done` with rc 0 → `None`.
      - Add `_kc_delete(service, keychain) -> "deleted" | "absent" | "rejected" | "unknown"`.
        It names the keychain as the last argument. rc 0 → `deleted`, rc 44 → `absent`,
        `not_started` or any other positive rc → `rejected`, `unknown` → `unknown`.
      - `_keychain_delete(service)` stays a bool adapter for the forget commands. It resolves the
        target and returns `True` only for `deleted` or `absent`.
- [ ] 5. `_kc_add_line(service, value, description, keychain)`:
      - Drop `-U`. The line ends `-T /usr/bin/security <quoted keychain>`, which names the target
        explicitly; an invalid path makes the plain insert fail instead of falling back.
      - The keychain counts toward `_KC_LINE_MAX` and gets the same control-character check.
      - Update its docstring.
- [ ] 6. Make `_keychain_write(service, value, description, keychain)` delete-then-add, with
      outcomes:
      - `"invalid"`: the line was refused and nothing ran.
      - `"rejected"`: the delete was `rejected`, or it was `absent` and the add was then rejected.
        Nothing changed.
      - `"uncertain"`: the delete was `unknown`; the add is NOT started.
      - `"lost"`: the delete was `deleted`, then the add was rejected or `not_started`.
      - `"uncertain"`: the add was `unknown`.
      - `"mismatch"`: the unpinned read-back differs.
      - `"ok"`.
      - `_keychain_set` resolves the target itself, and returns `False` when it is `None`.
- [ ] 7. `_keychain_set_all`:
      - Resolve the target once. If it is `None`, return `KeychainBatchResult(ok=False)` and
        nothing ran.
      - Validate every add line, then write the items in order. Only `"invalid"`/`"rejected"` on
        the FIRST item count as "nothing changed". Every other failure runs the existing cleanup,
        which deletes each batch item in the same target.
      - A `KeyboardInterrupt` that escapes a write runs the cleanup as well. The exception is:
        nothing can have mutated yet, meaning the interrupt came before the first delete
        returned `deleted`. The cleanup's deletes are interrupt-deferred by the runner, and the
        interrupt is then re-raised.
      - Update the `KeychainBatchResult`/`_keychain_set_all`/`_keychain_write` docstrings: no
        `-U`, pinned target, non-atomic.
- [ ] 8. Before the first write, `cmd_cscs_store_creds` and `cmd_biopolwifi_store_creds` print one
      stderr line: `If macOS shows a keychain dialog, answer it.` The line names no values. It is
      a hint only; the runner is the protection.
- [ ] 9. Offline tests. They are mocked, never run `security`, and the conftest default-deny guard
      stays on.
      - The fake `Popen` records argv, kwargs and input.
      - Rewrite `tests/test_keychain_batch.py`'s fake to be INSERT-ONLY: an add of an existing
        item → rc 45 (`errSecDuplicateItem`). Faults are keyed per operation (`delete`/`add`/`find`)
        and per occurrence.
      - Re-express every existing scenario, and add distinct cases for:
        - initial delete rejected;
        - delete `unknown` (no add follows);
        - add rejected after delete (`"lost"`, then cleanup, `changed=True`);
        - add `unknown`;
        - read-back mismatch;
        - cleanup-only failure (`surviving` populated).
      - Adapt `tests/test_credentials.py` to the runner. New regression tests:
        - (a) The add line has no `-U` and ends in `-T /usr/bin/security "<keychain>"\n`.
        - (b) Delete and add name the same keychain. In a mocked setup where the default keychain
          differs from the first search-list keychain, the pinned target is the default one and
          the unpinned read-back reports `"mismatch"` when a shadow copy exists.
        - (c) The runner passes `start_new_session=True` and no `timeout`. It never calls
          `kill`/`terminate`/`send_signal`: the fake `Popen` raises if they are called.
        - (d) A `KeyboardInterrupt` raised once from `communicate` is deferred until the child
          exits, then re-raised. Cover it during delete, add, read-back and cleanup. In a batch,
          an interrupt after a mutation triggers cleanup, and one before any mutation does not.
        - (e) `not_started` vs `unknown` are distinguished in every helper's outcome.
        - (f) The dialog hint is printed and contains no value.
        - (g) `_kc_target_keychain` returns `None` when the path is missing, and the write then
          runs nothing.
- [ ] 10. `tests/test_keychain_live.py`:
      - Route BELOW the production runner. The router patches `browser.subprocess.Popen`. It
        asserts `start_new_session=True`, rewrites the keychain argument of
        find/delete/add-line calls to the temp keychain, and answers
        `default-keychain -d user` itself with the temp path, without running it. It refuses any
        other shape or any argv that names another keychain, then calls the captured real
        `Popen` with the caller's kwargs.
      - Run the fixture's lifecycle calls (create/unlock/settings/info/list/delete-keychain)
        through `browser._security_run` as well, so they get the same no-kill/new-session
        behaviour. Delete `_exec_security`, or make it a thin wrapper over the runner.
      - Update the router tests (`test_bad_add_input_is_refused`,
        `test_add_line_drops_update_flag_and_names_keychain`, and the others) to the new shapes:
        the add line must NOT contain `-U`.
      - Add ONE live overwrite case: `_keychain_set` twice on one service with two dummy values,
        read back the second, then delete. It is not a loop.
      - The module docstring drops the `-U` fallback paragraph.
- [ ] 11. Update the keychain notes in README.md and the AGENTS.md conventions:
      - writes are delete-then-add, pinned to the default keychain, with no `-U`;
      - `security` is never killed or timed out, and reads wait for a locked keychain.
      Also fix stale `-U` wording elsewhere (`grep -n "\-U" README.md AGENTS.md bin/browser.py`).
- [ ] 12. Run every `## Verification` line in the foreground, fix until green, tick the boxes, then
      `ai.py push -m "fix(keychain): delete-then-add instead of -U, never kill security" bin/browser.py tests/conftest.py tests/test_credentials.py tests/test_keychain_batch.py tests/test_keychain_live.py README.md AGENTS.md PLAN_browser-py-keychain-set-fixed-timeout-15-unconditi.md`.

NOTE: No redeploy is needed, because `browser.py` is exec'd fresh on every call. Albert's
existing items were created with `-T /usr/bin/security`, so reads keep working. Albert re-runs
`store-creds` himself after this lands, and that run is the first real delete-then-add against
the login keychain.

NOTE: A throw-away item from tp#489, `tp489-probe-<hex>` (dummy value), may still be in the login
keychain. Only Albert removes it. Sessions never touch the login keychain.

## Verification

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff check bin/ tests/
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff format --check bin/ tests/
cd /Users/albert/obsidian/42-Git/home/browser-login && git diff --no-ext-diff --no-textconv --stat HEAD
cd /Users/albert/obsidian/42-Git/home/browser-login && git log --oneline -5
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run mypy bin/browser.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pylint bin/browser.py tests/test_keychain_live.py tests/conftest.py
cd /Users/albert/obsidian/42-Git/home/browser-login && env BROWSER_LIVE_KEYCHAIN=0 uv run pytest -q
cd /Users/albert/obsidian/42-Git/home/browser-login && env BROWSER_LIVE_KEYCHAIN=1 uv run pytest -q tests/test_keychain_live.py
```
