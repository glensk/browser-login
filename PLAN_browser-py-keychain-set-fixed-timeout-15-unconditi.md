# tp#504 — browser.py keychain writes: `-U` raises a SecurityAgent prompt, the 15 s timeout kills `security` mid-prompt

## Session

Resume: `c --resume d680a904-d489-4392-8c9f-f33b600b8bbe`

## Context

Classification: **DEFECT**. Updating an existing keychain item can open a GUI prompt. A fixed
timeout then kills the `security` process while that prompt is open. That crashed `securityd` once.

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

**Root cause, part 1: why an update prompts.** Established from Apple's source; moderate-high
confidence. See `SecurityTool/macOS/keychain_add.c`, `do_update_generic_password`, in
apple-oss-distributions/Security. With `-U`, when the item already exists, the tool calls
`SecKeychainItemModifyContent`. Because an access list was given (`-T`), it then also calls
`SecKeychainItemCopyAccess` → `merge_access` → `SecKeychainItemSetAccess`. Changing an item's
Access Control List (ACL) needs the item owner's authorization, so SecurityAgent shows a
confirmation dialog. A plain create with `-T` (no existing item) sets the ACL when the item is
made. That does not prompt: the tp#506 live test creates and deletes items this way without a
prompt. The same source shows that the update path looks the item up through `keychain_open`,
and on an invalid keychain path that falls back to the default keychain. This is the quirk
`tests/test_keychain_live.py` works around by stripping `-U`. I did not capture which dialog
appeared (ACL change or item modify). Either way, the fix below avoids both calls.

**Root cause, part 2: why it became a crash.** Here the evidence is correlation. The client was
killed while its SecurityAgent request was pending, and `securityd` aborted 15 s after the prompt
opened. That timing fits exactly, and it happened once. That the kill *causes* the abort is not
proven. I will **not reproduce it**: doing so means crashing `securityd` on Albert's live machine
again, and Albert's standing order forbids killing `security`.

**Why a reproduction of part 1 is not run here either.** A single `-U` update in a temp keychain
would pop a real GUI prompt in a headless session. Nobody could answer it, and the orders forbid
killing `security`. The source reading is enough to choose a fix. After the fix, the live test
checks the *new* update path in a temp keychain. That path makes no ACL change, so it cannot
prompt.

**Two more ways the same kill can happen:**

- Pressing Ctrl-C during `store-creds` sends SIGINT to the whole foreground process group. That
  includes a `security` child that is showing a prompt.
- A read (`_keychain_get`) against a LOCKED login keychain opens an unlock prompt. The 15 s
  timeout then kills that client in the same way. Reads of items whose ACL trusts
  `/usr/bin/security` do not prompt while the keychain is unlocked.

**Decisions** (settled from the evidence and recorded with `tp question -d`; Albert can overrule):

1. Replace `-U` with **delete-then-add** (drop `-U`, keep `-T /usr/bin/security`). A fresh add
   never calls `SetAccess`. Delete of these items is already exercised without a prompt by the
   forget commands and the tp#506 live test.
   - Rejected: `-U` without `-T`. It still calls `ModifyContent` on an item another tool might
     own, and whether that prompts is unmeasured.
   - Rejected: a longer timeout. Any timeout still kills `security` in the end.
   - Cost: for a moment the item is absent, and a concurrent login falls back to 1Password. The
     batch is already documented as non-atomic (`:3334-3335`). An add that fails after a
     successful delete loses the old item; the store command reports it. The user is at the
     terminal with the values in hand.
2. **Never kill `security`.** All three helpers go through one `_security_run` helper that
   starts `security` with `start_new_session=True`, so Ctrl-C does not reach it.
   - Writes and deletes wait with no timeout. Only the interactive `store-creds` and `forget`
     commands call them, and there the user can answer a dialog.
   - Reads wait at most 15 s. If the time runs out, the helper stops waiting WITHOUT killing,
     leaves the child to finish, and returns "no value", so the caller falls back to 1Password.
3. Reads are in scope. They are the same helper and the same kill, and the change stays bounded
   to `bin/browser.py`'s three keychain helpers and their tests.

**Blocked on Albert: no.** Nothing here is irreversible, external or costly. No step touches the
login keychain.

**Why the Verification block is not strict-eligible:** the change is to code, so the block runs
`mypy`, `pylint` and the test suite. It includes one opt-in live test, and that test uses only a
private temp keychain.

## Steps

- [ ] 1. Record the decisions (non-blocking):
      `tp question 504 -d "delete-then-add without -U" "Replace security -U updates with delete-then-add, or keep -U without -T?"`,
      `tp question 504 -d "never kill security: writes/deletes unbounded, reads 15 s wait then abandon without kill" "What timeout policy for security calls?"`,
      `tp question 504 -d "yes, all three helpers via one _security_run" "Include _keychain_get/_keychain_delete in the no-kill change?"`.
- [ ] 2. In `bin/browser.py`, add `_security_run(argv, *, input=None, wait=None)`, returning
      `subprocess.CompletedProcess | None`, next to the keychain helpers:
      - Start the child with `subprocess.Popen(argv, stdin=PIPE if input is not None else DEVNULL, stdout=PIPE, stderr=PIPE, start_new_session=True)`.
      - Call `communicate(input, timeout=wait)`.
      - On `TimeoutExpired`, return `None` and do NOT call `kill()`/`terminate()`. The child is
        abandoned, and it finishes or dies of SIGPIPE only after its dialog is answered. Suppress
        the `ResourceWarning` for this one case.
      - On `OSError`, return `None`.
      - Its docstring cites the 2026-09-24 securityd abort and says: never kill `security`.
      - Byte output. `_keychain_get` decodes stderr itself with `errors="replace"`, as today.
- [ ] 3. Route `_keychain_get` (`wait=15`), `_keychain_delete` (`wait=None`) and
      `_keychain_write` (`wait=None`) through `_security_run`. Remove every `timeout=15` from
      the `security` calls. Map `None` to the existing outcomes: `_keychain_get` → `None`,
      `_keychain_delete` → `False`, `_keychain_write` → `"uncertain"`.
- [ ] 4. Drop `-U` from `_kc_add_line`, which now ends in `-T /usr/bin/security`. Update its
      docstring, and the `_keychain_write` docstring that describes `-U`.
- [ ] 5. Make `_keychain_write` delete-then-add:
      - First call `_keychain_delete(service)`. If it fails, return `"rejected"`: nothing
        changed, the old item is intact.
      - Then run the add.
      - An add that exits non-zero after a successful delete returns a new outcome `"lost"`.
        The old item may be gone and the new one was not written.
      - `"uncertain"` and `"mismatch"` stay as they are.
      - `_keychain_set_all` keeps its structure. Only `"invalid"` and `"rejected"` on the FIRST
        item still count as "nothing changed". `"lost"` triggers the existing cleanup and the
        `changed=True` report.
      - Update the `KeychainBatchResult`/`_keychain_set_all` docstrings.
- [ ] 6. Before the first write, `cmd_cscs_store_creds` and `cmd_biopolwifi_store_creds` print one
      stderr line: `If macOS shows a keychain dialog, answer it — do not press Ctrl-C.` The line
      names no values.
- [ ] 7. Update the offline tests (mocked, never running `security`):
      - `tests/conftest.py`: its default-deny guard already wraps `subprocess.Popen`, so keep it
        and make the fakes `Popen`-shaped.
      - `tests/test_credentials.py`, `tests/test_keychain_batch.py`: adapt the fakes to
        `_security_run`/`Popen`. For example, monkeypatch `browser._security_run` with a fake
        that records argv/input/wait. Keep every existing behavioural assertion.
      - Add regression tests:
        - (a) The add line has no `-U` and still ends in `-T /usr/bin/security\n`.
        - (b) A write runs delete, then add, in that order. A failed delete → `"rejected"` and
          no add. A delete OK plus a rejected add → `"lost"`, and in a batch → cleanup plus
          `changed=True`.
        - (c) `_security_run` passes `start_new_session=True`, and on `TimeoutExpired` returns
          `None` and never calls `kill`/`terminate` (fake `Popen` asserts it).
        - (d) Writes/deletes pass `wait=None`, and reads pass `wait=15`.
        - (e) The dialog hint line is printed and contains no value.
- [ ] 8. Update `tests/test_keychain_live.py`:
      - The router no longer strips `-U`. It appends the temp keychain path to the add line,
        requires the line NOT to contain `-U`, and routes `Popen`-based `_security_run` calls
        (or patches `_security_run` to `_exec_security` with the keychain appended).
      - Update `test_bad_add_input_is_refused` and `test_add_line_drops_update_flag_and_names_keychain`
        to match.
      - Add ONE live update case in the temp keychain: `_keychain_set` twice on the same service
        with two dummy values, read back the second, then delete. That is a single overwrite,
        not a loop.
      - The module docstring drops the `-U` fallback paragraph and keeps "no timeout".
- [ ] 9. Update README.md "Requirements"/keychain notes and the AGENTS.md convention list:
      writes are delete-then-add (no `-U`), and `security` is never killed or timed out on
      writes. Update the stale `_keychain_write` wording anywhere else it appears (`grep -n "\-U" README.md bin/browser.py`).
- [ ] 10. Run every `## Verification` line in the foreground, fix until green, then
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
