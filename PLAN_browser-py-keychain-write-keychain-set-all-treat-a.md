# browser.py: a refused first add is trusted as "nothing changed" without evidence (tp#509)

## Session

Resume: `c --resume f5912622-f99d-4b0c-9303-8752e068a465`

## Context

**Classification: DEFECT**, mostly overtaken by events. The ticket was filed at 19:06 on
2026-09-24 against the pre-tp#504 code. Its line numbers (`:3219-3245`, `:3280-3299`, `:3845`,
`:5175`) no longer match. `b3f6398` (20:29, tp#504) replaced `add -U` with delete-then-add. I
re-checked both claims against HEAD `b3f6398`.

**Claim 1: "a non-zero exit on the FIRST write is treated as nothing changed".**

- Current code: `_keychain_write` (`bin/browser.py:3382-3439`) returns `"rejected"` in two cases.
  - (a) The delete was refused (`:3420-3422`).
  - (b) The item was absent in the target keychain (delete rc 44), and then the insert-only add
    exited non-zero. See `_kc_add_outcome` (`:3367-3374`) and the reset at `:3432-3433`.
- `_keychain_set_all` (`:3516-3520`) then returns `KeychainBatchResult(ok=False)`, which has
  `changed=False`. `_report_keychain_batch_failure` (`:3541-3559`) prints "nothing changed".
- Ctrl-C during that add follows the same rule (`:3426-3429`). A non-zero rc after an absent
  item resets `touched`, so the batch skips cleanup.
- tp#497's premise was: `keychain_add.c` mutates content before `SecKeychainItemSetAccess`.
  That premise is about the `-U` **update** path, `do_update_generic_password`
  (apple-oss-distributions/Security `SecurityTool/macOS/keychain_add.c:125-160`:
  `SecKeychainItemModifyContent`, then `SecKeychainItemSetAccess`). browser.py no longer uses
  that path.
- The insert-only path is `do_add_generic_password` (`keychain_add.c:170-248`, read on
  2026-09-24). Its only mutating call is `SecKeychainItemCreateFromContent(…, access, &itemRef)`,
  and the access list is passed in at creation. No step after creation can fail.
- `security -i` returns the last command's result (`security.c:1173-1218`). A single-line
  session therefore exits with the add's status.
- So case (b) is "nothing changed" only if `SecKeychainItemCreateFromContent` never commits an
  item and then returns an error. The public API contract implies that, but the source of the
  tool cannot prove it: the commit happens inside `securityd`.
- Case (a) is a single `SecKeychainItemDelete`. A refused delete leaves the item in place.
- **Residual defect:** in case (b) the code trusts that contract without evidence. If it is ever
  violated, item 0 holds the NEW value while items 1..n hold OLD values. That mixed set is the
  lockout risk the batch exists to prevent, and the user is told "nothing changed".
- **Not reproduced.** A reproduction needs `securityd` to commit an item and still report failure.
  That cannot be provoked safely: fault injection into `securityd` is out of the question on
  Albert's live machine. The evidence is the source reading above.
- **Confidence:** moderate-high that no current macOS path leaves an item behind after a refused
  add. High that the code has no evidence for it. A cheap probe closes that gap.

**Claim 2: "neither call site wraps the mutation phase in try/except BaseException".**

- Fixed in substance since `2fdac9e` (17:27, before the ticket was filed) and `b3f6398`.
- `_keychain_set_all` owns the mutation phase and catches `KeyboardInterrupt` around the whole
  write loop (`:3514-3534`). `SecurityInterrupted` subclasses `KeyboardInterrupt` (`:3197`).
  After a possible mutation (`touched`), the handler runs `_kc_cleanup` over every service, then
  re-raises.
- The call sites `cmd_cscs_store_creds` (`:4061`) and `cmd_biopolwifi_store_creds` (`:5392`)
  run no mutation outside that function. A call-site `try/except` would add nothing.
  - Before the call: prompts only.
  - After a successful return: the set is complete.
  - After a failed return: cleanup has already run.
- The one remaining hole is the Claim-1 reset inside the interrupt path (`:3426-3429`). This
  plan fixes it together with Claim 1.
- Other `BaseException`s (`SystemExit` and the like) cannot occur inside the loop: no code there
  calls `sys.exit`. Widening the handler would only add risk, so it stays `KeyboardInterrupt`.

**Blocked on Albert:** no. Every decision is settled from the evidence below, and the tests are
fully mocked. The only live check uses a private temp keychain behind `BROWSER_LIVE_KEYCHAIN=1`.

**Decisions** (recorded with `tp question 509 -d`; Albert can overrule):

1. **Probe instead of blanket cleanup.** After an absent-then-refused add, run one pinned,
   attributes-only probe: `security find-generic-password -a <acct> -s <svc> <target keychain>`,
   with no `-g` and no `-w`, so no secret is read and no ACL prompt is possible.
   - rc 44 (`errSecItemNotFound`) proves "nothing changed" → `"rejected"`, as today.
   - Anything else (rc 0 = the item exists, another rc, `unknown`, `not_started`) → `"uncertain"`,
     which leaves `touched` set, so the batch cleans up.
   - Rejected alternative: biopol-wifi's uniform rule (58057c9: any failed write → delete the
     whole set). A transient refusal of item 0 would then also delete an intact OLD set, turning
     a harmless no-op into a forced 1Password fallback. The probe keeps the no-op a no-op when
     it is provably one.
2. **Ctrl-C during that add.** Handle it the same way: probe (still inside the handler, before
   re-raising), and reset `touched` only on probe rc 44. If the probe itself is interrupted,
   leave `touched` set.
3. **The refused delete (case a) stays "nothing changed".** It is a single
   `SecKeychainItemDelete`, with no create or modify involved.
4. **No call-site `try/except`.** See Claim 2. Instead, a regression test pins the batch-owned
   cleanup for the first item's add.

Why the Verification block is not strict-eligible: it runs `pytest`, `mypy` and `pylint` (through
`uv run`), not only the allowlisted read-only checks.

## Steps

- [ ] 1. Add `_kc_probe(service: str, keychain: str) -> str` next to `_kc_delete`
      (`bin/browser.py` ~`:3360`).
      - It runs `_security_run(["security", "find-generic-password", "-a", _kc_account(), "-s",
        service, keychain])`, which names the keychain and passes no `-g`/`-w`.
      - It returns `"absent"` only for `state == "done"` and rc 44, and `"present"` for rc 0.
        Anything else returns `"unknown"`.
      - stdout/stderr are never printed. A `SecurityInterrupted` raised inside it propagates to
        the caller.
- [ ] 2. In `_keychain_write`, when the item was absent and the add was refused
      (`_kc_add_outcome` → `"rejected"`), call `_kc_probe`.
      - `"absent"` → reset `touched`, return `"rejected"`.
      - Otherwise → keep `touched` set, return `"uncertain"`.
      - Update the docstring: `"rejected"` now means proven unchanged, and it names the probe.
- [ ] 3. In `_keychain_write`'s `except SecurityInterrupted` around the add (`:3426-3429`), replace
      the rc-based reset.
      - When `gone == "absent"` and the interrupted add finished with `state == "done"` and a
        non-zero rc, run `_kc_probe`, and reset `touched` only on `"absent"`.
      - If the probe raises `SecurityInterrupted`, keep `touched` set.
      - Always re-raise the original interrupt, so the batch's `except KeyboardInterrupt` decides
        on cleanup.
- [ ] 4. Update the `_keychain_set_all` docstring (`:3491-3505`): cleanup is skipped only when the
      first write is PROVEN to have changed nothing (a refused delete, or a refused add confirmed
      absent by the probe).
      - No change to the `i == 0` branch logic, because `"uncertain"` already falls through to
        cleanup.
      - Remove the dead `"invalid"` from that tuple only if mypy/pylint stay clean. Otherwise
        leave it.
- [ ] 5. `tests/test_keychain_batch.py`: extend `FakeKeychain._apply` for the probe.
      - A `find` that names a keychain and carries no `-g` looks only in that keychain: rc 0 when
        present, 44 when absent.
      - Keep the existing assert that the `-g` read-back is unpinned.
      - Probe faults stay keyed as `("find", svc, n)`.
- [ ] 6. Tests in `tests/test_keychain_batch.py`, all mocked:
      - (a) Rework `test_first_item_absent_then_add_rejected_changes_nothing`. It must also assert
        that exactly one pinned probe ran and that no cleanup delete followed.
      - (b) New: absent, then the add is refused, but the fake stores the item anyway (a new fault
        kind `"commit_then_fail"`, where the add stores the value and returns 45) → probe rc 0 →
        `changed=True`, every service is deleted, and `_report_keychain_batch_failure` does NOT
        print "nothing changed".
      - (c) New: absent, the add is refused, and the probe returns `unknown` (-9) or rc 51 →
        cleanup runs (parametrized).
      - (d) New: Ctrl-C during the first item's add after an absent delete, with a non-zero rc.
        Probe rc 44 → no cleanup and nothing on stderr. Item present → cleanup, then propagate.
        Probe interrupted → cleanup, then propagate.
      - (e) New: `_kc_probe` argv names the target keychain last and contains neither `-g` nor
        `-w`.
      - Every existing test must stay green unchanged except (a).
- [ ] 7. `tests/test_keychain_live.py`: make sure the router accepts the pinned probe shape (a
      find with a keychain argument and no `-g`) and rewrites it to the temp keychain.
      - Add one live case: add an item to the temp keychain, confirm the probe returns
        `"present"`; delete it, confirm the probe returns `"absent"`.
      - It uses only the fixture's temp keychain and never the search list or the login keychain.
- [ ] 8. Update the README's keychain section (the "nothing changed" wording) and
      `repo_scope.md`, if either describes the first-write rule.

NOTE: after this lands, Albert re-runs `browser.py store-creds cscs` / `store-creds biopolwifi`
himself when he next rotates those credentials. No action is needed for items that are already
stored.

## Verification

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff check bin/ tests/
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff format --check bin/ tests/
cd /Users/albert/obsidian/42-Git/home/browser-login && git diff --no-ext-diff --no-textconv HEAD --stat
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run mypy bin/browser.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pylint bin/browser.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests/test_keychain_batch.py tests/test_credentials.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q
cd /Users/albert/obsidian/42-Git/home/browser-login && env BROWSER_LIVE_KEYCHAIN=1 uv run pytest -q tests/test_keychain_live.py
cd /Users/albert/obsidian/42-Git/home/browser-login && bin/browser.py -h
```
