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

**Decisions** (recorded with `tp question 509 -d`; Albert can overrule). The Opus-adversary debate
(below) revised decisions 1, 2 and 4 of the first plan version:

1. **No probe: uniform cleanup after an absent-then-refused add** (revises a4d021). The first
   version rejected this because "a transient refusal of item 0 would also delete an intact OLD
   set". That premise is false: in this path the delete just returned rc 44, so item 0 is already
   missing from the target keychain. Every consumer needs the whole set: `_keychain_creds` returns
   `None`, and the biopolwifi reader fails with "run store-creds". The leftover items 1..n are
   therefore unusable, and deleting them costs nothing. A finished add with a non-zero rc after
   `"absent"` → `"uncertain"`: `touched` stays set, and the batch cleans up. This matches
   biopol-wifi `58057c9`.
2. **An add that never started stays a provable no-op.** `not_started` means `Popen` raised
   `OSError`: after `"absent"` it returns `"rejected"`, after `"deleted"` it returns `"lost"`.
3. **Ctrl-C during the add keeps `touched` set** (revises a27faf). A `SecurityInterrupted` is
   raised only after the child ran (its state is never `not_started`), so no reset is possible.
   No probe runs inside the interrupt handler.
4. **A refused delete (case a) stays "nothing changed"** (d24f8c).
5. **No call-site `try/except`, but the batch catches `BaseException`** (revises 3bc9d2 in part).
   The batch's handler widens from `KeyboardInterrupt` to `BaseException`, so any unexpected
   exception after a possible mutation runs the same `touched`-gated cleanup and then re-raises.
   The message says "Interrupted" for `KeyboardInterrupt` and "Aborted" otherwise.
6. **The dead `"invalid"` stays in the `i == 0` tuple.** It cannot be reached because
   `_keychain_set_all` validates every line first. It is still a correct no-op mapping if that
   ever changes.

Why the Verification block is not strict-eligible: it runs `pytest`, `mypy` and `pylint` (through
`uv run`), not only the allowlisted read-only checks.

## Steps

- [ ] 1. `_kc_add_outcome` (`bin/browser.py`): `unknown` → `"uncertain"`; `done` with rc 0 →
      `"added"`; `not_started` → `"lost"` after `"deleted"`, `"rejected"` after `"absent"`;
      `done` with a non-zero rc → `"lost"` after `"deleted"`, `"uncertain"` after `"absent"`.
- [ ] 2. `_keychain_write`: remove the `touched` reset from the `except SecurityInterrupted`
      around the add, so it only re-raises. Keep the post-add reset for `"rejected"`, which now
      means `not_started`. Update the docstring: `"rejected"` = a refused delete, or an add that
      never started; `"uncertain"` includes a refused add after `"absent"`. A concurrent writer's
      item (rc 45) is deleted by the cleanup too.
- [ ] 3. `_keychain_set_all`: widen `except KeyboardInterrupt` to `except BaseException as exc`,
      with the message word depending on the exception type. Update the docstring: cleanup is
      skipped only when the first write provably changed nothing (a refused delete, or an add
      that never started).
- [ ] 4. `tests/test_keychain_batch.py`, all mocked:
      - (a) Rework `test_first_item_absent_then_add_rejected_changes_nothing`: now
        `changed=True`, and every service gets a cleanup delete.
      - (b) New: after `"absent"`, the add is `not_started` → `changed=False`, and there is no
        cleanup delete.
      - (c) New: Ctrl-C during the first item's add after `"absent"`, with a non-zero rc →
        cleanup, then propagate.
      - (d) New: an unexpected exception (the read-back raises `RuntimeError`) after a mutation →
        cleanup, the "Aborted" message, then propagate.
      - (e) New: a locked keychain, where the add after `"absent"` and every cleanup delete return
        51 → the message names every service as a survivor.
      - (f) Extend the `store` message tests (for both cscs and biopolwifi): an absent first item
        with a refused add prints the "removed" message, not "nothing changed", and prints no
        captured `security` output.
- [ ] 5. Update the README keychain section ("nothing changed" wording). Update `repo_scope.md`
      only if it describes the first-write rule.

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
cd /Users/albert/obsidian/42-Git/home/browser-login && env BROWSER_LIVE_KEYCHAIN=1 uv run pytest -q tests/test_keychain_live.py  # temp keychain only
cd /Users/albert/obsidian/42-Git/home/browser-login && bin/browser.py -h
```

## Debate outcome (Opus adversary)

Round 1 (a fresh Opus reviewer, read-only), and round 2 on the one severe objection I rejected.

| #   | Sev  | Objection                                                                                          | Disposition                                                                                                                |
| --- | ---- | -------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| 1   | high | The probe rests on a false premise: the old set is never intact after absent-then-refused          | **Accepted.** Probe dropped; uniform cleanup (Decision 1)                                                                  |
| 2   | high | A locked keychain gives "cleanup FAILED … run forget-creds", and forget-creds deletes old 1..n     | **Rejected.** Items 1..n are unusable without item 0, and forget-creds only touches the target keychain. Round 2 confirmed |
| 3   | med  | A `not_started` add was probed and cleaned up                                                      | **Accepted.** `not_started` = no-op (Decision 2)                                                                           |
| 4   | med  | rc 44 alone is weak proof for the probe                                                            | Moot (no probe)                                                                                                            |
| 5   | med  | The live-router rewrite would hide a mis-pinned probe                                              | Moot (no probe)                                                                                                            |
| 6   | med  | The probe's fault keys collide with the read-back's                                                | Moot (no probe)                                                                                                            |
| 7   | med  | A probe inside the Ctrl-C handler can block on an unlock dialog                                    | **Accepted.** No probe; the handler keeps `touched` (Decision 3)                                                           |
| 8   | low  | Non-`KeyboardInterrupt` exceptions skip cleanup                                                    | **Accepted.** `except BaseException` (Decision 5)                                                                          |
| 9   | low  | A racing writer's item gets deleted                                                                | **Accepted** as a docstring note (step 2)                                                                                  |
| 10  | low  | The "invalid" removal depends on the lint result                                                   | **Accepted.** Decided now: keep it (Decision 6)                                                                            |
| 11  | low  | Message tests for both stores; the live run must not be a gate                                     | Message tests **accepted** (4f). Live run kept: it uses only a temp keychain, never the search list                        |
| 12  | low  | The README should describe the refused-first-write outcomes                                        | **Accepted** (step 5)                                                                                                      |
| R2  | —    | The Ctrl-C reset condition is inverted relative to the plan                                        | **Accepted.** The reset is removed entirely (step 2)                                                                       |
