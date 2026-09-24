# tp#491 — cscs-login/token robustness (network error after caching, early TOTP, partial keychain write, odd himalaya JSON)

## Session

Resume: `c --resume c9055edc-878b-4711-8cf9-4fdd12616bfb`

## Context

Classification: **DEFECT** (four independent robustness defects in `bin/browser.py`, found by the
cloud review of PR glensk/browser-login#1). Line numbers below are HEAD `5ee62dd`; the ticket's
numbers predate tp#489/tp#490 and have shifted.

### D1 — network error after the token is cached → traceback

- **Symptom.** `_capture_and_cache_token` (`bin/browser.py:2995`) writes the token to
  `CSCS_TOKEN_CACHE` (`:3028-3035`), then calls `requests.get(PORTAL_API_ME, …)` (`:3037`) with no
  handler; `resp.json()` (`:3041`) is equally unguarded.
- **Reproduced 2026-09-24** (module loaded, `_scan_token` stubbed to a dummy 40-hex value,
  `CSCS_TOKEN_CACHE` redirected to a `mktemp -d` dir, `requests.get` raising
  `requests.ConnectionError`): the token is cached, then `ConnectionError` propagates as a traceback.
- **Root cause (established):** missing `requests.RequestException` / `ValueError` handling. In
  `cmd_cscs_login` (`:3593-3595`) the exception also skips `_close_stale_cscs_tabs`, and the process
  exits with Python's generic status 1 plus a traceback instead of a clean `_fail` line.
  `cscs-api.py` (`sdsc/cscs-api/cscs-api.py:483-490`) maps rc 0 → ok, 2 → needs_login, else failed,
  so the fix must return 1 (failed), never 2.
- Confidence: **high**.

### D2 — TOTP code generated before the password submit, filled up to ~20 s later

- **Symptom.** `_keychain_creds` (`:3294-3309`) computes the code with `_totp_now(seed)` and
  `_op_creds` (`:3357-3397`) fetches the live `op --otp` code, both BEFORE
  `_submit_keycloak_login` (`:3488-3515`) fills username/password, clicks submit, and then polls up
  to 40 × 500 ms (~20 s) for the OTP field, filling the code captured earlier.
- **Evidence:** code path only. **Not reproduced** — reproducing it needs the real CSCS Keycloak
  realm and credentials, and Keycloak's default TOTP look-around window (±1 step) accepts a code up
  to 30 s old, so it only fails under a strict realm (look-around 0) or when the code is minted in
  the last seconds of its 30 s step. The latency itself (code minted, then up to ~20 s + page time
  before use) is established from the code; whether CSCS's realm actually rejects it is undetermined.
- Confidence: **high** on the latency, **low** on real-world failure frequency.

### D3 — a failed keychain write leaves a mixed old/new credential set

- **Symptom.** `_keychain_set_all` (`:3234-3242`) validates every item first (tp#489), but then
  writes sequentially and stops at the first runtime failure (`security` non-zero, timeout, or
  read-back mismatch). Items written before the failure hold NEW values, later ones OLD values.
  Callers: `cmd_cscs_store_creds` (`:3659-3667`, user/password/TOTP seed) and the biopolwifi store
  (`:4942-4948`, email/password).
- **Root cause (established from code):** no rollback. A mixed set is worse than none: e.g. a new
  username with the old password makes `cscs-login` submit a wrong pair → failed attempts count
  toward the Keycloak lockout, whereas a MISSING item makes `_keychain_creds` return `None` and
  `cscs-login` falls back to 1Password (`:3440-3451`).
- Not reproduced against a real keychain (would need an induced mid-batch `security` failure);
  reproduction is by mocked `subprocess.run`, which is exactly how the test will pin it.
- Confidence: **high**.

### D4 — himalaya envelope with a non-dict `from`/`to` or non-string fields crashes

- **Symptom.** `_mail_sender` (`:3904-3905`) and the recipient check (`:4017`) call `.get` on
  `env["from"]` / `env["to"]`; `_looks_like_claude_login_mail` (`:3913`) calls `.lower()` on
  `env["subject"]`. `_himalaya_list_folder` (`:3985`) already drops non-dict envelopes, but not
  non-dict fields.
- **Reproduced 2026-09-24:** `{"from": "x@y.z"}` → `AttributeError: 'str' object has no attribute
  'get'`; `{"from": [{"addr": …}]}` → same for `list`; `{"subject": 5}` → `AttributeError`.
- **Root cause (established):** field shapes are trusted; himalaya's JSON shape varies across
  versions/backends (a list of addresses for multi-recipient `to`, a bare string, `null`).
- Confidence: **high**.

Blocked on Albert: **no**. All decisions below are settled by evidence and recorded as
non-blocking `tp question -d` defaults.

The Verification block is **not strict-eligible**: it runs pytest, mypy and pylint (via `uv run`,
inside the project venv), which the change needs because every fix is pinned by a regression test.
All tests mock `requests`, `subprocess` (keychain/`security`, `op`, himalaya) and the Playwright page;
nothing touches the real keychain, the browser profile or a mailbox.

## Steps

- [ ] **D1** In `_capture_and_cache_token`, wrap the `/api/me` check (`requests.get` + `resp.json()`)
      in `try/except (requests.RequestException, ValueError)`. On error return
      `_fail("Token cached at <path>, but verifying it against the portal failed (<ExcType>) — …")`
      (exit 1; the message names only the exception TYPE, never the token or the response body).
      Keep caching BEFORE verification (decision recorded: a token scanned from the logged-in
      portal is almost always valid, and `cscs-api.py` self-heals on 401; deleting it on a network
      blip would force a needless re-login). Also treat a 200 with a non-dict JSON body as failure.
- [ ] **D1** Make `cmd_cscs_login` still run `_close_stale_cscs_tabs` when token capture fails
      (it now returns 1 instead of raising — confirm by test, no `finally` gymnastics needed).
- [ ] **D2** Replace the precomputed OTP string with a lazy provider: `_keychain_creds` and
      `_op_creds` return `(user, password, otp_fn)` where `otp_fn: Callable[[], str | None]`
      (a small `NamedTuple` `CscsCreds(user, password, otp)` for readability; update the type
      hints of `_cscs_creds`, `_submit_keycloak_login`).
      - keychain: `_keychain_creds` still validates the seed up front (`_totp_now(seed)` must
        succeed, else `None` → 1Password fallback, as today); `otp_fn` = new `_fresh_totp(seed)`
        which, when fewer than **5 s** remain in the current step, waits for the next step
        (bounded ≤ 5 s via `time.sleep`) and returns the new code.
      - 1Password: `_op_creds` fetches username/password up front as today but NOT the code;
        `otp_fn` = new `_op_otp(item, account)` running `op item get … --otp` at fill time
        (same timeout/error handling; `None` on failure).
      - `_submit_keycloak_login` calls `otp_fn()` only when the OTP field is found, immediately
        before `fill`. If it returns `None`, stop and return `False` without submitting an OTP
        (no wrong-code attempt counts toward lockout).
- [ ] **D2** Keep the per-attempt fresh-credential call in `cmd_cscs_login` unchanged (attempt 2
      still calls `_cscs_creds` again).
- [ ] **D3** Add rollback to `_keychain_set_all`: track which items were attempted. On the first
      failure, if ANY item may have changed (an earlier item succeeded, or the failing call's
      `security` exit was 0 but the read-back mismatched), delete EVERY item of the batch with
      `_keychain_delete` and print one stderr line naming the service labels (never values) and
      whether each delete succeeded; if the very first item failed with a non-zero `security`
      exit, nothing changed → no delete. Still returns `bool`. Decision recorded: fail closed to
      "no stored set" (fallback to 1Password / prompt) rather than restoring a snapshot, because
      `find-generic-password -w` prints non-ASCII values as hex, so a snapshot restore is lossy.
      To support the "exit 0 but read-back mismatch" distinction, split `_keychain_set` into an
      internal helper returning a small status (`"ok" | "rejected" | "mismatch"`), keeping
      `_keychain_set` → `bool` for existing callers/tests.
- [ ] **D3** Adjust the caller messages in `cmd_cscs_store_creds` and the biopolwifi store: on
      failure say the partially written items were removed and the old set is gone (re-run the
      store command), or that nothing changed.
- [ ] **D4** Add `_env_addrs(env, key) -> list[str]` accepting a dict (`addr`), a list of dicts
      and/or strings, or a bare string (parse with `email.utils.parseaddr`); anything else → `[]`.
      `_mail_sender` = first address or `""`; the recipient check passes when `email` is in the
      list (or the list is empty, as today). Coerce `subject`/`date` with
      `x if isinstance(x, str) else ""`. Annotate `env` as `dict[str, object]`/`Mapping`.
- [ ] **Tests** (all mocked; `tests/test_credentials.py`, `tests/test_cscs_login_retry.py`,
      `tests/test_login_mail_match.py`):
      - D1: `requests.get` raising `ConnectionError` / `Timeout`, and a 200 whose `.json()` raises
        `ValueError` → rc 1, no traceback, token file written 0600, captured output contains
        neither the dummy token nor the response text; `cmd_cscs_login` still closes stale tabs.
      - D2: `_submit_keycloak_login` calls `otp_fn` only after the OTP field appears (fake page
        records call order), and not at all when the portal is reached directly; `otp_fn` → `None`
        returns `False` without filling. `_fresh_totp` with a mocked clock at 26 s into a step
        sleeps into the next step and returns that step's RFC 6238 code; at 10 s it does not sleep.
        `_op_creds` no longer calls `--otp`; `_op_otp` does.
      - D3: `security` rc 0 for item 1, rc 1 for item 2 → both items deleted, `False`; item 1
        rc 1 → no delete; item 1 rc 0 + read-back mismatch → delete issued; stderr names
        services, never values.
      - D4: envelopes with `from` as str / list / None / int, `to` as list containing / not
        containing the email, `subject` as int → no exception, correct accept/reject.
      - Update existing tests that pass `(user, pw, "123456")` tuples to the new shape.
- [ ] Run the Verification block; fix every lint/type finding on the spot.
- [ ] Update README (CSCS login section: OTP is generated at fill time; store-creds failure leaves
      no partial set) if it states otherwise.

NOTE: no live check against the real CSCS Keycloak is part of this plan (it needs Albert's real
credentials and the shared browser). Albert's next ordinary `browser.py cscs-login` exercises D1/D2
in production; nothing needs re-arming or deploying (browser.py is run from the repo on each call).

## Verification

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff check bin/ tests/
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff format --check bin/ tests/
cd /Users/albert/obsidian/42-Git/home/browser-login && git diff --no-ext-diff --no-textconv --stat HEAD
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run mypy bin/browser.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pylint bin/browser.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests/test_credentials.py tests/test_cscs_login_retry.py tests/test_login_mail_match.py tests/test_cscs_totp.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q
cd /Users/albert/obsidian/42-Git/home/browser-login && bin/browser.py -h
```
