# tp#491 — cscs-login/token robustness (network error after caching, early TOTP, partial keychain write, odd himalaya JSON)

## Session

Resume: `c --resume c9055edc-878b-4711-8cf9-4fdd12616bfb`

## Context

Classification: **DEFECT** (four independent robustness defects in `bin/browser.py`, found by the
cloud review of PR glensk/browser-login#1). Line numbers below are HEAD `5ee62dd`; the ticket's
numbers predate tp#489/tp#490 and have shifted.

Debated 2026-09-24 with Codex (gpt-6-astra), judge converged in round 1; all ten objections
accepted and folded into the steps below (O-numbers cited where a step comes from one).

### D1 — network error after the token is cached → traceback

- **Symptom.** `_capture_and_cache_token` (`bin/browser.py:2995`) writes the token to
  `CSCS_TOKEN_CACHE` (`:3028-3035`), then calls `requests.get(PORTAL_API_ME, …)` (`:3037`) with no
  handler; `resp.json()` (`:3041`) is equally unguarded. The non-200 branch (`:3044`) also prints
  `resp.text[:200]` — a response body that echoes the token would leak it (Codex O6, confirmed
  with a memory-only mock).
- **Reproduced 2026-09-24** (module loaded, `_scan_token` stubbed to a dummy 40-hex value,
  `CSCS_TOKEN_CACHE` redirected to a `mktemp -d` dir, `requests.get` raising
  `requests.ConnectionError`): the token is cached, then `ConnectionError` propagates as a traceback.
- **Root cause (established):** missing `requests.RequestException` / `ValueError` handling. Both
  callers — `cmd_token` (`:3094-3115`) and `cmd_cscs_login` (`:3593-3595`) — then skip
  `_close_stale_cscs_tabs`, and the process exits with a traceback instead of a clean `_fail` line.
  `cscs-api.py` runs `browser.py token` and maps rc 0 → ok, 2 → needs_login, else failed
  (`sdsc/cscs-api/cscs-api.py:483-490`), so the fix must return 1, never 2.
- Confidence: **high**.

### D2 — TOTP code generated before the password submit, filled up to ~20 s later

- **Symptom.** `_keychain_creds` (`:3294-3309`) computes the code with `_totp_now(seed)` and
  `_op_creds` (`:3357-3397`) fetches the live `op --otp` code, both BEFORE
  `_submit_keycloak_login` (`:3488-3515`) fills username/password, clicks submit, and then polls up
  to 40 × 500 ms (~20 s) for the OTP field, filling the code captured earlier.
- **Evidence:** code path only. **Not reproduced** — it needs the real CSCS Keycloak realm and
  credentials. Under Keycloak's default look-around of ±1 step a code at most one step old is
  accepted, and ~20 s + page time crosses at most one 30 s boundary, so the stale code is rejected
  only by a strict realm (look-around 0). The latency is established from the code; whether CSCS's
  realm rejects it is undetermined.
- Confidence: **high** on the latency, **low** on real-world failure frequency.

### D3 — a failed keychain write leaves a mixed old/new credential set

- **Symptom.** `_keychain_set_all` (`:3234-3242`) validates every item first (tp#489), but then
  writes sequentially and stops at the first runtime failure (`security` non-zero, timeout, or
  read-back mismatch). Items written before the failure hold NEW values, later ones OLD values.
  Callers: `cmd_cscs_store_creds` (`:3659-3667`, user/password/TOTP seed) and the biopolwifi store
  (`:4942-4948`, email/password).
- **Root cause (established from code):** no rollback. A mixed set is worse than none: a new
  username with the old password makes `cscs-login` submit a wrong pair → failed attempts count
  toward the Keycloak lockout, whereas a MISSING item makes `_keychain_creds` return `None` and
  `cscs-login` falls back to 1Password (`:3440-3451`). A `security` call that times out may have
  written anyway (Codex O2), so a timeout is an UNCERTAIN outcome, not "nothing changed".
- Not reproduced against a real keychain (needs an induced mid-batch `security` failure);
  reproduction is by a stateful mocked `subprocess.run`, which is how the tests pin it.
- **Scope limit (Codex O4):** the fix is best-effort cleanup, NOT an atomic update. A login that
  runs concurrently with `store-creds` can still read a mixed set in the window, and
  `sdsc/biopol-wifi/biopol-wifi.py:438` reads the biopolwifi items independently. A cross-process
  credential lock is out of scope: both store commands are one-time interactive setup.
- Confidence: **high**.

### D4 — himalaya envelope with a non-dict `from`/`to` or non-string fields crashes

- **Symptom.** `_mail_sender` (`:3904-3905`) and the recipient check (`:4017`) call `.get` on
  `env["from"]` / `env["to"]`; `_looks_like_claude_login_mail` (`:3913`) calls `.lower()` on
  `env["subject"]`. `_himalaya_list_folder` (`:3985`) already drops non-dict envelopes, but not
  non-dict fields.
- **Reproduced 2026-09-24:** `{"from": "x@y.z"}` → `AttributeError: 'str' object has no attribute
  'get'`; `{"from": [{"addr": …}]}` → same for `list`; `{"subject": 5}` → `AttributeError`.
- **Root cause (established):** field shapes are trusted; himalaya's JSON shape varies across
  versions/backends. The sender is an authorization check (tp#490), so tolerance must never turn
  malformed input into acceptance (Codex O7).
- Confidence: **high**.

Blocked on Albert: **no**. The design decisions are settled by evidence and recorded as
non-blocking `tp question -d` defaults (D1 cache-before-verify + exit 1; D2 lazy OTP provider;
D3 fail-closed cleanup; D4 accepted address shapes).

The Verification block is **not strict-eligible**: it runs pytest, mypy and pylint (via `uv run`,
inside the project venv), which the change needs because every fix is pinned by a regression test.
All tests mock `requests`, `subprocess` (`security`, `op`, himalaya) and the Playwright page; the
live keychain test is excluded with `--ignore` so an inherited `BROWSER_LIVE_KEYCHAIN=1` can never
make the verification run touch the real login keychain (Codex O5).

## Steps

- [ ] **Guard first (O1).** Add `tests/conftest.py` with an autouse fixture that replaces
      `subprocess.run` / `subprocess.Popen` with a default-deny wrapper: any call whose argv[0]
      basename is `security`, `op` or `himalaya` raises before executing; `tests/test_keychain_live.py`
      opts out via a marker. Update the `_store_creds_env` fixture (`tests/test_credentials.py:353`)
      to mock the new internal write helper and `_keychain_delete`, not only `_keychain_set`.
- [ ] **D1 (+O6).** In `_capture_and_cache_token`, wrap the `/api/me` check (`requests.get` +
      `resp.json()`) in `try/except (requests.RequestException, ValueError)`. On error return
      `_fail("Token cached at <path>, but verifying it against the portal failed (<ExcType>) …")`
      (exit 1; names only the exception TYPE). A 200 whose JSON is not a dict is a failure too.
      Non-200: report the status code and a fixed explanation — drop `resp.text` entirely. Keep
      caching BEFORE verification (a token scanned from the logged-in portal is almost always
      valid; `cscs-api.py` self-heals on 401).
- [ ] **D1 (O10).** Command-level tests for `cmd_token` AND `cmd_cscs_login` with a mocked
      `_connect`: verified → 0; `ConnectionError`/`Timeout`, a `ValueError` from `.json()`,
      non-dict JSON (`null`, list, scalar) and non-200 → 1 with the cache file written 0600;
      Keycloak redirect in `cmd_token` → 2 unchanged; `_close_stale_cscs_tabs`, `browser.close`
      and `pw.stop` called in every case; captured output never contains the dummy token, the
      response body (seeded with the token and control characters) or an exception message
      seeded with a dummy secret.
- [ ] **D2.** Replace the precomputed OTP string with a lazy provider: a `NamedTuple`
      `CscsCreds(user, password, otp)` where `otp: Callable[[], str | None]`; update the hints of
      `_keychain_creds`, `_op_creds`, `_cscs_creds`, `_submit_keycloak_login`.
      - keychain: `_keychain_creds` still validates the seed up front (`_totp_now(seed)` must
        succeed, else `None` → 1Password fallback, as today); `otp` = new `_fresh_totp(seed)`.
      - 1Password: `_op_creds` fetches username/password up front but NOT the code; `otp` = new
        `_op_otp(item, account)` running the existing `--otp` op call at fill time (timeout 20 s;
        `None` on any failure).
- [ ] **D2 (O9).** `_fresh_totp(seed)`: parse the OTP object once (seed or `otpauth://` URI, same
      rules as `_totp_now`), sample the clock once, `remaining = interval - (now % interval)` using
      the parsed `interval`; if `remaining < min(5, interval / 3)` sleep `remaining + 0.05`,
      re-sample, and return `otp.at(new_now)`; otherwise `otp.at(now)`. `None` for malformed input.
- [ ] **D2 (O8).** In `_submit_keycloak_login`, when the OTP field is first seen: call
      `creds.otp()`; if `None` → return `False` without filling. Then re-check that the page is
      not `_on_portal` and still on `auth.cscs.ch`, RE-QUERY the OTP field, and only then fill and
      submit. Catch `PlaywrightError` in this block and return `False` with a fixed message (no
      exception text). The ~20 s poll loop and the per-attempt fresh `_cscs_creds` call in
      `cmd_cscs_login` stay unchanged.
- [ ] **D2 tests.** `otp()` is called only after the OTP field appears (fake page records call
      order) and never when the portal is reached directly; `otp()` → `None` → no fill, no OTP
      submit; the page navigating / the field detaching while `otp()` runs → `False`, no fill, no
      submit click. `_fresh_totp` with a mocked clock: 10 s into a 30 s step → no sleep, RFC 6238
      code for that step; 26 s → sleeps into the next step and returns its code; exactly 5 s
      remaining → no sleep (strict `<`); fractional boundary; an `otpauth://` URI with
      `period=60`; malformed URI → `None`. `_op_creds` no longer calls `--otp`; `_op_otp` does.
      Update existing tests that pass `(user, pw, "123456")` tuples to the new shape.
- [ ] **D3 (+O2, O3).** Split `_keychain_set` into an internal `_keychain_write(service, value,
      description) -> str` returning `"invalid"` (validation failed, no call), `"rejected"`
      (`security` exited non-zero), `"uncertain"` (`OSError`/`TimeoutExpired`/`SubprocessError`
      after launch), `"mismatch"` (rc 0 but read-back differs) or `"ok"`; `_keychain_set` stays a
      `bool` wrapper for existing callers. `_keychain_set_all` returns a dataclass
      `KeychainBatchResult(ok, changed, removed, surviving)`: batch validation as today; on the
      first non-`ok` write, cleanup runs unless nothing can have changed (the FIRST item came back
      `"rejected"` or `"invalid"`). Cleanup attempts `_keychain_delete` for EVERY item of the batch,
      even after one fails, and records which were removed and which survive. Docstring states the
      best-effort, non-atomic contract (O4).
- [ ] **D3 callers.** `cmd_cscs_store_creds` and the biopolwifi store print exactly one of:
      "nothing changed"; "partially written items removed — no stored set remains, re-run
      `<store command>`"; or "cleanup FAILED for <service labels> — run `browser.py forget-creds
      <site>`" (all exit 1). Never claim the old set is gone unless every delete returned `True`.
      Messages name service labels only, never values.
- [ ] **D3 tests.** Stateful fake keychain behind the mocked `subprocess.run`: item 1 rc 0, item 2
      rc 1 → both deleted, `changed=True`, `surviving=[]`; item 1 rc 1 → no delete; item 1 rc 0 +
      read-back mismatch → cleanup; item 1 writes then raises `TimeoutExpired` → cleanup; one and
      all deletes failing → `surviving` lists them and every delete was still attempted; caller
      messages per case; stderr/stdout never contain a value.
- [ ] **D4 (O7).** Add `_env_addrs(env, key) -> tuple[str, list[str]]` with state
      `absent` (key missing, `None`, empty), `valid` or `malformed`: a dict uses its `addr`
      (non-string `addr` → malformed); a list is parsed element by element (dicts or strings),
      any bad element → malformed; a string is parsed completely with `email.utils.getaddresses`
      (comma-separated lists included); any other type → malformed. Addresses are lower-cased.
      Sender: exactly one valid address, else not a candidate (diag line; malformed or multiple
      senders never pass `_sender_allowed`). Recipient: absent → skip the check (today's
      behaviour); malformed → reject; valid → accept iff `email` is in the list. `subject` and
      `date` that are not strings are treated as `""`. Annotate `env` as `Mapping[str, object]`.
- [ ] **D4 tests** (`tests/test_login_mail_match.py`): `from` as str / display-name str / list /
      two senders / `None` / int / dict with non-string `addr`; `to` as a list containing and not
      containing the email, a mixed valid/invalid list, a comma-separated string, mixed case;
      `subject` as int; malformed `date` → no exception and the correct accept/reject.
- [ ] Run the Verification block; fix every lint/type finding on the spot.
- [ ] Update README (CSCS login section: OTP generated at fill time; store-creds failure leaves no
      partial set, or names what survived) where it states otherwise.

NOTE: no live check against the real CSCS Keycloak is part of this plan (it needs Albert's real
credentials and the shared browser). Albert's next ordinary `browser.py cscs-login` exercises D1/D2
in production; nothing needs re-arming or deploying (browser.py runs from the repo on each call).

## Verification

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff check bin/ tests/
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff format --check bin/ tests/
cd /Users/albert/obsidian/42-Git/home/browser-login && git diff --no-ext-diff --no-textconv --stat HEAD
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run mypy bin/browser.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pylint bin/browser.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests/test_credentials.py tests/test_cscs_login_retry.py tests/test_login_mail_match.py tests/test_cscs_totp.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q --ignore=tests/test_keychain_live.py
cd /Users/albert/obsidian/42-Git/home/browser-login && bin/browser.py -h
```
