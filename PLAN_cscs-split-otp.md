# PLAN: cscs split one-time-code fill (tp#1675)

> **Resume here.** Status: cause confirmed from the failure screenshot, planned, debated
> (Opus adversary, 2026-11-04, Codex seat unknown) and reconciled; nothing built.
> Next round: R1 (B1, B2, B3).
> B2/B3 change `broker/recipes.py`, and that file is broker code. The launchd broker runs the
> installed copy (`${LIBEXEC}/current/broker/daemon.py`, `install/install.sh`), not this
> checkout. So the fix reaches production only through B5, which reinstalls with `sudo -n`
> and is coordinated with tp#1672 B6. B5 is the same reinstall plus canary that was rolled
> back on 2026-11-03 because of this bug. Work in a worktree (`.worktrees.noindex/<name>`),
> because other agents build and test in this repo at the same time. Only one writer may work
> in the repo at a time. Another agent may be committing a different `PLAN_*.md` here: touch
> only the files named in your box.
> Resume: c --resume 5aa659e4-da4b-437b-8cb7-af851b04c9f2

## Session

Ticket: tp#1675 (follow-up of tp#1672, blocks tp#1672 B6)
Overseer session: 5aa659e4-da4b-437b-8cb7-af851b04c9f2 (cause + plan)
Base: 07265e2-era main. Release state on 2026-11-03/04 (Europe/Zurich):
`/usr/local/libexec/login-broker/current` and `previous` both point to
`releases/b3614002357f-20261031T165118Z`. That is the result of the rollback. The rolled-back
release `releases/1dfd33bf4a69-20261103T225039Z` is still on disk.

## Problem (evidence)

- CSCS Keycloak (`https://auth.cscs.ch/auth/realms/cscs/login-actions/authenticate`) now
  shows a themed "Two-Factor Authentication" page, "Enter the code from your authenticator
  app", "One-Time Code". The code goes into **six separate one-character boxes**, followed by
  a "Verify Code →" button. In the screenshot (taken 2026-11-03 23:53) the button is drawn
  pale, which suggests it stays disabled until all six boxes are filled (an inference from
  the image, not verified). The page also says "The code will refresh automatically", so a
  self-submit after the sixth digit is plausible. Evidence:
  `/var/db/login-broker-run/last-failure-cscs.png` (root-owned; read through a `sudo -n cp`
  copy).
- The `cscs` recipe waits for the OTP step with
  `otp_field = _visible(page, OTP_SELECTOR)` in its post-password settle loop (`cscs_login`,
  `broker/recipes.py` around :3031). `OTP_SELECTOR` (:93) is
  `input[autocomplete=one-time-code], input[name*=otp i], #otp`. None of the six boxes
  matches it. A hidden aggregate `name=otp` input, if the theme has one, also never matches,
  because `_visible` skips hidden elements. So the loop runs out its `settle_s`, and the
  recipe raises `LoginFailed("login did not reach the CSCS portal", submitted=True)`. That is
  the "phase submit" failure the canary `browser.py login cscs` showed (exit 2). The password
  had already been sent at that point, but no code was ever typed.
- The generic path would not cope either. `_otp_field` (:1224) falls back to
  `otp_detect.otp_field_like`, and the box's surrounding text ("Two-Factor", "One-Time")
  matches `OTP_WORD_RE`. So for an item on the generic recipe it would return the **first**
  box. Then `_fill_otp` calls `otp_field.fill(code)`. Into a `maxlength=1` box that keeps
  one digit at most. Split-box pages are therefore broken on every recipe today; cscs just
  shows it first.

### Who shares the OTP code path (must not break)

- `OTP_SELECTOR`: `_otp_field` (generic recipe; its call site is `_settle` around
  :2336-2342, which also runs `_same_field(otp_field, credential)`) and `cscs_login` (around
  :3031). Nothing else in `broker/`. `bin/browser.py` has its own legacy
  `_keycloak_otp_field` / `_fill_keycloak_otp` for `cmd_cscs_login` (`#otp`,
  `input[name=otp]`, `autocomplete=one-time-code`). That is the pre-broker shared-browser
  path. It is **out of scope** here (see Not in scope).
- `_fill_otp` (:1304): called by the generic recipe and by `cscs_login`. Existing tests that
  exercise it or the detector: `tests/test_infomaniak_otp.py` (the `otp_field_like` table
  plus an e2e Infomaniak-like single field with `maxlength=6`), `tests/test_ws2_calibre.py`
  (passes a `SimpleNamespace` page without `evaluate`/`query_selector_all` and monkeypatches
  `recipes._otp_field`, :461-473), `tests/test_invisible_captcha.py` (its fake `evaluate`
  returns `self.body` for any unknown JS, :371-376) and `tests/test_email_code_page.py`. All
  pass a bare handle as `_fill_otp`'s second argument. They must stay green unchanged.
- `fresh_totp` (:520-523) only waits for the next step when fewer than `min(5, interval/3)`
  seconds remain, i.e. it may hand out a code with ~5 s left.

### What is not known (the DOM was never seen)

No live DOM capture exists. The only evidence is the screenshot, and this plan makes no login
attempt. Unknown:

1. The box attributes: `maxlength=1`? `type=text|tel|number`? `inputmode=numeric`?
   `autocomplete=one-time-code` on the first box (a common pattern)? Are the boxes inside the
   `<form>`?
2. How the theme hands the code to Keycloak. Three candidates: a hidden `input[name=otp]`
   that JS fills on `input` events; a submit handler that joins the boxes; or the boxes
   posting as separate parameters that a custom authenticator reads.
3. Whether the theme's JS reacts only to real key events (`keydown`/`input` with
   auto-advance) or also to a programmatic value plus synthetic `input`/`change` events.
4. Whether the page submits itself after the sixth digit.
5. CSCS Keycloak's TOTP look-around window (whether a code one step old is still accepted).

The design below does not depend on the answers. It detects the group by shape, types with
real key events per box and verifies after every key, checks for a self-submit before
anything else after the last key, has exactly one fallback fill strategy, re-checks that the
code is still the current TOTP right before the submit, and never submits an unverified or
stale code. A wrong code counts towards Keycloak's brute-force lockout, so guessing is worse
than failing. Only B5's live canary can prove it works on the real page. If the canary
fails, B2's value-free page hint (field shapes, form membership, hidden-input state) names
the shape for the next round.

## Fix design

- **Detection (pure + one page read):** a new `SPLIT_OTP_DESCRIBE_JS` in
  `broker/otp_detect.py`. It reads the page once and returns, value-free, the groups of
  visible, editable, non-password, non-hidden `input`s with `maxLength == 1`. A group is the
  inputs that share the same nearest `<form>`, or, without a form, the same parent chain up
  to 4 levels. Each member is described in DOM order with `OTP_DESCRIBE_JS`'s fields plus
  `in_form: bool`; each group also gets its context text (≤ 300 chars, the same rule as
  `OTP_DESCRIBE_JS`) and a flag saying whether a hidden `input` whose name matches
  `/otp|totp|code/i` exists in the group's form or, without one, in the nearest form of the
  page. The pure judge `split_otp_group_like(group) -> bool` accepts a group only when all
  of these hold:
  - it has 4 to 8 members, and every member is `text|tel|number` with `maxlength == 1`;
  - no member matches the username selector;
  - no `OTP_NEGATIVE_RE` word (sms, e-mail, backup, …) appears in the attributes or context;
  - either some member has `autocomplete=one-time-code`, or the attributes/context hold an
    `OTP_WORD_RE` word, or every member is numeric (inputmode/type/pattern) and a
    `CODE_WORD_RE` word appears.

  A single code field never passes: it has `maxlength ≠ 1` or no siblings. So the single-
  field sites keep their exact current path.
- **Target type (recipes.py):** `OtpTarget(boxes: tuple[Any, ...])`, where a single field is
  `boxes=(field,)` and a split group is `boxes=(b1..bN)`. `_fill_otp` keeps accepting a bare
  handle in its second parameter (wrapped as `OtpTarget((handle,))`), so existing callers
  and tests stay unchanged. A new `_otp_target(page, *, generic: bool)`:
  - checks the **split group first** (a first box carrying `autocomplete=one-time-code`
    would otherwise match `OTP_SELECTOR` as a single field);
  - with `generic=True`, runs split detection only when no `PASSWORD_SELECTOR` field is
    visible (the same guard `_otp_field` has at :1233-1234);
  - treats any exception from `page.evaluate`, a missing `evaluate` attribute, or a
    non-list result as "no group";
  - then falls back to today's code: `generic=True` calls the module-global `_otp_field`
    (looked up at call time, so `test_ws2_calibre.py`'s monkeypatch still applies),
    `generic=False` (cscs) calls `_visible(page, OTP_SELECTOR)`.
- **Fill (`_fill_otp` takes an `OtpTarget` or a handle):** the code-wait, `watch.clear`,
  `_select_authenticator` and the e-mail-code `NeedsHuman` stay as they are. After the wait,
  the target is re-queried through `_otp_target` (same `generic` flag). Single field: today's
  path, byte for byte (including today's `fresh_totp` margin). Split group:
  1. `_guard` runs on **every** box (origin, frame, form action), so an OriginViolation sets
     `submitted=True` as today.
  2. **TOTP margin:** generate the code only when at least `SPLIT_OTP_MIN_REMAINING_S = 15`
     seconds of the current step remain; otherwise wait for the next step, then generate.
     The clock is injectable (module-level `_now = time.time`) so tests can drive it.
  3. If `len(code) != len(boxes)`, raise `LoginFailed("the one-time-code form has N boxes,
     the TOTP has M digits", submitted=True)` before anything is typed.
  4. **Submit scope**, resolved before typing: the boxes' common form; else the form of the
     hidden code input the describe step found; else the single visible enabled-or-disabled
     submit button within the group's 4-level ancestor. No scope → raise `LoginFailed(...
     "no submit target for the one-time-code boxes — nothing typed", submitted=True)`.
  5. **Primary strategy, real key events, checked per key:** for box *i* (0..N-2):
     `box.focus()` (or `click()` when focus is refused), `page.keyboard.press(digit_i)`,
     then `SPLIT_OTP_CHECK_JS(boxes[0..i], code[0..i])`; any mismatch (for example an
     auto-advance that put the digit into box *i+1*) aborts with `LoginFailed(... "nothing
     submitted", submitted=True)` **before** the next key, so the last digit, which may
     trigger a self-submit, is never typed into a wrong group. Then the last key.
  6. **Self-submit check first:** right after the last key, wait `OTP_SELF_SUBMIT_MS` and
     run `_submitted_itself(page, last_box, before)` (URL changed or a box detached). If it
     submitted itself, return as submitted; no check, no fallback, no click.
  7. Verify in the page with `SPLIT_OTP_CHECK_JS(boxes, code)`. It returns booleans and
     enum states only, never a value: `{boxes_ok, hidden: "match"|"mismatch"|"empty"|"none"}`.
     `hidden` is about the hidden code input in the submit scope, if one exists; `"empty"`
     (still unsynced) is reported separately from `"mismatch"`. The check is polled for up
     to 1 s, because the theme may sync on a debounce.
  8. **Fallback, only** when the URL is unchanged, every box is still attached and the check
     failed: clear every box, then for boxes 0..N-2 `box.fill(digit_i)` plus in-page
     `dispatchEvent(new Event('input', {bubbles:true}))` and `'change'`, check those, then
     the last box the same way, then the self-submit check (step 6) again, then verify again
     (step 7). Any Playwright error on a detached handle is treated as "page changed" and
     goes to the self-submit check, never to a second fill.
  9. If the check still fails, raise `LoginFailed("the one-time-code boxes did not keep the
     code — nothing submitted (hidden: <state>)", submitted=True)` with no click and no
     Enter. `mismatch` and `empty` both count as a failure; the state goes into the
     value-free error so the next round can tell "joins on submit" from "wrong digits".
  10. Wait until the submit-scope button is enabled: poll for up to 2 s until it is not
      `disabled`. Still disabled → raise `LoginFailed(... "nothing submitted")`.
  11. **Staleness check:** compare `parse_totp(seed).at(_now())` with the typed code. If it
      differs, raise `LoginFailed("the TOTP step rolled over before submit — nothing
      submitted", submitted=True)`; never retype a new code into a page that may already hold
      a hidden copy.
  12. Submit by clicking the identified submit-scope button (or `_submit_password` on the
      scope form's element when the scope is a form), never Enter in a form-less box.

  The code is passed into the page only as an `evaluate` argument for the check. It is never
  logged, never returned and never put into an error message.
- **cscs loop:** `otp_field = _visible(page, OTP_SELECTOR)` becomes
  `_otp_target(page, generic=False)`, and `_fill_otp` re-queries with `generic=False`. Today
  `_fill_otp` re-queries through the generic `_otp_field` even for cscs, which is a latent
  difference; this change fixes it. When the loop ends without the portal, the final
  `LoginFailed` gets `_kc_page_hint(page)` appended, and `_KC_PAGE_HINT_JS` adds `/1` to an
  entry whose `maxLength == 1` and `!f` when it is outside a form (value-free, for example
  `text#otp-0/1!f`). The next unknown form then shows its shape in the error.
- **Generic recipe (`_settle`, :2336-2342):** `_otp_target(page, generic=True)`; the target
  is dropped when any box `_same_field`s the credential field. Single-field sites do not
  change. Split-box sites go from "fills one digit" to the verified split fill. This is the
  only behaviour change outside cscs, and B2 pins it with tests.

## Boxes

Build rounds (at most 3 boxes per round, one writer agent per round, rounds in order):

- **R1** = B1, B2, B3. One builder, in order. B2 depends on B1's judge, and B3 depends on
  B2's target.
- **R2** = B4: the real-Chromium fixture tests. One builder.
- **R3** = B5: the production landing plus the live canary. It runs together with tp#1672
  B6: **one** reinstall carries both tp#1672 B1/B2 (already on `main`) and this fix. It is
  done by the main session or a big agent (`sudo -n`, launchd restart, live login), not by a
  lean builder.

- [x] B1 `broker/otp_detect.py`: add `SPLIT_OTP_DESCRIBE_JS` (value-free groups of visible,
  editable, `maxLength == 1` inputs per form or common ancestor, in DOM order, with `in_form`,
  context text and a hidden-code-input flag) and the pure `split_otp_group_like(group) ->
  bool` as designed. New `tests/test_split_otp.py`, hermetic with no Chromium. Accept cases:
  6 numeric boxes with "One-Time Code" context and no attributes (the CSCS shape); 6 boxes
  with `autocomplete=one-time-code` on the first only; 4 and 8 boxes. Reject cases: 3 and 9
  boxes; one box with `maxlength=2`; a group containing a username field; "SMS code" or
  "backup code" context; 6 `maxlength=1` boxes without OTP or code words and not numeric
  (for example initials fields); a single `maxlength=6` field. `tests/test_infomaniak_otp.py`
  stays green unchanged.
- [x] B2 `broker/recipes.py` target and wiring: add `OtpTarget` (bare handle still accepted
  by `_fill_otp`), `_otp_target(page, *, generic)` (split first; password-visible guard for
  `generic=True`; exception / missing `evaluate` / non-list → no group; fallback through the
  module-global `_otp_field` resp. `_visible(page, OTP_SELECTOR)`). Wire it into
  `cscs_login` (`generic=False`, settle loop and `_fill_otp` re-query) and into `_settle`
  (`generic=True`, with the per-box `_same_field` exclusion). Add the `/1` and `!f` markers
  to `_KC_PAGE_HINT_JS` and append `_kc_page_hint` to cscs's final "did not reach the CSCS
  portal" error. Hermetic tests in `tests/test_split_otp.py`:
  `test_a_single_otp_field_keeps_the_old_path` (`OTP_SELECTOR` field: one `fill(code)`, no
  per-box keys); `test_a_password_field_next_to_six_boxes_is_no_split_target`;
  `test_a_box_that_is_the_credential_field_drops_the_target`;
  `test_a_page_without_evaluate_falls_back_to_otp_field` (SimpleNamespace page plus a
  monkeypatched `recipes._otp_field`); `test_cscs_waits_for_a_split_otp_step` (the
  `cscs_login` settle loop finds the group and calls the split fill);
  `test_kc_page_hint_marks_one_char_and_formless_fields`. Re-run
  `tests/test_infomaniak_otp.py`, `tests/test_ws2_calibre.py`,
  `tests/test_invisible_captcha.py` and `tests/test_email_code_page.py` unchanged.
- [x] B3 `broker/recipes.py` split fill: add `SPLIT_OTP_CHECK_JS`,
  `SPLIT_OTP_MIN_REMAINING_S`, the injectable `_now`, and the split path in `_fill_otp`
  exactly as Fix design steps 1-12 (guard every box, 15 s TOTP margin, length check, submit
  scope, per-key key-event fill with per-key check, self-submit check first, verify with the
  four-valued `hidden`, the one guarded fill+events fallback, enabled-button wait, staleness
  check, click of the identified button). Hermetic tests in `tests/test_split_otp.py` on a
  scripted fake page in the style of `tests/test_ws2_cscs.py::_ScriptedKcPage`:
  `_SplitOtpPage` with N fake boxes, each recording focus, key presses and fills. Its
  switches are `takes_keys`, `takes_fill`, `auto_advance` (`ok|off_by_one|none`),
  `hidden_sync` (`ok|wrong|empty|none`), `self_submit_after_last`, `in_form`,
  `button_enabled_after_ms` and an injected clock. `page.evaluate(SPLIT_OTP_CHECK_JS, …)` is
  answered from the boxes' recorded state. Tests:
  `test_split_boxes_get_one_key_each_then_one_submit`;
  `test_keys_ignored_falls_back_to_fill_with_events`;
  `test_neither_strategy_kept_the_code_submits_nothing` (LoginFailed, `submitted=True`, no
  click or Enter);
  `test_a_wrong_hidden_code_submits_nothing`;
  `test_an_empty_hidden_code_is_reported_as_empty`;
  `test_an_off_by_one_auto_advance_stops_before_the_last_key`;
  `test_box_count_not_matching_the_code_types_nothing`;
  `test_a_page_that_submits_itself_is_not_submitted_again` (no check, no fallback, zero
  clicks/Enter after the last key);
  `test_a_still_disabled_verify_button_submits_nothing`;
  `test_boxes_outside_the_form_submit_through_the_hidden_inputs_form`;
  `test_short_step_remaining_waits_for_the_next_step`;
  `test_a_step_rollover_before_submit_submits_nothing`;
  `test_a_box_off_the_fill_origin_is_an_origin_violation`. Also check that no recorded log,
  exception text or page hint contains the code.
- [ ] B4 `tests/test_ws2_cscs.py` (real Chromium, `launches_chrome`, hermetic: local fixture
  server, no network): add `Portal.otp_form: str = "none"`, a switch with the values
  `"none" | "single" | "split" | "split-autosubmit" | "split-formless"`. After the password
  POST to `KC_POST`, `"single"` serves a classic Keycloak OTP page (`<input id=otp name=otp
  autocomplete=one-time-code>`). `"split"` serves six `maxlength=1` `inputmode=numeric`
  boxes with no OTP attributes, under a "One-Time Code" label, inside the form; its JS
  auto-advances on `input`, keeps a hidden `name=otp` in sync, and enables "Verify Code"
  only once all six boxes are filled. `"split-autosubmit"` is the same but submits the form
  itself on input into box six. `"split-formless"` renders the boxes outside the form and
  copies the code into the form's hidden `name=otp`. The server accepts the POST when `otp`
  equals the TOTP of the current step or the step before (Keycloak's default look-around,
  so a run crossing a 30 s boundary is not flaky), otherwise it re-serves the page with an
  error; it counts OTP POSTs. New broker end-to-end tests:
  `test_a_split_one_time_code_logs_in`, `test_a_self_submitting_split_code_posts_once`
  (exactly one OTP POST), `test_a_formless_split_code_logs_in` and
  `test_a_single_one_time_code_still_logs_in`. The item secret gets a test-only TOTP seed
  generated in the test (never a real one). The existing tests keep `otp_form="none"` and do
  not change.
- [ ] B5 Production landing and live canary (R3, coordinated with tp#1672 B6; main session or
  `[full-context: albert]` agent). Precondition: B1-B4 are merged to `origin/main`
  (`install.sh` installs `git archive HEAD` and refuses a HEAD that is not in `origin/main`),
  and tp#1672 B6 has not landed on its own in the meantime. Steps:
  1. Record `readlink /usr/local/libexec/login-broker/current`; expect
     `releases/b3614002357f-20261031T165118Z`. Call it `<old>`.
  2. Run `sudo -n install/install.sh -n` (dry run), then `sudo -n install/install.sh` from a
     clean checkout at `origin/main`. The install swaps `current` atomically, restarts the
     daemon and runs the boundary selfcheck, which rolls back by itself when it fails.
  3. Confirm that the new release dir contains `_otp_target` and
     `split_otp_group_like`. Confirm the fresh daemon pid with
     `sudo -n launchctl print system/com.albert.login-broker`, and the install line in
     `/var/log/login-broker.log`.
  4. Immediately before the canary (no gap in which a scheduled agent-login run could start
     its own cscs attempt), the main session releases the quarantine
     (`agent-login.py -Q cscs`, repo-root `agent-login.py`) and runs **one** canary,
     `browser.py login cscs`, and expects exit 0. On a failure, copy
     `/var/db/login-broker-run/last-failure-cscs.png` read-only and read the error's page
     hint (field shapes, `/1`, `!f`, hidden state). Do not retry in a loop, because of
     Keycloak's brute-force lockout. A post-submit failure re-quarantines `cscs` by itself
     (`bin/browser.py` around :14471-14475 calls `_als.quarantine`); confirm it in the
     agent-login status matrix (`agent-login.py -x`) rather than re-quarantining by hand.
  5. tp#1672 B6 is ticked by the same landing, and only when the canary passed and no
     rollback followed.

  Rollback (the same swap and restart `install.sh` uses, `swap_current` :490-496 and
  `restart_daemon` :513-527, then its selfcheck `run_selfcheck` :538-545):
  1. `sudo -n /bin/ln -sfn /usr/local/libexec/login-broker/<old> /usr/local/libexec/login-broker/current.new`
  2. `sudo -n /usr/local/libexec/login-broker/<old>/venv/bin/python -c 'import os, sys; os.replace(sys.argv[1], sys.argv[2])' /usr/local/libexec/login-broker/current.new /usr/local/libexec/login-broker/current`
  3. `sudo -n /bin/launchctl bootout system/com.albert.login-broker`, wait until
     `sudo -n launchctl print system/com.albert.login-broker` fails, then
     `sudo -n /bin/launchctl bootstrap system /Library/LaunchDaemons/com.albert.login-broker.plist`
     (the plist is unchanged between b3614 and `origin/main`).
  4. Run the three `selfcheck.py` calls of `run_selfcheck` against the restored `current`
     (`-b` as the invoking user, `-F -S <socket>` as `nobody`, `-P -H <broker home>` as root).
  5. `previous` already points at `<old>`; leave it. The rollback also reverts tp#1672
     B1/B2 in production: record that on tp#1672 and do not tick its B6. `cscs` stays
     quarantined (automatic on the failed canary).

## Verification

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff format --check /Users/albert/obsidian/42-Git/home/browser-login/broker/otp_detect.py /Users/albert/obsidian/42-Git/home/browser-login/broker/recipes.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_split_otp.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws2_cscs.py
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff check /Users/albert/obsidian/42-Git/home/browser-login/broker/otp_detect.py /Users/albert/obsidian/42-Git/home/browser-login/broker/recipes.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_split_otp.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws2_cscs.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run --project /Users/albert/obsidian/42-Git/home/browser-login mypy /Users/albert/obsidian/42-Git/home/browser-login/broker/otp_detect.py /Users/albert/obsidian/42-Git/home/browser-login/broker/recipes.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_split_otp.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run --project /Users/albert/obsidian/42-Git/home/browser-login pylint /Users/albert/obsidian/42-Git/home/browser-login/broker/otp_detect.py /Users/albert/obsidian/42-Git/home/browser-login/broker/recipes.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_split_otp.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws2_cscs.py
cd /Users/albert/obsidian/42-Git/home/browser-login && grep -n split_otp_group_like /Users/albert/obsidian/42-Git/home/browser-login/broker/otp_detect.py
cd /Users/albert/obsidian/42-Git/home/browser-login && grep -n _otp_target /Users/albert/obsidian/42-Git/home/browser-login/broker/recipes.py
cd /Users/albert/obsidian/42-Git/home/browser-login && grep -n SPLIT_OTP_MIN_REMAINING_S /Users/albert/obsidian/42-Git/home/browser-login/broker/recipes.py
cd /Users/albert/obsidian/42-Git/home/browser-login && grep -n split-autosubmit /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws2_cscs.py
cd /Users/albert/obsidian/42-Git/home/browser-login && timeout 900 uv run --project /Users/albert/obsidian/42-Git/home/browser-login pytest -q -rs -p no:cacheprovider /Users/albert/obsidian/42-Git/home/browser-login/tests/test_split_otp.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_infomaniak_otp.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_email_code_page.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_invisible_captcha.py
cd /Users/albert/obsidian/42-Git/home/browser-login && timeout 900 uv run --project /Users/albert/obsidian/42-Git/home/browser-login pytest -q -rs -p no:cacheprovider /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws2_calibre.py
cd /Users/albert/obsidian/42-Git/home/browser-login && timeout 900 uv run --project /Users/albert/obsidian/42-Git/home/browser-login pytest -q -rs -p no:cacheprovider /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws2_cscs.py -k "one_time_code or fresh_login_exports or reauth or keycloak_polls or password_only"
```

Why this block is not strict-eligible: the claims are about recipe behaviour against fake and
fixture pages, so they can only be shown by running pytest, mypy and pylint in the project
venv. The permissioned reviewer session runs it. The tests that tell old code from new: before
B1-B3, `tests/test_split_otp.py` does not exist (exit 4/5); on the old `_fill_otp`, the split
tests fail (one `fill` into box 1, no per-box keys); before B4, the `-k one_time_code` run
collects no `otp_form` tests. The `grep` lines fail (exit 1) until B1-B4 have landed.
`test_ws2_calibre.py` and `test_infomaniak_otp.py` are the regression guard for the shared
`_fill_otp` and the single-field path. B5's checks need root plus a live login, and they live
in its box, not in this read-only block.

## Not in scope

- `bin/browser.py` legacy `_keycloak_otp_field` / `_fill_keycloak_otp` (`cmd_cscs_login`,
  the shared-browser path): `browser.py login cscs` goes through the broker. If Albert still
  uses the legacy path, a follow-up ticket ports `_otp_target` there.
- Pinning the live CSCS DOM: no login attempt is made for planning. B5's canary, together
  with B2's page hint, is the first real observation.
- Releasing the `cscs` quarantine: the main session's call (B5 step 4).

## Open uncertainties

1. Real key events versus value plus events: unknown which one the CSCS theme needs. The
   design tries keys first, then fill plus `input`/`change`, and verifies both times.
2. Where the code travels (hidden input, a join on submit, or separate parameters): the check
   treats `hidden: "none"` as acceptable when every box holds its digit; `"empty"` fails but
   is named in the error. If the theme joins on submit, only the live canary proves it.
3. Box shape: if the live boxes do not carry `maxlength=1` (for example they cap length in
   JS instead), `split_otp_group_like` misses them. The failure then names the shapes through
   the page hint, and B1's judge gets a size/width rule in a follow-up round.
4. Disabled button: inferred from a pale button in the screenshot. The enabled-button wait
   covers it either way.
5. The CSCS card's context text may contain an `OTP_NEGATIVE_RE` word (for example a
   "recovery code" or "e-mail" link), which would reject the group; the canary's page hint
   shows it.

## Debate outcome (Opus adversary)

Critic: fresh Opus subagent, 2026-11-04, 1 round (Codex round 0 refused with
`debate_seat_unknown`, the fourth time in a day). Verdict: sound-with-fixes; no blockers, no
objection rejected, so no round 2.

1. [major] Self-submit was checked only after verify and fallback, so a theme that submits
   after digit six (or an off-by-one auto-advance) could get a wrong or second code —
   accepted: per-key check before the next key, self-submit check first after the last key,
   fallback only on an unchanged attached page and guarded against detached handles (Fix
   design steps 5, 6, 8); B3 tests for off-by-one and self-submit; B4 `split-autosubmit`
   fixture asserting exactly one POST.
2. [major] `fresh_totp` leaves ~5 s and the split path adds several seconds, so the code
   could roll over before submit — accepted: 15 s minimum remaining on the split path,
   injectable clock, staleness check right before the click with no retype (steps 2, 11);
   B3 tests for the margin and the rollover.
3. [major] Boxes outside the `<form>` leave no submit button and an ineffective Enter —
   accepted: explicit submit scope resolved before typing, click of the identified button
   (steps 4, 12); `in_form` in the describe output; B3 and B4 form-less variants.
4. [major] Split-first on the generic recipe skipped the password-visible guard and the
   `_same_field` exclusion; the call site is `_settle`, not `generic_login` — accepted:
   guard and per-box exclusion added, `_settle` named, two B2 tests.
5. [minor] `_otp_target` must cope with the fake pages of existing tests — accepted:
   exception / missing `evaluate` / non-list → no group, fallback through the module-global
   `_otp_field`, `_fill_otp` still takes a bare handle; B2 test.
6. [minor] Rollback differed from install.sh's swap and restart, skipped the selfcheck and
   did not say it reverts tp#1672 B1/B2 — accepted: rollback now uses `swap_current`'s
   `os.replace`, bootout/bootstrap and the three selfcheck calls; tp#1672 B6 not ticked on a
   rollback.
7. [minor] No re-quarantine command exists, the failure path quarantines automatically, and
   the release left a window — accepted: release immediately before the one canary, confirm
   the automatic quarantine, path corrected to repo-root `agent-login.py`.
8. [minor] Fixture accepting only the exact current TOTP is flaky at step boundaries —
   accepted: current or previous step accepted; risky variants added.
9. [minor] An unsynced hidden input was indistinguishable from a wrong one — accepted:
   four-valued `hidden` with `"empty"`, named in the value-free error.
