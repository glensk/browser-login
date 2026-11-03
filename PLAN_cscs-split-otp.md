# PLAN: cscs split one-time-code fill (tp#1675)

> **Resume here.** Status: cause confirmed from the failure screenshot, planned, not debated,
> nothing built. Next round: R1 (B1, B2, B3).
> B2 changes `broker/recipes.py`, and that file is broker code. The launchd broker runs the
> installed copy (`${LIBEXEC}/current/broker/daemon.py`, `install/install.sh`), not this
> checkout. So the fix reaches production only through B4, which reinstalls with `sudo -n`
> and is coordinated with tp#1672 B6. B4 is the same reinstall plus canary that was rolled
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
  the image, not verified). Evidence: `/var/db/login-broker-run/last-failure-cscs.png`
  (root-owned; read through a `sudo -n cp` copy).
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

- `OTP_SELECTOR`: `_otp_field` (generic recipe, `generic_login` around :2336) and `cscs_login`
  (around :3031). Nothing else in `broker/`. `bin/browser.py` has its own legacy
  `_keycloak_otp_field` / `_fill_keycloak_otp` for `cmd_cscs_login` (`#otp`,
  `input[name=otp]`, `autocomplete=one-time-code`). That is the pre-broker shared-browser
  path. It is **out of scope** here (see Not in scope).
- `_fill_otp` (:1304): called by the generic recipe and by `cscs_login`. Existing tests that
  exercise it or the detector: `tests/test_infomaniak_otp.py` (the `otp_field_like` table
  plus an e2e Infomaniak-like single field with `maxlength=6`), `tests/test_ws2_calibre.py`,
  `tests/test_invisible_captcha.py` and `tests/test_email_code_page.py`. They must stay
  green unchanged.

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

The design below does not depend on the answers. It detects the group by shape, types with
real key events per box, verifies in the page (booleans only) before anything is submitted,
has exactly one fallback fill strategy, and never submits an unverified code. A wrong code
counts towards Keycloak's brute-force lockout, so guessing is worse than failing. Only B4's
live canary can prove it works on the real page. If the canary fails, B2's value-free page
hint (fields with `maxlength`) names the shape for the next round.

## Fix design

- **Detection (pure + one page read):** a new `SPLIT_OTP_DESCRIBE_JS` in
  `broker/otp_detect.py`. It reads the page once and returns, value-free, the groups of
  visible, editable, non-password, non-hidden `input`s with `maxLength == 1`. A group is the
  inputs that share the same nearest `<form>`, or, without a form, the same parent chain up
  to 4 levels. Each member is described in DOM order with `OTP_DESCRIBE_JS`'s fields; each
  group also gets its context text (≤ 300 chars, the same rule as `OTP_DESCRIBE_JS`) and a
  flag saying whether it has a hidden `input` whose name matches `/otp|totp|code/i`. The
  pure judge `split_otp_group_like(group) -> bool` accepts a group only when all of these
  hold:
  - it has 4 to 8 members, and every member is `text|tel|number` with `maxlength == 1`;
  - no member matches the username selector;
  - no `OTP_NEGATIVE_RE` word (sms, e-mail, backup, …) appears in the attributes or context;
  - either some member has `autocomplete=one-time-code`, or the attributes/context hold an
    `OTP_WORD_RE` word, or every member is numeric (inputmode/type/pattern) and a
    `CODE_WORD_RE` word appears.

  A single code field never passes: it has `maxlength ≠ 1` or no siblings. So the single-
  field sites keep their exact current path.
- **Target type (recipes.py):** `OtpTarget(boxes: tuple[Any, ...])`, where a single field is
  `boxes=(field,)` and a split group is `boxes=(b1..bN)`. A new
  `_otp_target(page, *, generic: bool)` checks the **split group first**. This order matters,
  because a first box carrying `autocomplete=one-time-code` would otherwise match
  `OTP_SELECTOR` as a single field. After that, `generic=True` falls back to today's
  `_otp_field(page)`, and `generic=False` (cscs) to today's `_visible(page, OTP_SELECTOR)`.
  The fallbacks are exactly today's code.
- **Fill (`_fill_otp` takes an `OtpTarget`):** the code-wait, `watch.clear`,
  `_select_authenticator` and the e-mail-code `NeedsHuman` stay as they are. After the wait,
  the target is re-queried through `_otp_target` (same `generic` flag). Single field: today's
  path, byte for byte. Split group:
  1. `_guard` runs on **every** box (origin, frame, form action), so an OriginViolation sets
     `submitted=True` as today.
  2. If `len(code) != len(boxes)`, raise `LoginFailed("the one-time-code form has N boxes,
     the TOTP has M digits", submitted=True)` before anything is typed.
  3. Primary strategy, real key events: for box *i*, `box.focus()` (or `click()` when focus
     is refused), then `page.keyboard.press(digit_i)`. Focusing each box explicitly makes the
     typing independent of whether the theme auto-advances; when it does auto-advance, the
     focus is already where we put it.
  4. Verify in the page with `SPLIT_OTP_CHECK_JS(boxes, code)`. It returns booleans only,
     never a value: `{boxes_ok, hidden: "match"|"mismatch"|"none"}`. `hidden` is about a
     hidden code input in the same form, if one exists. The check is polled for up to 1 s,
     because the theme may sync on a debounce.
  5. If the check fails, exactly one fallback runs: clear every box, then for box *i*
     `box.fill(digit_i)` plus in-page `dispatchEvent(new Event('input', {bubbles:true}))`
     and `'change'`. Then verify again (step 4).
  6. If the check still fails, raise `LoginFailed("the one-time-code boxes did not keep the
     code — nothing submitted", submitted=True)` with no click and no Enter. A mismatching
     hidden input counts as a failure.
  7. Wait `OTP_SELF_SUBMIT_MS`, then call `_submitted_itself(page, last_box, before)`, as
     today.
  8. Wait until the button is enabled: poll for up to 2 s until the form's first submit
     button is not `disabled`. `pick_submit_button` reads "Verify Code" as a login default,
     which means **Enter**, and Enter does not submit a form whose default button is
     disabled. If the button is still disabled after 2 s, raise `LoginFailed(... "nothing
     submitted")`.
  9. Submit with `_submit_password(page, last_box, ...)`, the same rules as today.

  The code is passed into the page only as an `evaluate` argument for the check. It is never
  logged, never returned and never put into an error message.
- **cscs loop:** `otp_field = _visible(page, OTP_SELECTOR)` becomes
  `_otp_target(page, generic=False)`, and `_fill_otp` re-queries with `generic=False`. Today
  `_fill_otp` re-queries through the generic `_otp_field` even for cscs, which is a latent
  difference; this change fixes it. When the loop ends without the portal, the final
  `LoginFailed` gets `_kc_page_hint(page)` appended, and `_KC_PAGE_HINT_JS` adds `/1` to an
  entry whose `maxLength == 1` (value-free, for example `text#otp-0/1`). The next unknown
  form then shows its shape in the error.
- **Generic recipe:** `_otp_target(page, generic=True)`. Single-field sites do not change.
  Split-box sites go from "fills one digit" to the verified split fill. This is the only
  behaviour change outside cscs, and B2 pins it with a test.

## Boxes

Build rounds (at most 3 boxes per round, one writer agent per round, rounds in order):

- **R1** = B1, B2, B3. One builder, in order. B2 depends on B1's judge, and B3 depends on
  B2's fill.
- **R2** = B4: the production landing plus the live canary. It runs together with tp#1672 B6:
  **one** reinstall carries both tp#1672 B1/B2 (already on `main`) and this fix. It is done
  by the main session or a big agent (`sudo -n`, launchd restart, live login), not by a lean
  builder.

- [ ] B1 `broker/otp_detect.py`: add `SPLIT_OTP_DESCRIBE_JS` (value-free groups of visible,
  editable, `maxLength == 1` inputs per form or common ancestor, in DOM order, with context
  text and a hidden-code-input flag) and the pure `split_otp_group_like(group) -> bool` as
  designed. New `tests/test_split_otp.py`, hermetic with no Chromium. Accept cases: 6 numeric
  boxes with "One-Time Code" context and no attributes (the CSCS shape); 6 boxes with
  `autocomplete=one-time-code` on the first only; 4 and 8 boxes. Reject cases: 3 and 9
  boxes; one box with `maxlength=2`; a group containing a username field; "SMS code" or
  "backup code" context; 6 `maxlength=1` boxes without OTP or code words and not numeric (for
  example initials fields); a single `maxlength=6` field. `tests/test_infomaniak_otp.py`
  stays green unchanged.
- [ ] B2 `broker/recipes.py`: add `OtpTarget`, `_otp_target(page, *, generic)`
  (split first), `SPLIT_OTP_CHECK_JS`, and the split path in `_fill_otp` (guard every box,
  length check, key-event fill, verify, one fill+events fallback, verify, enabled-button
  wait, then `_submit_password` on the last box). Wire it into `cscs_login` (`generic=False`)
  and `generic_login` (`generic=True`). Add the `/1` marker to `_KC_PAGE_HINT_JS` and append
  `_kc_page_hint` to cscs's final "did not reach the CSCS portal" error. Hermetic tests, in a
  new section of `tests/test_split_otp.py`, on a scripted fake page in the style of
  `tests/test_ws2_cscs.py::_ScriptedKcPage`: `_SplitOtpPage` with N fake boxes, each
  recording focus, key presses and fills. Its switches are `takes_keys`, `takes_fill`,
  `auto_advance`, `hidden_sync` (`ok|wrong|none`), `self_submit_after_last` and
  `button_enabled_after_ms`. `page.evaluate(SPLIT_OTP_CHECK_JS, …)` is answered from the
  boxes' recorded state. Tests:
  `test_split_boxes_get_one_key_each_then_one_submit`;
  `test_keys_ignored_falls_back_to_fill_with_events`;
  `test_neither_strategy_kept_the_code_submits_nothing` (LoginFailed, `submitted=True`, no
  click or Enter);
  `test_a_wrong_hidden_code_submits_nothing`;
  `test_box_count_not_matching_the_code_types_nothing`;
  `test_a_page_that_submits_itself_is_not_submitted_again`;
  `test_a_still_disabled_verify_button_submits_nothing`;
  `test_a_box_off_the_fill_origin_is_an_origin_violation`;
  `test_a_single_otp_field_keeps_the_old_path` (`OTP_SELECTOR` field: one `fill(code)`, no
  per-box keys);
  `test_cscs_waits_for_a_split_otp_step` (the `cscs_login` settle loop finds the group and
  calls the split fill). Also check that no recorded log, exception text or page hint
  contains the code. Re-run `tests/test_infomaniak_otp.py`, `tests/test_ws2_calibre.py`,
  `tests/test_invisible_captcha.py` and `tests/test_email_code_page.py` unchanged.
- [ ] B3 `tests/test_ws2_cscs.py` (real Chromium, `launches_chrome`, hermetic: local fixture
  server, no network): add `Portal.otp_form: str = "none"`, a switch with the values
  `"none" | "single" | "split"`. After the password POST to `KC_POST`, `"single"` serves a
  classic Keycloak OTP page (`<input id=otp name=otp autocomplete=one-time-code>`).
  `"split"` serves six `maxlength=1` `inputmode=numeric` boxes with no OTP attributes, under
  a "One-Time Code" label. Its JS auto-advances on `input`, keeps a hidden `name=otp` in sync,
  and enables "Verify Code" only once all six boxes are filled. The server accepts the POST
  only when `otp` equals the current TOTP for the fixture item's seed (`fresh_totp`),
  otherwise it re-serves the page with an error. New broker end-to-end tests:
  `test_a_split_one_time_code_logs_in` and `test_a_single_one_time_code_still_logs_in`. The
  item secret gets a test-only TOTP seed generated in the test (never a real one). The
  existing tests keep `otp_form="none"` and do not change.
- [ ] B4 Production landing and live canary (R2, coordinated with tp#1672 B6; main session or
  `[full-context: albert]` agent). Precondition: B1-B3 are merged to `origin/main`
  (`install.sh` installs `git archive HEAD` and refuses a HEAD that is not in `origin/main`),
  and tp#1672 B6 has not landed on its own in the meantime. Steps:
  1. Record `readlink /usr/local/libexec/login-broker/current`; expect
     `releases/b3614002357f-20261031T165118Z`.
  2. Run `sudo -n install/install.sh -n` (dry run), then `sudo -n install/install.sh` from a
     clean checkout at `origin/main`. The install swaps `current` atomically, restarts the
     daemon and runs the boundary selfcheck, which rolls back by itself when it fails.
  3. Confirm that the new release dir contains `_otp_target` and
     `split_otp_group_like`. Confirm the fresh daemon pid with
     `sudo -n launchctl print system/com.albert.login-broker`, and the install line in
     `/var/log/login-broker.log`.
  4. The main session releases the quarantine (`agent-login.py -Q cscs`) and runs **one**
     canary, `browser.py login cscs`, and expects exit 0. On a failure, copy
     `/var/db/login-broker-run/last-failure-cscs.png` read-only and read the error's page hint
     (the field shapes). Do not retry in a loop, because of Keycloak's brute-force lockout.
  5. tp#1672 B6 is ticked by the same landing.

  Rollback: re-point `current` to the recorded release with
  `sudo -n ln -sfn <old> /usr/local/libexec/login-broker/current.tmp` plus
  `sudo -n mv -h /usr/local/libexec/login-broker/current.tmp
  /usr/local/libexec/login-broker/current`, then
  `sudo -n launchctl kickstart -k system/com.albert.login-broker`. Re-quarantine `cscs`
  through the main session if the canary failed.

## Verification

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff format --check /Users/albert/obsidian/42-Git/home/browser-login/broker/otp_detect.py /Users/albert/obsidian/42-Git/home/browser-login/broker/recipes.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_split_otp.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws2_cscs.py
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff check /Users/albert/obsidian/42-Git/home/browser-login/broker/otp_detect.py /Users/albert/obsidian/42-Git/home/browser-login/broker/recipes.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_split_otp.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws2_cscs.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run --project /Users/albert/obsidian/42-Git/home/browser-login mypy /Users/albert/obsidian/42-Git/home/browser-login/broker/otp_detect.py /Users/albert/obsidian/42-Git/home/browser-login/broker/recipes.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_split_otp.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run --project /Users/albert/obsidian/42-Git/home/browser-login pylint /Users/albert/obsidian/42-Git/home/browser-login/broker/otp_detect.py /Users/albert/obsidian/42-Git/home/browser-login/broker/recipes.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_split_otp.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws2_cscs.py
cd /Users/albert/obsidian/42-Git/home/browser-login && grep -n split_otp_group_like /Users/albert/obsidian/42-Git/home/browser-login/broker/otp_detect.py
cd /Users/albert/obsidian/42-Git/home/browser-login && grep -n _otp_target /Users/albert/obsidian/42-Git/home/browser-login/broker/recipes.py
cd /Users/albert/obsidian/42-Git/home/browser-login && grep -n otp_form /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws2_cscs.py
cd /Users/albert/obsidian/42-Git/home/browser-login && timeout 900 uv run --project /Users/albert/obsidian/42-Git/home/browser-login pytest -q -rs -p no:cacheprovider /Users/albert/obsidian/42-Git/home/browser-login/tests/test_split_otp.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_infomaniak_otp.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_email_code_page.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_invisible_captcha.py
cd /Users/albert/obsidian/42-Git/home/browser-login && timeout 900 uv run --project /Users/albert/obsidian/42-Git/home/browser-login pytest -q -rs -p no:cacheprovider /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws2_calibre.py
cd /Users/albert/obsidian/42-Git/home/browser-login && timeout 900 uv run --project /Users/albert/obsidian/42-Git/home/browser-login pytest -q -rs -p no:cacheprovider /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws2_cscs.py -k "one_time_code or fresh_login_exports or reauth or keycloak_polls or password_only"
```

Why this block is not strict-eligible: the claims are about recipe behaviour against fake and
fixture pages, so they can only be shown by running pytest, mypy and pylint in the project
venv. The permissioned reviewer session runs it. The tests that tell old code from new: before
B1/B2, `tests/test_split_otp.py` does not exist (exit 4/5); on the old `_fill_otp`, the split
tests fail (one `fill` into box 1, no per-box keys); before B3, the `-k one_time_code` run
collects no `otp_form` tests. The `grep` lines fail (exit 1) until B1, B2 and B3 have landed.
`test_ws2_calibre.py` and `test_infomaniak_otp.py` are the regression guard for the shared
`_fill_otp` and the single-field path. B4's checks need root plus a live login, and they live
in its box, not in this read-only block.

## Not in scope

- `bin/browser.py` legacy `_keycloak_otp_field` / `_fill_keycloak_otp` (`cmd_cscs_login`,
  the shared-browser path): `browser.py login cscs` goes through the broker. If Albert still
  uses the legacy path, a follow-up ticket ports `_otp_target` there.
- Pinning the live CSCS DOM: no login attempt is made for planning. B4's canary, together
  with B2's page hint, is the first real observation.
- Releasing or re-imposing the `cscs` quarantine: the main session's call.

## Open uncertainties

1. Real key events versus value plus events: unknown which one the CSCS theme needs. The
   design tries keys first, then fill plus `input`/`change`, and verifies both times.
2. Where the code travels (hidden input, a join on submit, or separate parameters): the check
   treats `hidden: "none"` as acceptable when every box holds its digit. If the theme joins
   on submit, only the live canary proves it.
3. Box shape: if the live boxes do not carry `maxlength=1` (for example they cap length in
   JS instead), `split_otp_group_like` misses them. The failure then names the shapes through
   the page hint, and B1's judge gets a size/width rule in a follow-up round.
4. Disabled button: inferred from a pale button in the screenshot. The enabled-button wait
   covers it either way.
