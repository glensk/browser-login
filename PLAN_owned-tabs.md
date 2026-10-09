# Plan: tp#845 — logged-in checks and logins always use a fresh tab they own

## Session

Resume: `c --resume 7d725bed-5c4e-4909-82fc-dd9a58934d10`

## Context

**Order:** implement AFTER tp#843 (`PLAN_cscs-login-timeout.md`) has landed. Both plans
touch `_background_page_run` and `cmd_token`. This plan builds on tp#843's raw-CDP close
by owned target id and its `_OWNED_TIDS` registry: `_owned_background_page` registers its
tid there, so the tp#843 deadline closes it too.

**Problem.** `_pick_page(browser, substr)` (bin/browser.py:4717) returns the first tab
whose URL contains `substr`; with no match it falls back to *any* content tab
(`content[-1]`). The site flows then `goto` that tab. The ticket's line numbers are stale —
the current call sites are listed below. AGENTS.md (tp#786) forbids this: consumers own
tabs by target id.

**Evidence.**

- (a) `login cscs` → `_pick_portal_page` → `_pick_page(browser, "cscs.ch")` found no CSCS
  tab, fell back to `content[-1]` — the ChatGPT tab openai-team had left — and navigated it
  to the portal.
- (b) During the tp#836 renewal test, `logged-in anthropic/openai` navigated other
  clients' tabs.
- (c) tp#844 hit: a leftover "ChatGPT - Admin | Members" tab; `logged-in openai` reuses
  its tab and then leaves it open.
- (d) Gaps beyond the ticket:
  - `logged-in cscs` (= `cmd_token`) and `logged-in biopolwifi` skip
    `_logged_in_page_check`, so during a guided login they still pick a tab and navigate
    it — against the AGENTS.md rule.
  - `_close_stale_cscs_tabs` *closes* any tab whose URL contains `auth.cscs.ch`,
    including other clients' tabs.

**Existing building block.** `_with_background_page` / `_background_page_run`:

- connect, `Target.createTarget{background:true}`, reconnect, find the page by target id
  (`_switch_page_by_target`), run `fn`, close it in `finally`;
- already used by the notion/switch/broker checks, `_guided_probe`, and
  `_logged_in_page_check` while a maintenance record lives;
- the first `_connect` registers before `createTarget`, so the BUSY/75 gate still applies.
  Keep that order.

**Inventory**

| Function : line                                                   | Now                                                                                | Becomes                                                                                                             |
| :---------------------------------------------------------------- | :--------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------ |
| `_logged_in_page_check` :7665 (anthropic, openai, slack, test site) | picked tab unless a maintenance record or `PROBE_BACKGROUND_ENV`                   | **always** `_with_background_page(port, "about:blank", check)`; drop `url_substr` and the env branch                 |
| `cmd_anthropic_login` :7594                                       | picks a `claude.ai` tab (or any), probes, `goto` login                             | one owned tab (`_owned_background_page`): warm probe there, then the lease, then `goto` login in the same tab; closed in `finally` |
| `cmd_openai_login` :7770                                          | same, `chatgpt.com`                                                                | same                                                                                                                |
| `cmd_slack_login` :7954, `cmd_slack_session` :8015                | same, `slack.com`                                                                  | login: owned tab; session: `_with_background_page` running the check + `_slack_session_from_page`                    |
| `cmd_biopolwifi_login` :8074, `_logged_in` :8144                  | pick + `goto`; logged-in ignores maintenance                                       | login: owned tab; logged-in: `_logged_in_page_check`                                                                |
| `cmd_token` :5930 (also `logged-in cscs`)                         | `_pick_portal_page`, `goto`, closes stale CSCS tabs                                | `_with_background_page(port, PORTAL_PROFILE_URL, fn)`; `fn`: Keycloak bounce → 2, else `_capture_and_cache_token`   |
| `cmd_cscs_login` :6714-6778                                       | `_pick_portal_page`, `_close_stale_cscs_tabs` ×3                                   | one owned tab on `PORTAL_PROFILE_URL`; the retry `goto` stays in that tab; token captured from it                   |
| `_pick_portal_page` :5885, `_close_stale_cscs_tabs` :5900         | pick by URL / close by URL                                                         | **delete**                                                                                                          |
| `cmd_switch_login` :8532-8536                                     | `cloud.switch.ch` substring pick, else `ctx.new_page()`                            | owned tab + `_bring_to_front` (no-op unless the mode-A lease is held)                                               |
| `cmd_notion_login` :9565                                          | `ctx.new_page()` (focusing), left open                                             | owned tab, closed in `finally`                                                                                      |
| `_test_site_logged_in` :9738 `probe: "pick"`                      | picks by origin                                                                    | branch removed; the fixture key becomes dead                                                                        |
| `_eval_attached` :4993 (`eval --url`)                             | `_pick_page(..., require_match=True)`                                              | **keep** (documented user CLI), renamed `_match_page`; evaluates only, never navigates; no fallback with `--url`    |
| `cmd_open -r` :4859, blank reuse :4867                            | navigates an existing tab                                                          | **out of scope**; help text "manual use only"; follow-up tp for blank-tab reuse grabbing another client's `open -N` target |
| doctor probe :5676                                                | finds its probe tab by unique probe URL                                            | keep (own nonce URL)                                                                                                |
| `agent_login_claude.claude_account_email` :72                     | `eval --url claude.ai`, else `open https://claude.ai/` (leaves a tab)              | `open -N` → `eval -T` → `close -i` in `finally`                                                                     |

**Cost.**

- One extra short-lived background tab per check plus a second Playwright attach (the
  reconnect makes Playwright see the new tab): about 0.5–3 s, depending on how many tabs
  are open (tp#693/786).
- No extra page loads for claude, chatgpt or slack — their checks already `goto` their
  surface.
- CSCS token/login and biopolwifi lose the "already-settled tab" shortcut: one cold SPA
  load, a few seconds.
- Cloudflare and sessions are unaffected: `cf_clearance`, session cookies and
  localStorage are profile-wide, and the plain-Chrome UA is a launch flag, so it applies
  to every target.
- Viewport: a background tab in a headed browser is ~800×460, and sentinels can hide at
  that size (`BROKER_PROBE_VIEWPORT` comment) → size check tabs with
  `_broker_probe_viewport`; never human-facing login tabs.
- A SIGKILLed process (e.g. the `_self_run` timeout in mode A) leaks its tab, but it is
  visible in `status`. Accepted; noted in README.

**Why tests, mypy, pylint.** AGENTS.md "Build / test / lint" requires
ruff/mypy/pylint for bin/browser.py. The behaviour change has to be pinned with fakes —
conftest's `CLAUDE_BROWSER_TEST_NO_LAUNCH=1` blocks a real Chrome, and
`-m "not launches_chrome"` excludes the disposable-browser E2E tests.

## Steps

- [ ] Work in a git worktree, not in place (AGENTS.md: live consumers exec
      bin/browser.py).
- [ ] Add `@contextlib.contextmanager _owned_background_page(port, url, *, prepare=None)`
      next to `_background_page_run`:
  - the same dance: register via the first `_connect`, `createTarget{background:true}`
    (tid → tp#843's `_OWNED_TIDS`), reconnect, find the page by tid;
  - yields the page, or `None` if setup failed;
  - `finally`: raw-CDP close by tid (tp#843), then close every target whose
    `openerId == tid` (one `Target.getTargets`), then `browser.close()` / `pw.stop()`;
  - journals `owned_tab` with `_id8(tid)` + `_tab_hint(url)`;
  - re-implement `_background_page_run` on top of it (keep its
    swallow-errors-return-None contract);
  - rename `_switch_page_by_target` → `_page_by_target` (alias kept for tests).
- [ ] `_logged_in_page_check(port, check)`: always
      `_with_prepared_background_page(port, "about:blank", _broker_probe_viewport, check)`.
      Update its 4 callers. Drop the `PROBE_BACKGROUND_ENV` branch (`_guided_probe` may
      keep setting it; it has no effect now). Rewrite the docstring.
- [ ] `cmd_token`: `_with_background_page(port, PORTAL_PROFILE_URL, fn)`; `fn` waits
      1500 ms; `auth.cscs.ch` in the URL → 2 with the existing message, else
      `_capture_and_cache_token(page.context, page)`. `None` →
      `_fail("could not open a background tab")`.
- [ ] `cmd_cscs_login`: `with _owned_background_page(port, PORTAL_PROFILE_URL) as page:`,
      then `_interaction_lease`, then the existing logic. Remove the three
      `_close_stale_cscs_tabs` calls; delete `_pick_portal_page` and
      `_close_stale_cscs_tabs`.
- [ ] anthropic/openai/slack logins: `with _owned_background_page(port, "about:blank") as
      page:`. The warm probe runs in that page outside the lease (same lock order as now);
      the cold path takes the lease and `goto`s in the *same* tab. A `None` page →
      `_fail`.
- [ ] `cmd_slack_session`: `_with_background_page(port, "about:blank", fn)`; `fn` returns
      creds or the "not logged in" sentinel (exit 2).
- [ ] biopolwifi: login in an owned tab on `BIOPOLWIFI_PORTAL_URL`; logged-in through
      `_logged_in_page_check` (`goto` + sentinel). Error lines use `_tab_hint(page.url)`
      instead of the raw `page.url` (8103, 8127).
- [ ] switch window flow and notion: pick / `ctx.new_page()` → `_owned_background_page`;
      keep `_bring_to_front`; remove the "stays open afterwards" comment.
- [ ] `_test_site_logged_in`: delete the `probe == "pick"` branch;
      tests/test_guided_login.py:913-915: drop `"probe": "pick"` and its comment.
- [ ] `_pick_page` → `_match_page(browser, url_substr)`: substring → first match or
      `None`; `None` substring → the current default for `eval` without `--url`;
      docstring "eval only; never navigate the result". Update `_ensure_page_target`'s
      docstring (935).
- [ ] `open -r` help text: "manual use; tools use -N". File the follow-up tp for
      blank-tab reuse in `cmd_open`.
- [ ] `agent_login_claude.py claude_account_email`: `_browser("open","-N",
      "https://claude.ai/")` → parse `target=` → `eval -T <tid> -t 30 JS` →
      `close -i <tid>` in `finally`; keep the 2-attempt loop.
- [ ] Tests (fakes only; never `_launch_browser`):
  - **New tests/test_owned_tabs_tp845.py:**
    - logged-in cmds (anthropic, openai, slack, biopolwifi, token) with *no* maintenance
      record, `_connect` patched to `pytest.fail`: assert the background helper ran with
      `about:blank` / `PORTAL_PROFILE_URL` and the viewport `prepare`;
    - login cmds (anthropic, openai, slack, cscs, biopolwifi, switch-window, notion) with a
      fake `_owned_background_page` yielding a fake page; the fake ctx's `.pages` raises
      (proves no foreign tab is enumerated); the fake records `goto`s and that `finally`
      ran even when the flow raises;
    - `_owned_background_page` with fake `_connect`/CDP: closes the page, falls back to
      `closeTarget` when not adopted, closes `openerId` children only;
    - AST guard over bin/browser.py: `_match_page` is called only from `_eval_attached`;
      `_pick_page`, `_pick_portal_page` and `_close_stale_cscs_tabs` no longer exist.
  - **Update** test_tab_selection.py (rename; delete
    `test_default_fallback_is_unchanged_for_the_site_flows`), test_token_verify.py `env`
    fixture, test_credentials.py `_cscs_login_env`, test_magic_link_flow.py:291 and
    test_headless_default.py:528 (fake `_owned_background_page` instead of
    `_pick_page`).
  - test_guided_login.py:588 stays; add a sibling test: no record → still background.
  - test_agent_login.py: fake `subprocess.run` asserts the `open -N`, `eval -T`,
    `close -i` order, with close also on eval failure.
- [ ] README:
  - Quick start `eval --url`: "evaluates only, never navigates; tools use
    `open -N`/`eval -T`/`close -i`".
  - Guided-login paragraph: generalize to "every `logged-in` check and every `login`
    runs in a fresh background tab it owns and closes" (plus the SIGKILL-leak note).
  - Site table rows for cscs, anthropic, openai, slack and biopolwifi: the notion/switch
    wording.
- [ ] AGENTS.md tp#786 bullet: add "the in-repo site flows obey it too: checks via
      `_logged_in_page_check`/`_with_background_page`, logins via
      `_owned_background_page`; `_match_page` is reserved for `eval --url` (read-only)".
      Simplify the guided-login sentence that limits fresh-tab checks to "while a record
      lives".
- [ ] After merge: `browser.py doctor` against a disposable instance (AGENTS.md). Then on
      live: `logged-in openai`; `status` shows no leftover chatgpt tab (tp#845
      acceptance).

## Verification

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff format --check bin/ tests/ agent_login_claude.py
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff check bin/ tests/ agent_login_claude.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run mypy bin/browser.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pylint bin/browser.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q -m "not launches_chrome" tests/test_owned_tabs_tp845.py tests/test_tab_selection.py tests/test_token_verify.py tests/test_credentials.py tests/test_magic_link_flow.py tests/test_headless_default.py tests/test_guided_login.py tests/test_agent_login.py tests/test_broker_spa_and_switch_eduid.py tests/test_switch_site.py tests/test_login_broker.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run python bin/browser.py -h
```
