# tp#365 — `browser.py status` prints every tab's full URL (query/fragment included)

## Session

Resume: `c --resume cd30846a-045c-4653-8403-ffdb2be49c85`

## Context

**Classification: DEFECT** (information leak). The repo's own ruling from tp#337 defines a
tab's full URL in captured output as a leak class: reset-token paths, magic-link tokens,
`data:` bodies, and OAuth/OIDC (OpenID Connect) query parameters land in the caller's log
and the LLM transcript. `status` is the widest surface of that class — nearly every LLM
session that touches the browser runs it first.

**Symptom.** `browser.py status` renders each page target as
`- <title>  →  <url>` with `t.get('url')` verbatim from `GET /json/list`
(`bin/browser.py:1845-1846`). No `_strip_query`, no path redaction.

**Evidence (reproduced live, 2026-09-22, this session).** With the shared browser up
(Chrome/151, 4 tabs) `bin/browser.py status` printed a Keycloak authorize tab in full:
`https://custos.datascience.ch/realms/sdsc/protocol/openid-connect/auth?scope=openid&state=…&response_type=code&client_id=runai&redirect_uri=…&nonce=…`
— `state`, `nonce` and `redirect_uri` values verbatim (masked here before they reached the
transcript). A magic-link tab (`/auth/magic/<token>`) or the callback leg (`?code=…`)
lands the same way; `doctor`'s disposable `data:` tab would print its whole body.

**Root cause (high confidence).** `cmd_status` (`bin/browser.py:1829-1848`) predates the
tp#337 fix and never used `_tab_hint` (`bin/browser.py:2064-2092`), the origin-only,
fail-closed renderer introduced for the `eval --url` no-match error. The line at
`bin/browser.py:1846` interpolates the raw URL.

**Consumers of `status` output.** Grep over `42-Git/` (`*.py`, `*.sh`, `*.md`),
`~/.claude/{hooks,skills,agents}`, `infra/status` and `mydotfiles/bin`: only prose
mentions (`README.md:67`, `AGENTS.md:26`, `sdsc/cscs-api/README.md:309`,
`~/.claude/skills/anthropic-api/SKILL.md:80`) and browser.py's own error messages that
point at `status`. **No script parses the tab lines.** Changing what a tab line contains
breaks nothing; the exit codes (0 up / 1 down) and the `Lifecycle:` line stay unchanged.

**Decision settled from the evidence (recorded: `tp question 365` assumption `be8733`,
non-blocking).** Origin-only by default via `_tab_hint`; an explicit `-f/--full` flag
prints the raw URL. Rationale:

- Consistency with tp#337: `_tab_hint` is an allowlist (`scheme://host[:port]` only),
  fails closed on malformed input, and its tests already pin the no-leak property.
- The tab **title stays** (it is what the user sees in the tab strip, e.g.
  `portal.cscs.ch/profile/`, `Sign in to SDSC`), so two same-origin tabs remain
  distinguishable; `status` keeps one line per tab and the `N tab(s):` count (unlike the
  eval error, no dedup/cap — status is a listing, not a hint).
- The host is exactly the vocabulary `eval --url SUBSTR` needs; the retry path when
  several tabs share a host is the tp#337 no-match error, which already dedups by origin.
- Humans who copy URLs get `status -f` — one deliberate keystroke, visible in the
  transcript, never the default an agent inherits.

**Alternatives considered and rejected.**

| Alternative                                           | Why not                                                                                                                                                                                              |
| :---------------------------------------------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Strip only query + fragment, keep the path            | Path-embedded tokens (magic links, reset links, `data:` bodies) are the tp#337 class; the ticket body names "no path/query redaction". Half a fix that still needs `-f` for the query case.        |
| Bare count (`4 tab(s), URLs withheld`)                | Rejected in the tp#337 debate: removes the one thing that lets the caller choose a `--url` host substring; the title alone does not name a host.                                                     |
| Heuristic redaction of token-shaped segments          | Rejected in tp#337: a denylist misses short tokens and `data:` bodies; origin-only is an allowlist.                                                                                                  |
| TTY-gate `--full` (refuse when stdout is not a TTY)   | `status -f \| pbcopy` is the human use-case. The guard targets the accidental default; a caller that types `-f` has read the help text, and any CDP client can read every tab's URL and DOM anyway. |
| Env var (`BROWSER_PY_STATUS_FULL=1`) instead of a flag | Invisible in the transcript; a session that inherits it leaks silently. A flag is per-invocation and auditable.                                                                                      |
| Truncate `data:` URLs under `-f`                      | Out of scope; `-f` is "raw", and the pre-existing behaviour for a `data:` tab is unchanged.                                                                                                          |

**Not in scope (observation, accepted in tp#337).** `open` echoes `page.url` after
navigation (`bin/browser.py:2106,2112,2115`); when the target redirects into an SSO flow
the echoed URL carries `state`/`nonce`. The tp#337 debate accepted "open already prints
every navigated URL" — the caller chose the URL and sees it once. Left as is.

**Blocked on Albert:** no. **Confidence:** high (repro + root cause + no parsers found).

## Steps

- [ ] **`cmd_status(port, full=False)`** (`bin/browser.py:1829`): render each page target as
      `- {title or '(untitled)'}  →  {_tab_hint(url)}`; when `full` is set, print the raw
      `url` as today. When at least one tab is listed and `full` is not set, print one
      trailer line after the list:
      `(origins only; \`status -f\` prints full URLs — for humans copying a link, never from an agent: in-flight auth tabs carry tokens)`.
      Non-page targets (`iframe`,`service_worker`,`background_page`) stay skipped; the
      `✓ Up …`,`N tab(s):`,`Lifecycle:` lines and exit codes are unchanged.
- [ ] **argparse** (`bin/browser.py:228-230`, dispatch at `:4952`): give the `status`
      subparser `-f/--full` (`store_true`, help: "print each tab's full URL (query and
      fragment included); default is origin only because in-flight auth tabs carry tokens
      and status output lands in logs and LLM transcripts"); dispatch `cmd_status(port,
      args.full)`. Update the epilog example (`bin/browser.py:198`) to
      `# CDP health + tabs (origins) + lifecycle; -f full URLs`.
- [ ] **`_tab_hint` docstring** (`bin/browser.py:2064-2077`): generalise "for the `eval
      --url` no-match error" to "for `status` and the `eval --url` no-match error"; the
      rendering rules do not change (the tp#337 tests stay green untouched).
- [ ] **Tests** — new `tests/test_status_output.py` (same module-loading shim as
      `tests/test_tab_selection.py`; monkeypatch `_cdp_get`, `_browser_mode`,
      `_print_lifecycle`; capture with `capsys`). Fixture target list: a Keycloak authorize
      URL with `state=`/`nonce=`/`redirect_uri=`, a magic-link path `/auth/magic/<token>`,
      a `data:text/html,<secret>` tab, `about:blank`, a `user:pw@host` URL, an IPv6 origin,
      a malformed URL, and one non-page target (`type: service_worker`) that must be
      skipped. Assert:
  - default: every title present; every tab line ends in `→  <origin>`; none of `state=`,
    the token, `secret`, `user:pw`, `?`, `#` appears anywhere in stdout; count line says
    `7 tab(s):`; the trailer line is present; return 0.
  - `full=True`: every raw URL verbatim; no trailer; return 0.
  - zero page targets: `0 tab(s):`, no trailer.
  - CDP down (`_cdp_get` → `None`): `✗ … DOWN` line, `_print_lifecycle` called, return 1,
    no tab lines (unchanged path, pinned so the refactor cannot regress it).
  - `tests/test_tab_selection.py::test_no_match_error_never_points_at_status` (or its
    current name) still passes — the eval error must not start advertising `status -f`.
- [ ] **Docs**: `README.md:67` (`# CDP health, version, open tabs (origins only; -f full
      URLs) + the lifecycle record`) and the `status` paragraph at `README.md:126-129`
      (one sentence: tab URLs are origin-only because status output lands in transcripts;
      `-f/--full` is the human opt-in); `AGENTS.md` Conventions: add a bullet "Tab URLs in
      any captured output (`status`, error lines) are origins only — reuse `_tab_hint`;
      full URLs are opt-in (`status -f`) and never the default"; `sdsc/cscs-api/README.md:309`
      comment stays accurate (no change needed — verify).
- [ ] **Lint + verify + commit** (Verification block below), then
      `ai.py push -m "fix(status): print tab origins only; -f/--full for raw URLs (tp#365)" bin/browser.py tests/test_status_output.py README.md AGENTS.md PLAN_browser-py-status-prints-every-tab-s-full-url-quer.md`.
- [ ] **Completion**: `tp tidy 365` (renames to `_DONE`, moves to `plans-done/`, fixes the
      tp link) in the closing commit.

## Verification

```commands
cd ~/obsidian/42-Git/home/browser-login
python3 -m pytest tests/ -q
ruff format bin/ tests/ && ruff check bin/ tests/ && mypy bin/browser.py && pylint bin/browser.py
bin/browser.py status -h                                  # exit 0, lists -f/--full
bin/browser.py status | grep -E '^\s+- .*→ ' | grep -E '[?#]' ; test $? -eq 1   # no query/fragment in any tab line
bin/browser.py status | grep -E '^\s+- .*→ [a-z]+://[^/]+/'; test $? -eq 1        # no path either (origin only)
bin/browser.py status -f | grep -qE '→ .*[?#]' && echo 'full URLs shown with -f'      # given one tab with a query
bin/browser.py status | grep -q 'origins only' && echo 'trailer present'
bin/browser.py doctor                                     # lifecycle/desktop invariants untouched
```
