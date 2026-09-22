# eval --url no-match error leaks every open tab's URL path (tp#337)

## Session

Resume: `c --resume fec06787-4102-4af3-955e-6c959811b419`

## Context

**Classification: DEFECT** — a diagnostic message prints material it was meant to withhold.

**Symptom.** `browser.py eval --url SUBSTR '<js>'` with no matching tab exits 1 (correct
since tp#317) and appends `Open tabs: <url>, <url>, …` to the stderr line. Each entry keeps
the full URL *path*, so a password-reset tab, a magic-link tab or a `data:` page puts its
secret into the caller's log and, for LLM consumers, into the session transcript.

**Evidence (reproduced 2026-09-22, stub tabs only — the live shared browser was not
touched).** With `_connect` monkeypatched to return a fake browser holding three tabs:

```commands
❌ No tab matching 'epflch.sharepoint.com' — nothing evaluated. Open one first: browser.py open <url>. Open tabs: https://example.test/reset/SECRET-IN-PATH, data:text/html,<b>secret-body</b>, https://app.slack.com/client/T1/C1
exit 1
```

`SECRET-IN-PATH` (path) and the whole `data:` body survive; only `?code=HIDDEN` and the
`#frag` were removed. The same holds for `user:pw@host` userinfo and `blob:` / `file:` /
`javascript:` URLs, none of which have a `?` to cut at.

**Root cause (confidence: high).** `cmd_eval` (`bin/browser.py:2096-2105`) renders the
hint with `_strip_query` (`bin/browser.py:2058-2060`), a helper written for `open -r`'s
tab-REUSE matching: it cuts at the first `#` and `?` and strips a trailing `/`, nothing
else. The path, the userinfo and every non-hierarchical URL pass through verbatim. The
comment above the call (`bin/browser.py:2099-2100`) shows the only case considered was an
OAuth callback's *query* — the reviewer of tp#317 caught the gap and filed this ticket.

**Blocked on Albert: no.** No external, irreversible or paid decision; the design choices
below are recorded as non-blocking assumptions (`tp question 337 …`).

### Design (settled; debated with Codex gpt-5.6-sol, converged round 1)

- **Origin-only hint, fail-closed.** A new `_tab_hint(url)` renders each tab as
  `scheme://hostname[:port]` (lower-cased host via `urlsplit().hostname`, userinfo dropped,
  IPv6 re-bracketed) when the URL has a hostname — `https://…`, `http://…`,
  `chrome://newtab`; a URL without one (`data:`, `blob:`, `file:`, `javascript:`,
  `about:` …) collapses to `<scheme>:…`, except the literal `about:blank`, which is printed
  as-is because it is the "you have only a blank tab — use `open`" signal. An empty URL
  (Chrome reports those; `_is_blank` already accepts them) renders as `(empty)`. Parsing is
  wrapped in `try/except ValueError` — `urlsplit` raises on a malformed IPv6 literal and
  `.port` on a non-numeric or out-of-range port — and returns the literal
  `<unparseable url>`, so one odd tab can never turn the exit-1 message into a traceback.
  No byte of a malformed input reaches the output.
- **What origin-only does and does not promise.** It removes the ticket's leak class —
  path, query, fragment, userinfo and the bodies of non-hierarchical URLs. It is **not** a
  secrecy invariant for hostnames: a capability-style host (an ngrok-type tunnel id, a
  tenant-specific subdomain) opened by hand in the shared window would be named. That
  residual is accepted because the hostname is the `--url` selector's own vocabulary (every
  real consumer call in the vault is `--url <host>`; help text `bin/browser.py:291-295`),
  `cmd_open` already prints `page.url` to stdout after every navigation
  (`bin/browser.py:2077-2085`) and the caller's own `browser.py open https://<host>/…` line
  sits in the same transcript — so for every agent-opened tab the host is already there —
  and every CDP client of the shared browser reads every tab's full URL and DOM by design
  (AGENTS.md "What this is"). Codex's alternative, a bare count (`Open tabs: 4 (URLs
  withheld)`), was rejected on that basis: it withholds nothing that is not already
  written elsewhere while removing the one thing that lets the caller choose a host
  substring for its next call.
- **Keep the list, deduplicated, then capped.** Deduplicate ALL hints first (order of first
  appearance, `×N` suffix per hint that occurs more than once: three Slack tabs →
  `https://app.slack.com ×3`), THEN cap at 8 unique hints and suffix `… (+N more origins)`
  naming the omitted unique hints — the unit is origins, not tabs. Token-shaped-segment
  heuristics (entropy, regex) were rejected: a denylist misses short magic-link tokens and
  `data:` bodies; origin-only is an allowlist.
- **No pointer to `status`.** The message ends after the list. `status` prints every tab's
  full URL including the query (`bin/browser.py:1844-1846`) — a wider surface of the same
  class, filed as **tp#365** (follow-up of this item) because it is the canonical "show me
  the tabs" command that humans copy URLs from, so hiding anything there is a contract
  decision of its own. Advertising it from an error line that agents capture would route
  them straight into that leak (Codex O2), so neither the message nor the README clause
  mentions it. Once `_tab_hint` exists, tp#365 can reuse it.
- **Matching is unchanged.** `_pick_page` still tests `url_substr in pg.url` against the
  full URL (`bin/browser.py:2041-2044`), so `--url /sites/foo` keeps working; only what is
  *printed* shrinks. A retry with `--url <host>` when several tabs share that host selects
  the oldest match — the existing documented rule shared with `open -r`
  (`bin/browser.py:284-287`), not a new failure mode; tp#317's wrong-tab bug was JS running
  in a NON-matching tab, which `require_match=True` still prevents. A stable tab-id selector
  (Codex O4) would be a new CLI feature, out of scope for a leak fix. `_strip_query` stays
  as it is — it is correct for `open -r`.

## Steps

- [ ] Add `_tab_hint(url: str) -> str` next to `_strip_query` (`bin/browser.py:~2058`)
      implementing the origin-only rules above (`urllib.parse.urlsplit`; the module already
      imports `urllib.error`/`urllib.request`): hostname present → `scheme://host[:port]`
      (IPv6 re-bracketed); empty → `(empty)`; literal `about:blank` → as-is; no hostname →
      `<scheme>:…`; `ValueError` from `urlsplit`/`.port` → `<unparseable url>`. Docstring
      names tp#337, says why the path is withheld and that hostnames are not promised secret.
- [ ] Rewrite the no-match branch of `cmd_eval` (`bin/browser.py:2096-2105`): hints from
      `_tab_hint`; deduplicate all hints in first-appearance order with a `×N` suffix where
      N > 1; then cap at 8 unique hints and append `… (+N more origins)` for the omitted
      unique ones; keep the `No tab matching … — nothing evaluated. Open one first:
      browser.py open <url>. Open tabs: …` wording; NO pointer to `status`. Replace the
      "Listed without query/fragment" comment with one stating the origin-only rule and the
      dedup-then-cap order.
- [ ] Tests in `tests/test_tab_selection.py` (module docstring: add the third pinned failure
      mode): a `_tab_hint` table — path+query+fragment, `user:pw@host:8443`,
      `http://[::1]:8080/p`, `data:`, `blob:`, `file:`, `javascript:`, `about:blank`,
      `chrome://newtab/`, empty string, scheme-only (`https:`), malformed IPv6
      (`http://[::1/x`), invalid ports (`http://h:99999/`, `http://h:abc/`), a URL with a
      control character — asserting for the malformed/empty rows that no input byte reaches
      the output; an end-to-end `cmd_eval` no-match test with `_connect` monkeypatched to the
      stub browser (the reproduction above, plus a userinfo tab, a `blob:` tab and one
      malformed-port tab) asserting via `capsys` that `SECRET-IN-PATH`, `HIDDEN`,
      `secret-body`, `user:pw` and `99999` are absent from stdout AND stderr, that
      `https://example.test` and `https://app.slack.com` are present, that the word `status`
      is absent, and that the exit code is 1 with no traceback; a dedup/cap test — 12 tabs
      over 10 origins with repeats at positions 1, 9 and 11 → 8 listed with the right `×N`
      counts and `(+2 more origins)`.
- [ ] `README.md:75-76`: one clause — the error names the open tabs by origin only (no
      path, query or fragment). No mention of `status`.
- [ ] Lint, tests and gates green: `ruff format bin/ tests/ && ruff check bin/ tests/ &&
      mypy bin/browser.py && pylint bin/browser.py`, `python3 -m pytest tests/ -q`,
      `pre-commit run --all-files` (gitleaks — if a fixture trips it, rename the fixture,
      never allowlist), `bin/browser.py -h` and `bin/browser.py eval -h` exit 0; commit with
      `ai.py push -m "fix(eval): name open tabs by origin only in the --url no-match error (tp#337)" bin/browser.py tests/test_tab_selection.py README.md PLAN_eval-url-with-no-match-writes-every-open-tab-s-url.md`.

## Verification

```commands
cd ~/obsidian/42-Git/home/browser-login
# 1. The reproduction from Context now prints origins only (stub browser, live browser untouched)
uv run --quiet python - <<'PY'
import sys; sys.path.insert(0, "tests")
import test_tab_selection as t
class _PW:
    def stop(self): pass
class _Br(t._Browser):
    def close(self): pass
br = _Br(["https://user:pw@example.test/reset/SECRET-IN-PATH?code=HIDDEN",
          "data:text/html,<b>secret-body</b>#frag", "http://h:99999/", "",
          "https://app.slack.com/client/T1/C1", "https://app.slack.com/client/T1/C2"])
t.browser._connect = lambda port: (_PW(), br)
sys.exit(t.browser.cmd_eval(9222, "1", "epflch.sharepoint.com"))
PY
# expected on stderr, exit 1, no traceback:
#   … Open tabs: https://example.test, data:…, <unparseable url>, (empty), https://app.slack.com ×2
# and none of SECRET-IN-PATH / HIDDEN / secret-body / user:pw / 99999 / the word "status"
# 2. Regression tests, lint, gates
python3 -m pytest tests/test_tab_selection.py -q
ruff format --check bin/ tests/ && ruff check bin/ tests/ && mypy bin/browser.py && pylint bin/browser.py
pre-commit run --all-files
bin/browser.py -h >/dev/null && bin/browser.py eval -h >/dev/null && echo help-ok
# 3. Matching itself is untouched: a path substring still selects the tab (stub)
uv run --quiet python -c 'import sys; sys.path.insert(0,"tests"); import test_tab_selection as t; _c,p=t.browser._pick_page(t._Browser(["https://x.test/sites/foo/a"]),"/sites/foo",require_match=True); assert p and p.url.endswith("/a"); print("match-ok")'
```
