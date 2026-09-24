# Claude magic-link login: sender allow-list, stale-mail exclusion, link↔email binding (tp#490)

## Session

Resume: `c --resume f9bfba63-863d-4040-b5cd-a51b9e9e75dd`

## Context

**Classification: DEFECT** (security — login Cross-Site Request Forgery (CSRF): the shared browser can be signed into an account that is not `ANTHROPIC_LOGIN_EMAIL`).

**Symptom.** `browser.py login anthropic` (full-auto path, `_claude_auto_login`) opens the first magic link it finds in a mail that merely *looks* like a Claude login mail. Two independent holes:

1. **Any sender.** `bin/browser.py:3780` — `_is_claude_login_mail` returns `True` as soon as the subject contains one of `_CLAUDE_SUBJECT_HINTS` ("secure link to Claude.ai", "log in to Claude.ai"), before the sender is looked at. A mail from `attacker@evil.example` carrying the attacker's own `https://claude.ai/magic-link#…` passes; `tests/test_login_mail_match.py:64` (`test_legacy_subject_still_matches`) asserts exactly this with an empty sender.
2. **Stale mail.** `bin/browser.py:3861` — a candidate is skipped only when `ts + 180 < since_ts`, so a link mail from a previous attempt up to 180 s *before* `trigger_ts` (`bin/browser.py:3920`) is accepted; the poll stops at the first hit and opens it. Mostly fail-closed (a consumed/expired link → assisted fallback), but combined with hole 1 an attacker's mail sent shortly before the trigger is also in the window.

**Evidence (reproduced 2026-09-24, himalaya mocked, no real mailbox):**

- `_is_claude_login_mail({"subject": "Please log in to Claude.ai", "from": {"addr": "attacker@evil.example"}})` → `True`; same with the 2026 subject "Your secure link to Claude.ai is here | x" → `True`.
- `_himalaya_latest_login_mail("h", "", ts + 170)` with one `@mail.anthropic.com` envelope dated `ts` → `('INBOX', 'old')` — a mail 170 s older than the trigger is selected.

**Root cause.** (1) the subject short-circuit at `bin/browser.py:3780` ranks the attacker-controlled subject above the sender; (2) the freshness guard is a ±180 s date window (himalaya envelope dates have minute precision, `_himalaya_date_epoch` `%Y-%m-%d %H:%M%z`) instead of "not present before we triggered"; (3) nothing ties the link to the account we asked for — the link's `#<token>:<b64email>` fragment names an account and is never compared to `email`.

**Security model after the fix.**

- **Primary: the sender allow-list** (Albert's assumption c4d0d1: explicit allow-list, default `mail.anthropic.com`, env override, others rejected with a clear message naming the sender). It is meaningful rather than cosmetic because `dig +short TXT _dmarc.mail.anthropic.com` and `_dmarc.anthropic.com` both return `p=reject; sp=reject`: a DMARC-honouring receiver (Gmail, Exchange Online) rejects or junk-folders a forged `From`, and only INBOX + Archive are scanned.
- **Primary: the pre-trigger baseline** — every login mail whose magic link existed before we submitted the form is never opened.
- **Defense in depth only: the fragment-email check** — the link's embedded email must equal `ANTHROPIC_LOGIN_EMAIL`. Whether Anthropic's server binds the token to that email is unverified, so this check alone is not claimed to close the CSRF.
- **Residual risk, stated:** a receiver that ignores DMARC *and* an attacker who forges the fragment email of a token the server does not bind to it; and the unavoidable race between the baseline snapshot and the form submission (a mail arriving in that gap is not in the baseline — the allow-list and fragment check still apply to it). A post-login identity check (claude.ai account API) would close the residual but relies on an undocumented endpoint and needs a logout design for the shared browser → work-session `### Observations` line, not in scope.

**Decisions** (settled by evidence, recorded as non-blocking `tp question -d` assumptions 9eebab, ba5ae7, 10f932, 375b2b; refined by the debate): allow-list format and strict validation; baseline by magic-link digest with fail-closed; fragment-email binding as defense in depth; no DKIM/`Authentication-Results` parsing (provider-specific — Gmail vs EPFL Exchange stamp it differently).

**Alternatives considered.** DKIM via `himalaya message read -H Authentication-Results`: provider-specific trust of the top header → rejected for now. `(sender, subject, date)` envelope fingerprint for the baseline: collides at minute precision and does not identify a message → replaced by the link digest (Codex O2). Tightening the 180 s window alone: minute-precision dates make any window leaky or flaky → kept only as a backstop.

**Confidence:** high on both holes and the fix shape; moderate that the server binds token to the fragment email (hence defense in depth only).

**Blocked on Albert:** no.

**Debate:** Codex `gpt-5.6-sol`, 1 round, judge converged; O1–O8 accepted and folded into the steps below.

**Verification strictness.** The block runs pytest, mypy, pylint and pre-commit (they execute repo code), so it is not strict-eligible; the allowlisted read-only checks come first. All tests mock himalaya, CDP and the clock completely — no real mailbox, keychain or browser profile is touched.

## Steps

- [ ] 1. **Sender allow-list + strict validation.** Add `_ANTHROPIC_LOGIN_MAIL_SENDERS_DEFAULT = ("mail.anthropic.com",)` and `_login_mail_senders() -> tuple[tuple[str, ...], str | None]` (entries, config error) reading `ANTHROPIC_LOGIN_MAIL_SENDERS`: comma-separated, surrounding whitespace stripped, lower-cased; unset or whitespace-only → default. Every non-empty entry is validated structurally: **exact address** = exactly one `@`, non-empty localpart without whitespace, valid domain; **exact domain** = bare or `@`-prefixed valid domain (labels `[a-z0-9-]`, not starting/ending with `-`, at least one dot). Any invalid entry in an explicit override → config error naming the entry (via `_printable`), and auto-login is NOT attempted (step 6). Add `_sender_allowed(addr, allow) -> bool`: exact-address or exact-domain match only — no suffix/subdomain match (`evilmail.anthropic.com`, `mail.anthropic.com.evil`, `x@sub.mail.anthropic.com` are rejected).
- [ ] 2. **Split subject recognition from sender authorization.** `_looks_like_claude_login_mail(env)` = subject-only (a hint in `_CLAUDE_SUBJECT_HINTS`, or `"claude"` and `"link"` in the subject); `_is_claude_login_mail(env, allow=None) -> bool` = looks-like AND `_sender_allowed`. The existing product-mail guard (same domain, non-link subject → rejected) stays.
- [ ] 3. **`_printable(s, limit=120)`**: drops every non-printable character (control chars incl. ESC, CR, LF, and Unicode categories `Cc`/`Cf`) and truncates with `…`; used for every sender, subject or config entry echoed to the terminal.
- [ ] 4. **Candidate listing.** Extract the shared "list one folder → `list[dict]` or diag" subprocess code (currently inline in `_himalaya_latest_login_mail`) into `_himalaya_list_folder(...)`. Replace `_himalaya_latest_login_mail` with `_himalaya_login_mail_candidates(himalaya, email, since_ts, account, diag, rejected_senders) -> list[tuple[str, str]]` returning every eligible `(folder, id)` newest-first (dated before undated, as today; recipient check and the `ts + 180 < since_ts` backstop kept). A login-looking mail from a non-allowed sender is not a candidate and adds `f"{folder}: rejected a Claude login-looking mail from {_printable(sender) or '<no sender>'} — not in ANTHROPIC_LOGIN_MAIL_SENDERS ({', '.join(allow)})"` to `rejected_senders` (de-duplicated, capped at 5). The "no Anthropic login mail" diag prints the allow-list.
- [ ] 5. **Baseline by magic-link digest.** `_himalaya_login_link_baseline(himalaya, account, diag) -> set[str] | None`: list both folders; for every `_looks_like_claude_login_mail` envelope (sender-independent, so a pre-planted forged mail is excluded too) read the body with `himalaya message read --preview` (no seen flag), extract the link with `_MAGIC_LINK_RE`, store `sha256(link).hexdigest()`; a body without a link is ignored; any folder-listing or body-read failure → `None`. `_himalaya_extract_magic_link` gains a `preview: bool = False` parameter (the poll reads with `--preview` too). The digest survives the INBOX→Archive server rule and has no minute-precision collisions; the link itself is never logged.
- [ ] 6. **Auto-login flow with tri-state result.** `_claude_auto_login` returns `"ok"`, `"submitted"` (email form submitted, login not completed) or `"not_submitted"` (nothing was requested). Order: validate the allow-list (config error → print it, `"not_submitted"`); take the baseline (`None` → print the diag lines plus "cannot tell old login mails from new ones — not auto-logging in", `"not_submitted"`); then `trigger_ts`, `_claude_fill_email_and_continue` (failure → `"not_submitted"`). Poll: for each round, walk the candidates newest-first; skip `(folder, id)` / digests already in a per-attempt `rejected` set; read the link; no link → add the envelope key to `rejected`; digest in baseline → add to `rejected`, diag "skipped a login mail that predates this attempt"; `_magic_link_email(link)` ≠ `email` (case-insensitive) or `None` → add to `rejected`, diag "found a login mail ({folder} id {id}) whose link is for a different account — refusing to open it" (never print the link or the foreign email); else open it. The per-round `diag` may be cleared, `rejected_senders` is not — on failure both are printed. `cmd_anthropic_login` (`bin/browser.py:4043-4065`) sets `auto_attempted` only when the result is `"submitted"`, so the assisted path submits the email itself after a `"not_submitted"` (this also fixes the existing case where `_claude_fill_email_and_continue` fails).
- [ ] 7. **`_magic_link_email(link) -> str | None`**: parse only a `_MAGIC_LINK_RE` full match; take the fragment part after the LAST `:`; decode standard or URL-safe base64 with padding tolerated; UTF-8; must contain exactly one `@`; lower-case; `None` on any error.
- [ ] 8. **Tests** (himalaya via mocked `subprocess.run`, CDP via stub pages, clock via monkeypatched `time.monotonic`/`time.sleep` and `ANTHROPIC_LOGIN_MAIL_TIMEOUT=10` — no real waits):
  - `tests/test_login_mail_match.py`: rewrite `test_legacy_subject_still_matches` to assert **rejection** with an empty and a foreign sender, plus acceptance of the legacy subject from `no-reply-X@mail.anthropic.com`; foreign sender + 2026 subject → not a candidate and its (sanitized) sender appears in `rejected_senders`; a sender with ESC/newline is printed without them; allow-list override cases (address entry, `@domain`, bare domain, mixed valid/invalid → config error, `@`, `a@@b`, internal whitespace, lookalike domains rejected, unset/whitespace-only → default); candidates are newest-first and dated beat undated; `_magic_link_email` decodes `dXNlckBleGFtcGxlLmNvbQ==` → `user@example.com`, URL-safe and unpadded variants, `None` on garbage.
  - Flow tests (`_claude_auto_login` with fake clock): a baseline mail that moved INBOX→Archive with a new id is skipped; a rejected newest candidate (foreign-account link) does not starve a valid second candidate in the same round; a mismatched link never reaches `page.goto`; baseline failure and invalid allow-list → `"not_submitted"` and `_claude_fill_email_and_continue` never called; `cmd_anthropic_login`-level: `"not_submitted"` → the assisted path submits the email, `"submitted"` → it does not; a rejected sender is still in the final printed diagnostics after later rounds.
  - Adjust `tests/test_login_log_and_sites.py:271` (`test_auto_login_reads_the_link_from_the_configured_account`) for the baseline call, the candidate API and the tri-state return (use `email="user@example.com"` to match `LINK`).
- [ ] 9. **Docs.** `.env.example`: add `ANTHROPIC_LOGIN_MAIL_SENDERS` (commented default, grammar, invalid entry disables auto-login, "must be EXPORTED") in the claude.ai section. `README.md:216` (`anthropic` row) and the auto-login description: sender allow-list (DMARC `p=reject` rationale), pre-trigger baseline, link must name `ANTHROPIC_LOGIN_EMAIL` (defense in depth), each rejection falls back to assisted login; stated residual risk.
- [ ] 10. Lint (`ruff format`, `ruff check`, `mypy`, `pylint` per AGENTS.md), run the Verification block, commit via `ai.py push -m "fix(anthropic): allow-list login-mail senders, skip pre-trigger mails, bind link to account" <files>`.

NOTE: the next real `browser.py login anthropic` after this lands is the live confirmation that the genuine Anthropic mail still passes all three checks — Albert's observation, not a box.

## Verification

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff check bin/ tests/
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff format --check bin/ tests/
cd /Users/albert/obsidian/42-Git/home/browser-login && git status --short
cd /Users/albert/obsidian/42-Git/home/browser-login && git log --oneline -5
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests/test_login_mail_match.py tests/test_login_log_and_sites.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run mypy bin/browser.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pylint bin/browser.py
cd /Users/albert/obsidian/42-Git/home/browser-login && pre-commit run --all-files
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run bin/browser.py -h
```
