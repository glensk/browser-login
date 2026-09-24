# tp#498 — browser.py `_keychain_get` returns hex for non-ASCII secrets

## Session

Resume: `c --resume 380d9f78-0e44-4016-a76e-f36ea603a904`

## Context

Classification: **DEFECT** — a stored secret is read back in a different form than it was written.

**Symptom.** `_keychain_get` (`bin/browser.py:3145-3176`) runs
`security find-generic-password -a <acct> -s <svc> -w` and returns stdout minus the newline. For
a value that `security` treats as non-printable, `-w` prints its UTF-8 bytes as lowercase hex.
A CSCS or biopol password containing `ä` would be typed into the login form as hex, so the
login fails, and repeated failures risk a lockout. `_keychain_write`
(`bin/browser.py:3219-3254`) hides the problem: its read-back check *expects* the hex form for
non-ASCII values (`bin/browser.py:3251-3254`). The tests encode the same wrong behaviour
(`tests/test_credentials.py:212`, `tests/test_keychain_live.py:643-644`).

**Reproduced 2026-09-24** in a throw-away keychain in the plan session. The keychain was created
with `security create-keychain` under a `mktemp -d` directory, named on every call, never on the
search list, and deleted afterwards. Only dummy values were used. In this plan `PW:` stands for the literal lowercase `password` label plus colon and space that `-g` prints (abbreviated so the repo's git-secrets hook does not flag the example lines).

| stored value           | `-w` stdout  | `-g` stderr                             |
| ---------------------- | ------------ | --------------------------------------- |
| `päss`                 | `70c3a47373` | `PW: 0x70C3A47373  "p\303\244ss"` |
| `cafe`                 | `cafe`       | `PW: "cafe"`                      |
| `c3a4`                 | `c3a4`       | `PW: "c3a4"`                      |
| `a"b`                  | `a"b`        | `PW: "a"b"`                       |
| `a\b`                  | `a\b`        | `PW: 0x615C62  "a\134b"`          |
| `sp␠` (␠ = trailing space) | `sp␠` | `PW: "sp␠"`                       |
| `t<TAB>b`              | `740962`     | `PW: 0x740962  "t\011b"`          |
| `ä"x`                  | `c3a42278`   | `PW: 0xC3A42278  "\303\244"x"`    |
| `0x41`                 | `0x41`       | `PW: "0x41"`                      |

The Codex debate added three more shapes. They come from Apple's formatter,
[keychain_utilities.c L747-807](https://github.com/apple-oss-distributions/Security/blob/main/SecurityTool/macOS/keychain_utilities.c#L747-L807),
and were not measured here:

- **Hex-only:** when no byte is printable ASCII other than `\`, the line is
  `PW: 0x<UPPER HEX>␠` with a trailing space (␠) and no quoted part. Examples: `ä` →
  `PW: 0xC3A4␠`, `\` → `PW: 0x5C␠`.
- **Empty:** an empty value gives `password:` with nothing after the prefix.

**Root cause (confidence: high, measured).** `-w` switches between two encodings and gives no
sign of which one it used. The two cannot be told apart afterwards: `cafe` and `c3a4` are valid
ASCII passwords that look exactly like hex output, and `c3a4` would decode to `ä`. So guessing
from `-w` output would corrupt real passwords. `-g` does label the form, on stderr:

- A value in quotes is printed exactly as stored. An inner `"` is not escaped, so the value is
  the text between the first and the last quote.
- Otherwise the line starts with `0x` and uppercase hex, optionally followed by a rendering we
  ignore.

The two flags also judge printability differently: `-w` prints `a\b` as-is, `-g` prints it as
hex. The plan therefore relies only on the label `-g` prints, never on either flag's printability
rule.

**Alternatives rejected.**

- *Decoding `-w` output by guessing:* ambiguous, as shown above. It would corrupt all-hex
  ASCII passwords.
- *Security framework through `ctypes` (`SecItemCopyMatching`):* the items' access list trusts
  only `/usr/bin/security` (`-T /usr/bin/security`, `bin/browser.py:3198`). A read from the
  Python process would open an access prompt, which breaks the prompt-free promise
  (`bin/browser.py:3148-3150`). It would also need a lot of CoreFoundation glue code.
- *Refusing non-ASCII when writing* (the biopol-wifi approach, `sdsc/biopol-wifi/README.md:46-47`):
  it hides the bug and leaves values stored today unreadable. A site can also require a real
  non-ASCII password.

**Decisions recorded** (`tp question -d`, non-blocking):

- Read with `-g` and parse the labelled stderr line (assumption 05d809).
- Invalid UTF-8 in the hex, or output that cannot be parsed: return `None` and warn, naming the
  service label only (43a642).
- The biopol-wifi port is out of scope (2e0e5c).

**Constraints.**

- Only the `security` read path changes. Secrets never go on argv, so tp#489 stays fixed.
- No new dependency.
- The read stays prompt-free: it still goes through `/usr/bin/security`.
- The secret must never be printed or logged in any form. That includes its hex and its octal
  rendering, and the raw stderr of the `-g` call.
- Tests mock `security` completely. The only live execution is the existing opt-in live test,
  which runs through the tp#506 router against its own temp keychain. The work session runs no
  other keychain experiment.

**Blocked on Albert: no.** No step touches real keychain items.

**Verification strictness.** The block runs pytest, mypy, pylint and `bin/browser.py -h`, all of
which execute repo code, so it is not strict-eligible. The allowlisted read-only checks come
first. The one live line uses only the throw-away keychain from the tp#506 fixture.

## Steps

- [ ] 1. Add `_kc_parse_password(stderr: str) -> str | None` next to `_keychain_get`.
      - Take the **last** line of `stderr` that starts with `password:`. Strip only its
        trailing `\n` (and `\r`), and look at the text after the prefix.
      - **Hex form:** the text starts with `0x`. Match `^0x([0-9A-Fa-f]*)(?: .*)?$` and ignore
        everything after the first space (a quoted rendering, or the hex-only trailing space).
        Then run `bytes.fromhex(payload).decode("utf-8")` in strict mode. An odd-length payload,
        invalid UTF-8 or an empty payload gives `None`.
      - **Quoted form:** the text starts with `"`. It must end with `"` and be at least 2 chars
        long. Return `text[1:-1]` verbatim, with no whitespace trimming. An empty result gives
        `None`.
      - **Anything else** gives `None`. That covers an empty value (nothing after the prefix,
        or only spaces), a missing closing quote, and no `PW:` line at all.
      - The function never logs.
- [ ] 2. Switch `_keychain_get` to `find-generic-password -a <acct> -s <svc> -g`, without `-w`.
      - Keep `capture_output=True`, `text=True`, `timeout=15` and `check=False`, and add
        `errors="replace"`.
      - Discard stdout. It holds only the attribute dump: account, service and description.
      - On exit 0, return `_kc_parse_password(r.stderr)`.
      - If the exit code is 0 but the parser returns `None`, print exactly one warning line to
        stderr: `Keychain item <service> has an unreadable value — ignoring it.` It names the
        service label only. Then return `None`, so `_keychain_creds` keeps its "missing item →
        1Password fallback".
      - A non-zero exit, `OSError` or `TimeoutExpired` returns `None` silently. The captured
        stderr is never printed.
      - Update the docstring to explain why `-g` is used: `-w` is ambiguous (tp#498).
- [ ] 3. In `_keychain_write` (`bin/browser.py:3219-3254`), the read-back must equal `value`
      exactly: `_keychain_get(service) == value`. Delete the `printable_ascii`/hex branch.
      Rewrite the docstring paragraph that calls the read-back "a consistency check … not proof
      of byte-exact storage (tp#498)": it is now a byte-exact round-trip check.
- [ ] 4. Add a test helper `_security_g(value: str) -> str` that renders a value exactly like
      Apple's formatter, covering all three branches:
      - **Quoted:** every byte is printable ASCII and not `\` → `PW: "<value>"`.
      - **Mixed:** at least one byte is printable and not `\` →
        `PW: 0x<UPPER>  "<octal-escaped rendering>"`.
      - **Hex-only:** no such byte → `PW: 0x<UPPER>␠`, with the trailing space (␠).
      - Put the helper in `tests/conftest.py` so every test file can use it.
- [ ] 5. Move **every** mocked keychain read to the `-g` stderr form:
      - `tests/test_credentials.py`: every `find-generic-password` answer moves from stdout to
        stderr through `_security_g`. That includes the reader tests at lines 83-104 and the
        write/batch reads at lines 108, 121, 206 and 234. The reader test asserts that argv
        contains `-g` and not `-w`.
      - Replace the hex-expectation test at line 212 with three tests:
        (a) writing `päss` succeeds when the read-back is the mixed hex form;
        (b) writing `päss` returns `"mismatch"` when the read-back is the quoted literal
        `PW: "70c3a47373"`;
        (c) writing the all-hex ASCII password `70c3a47373` succeeds with a quoted read-back.
      - `tests/test_keychain_batch.py:83-86` (`FakeKeychain`): answer on stderr through
        `_security_g`.
      - `tests/test_keychain_live.py`:
        - The router shape at line 210 changes from `…, "-w"]` to `…, "-g"]`.
        - `_Recorder` (line 322) answers through `_security_g`.
        - Update the offline router tests that name `-w` (lines 394-449). A `-w` read is now a
          refused shape.
        - The live assertion at lines 643-644 becomes `got == value` for every case.
        - Add to `CASES`: `"hexlike": "cafe"`, `"hexutf8": "c3a4"`, `"hexprefix": "0x41"`,
          `"quote_end": 'ab"'`, `"utf8_quote": 'ä"x'`, `"only_utf8": "ä"`, `"emoji": "😀"`,
          `"lone_backslash": "\\"`. Keep the existing cases.
- [ ] 6. Add unit tests for `_kc_parse_password`, using the literal stderr fixtures from the
      Context table and the formatter shapes. Cover:
      - the hex-only form with its trailing space (`PW: 0xC3A4␠` → `ä`, `PW: 0x5C␠`
        → `\`);
      - the empty form `password:` → `None`;
      - several `PW:` lines (the last one wins), and stray other lines;
      - an uppercase and a lowercase hex payload;
      - an odd-length payload, `0xFF` (invalid UTF-8) and a missing closing quote → `None`;
      - a quoted value with leading and trailing spaces, kept verbatim.
- [ ] 7. Add secrecy tests with `capsys`:
      - Feed an **unparsable** exit-0 stderr (for example `PW: 0x70C3A47373Z`) that
        contains the dummy secret in plain, hex and octal-escaped form. Assert that stdout is
        empty and that stderr is exactly the one permitted warning line, with none of the three
        renderings in it.
      - Repeat for a non-zero exit with captured stderr, and for a `TimeoutExpired` carrying
        `output`/`stderr`. Both must print nothing.
- [ ] 8. `README.md` § Security, around lines 292-303: add one sentence. The keychain read uses
      `security`'s labelled attribute dump, so a non-ASCII or hex-looking password round-trips
      exactly.
- [ ] 9. Run every `## Verification` line in the foreground. That includes the single opt-in
      live line, run once against the temp keychain with no loops. Fix every lint and type
      finding in the touched files. Commit with
      `ai.py push -m "fix(keychain): read secrets via labelled dump, decode hex exactly" bin/browser.py tests/conftest.py tests/test_credentials.py tests/test_keychain_batch.py tests/test_keychain_live.py README.md PLAN_browser-py-keychain-get-returns-hex-for-non-ascii.md`.

NOTE: `sdsc/biopol-wifi/biopol-wifi.py:365-389` has the same `-w` reader. Its own write path
refuses non-ASCII, so its own writes cannot trigger the bug. But `browser.py store-creds
biopolwifi` writes the **same** items without that refusal. The work session lists this under
`### Observations` (defect) for the overseer. It is not fixed here: it is another repo with a
different behaviour contract.

NOTE: after this lands, Albert re-runs `browser.py store-creds cscs` / `store-creds biopolwifi`
himself if he wants the new byte-exact read-back to check his real items. No session touches
the login keychain.

## Verification

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff check bin/ tests/
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff format --check bin/ tests/
cd /Users/albert/obsidian/42-Git/home/browser-login && git diff --no-ext-diff --no-textconv --stat HEAD
cd /Users/albert/obsidian/42-Git/home/browser-login && git log --oneline -5
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run mypy bin/browser.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pylint bin/browser.py tests/conftest.py tests/test_credentials.py tests/test_keychain_batch.py tests/test_keychain_live.py
cd /Users/albert/obsidian/42-Git/home/browser-login && env BROWSER_LIVE_KEYCHAIN=0 uv run pytest -q
cd /Users/albert/obsidian/42-Git/home/browser-login && env BROWSER_LIVE_KEYCHAIN=1 uv run pytest -q tests/test_keychain_live.py
cd /Users/albert/obsidian/42-Git/home/browser-login && bin/browser.py -h
```
