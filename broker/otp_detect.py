"""Generic second-factor (TOTP) input detection for the login recipes.

``recipes.OTP_SELECTOR`` catches the well-tagged fields (``autocomplete=
one-time-code``, ``name*=otp``, ``#otp``). Everything else is judged here:
the page describes each visible text-like input (``OTP_DESCRIBE_JS``) and the
pure function ``otp_field_like`` decides — so the rules are testable without a
browser. Nothing read here is a secret (attributes, labels, nearby text).
A code split into one-digit boxes is described as a group
(``SPLIT_OTP_DESCRIBE_JS``) and judged by ``split_otp_group_like``.
"""

from __future__ import annotations

import re
from typing import Any

# Second-factor inputs ``recipes.OTP_SELECTOR`` misses (Infomaniak, verified
# from its login bundle 2026-10-07: ``<input type=tel name=number
# pattern=[0-9]* maxlength=6 placeholder=000000 autocomplete=off>`` under an
# <h3> "OTP connection code"). Candidates are visible text-like inputs; each is
# described in the page (``OTP_DESCRIBE_JS``) and judged by ``otp_field_like``.
OTP_CANDIDATE_SELECTOR = (
    "input:not([type]), input[type=text], input[type=tel], input[type=number]"
)
OTP_WORD_RE = re.compile(
    r"\b(?:otp|totp|2fa|mfa|one[\s-]?time|two[\s-]?factor|multi[\s-]?factor"
    r"|authenticat\w*|verification|security\s+code|connection\s+code"
    r"|einmal\w*|best[aä]tigungscode|sicherheitscode|code\s+de\s+connexion"
    r"|code\s+de\s+v[eé]rification|code\s+d.authentification)\b",
    re.IGNORECASE,
)
CODE_WORD_RE = re.compile(r"\b(?:code|tan|pin|token)\b", re.IGNORECASE)
# A TOTP never goes into these: other second factors (SMS / e-mail codes,
# backup codes) and ordinary numeric form fields.
OTP_NEGATIVE_RE = re.compile(
    r"\b(?:sms|e-?mail|text\s+message|backup|recovery|secours|wiederherstell\w*"
    r"|postal|post\s*code|zip|plz|npa|promo\w*|coupon|voucher|gutschein"
    r"|discount|rabatt|captcha|iban|card)\b",
    re.IGNORECASE,
)
_DIGITS_PLACEHOLDER_RE = re.compile(r"^[\d\s.\-_•·]*$")

# Attributes and nearby text of an OTP candidate (labels are not secrets).
# ``context``: the closest ancestor (<= 10 levels) with text beyond its own
# buttons/links — Infomaniak's <h3> label sits beside the input, not in a <label>.
OTP_DESCRIBE_JS = """(e, userSel) => {
  const a = n => (e.getAttribute(n) || '');
  const own = [...(e.labels || [])].map(l => l.innerText || '');
  for (const id of a('aria-labelledby').split(/\\s+/).filter(Boolean)) {
    const l = document.getElementById(id);
    if (l) own.push(l.innerText || '');
  }
  const clean = t => t.replace(/\\s+/g, '');
  let context = '';
  let n = e.parentElement;
  for (let i = 0; n && i < 10; i++, n = n.parentElement) {
    const text = n.innerText || '';
    const btn = [...n.querySelectorAll('button,a,[role=button]')]
        .map(b => b.innerText || '').join('');
    if (clean(text).length > clean(btn).length) { context = text.slice(0, 300); break; }
  }
  return {type: a('type').toLowerCase(), name: a('name'), id: e.id || '',
          autocomplete: a('autocomplete').toLowerCase(),
          inputmode: a('inputmode').toLowerCase(), pattern: a('pattern'),
          maxlength: e.maxLength, placeholder: a('placeholder'),
          aria_label: a('aria-label'), title: a('title'),
          labels: own.join(' '), context: context,
          username: e.matches(userSel)};
}"""


def _numeric_code_shape(desc: dict[str, Any]) -> tuple[bool, bool]:
    """(numeric 6–8 digit shape, all-digit placeholder such as ``000000``)."""
    placeholder = str(desc.get("placeholder") or "")
    digits = sum(c.isdigit() for c in placeholder)
    digit_placeholder = 6 <= digits <= 8 and bool(
        _DIGITS_PLACEHOLDER_RE.match(placeholder)
    )
    try:
        maxlength = int(desc.get("maxlength") or -1)
    except (TypeError, ValueError):
        maxlength = -1
    numeric = _numeric_input(desc)
    return numeric and (6 <= maxlength <= 8 or digit_placeholder), digit_placeholder


def _numeric_input(desc: dict[str, Any]) -> bool:
    """The input takes digits: ``type`` tel/number, a numeric ``inputmode``
    or a digit ``pattern``."""
    pattern = str(desc.get("pattern") or "")
    return (
        str(desc.get("type") or "") in ("tel", "number")
        or str(desc.get("inputmode") or "") in ("numeric", "decimal")
        or "0-9" in pattern
        or "\\d" in pattern
    )


def _words(descs: list[dict[str, Any]], context: str) -> str:
    """The attribute / label words of `descs` plus `context`, camelCase and
    snake_case split (name/id like "otp_code" / "mfaToken": word boundaries
    need separators)."""
    words = " ".join(
        str(desc.get(k) or "")
        for desc in descs
        for k in ("name", "id", "placeholder", "aria_label", "title", "labels")
    )
    words += " " + context
    return re.sub(r"([a-z])([A-Z])", r"\1 \2", words).replace("_", " ")


def otp_field_like(desc: dict[str, Any]) -> bool:
    """True iff an input described by ``OTP_DESCRIBE_JS`` is a TOTP code field.

    Never a username field or a non-text input. ``autocomplete=one-time-code``
    always is. Otherwise nothing that names another factor or an ordinary
    numeric field (``OTP_NEGATIVE_RE``), and then either an OTP word in the
    field's own attributes / label / context, or a numeric 6–8 digit shape
    (inputmode/type/pattern + maxlength or an all-digit placeholder such as
    ``000000``) together with a "code" word or that placeholder.
    """
    kind = str(desc.get("type") or "text")
    tokens = set(str(desc.get("autocomplete") or "").split())
    if desc.get("username") or kind not in ("text", "tel", "number"):
        return False
    if "one-time-code" in tokens:
        return True
    words = _words([desc], str(desc.get("context") or ""))
    if tokens & {"username", "email", "tel", "current-password"} or (
        OTP_NEGATIVE_RE.search(words)
    ):
        return False
    shape, digit_placeholder = _numeric_code_shape(desc)
    return bool(OTP_WORD_RE.search(words)) or (
        shape and (digit_placeholder or bool(CODE_WORD_RE.search(words)))
    )


# Split one-time-code boxes (CSCS Keycloak theme, 2026-11-03: six one-digit
# boxes under "One-Time Code", then "Verify Code"). A group: the visible,
# editable, non-password ``maxLength == 1`` inputs that share their form or,
# without one, their ancestor four levels up. Shared JS pieces (function
# sources, spliced into the page scripts here and in ``recipes``):
# ``SPLIT_OTP_ROOT_JS`` (box -> that ancestor) and ``SPLIT_OTP_HIDDEN_JS``
# ((form, root) -> the hidden input whose name looks like a code: in the form,
# without one in the nearest form around the root; else null).
SPLIT_OTP_ROOT_JS = """e => {
  let n = e;
  for (let k = 0; k < 4 && n.parentElement && n.parentElement !== document.body; k++) {
    n = n.parentElement;
  }
  return n;
}"""
SPLIT_OTP_HIDDEN_JS = """(form, root) => {
  let f = form;
  for (let n = root; !f && n; n = n.parentElement) f = n.querySelector('form');
  if (!f) return null;
  return [...f.elements].find(h => (h.type || '').toLowerCase() === 'hidden'
      && /otp|totp|code/i.test(h.name || '')) || null;
}"""

# The candidate groups, value-free, as a list: each member described like
# ``OTP_DESCRIBE_JS`` plus ``in_form``, in DOM order; ``indexes`` are the
# members' positions in ``document.querySelectorAll('input')`` (``total``
# inputs then), ``context`` is the first member's, ``hidden_code`` whether
# ``SPLIT_OTP_HIDDEN_JS`` finds an input (never its value).
SPLIT_OTP_DESCRIBE_JS = (
    """(userSel) => {
  const describe = """
    + OTP_DESCRIBE_JS
    + """;
  const rootOf = """
    + SPLIT_OTP_ROOT_JS
    + """;
  const hiddenOf = """
    + SPLIT_OTP_HIDDEN_JS
    + """;
  const vis = e => !!(e.offsetWidth || e.offsetHeight || e.getClientRects().length);
  const all = [...document.querySelectorAll('input')];
  const groups = new Map();
  all.forEach((e, i) => {
    const t = (e.getAttribute('type') || 'text').toLowerCase();
    if (t === 'hidden' || t === 'password' || e.maxLength !== 1) return;
    if (!vis(e) || e.disabled || e.readOnly) return;
    const key = e.form || rootOf(e);
    if (!groups.has(key)) groups.set(key, {form: e.form || null, root: rootOf(e), boxes: [], indexes: []});
    const g = groups.get(key);
    g.boxes.push(e);
    g.indexes.push(i);
  });
  return [...groups.values()].filter(g => g.boxes.length > 1).map(g => {
    const members = g.boxes.map(e => Object.assign(describe(e, userSel), {in_form: !!e.form}));
    return {members: members, indexes: g.indexes, total: all.length,
            in_form: !!g.form, context: members[0].context,
            hidden_code: !!hiddenOf(g.form, g.root)};
  });
}"""
)

SPLIT_OTP_MIN_BOXES = 4
SPLIT_OTP_MAX_BOXES = 8


def _one_digit_box(desc: Any) -> bool:
    """A described input that can be one box of a split code: a ``text`` /
    ``tel`` / ``number`` input with ``maxlength == 1``, not a username field."""
    if not isinstance(desc, dict) or desc.get("username"):
        return False
    if str(desc.get("type") or "text") not in ("text", "tel", "number"):
        return False
    try:
        return int(desc.get("maxlength") or -1) == 1
    except (TypeError, ValueError):
        return False


def split_otp_group_like(group: dict[str, Any]) -> bool:
    """True iff a ``SPLIT_OTP_DESCRIBE_JS`` group is one TOTP code split into
    one-digit boxes.

    4 to 8 members, each a ``text``/``tel``/``number`` input with
    ``maxlength == 1`` and none a username field; no ``OTP_NEGATIVE_RE`` word
    (sms, e-mail, backup, …) in the members' attributes / labels or the
    group's context; then ``autocomplete=one-time-code`` on some member, an
    ``OTP_WORD_RE`` word, or every member numeric (inputmode/type/pattern)
    together with a ``CODE_WORD_RE`` word. A single code field (no siblings,
    ``maxlength`` other than 1) never is one."""
    members = group.get("members") if isinstance(group, dict) else None
    if not isinstance(members, list) or not (
        SPLIT_OTP_MIN_BOXES <= len(members) <= SPLIT_OTP_MAX_BOXES
        and all(_one_digit_box(m) for m in members)
    ):
        return False
    words = _words(members, str(group.get("context") or ""))
    if OTP_NEGATIVE_RE.search(words):
        return False
    tagged = any(
        "one-time-code" in str(m.get("autocomplete") or "").split() for m in members
    )
    numeric_code = all(_numeric_input(m) for m in members) and bool(
        CODE_WORD_RE.search(words)
    )
    return tagged or bool(OTP_WORD_RE.search(words)) or numeric_code
