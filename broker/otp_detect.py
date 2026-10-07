"""Generic second-factor (TOTP) input detection for the login recipes.

``recipes.OTP_SELECTOR`` catches the well-tagged fields (``autocomplete=
one-time-code``, ``name*=otp``, ``#otp``). Everything else is judged here:
the page describes each visible text-like input (``OTP_DESCRIBE_JS``) and the
pure function ``otp_field_like`` decides — so the rules are testable without a
browser. Nothing read here is a secret (attributes, labels, nearby text).
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
    pattern = str(desc.get("pattern") or "")
    numeric = (
        str(desc.get("type") or "") in ("tel", "number")
        or str(desc.get("inputmode") or "") in ("numeric", "decimal")
        or "0-9" in pattern
        or "\\d" in pattern
    )
    return numeric and (6 <= maxlength <= 8 or digit_placeholder), digit_placeholder


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
    words = " ".join(
        str(desc.get(k) or "")
        for k in ("name", "id", "placeholder", "aria_label", "title", "labels")
    )
    words += " " + str(desc.get("context") or "")
    # name/id like "otp_code" / "mfaToken": word boundaries need separators
    words = re.sub(r"([a-z])([A-Z])", r"\1 \2", words).replace("_", " ")
    if tokens & {"username", "email", "tel", "current-password"} or (
        OTP_NEGATIVE_RE.search(words)
    ):
        return False
    shape, digit_placeholder = _numeric_code_shape(desc)
    return bool(OTP_WORD_RE.search(words)) or (
        shape and (digit_placeholder or bool(CODE_WORD_RE.search(words)))
    )
