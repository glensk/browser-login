"""Login-form vs registration-form detection for the login recipes.

Some sites put a REGISTER form on the login page, before the login form
(WeLib ``/account``, 2026-10-08: ``reg_email`` / ``nickname`` /
``reg_password`` first, then the login form with ``input#email`` and
``input#password autocomplete=current-password``). Taking "the first visible
password field" typed the secret into the registration form. The page
describes each candidate input (``FIELD_DESCRIBE_JS``) and the pure functions
here decide — so the rules are testable without a browser. Nothing read here
is a secret (attributes and counts only, never a value).
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from typing import Any

# Attributes of an input and of the <form> around it. ``form_passwords``:
# visible password inputs in that form; ``form_confirm``: a visible input in
# it named like a password confirmation.
FIELD_DESCRIBE_JS = """e => {
  const a = (el, n) => ((el && el.getAttribute(n)) || '');
  const vis = el => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
  const f = e.form;
  const inputs = f ? Array.from(f.querySelectorAll('input')).filter(vis) : [];
  const confirm = /confirm|repeat|retype|again|password2|passwd2|pwd2|verify/i;
  return {
    type: a(e, 'type').toLowerCase(), name: a(e, 'name'), id: e.id || '',
    autocomplete: a(e, 'autocomplete').toLowerCase(),
    form: !!f, form_action: a(f, 'action'), form_id: (f && f.id) || '',
    form_class: a(f, 'class'), form_name: a(f, 'name'),
    form_passwords: inputs.filter(i => (i.type || '').toLowerCase() === 'password').length,
    form_confirm: inputs.some(i => i !== e && confirm.test(a(i, 'name') + ' ' + (i.id || ''))),
  };
}"""

# Effective action of the form around an input: the default submit button's
# `formaction` overrides the form's `action`. `null` = no form.
FORM_ACTION_JS = """e => {
  const f = e.form;
  if (!f) return {form: false, action: null};
  const b = f.querySelector('button[type=submit], input[type=submit], button:not([type])');
  return {form: true, action: (b && b.getAttribute('formaction')) || f.getAttribute('action')};
}"""

# The visible submit button of the form around an input (first in DOM order).
SUBMIT_BUTTON_JS = """e => {
  const scope = e.form || document;
  const vis = el => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
  return Array.from(scope.querySelectorAll(
      'button[type=submit], input[type=submit], button:not([type])')).find(vis) || null;
}"""

# Username field for the chosen password input: an autocomplete=username input
# in the SAME form (no form: the document), else the nearest preceding visible
# text/email input there — never one of a registration form beside it.
# Fallback when that finds nothing (Home Assistant, 2026-10-08: each input sits
# in its own web component's shadow root, so it has no form and
# document.querySelectorAll never reaches it): the same two rules over every
# input of the password's frame, open shadow roots included, skipping inputs
# that belong to ANOTHER form than the password's (a register or search form).
USERNAME_JS = """pw => {
  const vis = el => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
  const isUser = i => (i.getAttribute('autocomplete') || '').split(/\\s+/)
      .includes('username');
  const isText = i => ['text', 'email'].includes(
      (i.getAttribute('type') || 'text').toLowerCase());
  const pick = inputs => {
    const tagged = inputs.find(i => i !== pw && isUser(i) && vis(i));
    if (tagged) return tagged;
    let best = null;
    for (const i of inputs) {
      if (i === pw) break;
      if (isText(i) && vis(i)) best = i;
    }
    return best;
  };
  const scope = pw.form || document;
  const found = pick(Array.from(scope.querySelectorAll('input')));
  if (found) return found;
  const deep = [];
  const walk = root => {
    for (const el of root.querySelectorAll('*')) {
      if (el.tagName === 'INPUT') deep.push(el);
      if (el.shadowRoot) walk(el.shadowRoot);
    }
  };
  walk(pw.ownerDocument);
  return pick(deep.filter(i => !i.form || i.form === pw.form));
}"""


# Words that mark a registration form / field once separators and camelCase
# are normalised away ("signUpForm" -> "sign up form" -> "signupform").
_REG_JOINED_RE = re.compile(r"register|registration|signup|createaccount|newpassword")
# Whole tokens that mark a registration form ("reg-form", "/account/register").
_REG_FORM_TOKENS = frozenset({"reg", "register", "registration", "signup"})
# ... and a registration field ("reg_password", "new-password").
_REG_FIELD_TOKENS = _REG_FORM_TOKENS | {"new"}
# A form that ALSO names the login ("login-or-signup") is not judged by words.
_LOGIN_JOINED_RE = re.compile(r"login|signin|logon")
_CAMEL_RE = re.compile(r"([a-z0-9])([A-Z])")
_SPLIT_RE = re.compile(r"[^a-z0-9]+")


def _tokens(text: str) -> list[str]:
    return [t for t in _SPLIT_RE.split(_CAMEL_RE.sub(r"\1 \2", text).lower()) if t]


def _reg_words(texts: Sequence[str], tokens: frozenset[str]) -> bool:
    """True iff any text names a registration (whole token or joined form)."""
    for text in texts:
        parts = _tokens(text or "")
        if tokens.intersection(parts) or _REG_JOINED_RE.search("".join(parts)):
            return True
    return False


def _login_words(texts: Sequence[str]) -> bool:
    return any(_LOGIN_JOINED_RE.search("".join(_tokens(t or ""))) for t in texts)


def _autocomplete(desc: dict[str, Any]) -> list[str]:
    return str(desc.get("autocomplete") or "").lower().split()


def registration_form_like(desc: dict[str, Any]) -> bool:
    """The input's <form> looks like a registration form: its action / id /
    class / name says register or sign-up (and not also log-in), or it holds two visible password
    fields or a password-confirmation field. No form: False."""
    if not desc.get("form"):
        return False
    texts = [
        str(desc.get(k) or "")
        for k in ("form_action", "form_id", "form_class", "form_name")
    ]
    if _reg_words(texts, _REG_FORM_TOKENS) and not _login_words(texts):
        return True
    try:
        passwords = int(desc.get("form_passwords") or 0)
    except (TypeError, ValueError):
        passwords = 0
    return passwords >= 2 or bool(desc.get("form_confirm"))


def registration_field_like(desc: dict[str, Any]) -> bool:
    """The input looks like a registration field: ``autocomplete=new-password``,
    a name / id naming a registration (``reg_password``, ``signupEmail``,
    ``new-password``), or it sits in a registration-like form."""
    if "new-password" in _autocomplete(desc):
        return True
    names = [str(desc.get("name") or ""), str(desc.get("id") or "")]
    if _reg_words(names, _REG_FIELD_TOKENS):
        return True
    return registration_form_like(desc)


def current_password(desc: dict[str, Any]) -> bool:
    """True iff the input declares ``autocomplete=current-password``."""
    return "current-password" in _autocomplete(desc)


def pick_login_password(descs: Sequence[dict[str, Any]]) -> int | None:
    """Index of the login password among visible password inputs (DOM order).

    The first ``autocomplete=current-password`` one wins; else the first that
    does not look like a registration field; else None (only registration
    fields are showing — never type the login secret into one)."""
    for i, desc in enumerate(descs):
        if current_password(desc):
            return i
    for i, desc in enumerate(descs):
        if not registration_field_like(desc):
            return i
    return None


def pick_login_username(descs: Sequence[dict[str, Any]]) -> int | None:
    """Index of the first visible username candidate that is not a
    registration field, or None."""
    for i, desc in enumerate(descs):
        if not registration_field_like(desc):
            return i
    return None


def _visible_all(page: Any, selector: str) -> list[Any]:
    """Every visible element matching `selector`, in DOM order."""
    try:
        return [el for el in page.query_selector_all(selector) if el.is_visible()]
    except Exception:  # pylint: disable=broad-exception-caught
        return []


def pick_visible(
    page: Any,
    selector: str,
    pick: Callable[[Sequence[dict[str, Any]]], int | None],
) -> Any:
    """The visible `selector` element that `pick` chooses from the
    ``FIELD_DESCRIBE_JS`` descriptors, or None (none visible, none chosen, or a
    field that could not be described — e.g. detached by a re-render)."""
    fields = _visible_all(page, selector)
    if not fields:
        return None
    descs: list[dict[str, Any]] = []
    try:
        for el in fields:
            desc = el.evaluate(FIELD_DESCRIBE_JS)
            if not isinstance(desc, dict):
                return None
            descs.append(desc)
    except Exception:  # pylint: disable=broad-exception-caught
        return None
    idx = pick(descs)
    return None if idx is None else fields[idx]
