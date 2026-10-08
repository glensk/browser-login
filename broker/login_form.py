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
# it named like a password confirmation. ``concealed``: the input has a box
# (Playwright calls it visible) but no human can see it — see CONCEALED_JS.
#
# CONCEALED_JS: identifier-first logins that pre-render the password field of
# step 2 hide it from humans without `display: none` (verified 2026-10-08):
# Galaxus (id.digitecgalaxus.ch / id.galaxus.eu) gives it `aria-hidden=true`
# inside an `opacity: 0; height: 0` wrapper, Zoho (accounts.zoho.eu) puts it in
# a `height: 0; overflow: hidden` container. Typing the secret there and
# pressing Enter submits step 1 only. So an input counts as concealed when it
# says `aria-hidden=true` itself, when it or an ancestor has `opacity: 0` /
# `visibility: hidden`, or when an ancestor with `overflow: hidden|clip` that
# clips it leaves no visible area (ancestors that are not its containing
# block do not clip an absolutely / fixed positioned box). Ancestors are
# walked across slots and shadow roots. `overflow: auto|scroll` never counts:
# such a container can be scrolled to the field.
CONCEALED_JS = """e => {
  if ((e.getAttribute('aria-hidden') || '').toLowerCase() === 'true') return true;
  if (e.checkVisibility
      && !e.checkVisibility({opacityProperty: true, visibilityProperty: true})) return true;
  const up = n => n.assignedSlot || n.parentElement
      || (n.getRootNode() instanceof ShadowRoot ? n.getRootNode().host : null);
  const clipping = v => v === 'hidden' || v === 'clip';
  const r = e.getBoundingClientRect();
  let left = r.left, top = r.top, right = r.right, bottom = r.bottom;
  let mode = getComputedStyle(e).position;
  for (let p = up(e); p && mode !== 'fixed'; p = up(p)) {
    const s = getComputedStyle(p);
    if (mode === 'absolute' && s.position === 'static') continue;
    if (clipping(s.overflowX) || clipping(s.overflowY)) {
      const q = p.getBoundingClientRect();
      if (clipping(s.overflowX)) { left = Math.max(left, q.left); right = Math.min(right, q.right); }
      if (clipping(s.overflowY)) { top = Math.max(top, q.top); bottom = Math.min(bottom, q.bottom); }
      if (right - left < 1 || bottom - top < 1) return true;
    }
    mode = s.position;
  }
  return false;
}"""

FIELD_DESCRIBE_JS = (
    """e => {
  const concealed = """
    + CONCEALED_JS
    + """;
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
    concealed: concealed(e),
  };
}"""
)

# Effective action of the form around an input: the default submit button's
# `formaction` overrides the form's `action`. `null` = no form.
FORM_ACTION_JS = """e => {
  const f = e.form;
  if (!f) return {form: false, action: null};
  const b = f.querySelector('button[type=submit], input[type=submit], button:not([type])');
  return {form: true, action: (b && b.getAttribute('formaction')) || f.getAttribute('action')};
}"""

# Every submit button of the password's form in tree order (`form.elements`,
# so `form=`-associated buttons count, hidden ones too): the FIRST is the
# form's default button, the one Enter in a field activates. A form-less
# field: an empty list (Enter is the page script's business).
SUBMIT_BUTTONS_JS = """e => {
  const f = e.form;
  if (!f) return [];
  return Array.from(f.elements).filter(b =>
      (b.tagName === 'BUTTON' && (b.getAttribute('type') || 'submit').toLowerCase() === 'submit')
      || (b.tagName === 'INPUT' && ['submit', 'image'].includes((b.type || '').toLowerCase())));
}"""

# What `pick_submit_button` judges a submit button by — labels and attribute
# names, never a field value.
BUTTON_DESCRIBE_JS = """b => {
  const a = n => b.getAttribute(n) || '';
  const label = (b.tagName === 'INPUT' ? a('value') : (b.innerText || b.textContent || ''));
  return {
    name: a('name'), id: b.id || '', cls: a('class'),
    text: label.replace(/\\s+/g, ' ').trim().slice(0, 60),
    aria: (a('aria-label') + ' ' + a('title')).trim().slice(0, 60),
    disabled: !!b.disabled,
    visible: !!(b.offsetWidth || b.offsetHeight || b.getClientRects().length),
  };
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


def concealed(desc: dict[str, Any]) -> bool:
    """True iff the page hides the input from humans (``CONCEALED_JS``)."""
    return bool(desc.get("concealed"))


def pick_login_password(descs: Sequence[dict[str, Any]]) -> int | None:
    """Index of the login password among visible password inputs (DOM order).

    Concealed inputs never count. The first ``autocomplete=current-password``
    one wins; else the first that does not look like a registration field;
    else None (only registration fields are showing — never type the login
    secret into one)."""
    shown = [(i, d) for i, d in enumerate(descs) if not concealed(d)]
    for i, desc in shown:
        if current_password(desc):
            return i
    for i, desc in shown:
        if not registration_field_like(desc):
            return i
    return None


def pick_login_username(descs: Sequence[dict[str, Any]]) -> int | None:
    """Index of the first visible username candidate that is neither
    concealed nor a registration field, or None."""
    for i, desc in enumerate(descs):
        if not concealed(desc) and not registration_field_like(desc):
            return i
    return None


# Submit buttons that do something else than log in. Calibre-Web Automated
# (calibre.dom42.space, 2026-10-08) puts `<button type=submit name=forgot>
# Forgot Password?` BEFORE its Login button, so Enter in the password field
# submitted "forgot password" and never logged in.
_SECONDARY_JOINED_RE = re.compile(
    r"forgot|resetpass|recover|lostpass|register|signup|createaccount|passkey"
    r"|webauthn|securitykey|showpassword|hidepassword|togglepassword|revealpassword"
    r"|passwortanzeigen|passwortverbergen|afficherlemotdepasse|masquerlemotdepasse"
)
# In a class name only a password-visibility toggle is unambiguous.
_PASSWORD_TOGGLE_RE = re.compile(r"(?:show|hide|toggle|reveal)password|passwordtoggle")
_SECONDARY_TOKENS = frozenset(
    {
        "cancel",
        "back",
        "forgot",
        "register",
        "reset",
        "toggle",
        "reveal",
        "show",
        "hide",
    }
)


def secondary_button_like(desc: dict[str, Any]) -> bool:
    """The submit button names another action than the login (forgot
    password, register, cancel, show password, passkey ...) and not also the
    login itself. In the class only a password toggle counts — words like
    ``show``, ``back`` or ``signup`` there are layout noise."""
    named = [str(desc.get(k) or "") for k in ("name", "id", "text", "aria")]
    cls = str(desc.get("cls") or "")
    if _login_words(named):
        return False
    for text in named:
        if _SECONDARY_TOKENS.intersection(_tokens(text)):
            return True
    if any(_SECONDARY_JOINED_RE.search("".join(_tokens(t))) for t in named):
        return True
    return bool(_PASSWORD_TOGGLE_RE.search("".join(_tokens(cls))))


def pick_submit_button(descs: Sequence[dict[str, Any]]) -> int | None:
    """How to submit the password, from the form's submit buttons in tree
    order (``SUBMIT_BUTTONS_JS`` + ``BUTTON_DESCRIBE_JS``).

    None: press Enter — no form buttons, or the default (first) button is a
    login button. Else the index of the first visible, enabled submit button
    that is not ``secondary_button_like`` — the button to click instead of
    Enter. -1: the default button is secondary and no login button is
    showing; never submit (the secret would go to the wrong action)."""
    if not descs or not secondary_button_like(descs[0]):
        return None
    for i, desc in enumerate(descs):
        if desc.get("visible") and not desc.get("disabled"):
            if not secondary_button_like(desc):
                return i
    return -1


def form_submit_buttons(field: Any) -> list[Any]:
    """The submit buttons of `field`'s form in tree order (``SUBMIT_BUTTONS_JS``);
    [] when there is no form or they cannot be read."""
    try:
        handle = field.evaluate_handle(SUBMIT_BUTTONS_JS)
        props = handle.get_properties()
        ordered = sorted(
            ((int(k), v) for k, v in props.items() if str(k).isdigit()),
            key=lambda kv: kv[0],
        )
        return [el for _, v in ordered if (el := v.as_element()) is not None]
    except Exception:  # pylint: disable=broad-exception-caught
        return []


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
