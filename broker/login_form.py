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

import json
import re
import urllib.parse
from collections.abc import Callable, Collection, Sequence
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
    value: (b.tagName === 'BUTTON' ? a('value') : '').slice(0, 60),
    formaction: a('formaction').slice(0, 200),
    post_value: String(b.value == null ? '' : b.value).slice(0, 200),
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
    r"forgot|resetpass|recover|lostpass|register|signup|createaccount|passkey|logout|signout|resend"
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
        # destructive account actions: never the login, whatever the layout
        "delete",
        "remove",
        "deactivate",
        "unsubscribe",
        "logout",
        "resend",
    }
)


def secondary_button_like(desc: dict[str, Any]) -> bool:
    """The submit button names another action than the login (forgot
    password, register, cancel, show password, passkey ...) and not also the
    login itself. In the class only a password toggle counts — words like
    ``show``, ``back`` or ``signup`` there are layout noise. A ``<button>``'s
    ``value`` counts like its name (``name=op value=forgot`` posts
    ``op=forgot``), and a ``formaction`` whose last path segment is a
    secondary action (``/forgot-password``) makes it secondary whatever its
    label says."""
    named = [str(desc.get(k) or "") for k in ("name", "id", "text", "aria", "value")]
    cls = str(desc.get("cls") or "")
    if _action_path(str(desc.get("formaction") or "")) in SECONDARY_ACTIONS:
        return True
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


def form_submit_buttons(field: Any) -> list[Any] | None:
    """The submit buttons of `field`'s form in tree order (``SUBMIT_BUTTONS_JS``);
    [] when there is no form or it has none; None when they cannot be read
    (the field detached, the script failed, an entry is no element) — the
    caller must then refuse to submit: Enter fires whatever the form's
    default button is, and nobody knows which one that is."""
    try:
        handle = field.evaluate_handle(SUBMIT_BUTTONS_JS)
        props = handle.get_properties()
        ordered = sorted(
            ((int(k), v) for k, v in props.items() if str(k).isdigit()),
            key=lambda kv: kv[0],
        )
        out = [v.as_element() for _, v in ordered]
    except Exception:  # pylint: disable=broad-exception-caught
        return None
    if any(el is None for el in out):
        return None
    return out


# The keys `BUTTON_DESCRIBE_JS` returns; a descriptor without them was not
# read (a detached button, a script error) and cannot be judged.
BUTTON_DESC_KEYS = ("name", "id", "cls", "text", "aria", "disabled", "visible")


def describe_buttons(buttons: Sequence[Any]) -> list[dict[str, Any]] | None:
    """``BUTTON_DESCRIBE_JS`` of every button, or None when ANY of them cannot
    be read: one unreadable button could be the form's default (secondary)
    one, so a partial picture is no picture."""
    descs: list[dict[str, Any]] = []
    for button in buttons:
        try:
            desc = button.evaluate(BUTTON_DESCRIBE_JS)
        except Exception:  # pylint: disable=broad-exception-caught
            return None
        if not isinstance(desc, dict) or any(k not in desc for k in BUTTON_DESC_KEYS):
            return None
        descs.append(desc)
    return descs


def read_submit_buttons(field: Any) -> tuple[list[Any], list[dict[str, Any]]] | None:
    """(buttons, descriptors) of `field`'s form — both empty without a form
    or without submit buttons — or None when they cannot be read
    (``form_submit_buttons`` / ``describe_buttons``)."""
    buttons = form_submit_buttons(field)
    if buttons is None:
        return None
    descs = describe_buttons(buttons)
    if descs is None:
        return None
    return buttons, descs


def secondary_pairs(descs: Sequence[dict[str, Any]]) -> set[tuple[str, str]]:
    """The (name, posted value) of every NAMED secondary submit button
    (``secondary_button_like``) — a request that carries exactly that pair
    was submitted by that button. A name that a non-secondary button of the
    form also uses is dropped (Rails: ``commit=Sign in`` next to
    ``commit=Cancel``; Auth0: ``action=default`` next to another action):
    the name alone says nothing, and the value check is ``ACTION_KEYS``'
    business. Names compare case-insensitively."""
    login_names = {
        str(d.get("name") or "").lower()
        for d in descs
        if d.get("name") and not secondary_button_like(d)
    }
    return {
        (name, str(d.get("post_value") or ""))
        for d in descs
        if (name := str(d.get("name") or "").lower())
        and name not in login_names
        and secondary_button_like(d)
    }


# --- "Remember me" ---------------------------------------------------------
# Apps that tie a session to IP + User-Agent (Flask-Login "strong" session
# protection: Calibre-Web Automated) keep a session injected into another
# browser only through their remember-me cookie, so the broker ticks the box
# when the login form has one. Judged on the checkbox's name / id /
# aria-label and its label text.
REMEMBER_ME_RE = re.compile(
    r"\bremember\s*me\b|keep\s*me\s*(?:signed|logged)\s*in"
    r"|stay\s*(?:signed|logged)\s*in|angemeldet\s*bleiben|eingeloggt\s*bleiben"
    r"|rester\s*connect|se\s*souvenir\s*de\s*moi",
    re.IGNORECASE,
)
# The same choice as a field name / id (separators and camelCase dropped).
REMEMBER_ME_NAMES = frozenset(
    {
        "remember",
        "rememberme",
        "rememberlogin",
        "keepmeloggedin",
        "keepmesignedin",
        "staysignedin",
        "stayloggedin",
    }
)
# Never ticked: a box about a device, a browser, a choice or the user name is
# another policy (a trusted device skips the second factor) — not a session.
REMEMBER_NOT_RE = re.compile(
    r"device|browser|computer|choice|trust|ger[aä]t|appareil|navigateur"
    r"|user\s*name|e-?mail|benutzer"
    r"|don[\u2019']?t|do\s*not|nicht|ne\s*pas",
    re.IGNORECASE,
)

# The checkboxes of the password's form (no form: its document), each with
# what `remember_me_like` judges — attribute names and label text, never a
# value.
REMEMBER_BOXES_JS = """pw => {
  const scope = pw.form || pw.ownerDocument;
  const vis = el => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
  const a = (el, n) => ((el && el.getAttribute(n)) || '');
  return Array.from(scope.querySelectorAll('input[type=checkbox]')).map(b => {
    const labels = Array.from(b.labels || []);
    const wrap = b.closest('label');
    if (wrap && !labels.includes(wrap)) labels.push(wrap);
    const text = labels.map(l => (l.innerText || l.textContent || '')).join(' ');
    return {
      name: a(b, 'name'), id: b.id || '',
      aria: (a(b, 'aria-label') + ' ' + a(b, 'title')).trim().slice(0, 80),
      label: text.replace(/\\s+/g, ' ').trim().slice(0, 80),
      checked: !!b.checked, disabled: !!b.disabled, visible: vis(b),
      label_visible: labels.some(vis),
    };
  });
}"""

# The same checkboxes as element handles, index-aligned with REMEMBER_BOXES_JS.
REMEMBER_BOX_HANDLES_JS = """pw => Array.from(
  (pw.form || pw.ownerDocument).querySelectorAll('input[type=checkbox]'))"""


def remember_me_like(desc: dict[str, Any]) -> bool:
    """The checkbox is a "remember me" / "keep me signed in" choice for the
    SESSION: its label or aria-label says so (``REMEMBER_ME_RE``), or its
    name / id is one (``REMEMBER_ME_NAMES``) — and nothing about it names a
    device, a browser, a choice or the user name (``REMEMBER_NOT_RE``)."""
    names = [str(desc.get(k) or "") for k in ("name", "id")]
    texts = [str(desc.get("aria") or ""), str(desc.get("label") or "")]
    if any(REMEMBER_NOT_RE.search(t) for t in [*names, *texts]):
        return False
    if any(_joined(n) in REMEMBER_ME_NAMES for n in names):
        return True
    return any(REMEMBER_ME_RE.search(t) for t in texts)


def pick_remember_me(descs: Sequence[dict[str, Any]]) -> int | None:
    """Index of the first enabled "remember me" checkbox a human could tick
    (it or its label is visible), or None."""
    for i, desc in enumerate(descs):
        if desc.get("disabled"):
            continue
        if not (desc.get("visible") or desc.get("label_visible")):
            continue
        if remember_me_like(desc):
            return i
    return None


# --- POST tripwire ---------------------------------------------------------
# While the broker submits a login form, every request to a fill origin that
# carries a body is screened (``recipes.SubmitTripwire``): one that names a
# secondary action — forgot password, reset, register, sign-up, resend — is
# aborted before it leaves the browser. Calibre-Web Automated (2026-10-08):
# Enter fired its `forgot` button and the server reset the admin password,
# twice. Whole names only: GitHub's login form carries a hidden `allow_signup`
# field, which names no action of its own.
SECONDARY_ACTIONS = frozenset(
    {
        "forgot",
        "forgotten",
        "forgotpassword",
        "forgotpwd",
        "forgotusername",
        "lostpassword",
        "reset",
        "resetpassword",
        "passwordreset",
        "resetpwd",
        "recover",
        "recovery",
        "recoverpassword",
        "register",
        "registration",
        "signup",
        "createaccount",
        "resend",
        "resendcode",
        "resendemail",
        "resendverification",
    }
)
# A body key that names an action with one of these values does not ask for it
# (``signup=false``).
_FALSEY = frozenset({"false", "0", "no", "off", "null"})
# Body keys whose VALUE names the action (``action=forgot``, ``submit=Register``).
ACTION_KEYS = frozenset(
    {"action", "_action", "op", "submit", "commit", "button", "btn", "intent", "do"}
)
_MAX_ACTION_VALUE = 64


def _joined(text: str) -> str:
    return "".join(_tokens(text))


def _action_path(url: str) -> str:
    """The last path segment of `url`, normalised (``/forgot-password`` →
    ``forgotpassword``); "" when there is none."""
    try:
        path = urllib.parse.urlsplit(url).path
    except ValueError:
        return ""
    segments = [seg for seg in path.split("/") if seg]
    return _joined(urllib.parse.unquote(segments[-1])) if segments else ""


def _json_pairs(body: str, *, nested: bool = False) -> list[tuple[str, str]]:
    """Keys of a JSON object body with their scalar values — the top level
    only, nested objects too with `nested`."""
    try:
        data = json.loads(body or "null")
    except ValueError:
        return []
    out: list[tuple[str, str]] = []
    stack = [data] if isinstance(data, dict) else []
    while stack:
        obj = stack.pop()
        for key, value in obj.items():
            if isinstance(value, dict) and nested:
                stack.append(value)
            scalar = isinstance(value, (str, int, float)) and not isinstance(
                value, bool
            )
            out.append((str(key), str(value) if scalar else ""))
    return out


def _multipart_pairs(body: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for part in re.split(r"\r?\n?--[^\r\n]*\r?\n", body or ""):
        head, _, value = part.partition("\r\n\r\n")
        match = re.search(r'\bname="([^"]*)"', head)
        if match:
            out.append((match.group(1), value.rstrip("\r\n")))
    return out


def body_pairs(
    body: str, content_type: str, *, nested: bool = False
) -> list[tuple[str, str]]:
    """(key, value) pairs of a form-urlencoded, JSON or multipart body (JSON:
    top-level keys, nested objects too with `nested`); unknown types: none."""
    ctype = (content_type or "").split(";", 1)[0].strip().lower()
    if ctype == "application/json" or ctype.endswith("+json"):
        return _json_pairs(body, nested=nested)
    if ctype == "multipart/form-data":
        return _multipart_pairs(body)
    if ctype in ("", "application/x-www-form-urlencoded", "text/plain"):
        return urllib.parse.parse_qsl(body or "", keep_blank_values=True)
    return []


def secondary_hit(
    url: str,
    pairs: Sequence[tuple[str, str]],
    *,
    protect: Collection[str] = (),
    button_pairs: Collection[tuple[str, str]] = (),
) -> str | None:
    """What makes a request with these body/query `pairs` a secondary form
    action, or None.

    Tripped by: a (key, value) pair that one of the form's secondary submit
    buttons posts (`button_pairs`, ``secondary_pairs``), a key — or the value
    of an ``ACTION_KEYS`` key — that IS a secondary action word
    (``SECONDARY_ACTIONS``, the whole name after separators and camelCase are
    dropped; a key whose value says no — ``signup=false`` — does not trip),
    or a `url` whose last path segment is one ("" = no path check). Keys in
    `protect` (the password and username fields) are skipped and their values
    never read. The answer names the key (or ``path``) and the action word
    only — never a value."""
    shield = {p.lower() for p in protect if p}
    named = {(n.lower(), v) for n, v in button_pairs if n}
    for key, value in pairs:
        low = key.lower()
        if low in shield:
            continue
        if (low, value) in named:
            return f"button {key[:40]}"
        if _joined(key) in SECONDARY_ACTIONS and value.strip().lower() not in _FALSEY:
            return f"field {key[:40]}"
        if low in ACTION_KEYS and len(value) <= _MAX_ACTION_VALUE:
            word = _joined(value)
            if word in SECONDARY_ACTIONS:
                return f"{key}={word}"
    last = _action_path(url) if url else ""
    return f"path {last}" if last in SECONDARY_ACTIONS else None


def secondary_post(
    url: str,
    body: str,
    content_type: str,
    *,
    protect: Collection[str] = (),
    button_pairs: Collection[tuple[str, str]] = (),
) -> str | None:
    """``secondary_hit`` over a request body (top-level keys)."""
    return secondary_hit(
        url,
        body_pairs(body, content_type),
        protect=protect,
        button_pairs=button_pairs,
    )


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
