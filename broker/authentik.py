"""authentik login through its flow executor API (auth.dev.renku.ch).

Why not the generic form recipe: authentik's login page is a Lit app whose
stage forms live in shadow roots, and its identification stage ALSO appends a
helper ``<form>`` to ``<html>`` for password managers (2026.8.1,
``IdentificationStage.#createHelperForm``): a text ``username``, a
``password`` and a ``code`` input, moved off-screen by
``html > form > input {top: -2000px}`` — which still counts as visible. The
generic recipe picked that helper password field (the only one: the default
flow asks for the password on its own stage), typed into the helper username
— whose value reaches the real ``uidField`` only on a ``keyup`` — and pressed
Enter, which makes the stage submit its OWN form: ``uid_field`` empty, the
password never sent. authentik answered with the identification challenge
again: "still on the login page after submitting the password".

So this recipe speaks authentik's documented flow executor protocol, the one
its own web UI uses (``flowsExecutorGet`` / ``flowsExecutorSolve``):
``GET /api/v3/flows/executor/<slug>/?query=<the login URL's query>`` returns
the current stage's challenge (JSON, ``component`` names the stage);
``POST`` of ``{"component": <stage>, …}`` to the same URL solves it — the
server answers 302 back to the same URL (followed: the next challenge) or the
same challenge with ``response_errors``. Stages handled:

- ``ak-stage-identification``: ``uid_field`` (and ``password`` when the
  stage shows a password field); a captcha → ``NeedsHuman``;
- ``ak-stage-password``: ``password``;
- ``ak-stage-authenticator-validate``: a TOTP ``code`` from the item's seed
  when a TOTP device is offered; anything else (WebAuthn only, an enrolment)
  → ``NeedsHuman``;
- ``ak-stage-user-login``: ``remember_me`` true (a session "stay signed in",
  never a trusted device);
- ``xak-flow-redirect``: the flow is done — the caller's positive proof
  decides;
- ``ak-stage-access-denied`` / ``ak-stage-flow-error`` / anything else: fail.

Rules (AGENTS.md): every request runs in a FRESH CDP isolated world of the
login page (the page's scripts cannot hook its ``fetch``), same-origin only
(``mode: 'same-origin'``, the final URL must be the executor URL itself), on
the item's fill origin (checked in Python and in the page). The answer the
page hands back is a value-free summary (stage name, error field names and
codes, device classes) — never a page text, never a secret. ``entered()``
and ``mark_submitted()`` run right before the request that carries the
password; nothing is ever re-sent after it: a stage that comes back after its
secret was posted is a failure, never a retry.
"""

from __future__ import annotations

import contextlib
import re
import secrets
import time
import urllib.parse
from typing import TYPE_CHECKING, Any

from broker.origins import origin_allowed, url_origin
from broker.recipes import (
    AUTHENTIK_SITES,
    NO_ATTEMPT,
    SETTLE_TIMEOUT_S,
    AttemptController,
    LoginFailed,
    NeedsHuman,
    OriginViolation,
    fresh_totp,
    open_login_page,
)

__all__ = ["AUTHENTIK_SITES", "authentik_login", "executor_path", "flow_slug"]

if TYPE_CHECKING:
    from broker.vault import Secret, SiteItem


# authentik's flow interface: /if/flow/<flow slug>/ (a Django SlugField).
FLOW_PAGE = re.compile(r"^/if/flow/([A-Za-z0-9_-]{1,100})/$")
EXECUTOR_PATH = "/api/v3/flows/executor/{slug}/"

FETCH_MS = 15000
TOTAL_MS = 20000
# The page's own executor GET (its SPA) runs on load: give it a moment, so
# the two first requests do not both start a flow plan.
SETTLE_PAGE_MS = 1000
# More stages than the default authentication flow has, twice.
MAX_STEPS = 10

IDENTIFICATION = "ak-stage-identification"
PASSWORD = "ak-stage-password"
AUTHENTICATOR = "ak-stage-authenticator-validate"
USER_LOGIN = "ak-stage-user-login"
REDIRECT = "xak-flow-redirect"
ACCESS_DENIED = "ak-stage-access-denied"
FLOW_ERROR = "ak-stage-flow-error"
# Stages only a human can solve.
HUMAN_STAGES = frozenset(
    {
        "ak-stage-captcha",
        "ak-stage-consent",
        "ak-stage-authenticator-totp",
        "ak-stage-authenticator-webauthn",
        "ak-stage-authenticator-static",
        "ak-stage-authenticator-email",
        "ak-stage-authenticator-sms",
        "ak-stage-authenticator-duo",
        "ak-stage-prompt",
        "ak-stage-email",
    }
)

# ONE request to the flow executor in an isolated world of the login page:
# GET (`body` null) or POST of `body` as JSON, same-origin only, the
# authentik CSRF cookie echoed in its header (as authentik's UI does). Only
# a value-free summary of the answer leaves the page. A POST never follows a
# redirect (`redirect: 'manual'`: a 307/308 would re-send its body, the
# password): authentik answers a solved stage with a 302 back to the
# executor, so on any redirect the step GETs the fixed executor URL itself —
# never the redirect's target, never the body again.
STEP_JS = r"""async (a) => {
  const work = async () => {
    if (location.origin !== a.origin) return {error: 'origin'};
    const url = new URL(a.path, a.origin);
    if (url.origin !== a.origin) return {error: 'origin'};
    const headers = {Accept: 'application/json'};
    for (const part of document.cookie.split(';')) {
      const i = part.indexOf('=');
      if (i > 0 && part.slice(0, i).trim() === 'authentik_csrf') {
        const v = part.slice(i + 1).trim();
        if (/^[A-Za-z0-9]{1,256}$/.test(v)) headers['X-authentik-CSRF'] = v;
      }
    }
    const init = {method: a.body === null ? 'GET' : 'POST', headers: headers,
      credentials: 'same-origin', mode: 'same-origin',
      redirect: a.body === null ? 'follow' : 'manual', cache: 'no-store'};
    if (a.body !== null) {
      headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(a.body);
    }
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), a.fetch_ms);
    init.signal = ctl.signal;
    let r, body;
    try {
      r = await fetch(url.href, init);
      if (a.body !== null && r.type === 'opaqueredirect') {
        delete headers['Content-Type'];
        r = await fetch(url.href, {method: 'GET', headers: headers,
          credentials: 'same-origin', mode: 'same-origin', redirect: 'follow',
          cache: 'no-store', signal: ctl.signal});
      }
      let final = null;
      try { final = new URL(r.url); } catch (e) { final = null; }
      if (!final || final.href !== url.href) return {error: 'redirect', status: r.status};
      if (r.status !== 200) return {error: 'status', status: r.status};
      const ct = (r.headers.get('content-type') || '').toLowerCase();
      if (!/^application\/json\s*(;|$)/.test(ct))
        return {error: 'content-type', status: r.status};
      try { body = await r.json(); } catch (e) { return {error: 'body', status: r.status}; }
    } catch (e) {
      return {error: e && e.name === 'AbortError' ? 'timeout' : 'network'};
    } finally { clearTimeout(timer); }
    if (body === null || typeof body !== 'object' || Array.isArray(body))
      return {error: 'schema', status: 200};
    const pick = (v, re) => (typeof v === 'string' && re.test(v) ? v : null);
    const name = /^[a-z_]{1,32}$/;
    const errors = [];
    const errs = body.response_errors;
    if (errs !== null && typeof errs === 'object' && !Array.isArray(errs)) {
      for (const k of Object.keys(errs).sort().slice(0, 8)) {
        const list = Array.isArray(errs[k]) ? errs[k].slice(0, 4) : [];
        errors.push([name.test(k) ? k : '?', list.map(e =>
          (e !== null && typeof e === 'object' && pick(e.code, name)) || '?')]);
      }
    }
    const devices = Array.isArray(body.device_challenges) ? body.device_challenges : [];
    const classes = [];
    for (const d of devices.slice(0, 16)) {
      const c = d !== null && typeof d === 'object' ? pick(d.device_class, name) : null;
      if (c && classes.indexOf(c) < 0) classes.push(c);
    }
    let to = null, offOrigin = false;
    if (typeof body.to === 'string') {
      try {
        const t = new URL(body.to, a.origin);
        if (t.origin === a.origin) to = t.pathname.slice(0, 256); else offOrigin = true;
      } catch (e) { offOrigin = true; }
    }
    const fields = Array.isArray(body.user_fields) ? body.user_fields : [];
    return {
      status: 200,
      component: pick(body.component, /^[a-z][a-z0-9-]{0,63}$/) || '?',
      errors: errors,
      password_fields: body.password_fields === true,
      user_fields: fields.filter(f => pick(f, name)).slice(0, 8),
      captcha: body.captcha_stage !== undefined && body.captcha_stage !== null,
      device_classes: classes.sort(),
      configuration_stages: Array.isArray(body.configuration_stages)
        ? Math.min(body.configuration_stages.length, 99) : 0,
      to: to,
      off_origin: offOrigin,
    };
  };
  let timer;
  const cap = new Promise(res => {
    timer = setTimeout(() => res({error: 'deadline'}), a.total_ms);
  });
  try { return await Promise.race([work(), cap]); }
  catch (e) { return {error: 'error'}; }
  finally { clearTimeout(timer); }
}"""


def flow_slug(login_url: str) -> str | None:
    """The flow slug of an authentik flow page URL (``/if/flow/<slug>/``)."""
    try:
        path = urllib.parse.urlsplit(login_url).path
    except ValueError:
        return None
    m = FLOW_PAGE.match(path)
    return m.group(1) if m else None


def executor_path(login_url: str) -> str | None:
    """The executor URL path for the flow page `login_url`: its slug, and its
    query string passed on as ``query`` (what authentik's UI sends:
    ``location.search`` without the ``?``). None when it is not a flow page."""
    slug = flow_slug(login_url)
    if slug is None:
        return None
    query = urllib.parse.urlsplit(login_url).query
    return (
        EXECUTOR_PATH.format(slug=slug) + "?" + urllib.parse.urlencode({"query": query})
    )


def evaluate_isolated(page: Any, js: str, arg: Any) -> Any:
    """``js(arg)`` in a FRESH CDP isolated world of `page`'s main frame, its
    value returned by value (the same mechanism as the broker's identity
    proof, ``daemon.evaluate_isolated``; the daemon imports this module's
    caller, so it is not imported here). Service workers are bypassed for
    this DevTools session only. Any CDP or script failure raises."""
    session = page.context.new_cdp_session(page)
    try:
        tree = session.send("Page.getFrameTree")
        frame_id = tree["frameTree"]["frame"]["id"]
        world = session.send(
            "Page.createIsolatedWorld",
            {"frameId": frame_id, "worldName": f"ak-{secrets.token_hex(6)}"},
        )
        context_id = world["executionContextId"]
        this = session.send(
            "Runtime.evaluate", {"expression": "globalThis", "contextId": context_id}
        )
        object_id = this["result"]["objectId"]
        session.send("Network.enable")
        session.send("Network.setBypassServiceWorker", {"bypass": True})
        got = session.send(
            "Runtime.callFunctionOn",
            {
                "functionDeclaration": js,
                "objectId": object_id,
                "arguments": [{"value": arg}],
                "awaitPromise": True,
                "returnByValue": True,
            },
        )
        if got.get("exceptionDetails"):
            raise RuntimeError("the authentik flow step raised")
        return (got.get("result") or {}).get("value")
    finally:
        with contextlib.suppress(Exception):
            session.detach()


# Step errors that mean "no answer" (not a refusal by authentik).
TRANSPORT_ERRORS = frozenset({"timeout", "network", "deadline"})


class _NoAnswer(Exception):
    """A flow request got no answer (``TRANSPORT_ERRORS``)."""


def _errors_text(answer: dict[str, Any]) -> str:
    """The answer's error fields and codes, value-free (``password: invalid``)."""
    parts = []
    for entry in answer.get("errors") or []:
        if isinstance(entry, list) and len(entry) == 2:
            parts.append(f"{entry[0]}: {', '.join(str(c) for c in entry[1])}")
    return "; ".join(parts)


class _Flow:  # pylint: disable=too-many-instance-attributes  # one login's state
    """One authentik login: the executor URL, what was posted so far."""

    def __init__(  # pylint: disable=too-many-arguments
        self,
        page: Any,
        item: SiteItem,
        secret: Secret,
        *,
        dev: bool,
        attempt: AttemptController,
    ) -> None:
        self.page = page
        self.item = item
        self.secret = secret
        self.dev = dev
        self.attempt = attempt
        self.allowed = list(item.fill_origins)
        self.origin = url_origin(item.login_url, dev=dev) or ""
        self.path = executor_path(item.login_url) or ""
        self.uid_sent = False
        self.password_sent = False
        self.code_sent = False
        self.login_sent = False

    def check_origin(self) -> None:
        """The page is still on the fill origin it started on (before every
        request, and before the password is marked and sent)."""
        if not origin_allowed(self.page.url, self.allowed, dev=self.dev):
            raise OriginViolation("the authentik page left the fill origins")
        if url_origin(self.page.url, dev=self.dev) != self.origin:
            raise OriginViolation("the authentik page is not on the login origin")

    def fail(self, detail: str, **kw: Any) -> LoginFailed:
        """A ``LoginFailed`` marked submitted once the password went out."""
        kw.setdefault("submitted", self.password_sent)
        return LoginFailed(detail, **kw)

    def step(self, body: dict[str, Any] | None) -> dict[str, Any]:
        """One executor request; its value-free summary. The page must still
        be on the fill origin (checked here and again in the page)."""
        self.check_origin()
        try:
            answer = evaluate_isolated(
                self.page,
                STEP_JS,
                {
                    "origin": self.origin,
                    "path": self.path,
                    "body": body,
                    "fetch_ms": FETCH_MS,
                    "total_ms": TOTAL_MS,
                },
            )
        except Exception as exc:  # pylint: disable=broad-exception-caught
            raise self.fail("the authentik flow request could not run") from exc
        if not isinstance(answer, dict):
            raise self.fail("the authentik flow request returned nothing")
        if answer.get("error") in TRANSPORT_ERRORS:
            raise _NoAnswer(str(answer["error"]))
        if answer.get("error"):
            status = answer.get("status")
            raise self.fail(
                "the authentik flow executor did not answer a challenge ("
                + str(answer["error"])
                + (f", HTTP {status}" if isinstance(status, int) else "")
                + ")"
            )
        return answer

    def password_body(
        self, body: dict[str, Any], answer: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """POST `body` + the password: the submit marker first. Never twice:
        a stage asking again after it was sent (`answer`, its error codes) is
        a failure."""
        if self.password_sent:
            errors = _errors_text(answer or {})
            raise self.fail(
                "authentik refused the password" + (f" ({errors})" if errors else "")
            )
        self.check_origin()  # before the marker, not only before the request
        self.attempt.entered()
        self.attempt.mark_submitted()
        self.password_sent = True
        return self.step({**body, "password": self.secret.password})

    def identification(self, answer: dict[str, Any]) -> dict[str, Any]:
        """The username (and, on a one-page stage, the password)."""
        if self.uid_sent:
            errors = _errors_text(answer)
            raise self.fail(
                "authentik refused the identification"
                + (f" ({errors})" if errors else ""),
            )
        if answer.get("captcha"):
            raise NeedsHuman("authentik's identification stage shows a captcha")
        if not answer.get("user_fields"):
            raise self.fail("authentik's identification stage takes no username")
        if not self.secret.username:
            raise self.fail("the item has no username")
        self.uid_sent = True
        body = {"component": IDENTIFICATION, "uid_field": self.secret.username}
        if answer.get("password_fields"):
            return self.password_body(body)
        return self.step(body)

    def authenticator(self, answer: dict[str, Any]) -> dict[str, Any]:
        """A TOTP code from the item's seed, when a TOTP device is offered."""
        if self.code_sent:
            errors = _errors_text(answer)
            raise self.fail(
                "authentik refused the TOTP code" + (f" ({errors})" if errors else "")
            )
        classes = [str(c) for c in answer.get("device_classes") or []]
        if "totp" not in classes:
            if answer.get("configuration_stages") and not classes:
                raise NeedsHuman(
                    "authentik asks to enrol a second factor",
                    submitted=self.password_sent,
                )
            raise NeedsHuman(
                "authentik asks for a second factor the item cannot give ("
                + (", ".join(classes) or "none offered")
                + ")",
                submitted=self.password_sent,
            )
        if not self.secret.totp_seed:
            raise NeedsHuman(
                "authentik asks for a TOTP code but the item has no TOTP seed",
                submitted=self.password_sent,
            )
        code = fresh_totp(self.secret.totp_seed)
        if code is None:
            raise NeedsHuman(
                "the item's TOTP seed is not usable", submitted=self.password_sent
            )
        self.check_origin()
        self.attempt.mark_submitted()
        self.code_sent = True
        return self.step({"component": AUTHENTICATOR, "code": code})

    def user_login(self) -> dict[str, Any]:
        """authentik's "stay signed in?" prompt: a session remember-me."""
        if self.login_sent:
            raise self.fail("authentik asked to stay signed in twice")
        self.login_sent = True
        return self.step({"component": USER_LOGIN, "remember_me": True})

    def run(self, settle_s: float) -> None:
        """Solve the stages until the flow redirects (done) or fails. Once
        the password went out, a passed deadline or a request that got no
        answer (timeout, network) ends the recipe WITHOUT a verdict: the
        caller's logged-in check decides — a slow last stage of a login that
        worked is no failure (and never a quarantine)."""
        try:
            self._solve(time.monotonic() + settle_s)
        except _NoAnswer as exc:
            if self.password_sent:
                return
            raise self.fail(
                f"the authentik flow executor did not answer ({exc})"
            ) from exc

    def _solve(self, deadline: float) -> None:  # pylint: disable=too-many-branches
        """The stage loop of `run`."""
        answer = self.step(None)
        for _ in range(MAX_STEPS):
            component = answer.get("component")
            if component != REDIRECT and time.monotonic() > deadline:
                if self.password_sent:
                    return  # the caller's logged-in check decides
                break
            if component == REDIRECT:
                if answer.get("to") != self.path.split("?", 1)[0]:
                    # the flow is done (a session that is still valid ends
                    # here at once, nothing typed): the caller's proof decides
                    return
                # back to the executor itself (a query authentik encodes
                # differently): fetch the next challenge
                answer = self.step(None)
            elif component == IDENTIFICATION:
                answer = self.identification(answer)
            elif component == PASSWORD:
                answer = self.password_body({"component": PASSWORD}, answer)
            elif component == AUTHENTICATOR:
                answer = self.authenticator(answer)
            elif component == USER_LOGIN:
                answer = self.user_login()
            elif component == ACCESS_DENIED:
                raise self.fail("authentik denied the login")
            elif component == FLOW_ERROR:
                raise self.fail("authentik's flow failed (flow error)")
            elif component in HUMAN_STAGES:
                raise NeedsHuman(
                    f"authentik asks for {component}", submitted=self.password_sent
                )
            else:
                raise self.fail(f"unknown authentik stage {component}")
        raise self.fail("the authentik flow did not finish")


def authentik_login(  # pylint: disable=too-many-arguments
    page: Any,
    item: SiteItem,
    secret: Secret,
    *,
    dev: bool = False,
    settle_s: float = SETTLE_TIMEOUT_S,
    attempt: AttemptController | None = None,
) -> None:
    """authentik login through the flow executor API (module docstring).

    The login URL must be an authentik flow page (``/if/flow/<slug>/``) on
    one of the item's fill origins; it is loaded first (Cloudflare Access →
    ``AccessGated``, HTTP 401/403 → ``LoginBlocked``, a challenge page →
    ``NeedsHuman``), then the stages are solved in its isolated world.
    Returns once the flow redirects; the caller's ``check_logged_in`` is the
    proof."""
    if not origin_allowed(item.login_url, list(item.fill_origins), dev=dev):
        raise OriginViolation("the authentik login URL is not on a fill origin")
    if executor_path(item.login_url) is None:
        raise LoginFailed("the authentik login URL is not a flow page (/if/flow/…/)")
    open_login_page(page, item.login_url)
    page.wait_for_timeout(SETTLE_PAGE_MS)
    _Flow(page, item, secret, dev=dev, attempt=attempt or NO_ATTEMPT).run(settle_s)
