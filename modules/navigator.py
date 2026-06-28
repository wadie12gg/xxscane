from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import math
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import parse_qsl, urlparse

from xsscane.core.config import ScanConfig
from xsscane.core.models import Endpoint
from xsscane.modules.crawler import _MODERN_UA
from xsscane.utils.bloom import BloomFilter

# Injected before any page script. Masks automation, marks elements that register
# click-like listeners (so DOM-driven actions become discoverable), and exposes
# helpers to build a stable selector, enumerate clickables and fingerprint state.
_INIT_JS = r"""
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
(() => {
  const add = EventTarget.prototype.addEventListener;
  EventTarget.prototype.addEventListener = function (type, fn, opts) {
    try {
      if (/^(click|mousedown|mouseup|pointerup|pointerdown)$/i.test(type) && this instanceof Element) {
        this.setAttribute('data-xnav-clickable', '1');
      }
    } catch (e) {}
    return add.call(this, type, fn, opts);
  };
})();
window.__xnavPath = function (el) {
  if (!(el instanceof Element)) return '';
  if (el.id) return '#' + CSS.escape(el.id);
  const path = [];
  while (el && el.nodeType === 1 && el !== document.body) {
    let sel = el.nodeName.toLowerCase();
    if (el.id) { path.unshift('#' + CSS.escape(el.id)); break; }
    let nth = 1, sib = el;
    while ((sib = sib.previousElementSibling)) { if (sib.nodeName === el.nodeName) nth++; }
    path.unshift(sel + ':nth-of-type(' + nth + ')');
    el = el.parentElement;
  }
  return path.join(' > ');
};
window.__xnavClickables = function () {
  const q = 'button,[onclick],[role=button],[role=tab],a[href],summary,'
          + 'input[type=button],input[type=submit],[data-xnav-clickable],[tabindex]';
  const seen = new Set(), out = [];
  document.querySelectorAll(q).forEach((el) => {
    const r = el.getBoundingClientRect();
    if (r.width === 0 || r.height === 0) return;
    const sel = window.__xnavPath(el);
    if (sel && !seen.has(sel)) {
      seen.add(sel);
      out.push({selector: sel, label: (el.textContent || el.getAttribute('aria-label') || el.tagName).trim().slice(0, 40)});
    }
  });
  return out;
};
window.__xnavState = function () {
  const els = document.querySelectorAll('a,button,input,select,textarea,form,[onclick],[role],[data-xnav-clickable]');
  const parts = [];
  els.forEach((e) => parts.push(e.tagName + ':' + (e.id || '') + ':' + (e.getAttribute('role') || '')
                              + ':' + (e.className || '') + ':' + (e.textContent || '').trim().slice(0, 24)));
  return location.pathname + '#' + parts.sort().join('|');
};
window.__xnavLoginForm = function () {
  const visible = (el) => { const r = el.getBoundingClientRect(); return r.width > 0 && r.height > 0; };
  const pwds = Array.from(document.querySelectorAll('input[type=password]')).filter(visible);
  if (!pwds.length) return null;               // password field is the anchor
  const pw = pwds[0];
  const form = pw.closest('form') || pw.parentElement;
  const scope = form || document;
  const HINTS = ['user', 'email', 'login', 'account', 'uid', 'mail', 'name'];
  const texts = Array.from(scope.querySelectorAll('input')).filter((el) => {
    const t = (el.getAttribute('type') || 'text').toLowerCase();
    return visible(el) && el !== pw && ['text', 'email', 'tel', ''].includes(t);
  });
  let best = null, bestScore = -1;
  texts.forEach((el) => {
    const a = ((el.name || '') + ' ' + (el.id || '') + ' ' + (el.placeholder || '')
               + ' ' + (el.autocomplete || '')).toLowerCase();
    let s = 0;
    const t = (el.getAttribute('type') || 'text').toLowerCase();
    if (t === 'email' || t === 'text') s += 2;
    if (HINTS.some((h) => a.includes(h))) s += 3;
    if (['username', 'email'].includes((el.autocomplete || '').toLowerCase())) s += 4;
    if (el.compareDocumentPosition(pw) & Node.DOCUMENT_POSITION_FOLLOWING) s += 2;  // el precedes pw
    if (s > bestScore) { bestScore = s; best = el; }
  });
  const hidden = Array.from(scope.querySelectorAll('input[type=hidden]')).map((el) => ({
    name: el.name || '', value: el.value || '', selector: window.__xnavPath(el),
  }));
  const submit = (form && form.querySelector('button[type=submit], input[type=submit]'))
              || scope.querySelector('button[type=submit], input[type=submit], button');
  return {
    username: best ? window.__xnavPath(best) : null,
    password: window.__xnavPath(pw),
    submit: submit ? window.__xnavPath(submit) : null,
    hidden: hidden,
    action: form ? (form.getAttribute('action') || location.href) : location.href,
    method: form ? ((form.getAttribute('method') || 'GET').toUpperCase()) : 'GET',
  };
};
window.__xnavAuthSignals = function () {
  const t = (document.body ? document.body.innerText : '').toLowerCase();
  const title = (document.title || '').toLowerCase();
  const url = location.href.toLowerCase();
  const has = (sel) => { try { return !!document.querySelector(sel); } catch (e) { return false; } };
  const txt = (kw) => kw.some((k) => t.includes(k));
  const anyText = (kw) => kw.some((k) => t.includes(k) || title.includes(k) || url.includes(k));
  const buttons = Array.from(document.querySelectorAll('button, input[type=submit], [role=button]'))
    .map((b) => (b.textContent || b.value || '').toLowerCase()).join(' ');
  const actions = Array.from(document.querySelectorAll('form'))
    .map((f) => (f.getAttribute('action') || '').toLowerCase()).join(' ');
  const loginWords = ['log in', 'login', 'log-in', 'sign in', 'signin', 'sign-in', 'authenticate'];
  return {
    loginForm: has('input[type=password]'),
    loginKeywords: anyText(loginWords) || loginWords.some((w) => buttons.includes(w))
                   || /(login|signin|sign-in|auth|session)/.test(actions),
    otp: has('input[autocomplete="one-time-code"], input[name*="otp" i], input[name*="2fa" i], '
           + 'input[name*="mfa" i], input[id*="otp" i], input[name*="totp" i]')
         || txt(['two-factor', 'two factor', '2fa', 'one-time', 'one time code',
                 'verification code', 'authenticator app', 'enter the code']),
    captcha: has('.g-recaptcha, #g-recaptcha, iframe[src*="recaptcha"], iframe[src*="hcaptcha"], '
              + '.h-captcha, iframe[src*="turnstile"], .cf-turnstile')
             || txt(['captcha', "i'm not a robot", 'verify you are human']),
    blocked: txt(['access denied', 'rate limit', 'too many requests',
                  'temporarily blocked', 'request blocked', 'unusual traffic']),
    logout: has('a[href*="logout" i], a[href*="signout" i], a[href*="sign-out" i], '
              + 'button[id*="logout" i], [onclick*="logout" i]')
            || txt(['log out', 'logout', 'sign out']),
    accountUi: has('a[href*="dashboard" i], a[href*="account" i], a[href*="profile" i], '
                 + 'a[href*="settings" i], [class*="avatar" i], [class*="user-menu" i], '
                 + '[aria-label*="account" i], img[alt*="avatar" i]')
               || txt(['my account', 'welcome back', 'dashboard']),
  };
};
window.__xnavPageDigest = function () {
  // Compact, value-free page summary for the optional local LLM. Field *values*
  // are intentionally omitted so no typed secret ever leaves the browser.
  const clip = (s, n) => (s || '').replace(/\s+/g, ' ').trim().slice(0, n);
  const take = (sel, n, fn) => Array.from(document.querySelectorAll(sel)).slice(0, n).map(fn).filter(Boolean);
  return {
    url: location.href,
    title: clip(document.title, 100),
    headings: take('h1,h2,h3', 6, (h) => clip(h.textContent, 60)),
    fields: take('input,select,textarea', 15, (e) => ({
      name: e.getAttribute('name') || '', type: (e.getAttribute('type') || e.tagName).toLowerCase(),
    })),
    buttons: take('button, input[type=submit], [role=button]', 12, (b) => clip(b.textContent || b.value, 30)),
    text: clip(document.body ? document.body.innerText : '', 500),
  };
};
"""

_KEEP_HEADERS = (
    "authorization", "content-type", "x-csrf-token", "x-xsrf-token",
    "x-requested-with", "x-api-key", "cookie",
)
_SKIP_RESOURCE = ("stylesheet", "image", "font", "media")


@dataclass
class _Node:
    """A reachable application state, identified by the click-path that reaches it."""

    path: list = field(default_factory=list)  # list of {selector, label}
    depth: int = 0


class StateTracker:
    """De-duplicates application states by fingerprint, so a state reachable via
    several click-paths is explored once. Bloom-filter backed."""

    def __init__(self, capacity: int = 50_000):
        self._states = BloomFilter(capacity=capacity)
        self.count = 0

    @staticmethod
    def fingerprint(raw_state: str) -> str:
        return hashlib.blake2b(raw_state.encode("utf-8", "ignore"), digest_size=16).hexdigest()

    def mark(self, raw_state: str) -> bool:
        """Record a state; return True if it is new (not seen before)."""
        digest = self.fingerprint(raw_state)
        if self._states.add(digest):
            return False
        self.count += 1
        return True


@dataclass
class LoginForm:
    """A login form located by DOM analysis, expressed as actionable selectors."""

    password: str
    username: str | None = None
    submit: str | None = None
    hidden: list[dict] = field(default_factory=list)  # [{name, value, selector}]
    action: str = ""
    method: str = "GET"

    def is_actionable(self) -> bool:
        return bool(self.password and self.username and self.submit)


class LoginFormLocator:
    """Locates the login form and its fields from the DOM: the password input is
    the anchor, the username is the best-scored text field near it."""

    async def locate(self, page) -> LoginForm | None:
        try:
            data = await page.evaluate("window.__xnavLoginForm ? window.__xnavLoginForm() : null")
        except Exception:
            return None
        if not data or not data.get("password"):
            return None
        return LoginForm(
            password=data["password"],
            username=data.get("username"),
            submit=data.get("submit"),
            hidden=data.get("hidden") or [],
            action=data.get("action") or page.url,
            method=data.get("method") or "GET",
        )


class TokenManager:
    """Identifies anti-CSRF / hidden token fields so a legitimate login can carry
    them. Detection combines name keywords with Shannon-entropy of the value, which
    keeps false positives low on benign hidden inputs (e.g. redirect targets)."""

    _KEYWORDS = ("csrf", "xsrf", "token", "nonce", "authenticity", "verification", "_token")

    @staticmethod
    def _entropy(value: str) -> float:
        if not value:
            return 0.0
        length = len(value)
        return -sum((c / length) * math.log2(c / length) for c in Counter(value).values())

    @classmethod
    def is_token(cls, name: str, value: str) -> bool:
        name = (name or "").lower()
        if any(keyword in name for keyword in cls._KEYWORDS):
            return True
        return bool(value) and len(value) >= 16 and cls._entropy(value) > 3.5

    @classmethod
    def discover(cls, form: LoginForm) -> list[dict]:
        return [h for h in form.hidden if cls.is_token(h.get("name", ""), h.get("value", ""))]


class AuthState(str, Enum):
    ANONYMOUS = "anonymous"          # not authenticated, generic page
    LOGIN_PAGE = "login_page"        # a login form is presented (never authed yet)
    AUTHENTICATED = "authenticated"  # session is active
    EXPIRED = "expired"              # was authenticated, session has dropped
    MFA_REQUIRED = "mfa_required"    # second-factor / OTP wall  -> manual
    CAPTCHA = "captcha"              # captcha challenge          -> manual
    BLOCKED = "blocked"              # rate-limited / WAF block   -> back off
    UNKNOWN = "unknown"


class AuthStateDetector:
    """Classifies a page into an explicit auth state. Hard walls (BLOCKED / CAPTCHA /
    MFA) are decisive and checked first; soft states use weighted scoring over DOM
    signals so an in-session change-password page isn't read as an expired session.
    History-aware: a login surface is LOGIN_PAGE first, EXPIRED after a session."""

    def classify(self, signals: dict, status: int | None, was_authenticated: bool) -> AuthState:
        return self.classify_detailed(signals, status, was_authenticated)[0]

    def classify_detailed(
        self, signals: dict, status: int | None, was_authenticated: bool
    ) -> tuple[AuthState, float, list[str]]:
        g = lambda key: bool(signals.get(key))

        # --- hard walls: decisive, ordered ------------------------------------
        if status == 429 or g("blocked"):
            return AuthState.BLOCKED, 0.95, ["rate-limit / WAF signal"]
        if status == 403 and not g("loginForm"):
            return AuthState.BLOCKED, 0.80, ["HTTP 403 without a login form"]
        if g("captcha"):
            return AuthState.CAPTCHA, 0.90, ["captcha widget / text"]
        if g("otp"):
            return AuthState.MFA_REQUIRED, 0.90, ["one-time-code / 2FA field"]

        # --- weighted scoring for the soft states -----------------------------
        authed = (3 if g("logout") else 0) + (2 if g("accountUi") else 0) + (1 if was_authenticated else 0)
        authed_reasons = [r for r, c in (("logout control", g("logout")),
                                         ("account/dashboard UI", g("accountUi")),
                                         ("prior session", was_authenticated)) if c]

        if g("loginForm"):
            # A password field is the decisive login trigger; keywords only sharpen
            # confidence. If stronger authenticated signals coexist (logout + UI),
            # the page is an in-session form (e.g. change password), not a wall.
            login = 3 + (2 if g("loginKeywords") else 0)
            login_reasons = ["password field"] + (["login keywords"] if g("loginKeywords") else [])
            if authed > login:
                return AuthState.AUTHENTICATED, round(authed / (authed + login), 2), authed_reasons
            state = AuthState.EXPIRED if was_authenticated else AuthState.LOGIN_PAGE
            return state, round(login / (login + authed + 1), 2), login_reasons

        if authed >= 2:
            return AuthState.AUTHENTICATED, round(authed / (authed + 1), 2), authed_reasons
        if was_authenticated:
            return AuthState.AUTHENTICATED, 0.50, ["sticky prior session"]
        # A logged-out page that merely links to a login screen lands here.
        return AuthState.ANONYMOUS, 0.30, ["no decisive auth signal"]


class DeepNavigationEngine:
    """Stateful, auth-aware SPA crawler: BFS over application *states* (not URLs).
    Discovers clickables (including runtime-bound listeners), replays click-paths to
    reach a state, intercepts XHR/fetch to capture API requests, and re-authenticates
    if a click drops the session. Returns Endpoints for the fuzzer."""

    def __init__(self, config: ScanConfig, logger: logging.Logger):
        self.config = config
        self.log = logger
        self._seed = urlparse(config.url)
        self._apex = self._registrable_domain(self._seed.netloc)

        self.tracker = StateTracker(capacity=max(config.max_interactions * 20, 10_000))
        self._queue: asyncio.Queue[_Node] = asyncio.Queue()
        self._endpoints: dict[tuple, Endpoint] = {}
        self._interactions = 0
        self._auth_lock = asyncio.Lock()
        self._workers = max(1, min(config.concurrency, 3))
        self.session_cookie = ""  # exported so the fuzzer can reuse the auth session
        self._locator = LoginFormLocator()

        # Authentication state machine
        self._detector = AuthStateDetector()
        self._auth_state = AuthState.ANONYMOUS
        self._was_authenticated = False
        self._stop = False                 # set on MFA/CAPTCHA halt or tripped breaker
        self._halt_reason: AuthState | None = None
        self._block_count = 0
        self._block_threshold = 3          # consecutive BLOCKED signals before backing off

        # Optional local-LLM assist: lazy-imported only when enabled, local-only
        # (never a paid API), so the default path is unaffected.
        self._llm = None
        if getattr(config, "llm_assist", False):
            from xsscane.modules.llm_assist import LocalLLMClassifier

            self._llm = LocalLLMClassifier(config.llm_endpoint, config.llm_model, self.log)

        self._pw = None
        self._browser = None
        self._context = None
        self._page_sem: asyncio.Semaphore | None = None

    async def run(self) -> list[Endpoint]:
        if not await self._setup():
            self.log.warning("[warning]Deep navigation needs Playwright; skipping (no endpoints added)[/]")
            return []
        try:
            await self._seed_state()
            workers = [asyncio.create_task(self._worker()) for _ in range(self._workers)]
            await self._queue.join()
            for worker in workers:
                worker.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
        finally:
            await self._export_session()
            await self._teardown()

        self.log.info(
            f"[info]Deep navigation:[/] {self._interactions} interaction(s), "
            f"{self.tracker.count} unique state(s), {len(self._endpoints)} endpoint(s)"
        )
        if self._halt_reason is not None:
            self.log.warning(f"[warning]Stopped early - state: {self._halt_reason.value.upper()}[/]")
        return list(self._endpoints.values())

    async def _seed_state(self) -> None:
        page = await self._context.new_page()
        status = self._attach_status(page)
        captured: list[dict] = []
        page.on("request", lambda request: self._on_request(captured, request))
        try:
            await self._safe_goto(page, self.config.url)
            await self._react(page, status)
            self.tracker.mark(await self._state(page))
        finally:
            for request in captured:
                self._handle_request(request)
            await page.close()
        self._queue.put_nowait(_Node([], 0))

    # -- BFS workers ----------------------------------------------------------

    async def _worker(self) -> None:
        while True:
            node = await self._queue.get()
            try:
                if not self._stop and self._interactions < self.config.max_interactions \
                        and node.depth < self.config.max_depth:
                    await self._expand(node)
            except Exception as exc:
                self.log.debug(f"[muted]Navigation error (depth {node.depth}): {exc}[/]")
            finally:
                self._queue.task_done()

    async def _expand(self, node: _Node) -> None:
        async with self._page_sem:
            page = await self._context.new_page()
            status = self._attach_status(page)
            captured: list[dict] = []
            page.on("request", lambda request: self._on_request(captured, request))
            page.on("popup", lambda popup: asyncio.create_task(self._drain_popup(popup)))
            try:
                if not await self._reach(page, node, status):
                    return
                if not await self._react(page, status) or self._stop:
                    return
                base_state = await self._state(page)
                clickables = await self._clickables(page)
                self.log.debug(f"[muted]State {self._auth_state.value} (depth {node.depth}): "
                               f"{len(clickables)} clickable(s)[/]")

                for action in clickables:
                    if self._stop or self._interactions >= self.config.max_interactions:
                        break
                    # Re-establish this node's state if a previous sibling click moved us.
                    if await self._state(page) != base_state and not await self._reach(page, node, status):
                        break
                    if not await self._do_click(page, action):
                        continue
                    self._interactions += 1
                    if not await self._react(page, status):
                        if self._stop:
                            break
                        continue  # this transition was blocked/declined, try the next
                    new_state = await self._state(page)
                    if self.tracker.mark(new_state):
                        self._queue.put_nowait(_Node(node.path + [action], node.depth + 1))
            finally:
                for request in captured:
                    self._handle_request(request)
                await page.close()

    async def _reach(self, page, node: _Node, status: dict) -> bool:
        """Replay the click-path from the seed to reproduce a node's state."""
        if not await self._safe_goto(page, self.config.url):
            return False
        if not await self._react(page, status) or self._stop:
            return False
        for action in node.path:
            if not await self._do_click(page, action):
                return False  # path no longer valid (DOM drifted)
        return True

    async def _do_click(self, page, action: dict) -> bool:
        # Let Playwright auto-wait for any navigation the click triggers; using
        # no_wait_after here races the redirect and hides login bounces.
        try:
            await page.click(action["selector"], timeout=2500)
        except Exception:
            return False
        await self._wait_idle(page, short=True)
        return True

    # -- authentication state machine -----------------------------------------

    def _has_credentials(self) -> bool:
        return bool(self.config.login_url and self.config.username and self.config.password)

    async def _signals(self, page) -> dict:
        try:
            return await page.evaluate("window.__xnavAuthSignals ? window.__xnavAuthSignals() : null") or {}
        except Exception:
            return {}

    async def _sync_state(self, page, status: dict) -> AuthState:
        signals = await self._signals(page)
        state, confidence, reasons = self._detector.classify_detailed(
            signals, status.get("status"), self._was_authenticated
        )
        # Optional local-LLM refinement, only when the heuristic verdict is weak.
        # Hard walls (BLOCKED/CAPTCHA/MFA) score high, so they are never overridden.
        if self._llm is not None and confidence < self.config.llm_min_confidence and await self._llm.available():
            verdict = await self._llm.classify(await self._page_digest(page))
            if verdict:
                llm_state, llm_conf, reason = verdict
                mapped = self._to_auth_state(llm_state)
                if mapped not in (None, AuthState.UNKNOWN) and llm_conf >= self.config.llm_min_confidence:
                    state, confidence, reasons = mapped, llm_conf, [f"local-LLM: {reason}"]

        if state != self._auth_state:
            self.log.debug(
                f"[muted]auth: {self._auth_state.value} -> {state.value} "
                f"(conf {confidence:.2f}: {', '.join(reasons)})[/]"
            )
            self._auth_state = state
        return state

    async def _page_digest(self, page) -> dict:
        try:
            return await page.evaluate("window.__xnavPageDigest ? window.__xnavPageDigest() : null") or {}
        except Exception:
            return {}

    @staticmethod
    def _to_auth_state(value: str):
        try:
            return AuthState(value)
        except ValueError:
            return None

    async def _react(self, page, status: dict) -> bool:
        """Classify the current page and act on the auth state. Returns False when
        the caller should not continue this navigation (halt or blocked)."""
        if self._stop:
            return False
        state = await self._sync_state(page, status)

        if state == AuthState.AUTHENTICATED:
            self._was_authenticated = True
            self._block_count = 0
            return True
        if state in (AuthState.LOGIN_PAGE, AuthState.EXPIRED):
            if state == AuthState.EXPIRED:
                self.log.warning("[warning]Session EXPIRED - re-authenticating[/]")
            return await self._authenticate(page, status)
        if state == AuthState.MFA_REQUIRED:
            return self._halt(state, "Multi-factor authentication (MFA) required")
        if state == AuthState.CAPTCHA:
            return self._halt(state, "CAPTCHA challenge present")
        if state == AuthState.BLOCKED:
            return self._trip_breaker()
        return True  # ANONYMOUS / UNKNOWN -> nothing to do, keep crawling

    async def _authenticate(self, page, status: dict) -> bool:
        if not self._has_credentials():
            return True  # no creds supplied; treat protected areas as out of reach
        async with self._auth_lock:
            if self._auth_state == AuthState.AUTHENTICATED:
                return True  # another worker already restored the session
            await self._login(page)
            post = await self._sync_state(page, status)

        if post in (AuthState.MFA_REQUIRED, AuthState.CAPTCHA):
            return self._halt(post, "Second factor required after login")
        if post == AuthState.BLOCKED:
            return self._trip_breaker()
        if post in (AuthState.LOGIN_PAGE, AuthState.EXPIRED):
            self.log.warning("[warning]Authentication did not succeed (check credentials)[/]")
            return True
        # Left the login page without a wall -> the session is established.
        self._was_authenticated = True
        self.log.info("[success]Authenticated session established[/]")
        return True

    async def _login(self, page) -> None:
        """Perform the login form submission only (state is judged by the caller)."""
        try:
            # Re-fetch the login page each time so any single-use CSRF token read
            # from the live DOM is current; the browser submits hidden token fields
            # with the form automatically once we fill and click.
            await self._safe_goto(page, self.config.login_url)
            form = await self._locator.locate(page)
            if form and form.is_actionable():
                tokens = TokenManager.discover(form)
                names = ", ".join(t["name"] for t in tokens if t["name"]) or "none"
                self.log.info(f"[info]Login form auto-detected (CSRF field(s): {names})[/]")
                await page.fill(form.username, self.config.username, timeout=4000)
                await page.fill(form.password, self.config.password, timeout=4000)
                await page.click(form.submit, timeout=4000)
            else:
                self.log.debug("[muted]Auto-detection inconclusive; using configured selectors[/]")
                await page.fill(self.config.username_selector, self.config.username, timeout=4000)
                await page.fill(self.config.password_selector, self.config.password, timeout=4000)
                await page.click(self.config.submit_selector, timeout=4000)
            await self._wait_idle(page)
        except Exception as exc:
            self.log.warning(f"[warning]Auto-login failed: {exc}[/]")

    def _halt(self, state: AuthState, reason: str) -> bool:
        if not self._stop:
            self._stop = True
            self._halt_reason = state
            self.log.warning(
                f"[danger]HALT: {reason} - outside the scope of automated authentication. "
                f"Supply an established session via --cookies to continue.[/]"
            )
        return False

    def _trip_breaker(self) -> bool:
        # Circuit breaker: a few blocking responses are tolerated; sustained
        # blocking stops the engine so it never hammers the target.
        self._block_count += 1
        self.log.warning(f"[warning]BLOCKED signal {self._block_count}/{self._block_threshold} "
                         f"(rate-limit / WAF)[/]")
        if self._block_count >= self._block_threshold:
            self._stop = True
            self._halt_reason = AuthState.BLOCKED
            self.log.warning("[danger]HALT: target is blocking the scanner - backing off.[/]")
        return False

    def _attach_status(self, page) -> dict:
        # Track the latest main-document HTTP status for the state classifier.
        holder = {"status": None}

        def on_response(response):
            try:
                if response.request.resource_type == "document":
                    holder["status"] = response.status
            except Exception:
                pass

        page.on("response", on_response)
        return holder

    # -- network interception -------------------------------------------------

    def _on_request(self, captured: list[dict], request) -> None:
        try:
            captured.append({
                "url": request.url,
                "method": request.method,
                "headers": dict(request.headers),
                "post_data": request.post_data,
                "resource_type": request.resource_type,
            })
        except Exception:
            pass

    def _handle_request(self, request: dict) -> None:
        url = request.get("url")
        if not url or not self._in_scope(url):
            return
        if request.get("resource_type") in _SKIP_RESOURCE:
            return
        method = (request.get("method") or "GET").upper()
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))
        data = self._parse_body(request.get("post_data")) if method != "GET" else {}
        if not params and not data:
            return
        endpoint = Endpoint(
            url=url, method=method, params=params, data=data,
            headers=self._filter_headers(request.get("headers")),
            source=request.get("resource_type") or "xhr",
        )
        self._endpoints.setdefault(endpoint.key(), endpoint)

    @staticmethod
    def _parse_body(body) -> dict:
        if not body:
            return {}
        body = body.strip()
        if body[:1] in "{[":
            try:
                import json

                obj = json.loads(body)
                if isinstance(obj, dict):
                    return {k: str(v) for k, v in obj.items() if isinstance(v, (str, int, float, bool))}
            except Exception:
                return {}
        return dict(parse_qsl(body))

    @staticmethod
    def _filter_headers(headers) -> dict:
        out = {}
        for key, value in (headers or {}).items():
            low = key.lower()
            if low in _KEEP_HEADERS or low.startswith("x-"):
                out[key] = value
        return out

    # -- page helpers ---------------------------------------------------------

    async def _clickables(self, page) -> list[dict]:
        try:
            return await page.evaluate("window.__xnavClickables ? window.__xnavClickables() : []")
        except Exception:
            return []

    async def _state(self, page) -> str:
        try:
            return await page.evaluate("window.__xnavState ? window.__xnavState() : location.href")
        except Exception:
            return page.url

    async def _safe_goto(self, page, url: str) -> bool:
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=int(self.config.timeout * 1000))
            await self._wait_idle(page)
            return True
        except Exception as exc:
            self.log.debug(f"[muted]Navigation to {url} failed: {exc}[/]")
            return False

    async def _wait_idle(self, page, short: bool = False) -> None:
        try:
            await page.wait_for_load_state("networkidle", timeout=3000 if short else int(self.config.timeout * 1000))
        except Exception:
            pass

    async def _drain_popup(self, page) -> None:
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=5000)
        except Exception:
            pass
        finally:
            try:
                await page.close()
            except Exception:
                pass

    # -- scope ----------------------------------------------------------------

    @staticmethod
    def _registrable_domain(netloc: str) -> str:
        host = netloc.split("@")[-1].split(":")[0].lower()
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            labels = host.split(".")
            return ".".join(labels[-2:]) if len(labels) >= 2 else host

    def _in_scope(self, url: str) -> bool:
        host = (urlparse(url).hostname or "").lower()
        return bool(host) and (host == self._apex or host.endswith("." + self._apex))

    # -- browser lifecycle ----------------------------------------------------

    async def _setup(self) -> bool:
        try:
            from playwright.async_api import async_playwright
            import random

            self._pw = await async_playwright().start()
            self._browser = await self._pw.chromium.launch(
                headless=self.config.headless,
                args=["--no-sandbox", "--disable-blink-features=AutomationControlled"],
            )
            self._context = await self._browser.new_context(
                user_agent=random.choice(_MODERN_UA),
                locale="en-US",
                viewport={"width": 1366, "height": 768},
                ignore_https_errors=not self.config.verify_tls,
            )
            await self._context.add_init_script(_INIT_JS)
            self._page_sem = asyncio.Semaphore(self._workers)
            self.log.info("[info]Deep navigation engine:[/] stateful SPA exploration online")
            return True
        except Exception as exc:
            self.log.warning(f"[warning]Deep navigation unavailable ({type(exc).__name__})[/]")
            await self._teardown()
            return False

    async def _export_session(self) -> None:
        # Browsers omit Cookie from request.headers, so pull the live session from
        # the context to hand to the (httpx-based) fuzzer for authenticated targets.
        if self._context is None:
            return
        try:
            cookies = await self._context.cookies()
            self.session_cookie = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
        except Exception:
            pass

    async def _teardown(self) -> None:
        for closer in (
            getattr(self._context, "close", None),
            getattr(self._browser, "close", None),
            getattr(self._pw, "stop", None),
        ):
            if closer is not None:
                try:
                    await closer()
                except Exception:
                    pass
        self._context = self._browser = self._pw = None
