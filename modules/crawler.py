from __future__ import annotations

import asyncio
import ipaddress
import itertools
import json
import logging
import random
import re
from urllib.parse import parse_qsl, urldefrag, urljoin, urlparse

from bs4 import BeautifulSoup

from xsscane.core.async_http import AsyncHttpClient
from xsscane.core.config import ScanConfig
from xsscane.core.models import Endpoint
from xsscane.utils.bloom import BloomFilter

# Modern desktop browser fingerprints across Windows, macOS and Linux, rotated
# per request to avoid a static, easily-blocked client signature.
_MODERN_UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
]

# Hides the headless automation tell-tales and hooks fetch / XMLHttpRequest so
# endpoints assembled at runtime are captured even if they never touch the DOM.
_STEALTH_JS = """
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3]});
window.__intercepted = [];
(() => {
  const push = (method, url, body) => {
    try { window.__intercepted.push({url: String(url), method: (method || 'GET').toUpperCase(),
                                     post_data: body ? String(body) : null}); } catch (e) {}
  };
  const origFetch = window.fetch;
  window.fetch = function (input, init) {
    try { push((init && init.method) || 'GET',
               (typeof input === 'string') ? input : input.url, init && init.body); } catch (e) {}
    return origFetch.apply(this, arguments);
  };
  const open = XMLHttpRequest.prototype.open;
  const send = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (m, u) { this.__m = m; this.__u = u; return open.apply(this, arguments); };
  XMLHttpRequest.prototype.send = function (b) { push(this.__m, this.__u, b); return send.apply(this, arguments); };
})();
"""

# Quoted absolute / protocol-relative / root-relative URLs embedded in scripts.
_JS_URL = re.compile(r"""['"]((?:https?:)?//[^'"\\\s]+|/[A-Za-z0-9_\-./?=&%]+)['"]""")
_LINK_SOURCES = (("a", "href"), ("link", "href"), ("area", "href"), ("iframe", "src"), ("script", "src"))
_INTERACTIVE = (
    "button, [role=button], [role=tab], [onclick], summary, select, "
    "[aria-haspopup], [data-toggle], [data-target], .tab, .dropdown-toggle"
)

# Path keywords that usually expose user input, and the static resources that do not.
_HIGH_VALUE = (
    "search", "profile", "login", "signin", "sign-in", "register", "signup",
    "account", "admin", "api", "graphql", "query", "comment", "feedback",
    "contact", "upload", "cart", "checkout", "user", "settings", "auth", "redirect",
)
_LOW_VALUE = ("/assets", "/static", "/img", "/images", "/css", "/js/", "/fonts", "/media", "/vendor")
_ASSET_EXT = (
    ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
    ".ttf", ".eot", ".mp4", ".webm", ".mp3", ".pdf", ".zip", ".gz", ".map",
)


class AsyncCrawler:
    """Browser-first SPA crawler: drives headless Chromium to run JS, exercises
    interactive elements as state transitions, and hooks fetch/XHR to recover
    endpoints absent from static HTML. Falls back to httpx + BeautifulSoup when the
    browser is unavailable. Bloom-filter dedup; priority queue favours input-rich paths."""

    def __init__(self, config: ScanConfig, http: AsyncHttpClient, logger: logging.Logger):
        self.config = config
        self.http = http
        self.log = logger

        self._seed = urlparse(config.url)
        self._apex = self._registrable_domain(self._seed.netloc)
        self._queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self._counter = itertools.count()
        self._seen = BloomFilter(capacity=max(config.max_pages * 20, 50_000))
        self._endpoints: dict[tuple, Endpoint] = {}
        self._pages = 0
        self._fetched = 0  # pages that actually returned content (vs. dead/timeout)

        self._pw = None
        self._browser = None
        self._context = None
        self._page_sem: asyncio.Semaphore | None = None
        self._browser_budget = 0
        self._progress_cb = None

    async def crawl(self, progress_cb=None) -> list[Endpoint]:
        self._progress_cb = progress_cb
        use_browser = await self._setup_browser()
        self._seen.add(self._canonical(self._seed))
        self._enqueue(self.config.url, 0)

        workers = [asyncio.create_task(self._worker(use_browser)) for _ in range(self.config.concurrency)]
        await self._queue.join()
        for worker in workers:
            worker.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        await self._teardown_browser()

        if self._fetched == 0:
            self.log.warning(
                f"[warning]Target unreachable: could not fetch any content from "
                f"{self.config.url} — the connection failed or timed out. "
                f"Check connectivity (is the host up and not firewalled?), "
                f"raise --timeout, or route through --proxy.[/]"
            )
        else:
            self.log.info(
                f"[info]Crawl complete:[/] {self._pages} page(s), "
                f"{len(self._endpoints)} endpoint(s), {len(self._seen)} URLs fingerprinted"
            )
        return list(self._endpoints.values())

    # -- crawl loop -----------------------------------------------------------

    async def _worker(self, use_browser: bool) -> None:
        while True:
            _, _, url, depth = await self._queue.get()
            try:
                if self._pages < self.config.max_pages and depth <= self.config.max_depth:
                    await self._throttle()
                    await self._process(url, depth, use_browser)
            except Exception as exc:
                self.log.debug(f"[muted]Crawl error {url}: {exc}[/]")
            finally:
                self._queue.task_done()

    async def _throttle(self) -> None:
        # Randomised inter-request delay (jitter) to slip under naive rate limits
        # while remaining efficient under concurrency.
        low, high = self.config.jitter_min, self.config.jitter_max
        if high > 0:
            await asyncio.sleep(random.uniform(min(low, high), max(low, high)))

    async def _process(self, url: str, depth: int, use_browser: bool) -> None:
        self._pages += 1
        html, captured = await self._fetch(url, use_browser)
        if html is None:
            return
        self._fetched += 1

        for request in captured:
            self._handle_request(request, depth)
        for link in self._links_from_html(url, html):
            self._consider_link(link, depth)
        for endpoint in self._endpoints_from_forms(url, html):
            self._record(endpoint)

        if self._progress_cb is not None:
            self._progress_cb(self._pages, len(self._endpoints))

    async def _fetch(self, url: str, use_browser: bool) -> tuple[str | None, list[dict]]:
        if use_browser and self._browser_budget > 0:
            self._browser_budget -= 1
            result = await self._render_and_explore(url)
            if result is not None:
                return result
            self.log.debug(f"[muted]Falling back to static fetch for {url}[/]")

        text = await self.http.text("GET", url)
        return (text, []) if text is not None else (None, [])

    # -- browser rendering + state machine ------------------------------------

    async def _render_and_explore(self, url: str) -> tuple[str, list[dict]] | None:
        async with self._page_sem:
            page = await self._context.new_page()
            captured: list[dict] = []
            page.on("request", lambda request: self._on_request(captured, request))
            page.on("popup", lambda popup: asyncio.create_task(self._drain_popup(popup)))
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=int(self.config.timeout * 1000))
                await self._wait_idle(page)
                navigations = await self._exercise_states(page)
                html = await page.content()

                for hit in await self._read_hooks(page):
                    captured.append(hit)
                for nav in navigations:
                    captured.append({"url": nav, "method": "GET", "post_data": None,
                                     "resource_type": "document", "source": "state"})
                return html, captured
            except Exception as exc:
                self.log.debug(f"[muted]Render failed {url}: {exc}[/]")
                return None
            finally:
                try:
                    await page.close()
                except Exception:
                    pass

    async def _exercise_states(self, page) -> list[str]:
        """Treat interactive widgets as state transitions: click each one, let any
        XHR/fetch fire (captured globally), and follow in-scope navigations."""
        navigations: list[str] = []
        try:
            handles = await page.query_selector_all(_INTERACTIVE)
        except Exception:
            return navigations

        base = page.url
        interactions = 0
        for handle in handles:
            if interactions >= self.config.max_interactions:
                break
            try:
                if not await handle.is_visible():
                    continue
                tag = (await handle.evaluate("el => el.tagName")).lower()
                if tag == "select":
                    options = await handle.query_selector_all("option")
                    for option in options[:3]:
                        value = await option.get_attribute("value")
                        if value is not None:
                            await handle.select_option(value=value)
                            await self._wait_idle(page, short=True)
                    interactions += 1
                    continue

                before = page.url
                await handle.click(timeout=1500, no_wait_after=True)
                interactions += 1
                await self._wait_idle(page, short=True)
                if page.url != before:
                    if self._in_scope(page.url):
                        navigations.append(page.url)
                    await page.goto(base, wait_until="domcontentloaded", timeout=int(self.config.timeout * 1000))
                    await self._wait_idle(page, short=True)
            except Exception:
                continue
        return navigations

    async def _read_hooks(self, page) -> list[dict]:
        try:
            hooks = await page.evaluate("window.__intercepted || []")
        except Exception:
            return []
        for hook in hooks:
            hook["resource_type"] = "xhr"
            hook["source"] = "hook"
        return hooks

    async def _wait_idle(self, page, short: bool = False) -> None:
        timeout = 3000 if short else int(self.config.timeout * 1000)
        try:
            await page.wait_for_load_state("networkidle", timeout=timeout)
        except Exception:
            pass  # long-poll / websockets never go idle; best effort only

    async def _drain_popup(self, page) -> None:
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=5000)
            if self._in_scope(page.url):
                self._enqueue(page.url, 0)
        except Exception:
            pass
        finally:
            try:
                await page.close()
            except Exception:
                pass

    @staticmethod
    def _on_request(captured: list[dict], request) -> None:
        try:
            captured.append({
                "url": request.url,
                "method": request.method,
                "post_data": request.post_data,
                "resource_type": request.resource_type,
                "source": "net",
            })
        except Exception:
            pass

    # -- discovery bookkeeping ------------------------------------------------

    def _handle_request(self, request: dict, depth: int) -> None:
        url = request.get("url")
        if not url or not self._in_scope(url):
            return
        method = (request.get("method") or "GET").upper()
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))
        data = {}
        body = request.get("post_data")
        if body and method != "GET":
            data = self._parse_body(body)

        if params or data:
            self._record(Endpoint(url, method, params=params, data=data,
                                   source=request.get("source", "xhr")))
        if method == "GET" and request.get("resource_type") in ("document", None):
            self._consider_link(url, depth)

    def _consider_link(self, url: str, depth: int) -> None:
        url = urldefrag(url)[0]
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not self._in_scope(url):
            return
        if self._is_asset(parsed.path):
            return
        if parsed.query:
            self._record(Endpoint(url, "GET", params=dict(parse_qsl(parsed.query)), source="link"))

        if self._seen.add(self._canonical(parsed)):
            return  # probably already queued/visited
        if depth + 1 <= self.config.max_depth and self._pages < self.config.max_pages:
            self._enqueue(url, depth + 1)

    def _record(self, endpoint: Endpoint) -> None:
        if self._in_scope(endpoint.url):
            self._endpoints.setdefault(endpoint.key(), endpoint)

    def _enqueue(self, url: str, depth: int) -> None:
        self._queue.put_nowait((self._priority(url), next(self._counter), url, depth))

    # -- parsing --------------------------------------------------------------

    def _links_from_html(self, base: str, html: str) -> list[str]:
        soup = BeautifulSoup(html, "html.parser")
        links = []
        for tag, attr in _LINK_SOURCES:
            for element in soup.find_all(tag):
                value = element.get(attr)
                if value:
                    links.append(urljoin(base, value))
        for match in _JS_URL.finditer(html):
            links.append(urljoin(base, match.group(1)))
        return links

    def _endpoints_from_forms(self, base: str, html: str) -> list[Endpoint]:
        soup = BeautifulSoup(html, "html.parser")
        endpoints = []
        for form in soup.find_all("form"):
            action = urljoin(base, form.get("action") or base)
            method = (form.get("method") or "GET").upper()
            method = method if method in ("GET", "POST") else "GET"
            fields = {}
            for field in form.find_all(["input", "textarea", "select"]):
                name = field.get("name")
                if name:
                    fields[name] = field.get("value") or "1"
            if not fields:
                continue
            existing = dict(parse_qsl(urlparse(action).query))
            if method == "POST":
                endpoints.append(Endpoint(action, "POST", params=existing, data=fields, source="form"))
            else:
                existing.update(fields)
                endpoints.append(Endpoint(action, "GET", params=existing, source="form"))
        return endpoints

    @staticmethod
    def _parse_body(body: str) -> dict[str, str]:
        body = body.strip()
        if body[:1] in "{[":
            try:
                obj = json.loads(body)
                if isinstance(obj, dict):
                    return {k: str(v) for k, v in obj.items() if isinstance(v, (str, int, float, bool))}
            except Exception:
                pass
        return dict(parse_qsl(body))

    # -- scope / priority -----------------------------------------------------

    @staticmethod
    def _registrable_domain(netloc: str) -> str:
        host = netloc.split("@")[-1].split(":")[0].lower()
        try:
            ipaddress.ip_address(host)
            return host  # IP literals get exact-host scope, never a derived apex
        except ValueError:
            labels = host.split(".")
            return ".".join(labels[-2:]) if len(labels) >= 2 else host

    def _in_scope(self, url: str) -> bool:
        host = (urlparse(url).hostname or "").lower()
        return bool(host) and (host == self._apex or host.endswith("." + self._apex))

    @staticmethod
    def _is_asset(path: str) -> bool:
        return path.lower().endswith(_ASSET_EXT)

    def _priority(self, url: str) -> int:
        parsed = urlparse(url)
        path = parsed.path.lower()
        score = 50
        if any(keyword in path for keyword in _HIGH_VALUE):
            score -= 30
        if parsed.query:
            score -= 10
        if any(marker in path for marker in _LOW_VALUE):
            score += 30
        if self._is_asset(path):
            score += 40
        score += min(path.count("/") * 2, 12)  # gently deprioritise deep paths
        return max(0, score)

    @staticmethod
    def _canonical(parsed) -> str:
        names = ",".join(sorted(k for k, _ in parse_qsl(parsed.query)))
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{names}"

    # -- browser lifecycle ----------------------------------------------------

    async def _setup_browser(self) -> bool:
        try:
            from playwright.async_api import async_playwright

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
            await self._context.add_init_script(_STEALTH_JS)
            await self._context.route("**/*", self._route)
            await self._seed_session()
            self._page_sem = asyncio.Semaphore(min(self.config.concurrency, 6))
            self._browser_budget = self.config.render_limit
            self.log.info("[info]Crawler engine:[/] headless Chromium (JS render + state-machine + XHR hooks)")
            return True
        except Exception as exc:
            self.log.warning(
                f"[warning]Browser unavailable ({type(exc).__name__}); "
                f"using static httpx + BeautifulSoup crawl[/]"
            )
            await self._teardown_browser()
            return False

    async def _route(self, route) -> None:
        # Rewrite the identity on every outgoing request for per-request UA rotation.
        try:
            headers = dict(route.request.headers)
            headers["user-agent"] = random.choice(_MODERN_UA)
            headers["accept-language"] = "en-US,en;q=0.9"
            await route.continue_(headers=headers)
        except Exception:
            try:
                await route.continue_()
            except Exception:
                pass

    async def _seed_session(self) -> None:
        if not self.config.cookies:
            return
        host = self._seed.hostname
        cookies = []
        for pair in self.config.cookies.split(";"):
            if "=" in pair:
                name, value = pair.strip().split("=", 1)
                cookies.append({"name": name, "value": value, "domain": host, "path": "/"})
        if cookies:
            try:
                await self._context.add_cookies(cookies)
            except Exception as exc:
                self.log.debug(f"[muted]Could not seed cookies: {exc}[/]")

    async def _teardown_browser(self) -> None:
        if self._context is not None:
            try:
                await self._context.close()
            except Exception:
                pass
        if self._browser is not None:
            try:
                await self._browser.close()
            except Exception:
                pass
        if self._pw is not None:
            try:
                await self._pw.stop()
            except Exception:
                pass
        self._context = self._browser = self._pw = None
