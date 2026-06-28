from __future__ import annotations

import logging
import random
import threading
import time
from typing import Optional

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from xsscane.core.config import ScanConfig

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]

_REFERERS = [
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://duckduckgo.com/",
    "https://t.co/",
    "https://www.linkedin.com/",
]


class HttpClient:
    """Resilient HTTP transport with connection pooling, retries and per-request
    fingerprint rotation."""

    def __init__(self, config: ScanConfig, logger: logging.Logger):
        self.config = config
        self.log = logger
        self.session = self._build_session()

        # Politeness: thread-safe request pacing (429/Retry-After handled by urllib3).
        rate = max(0.0, getattr(config, "rate_limit", 0.0))
        self._min_interval = (1.0 / rate) if rate > 0 else 0.0
        self._rate_lock = threading.Lock()
        self._next_slot = 0.0

    def _pace(self) -> None:
        if self._min_interval <= 0:
            return
        with self._rate_lock:
            slot = max(time.monotonic(), self._next_slot)
            self._next_slot = slot + self._min_interval
        delay = slot - time.monotonic()
        if delay > 0:
            time.sleep(delay)

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        retry = Retry(
            total=self.config.retries,
            connect=self.config.retries,
            read=self.config.retries,
            backoff_factor=0.6,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET", "POST"}),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry, pool_maxsize=max(self.config.threads * 2, 8))
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        if self.config.proxy:
            session.proxies = {"http": self.config.proxy, "https": self.config.proxy}
        if self.config.cookies:
            session.headers["Cookie"] = self.config.cookies
        session.headers.update(self.config.custom_headers)
        return session

    def _stealth_headers(self) -> dict[str, str]:
        # Rotating identity on every request defeats naive IP/rate-limiting and the
        # behavioural WAF heuristics that key on a static client fingerprint. The
        # spoofed forwarding headers also probe trust-the-proxy IP allowlists.
        octet = lambda: random.randint(1, 254)
        spoofed_ip = f"{octet()}.{octet()}.{octet()}.{octet()}"
        return {
            "User-Agent": random.choice(_USER_AGENTS),
            "X-Forwarded-For": spoofed_ip,
            "X-Real-IP": spoofed_ip,
            "X-Originating-IP": spoofed_ip,
            "Referer": random.choice(_REFERERS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
        }

    def request(self, method: str, url: str, data=None, extra_headers=None) -> Optional[requests.Response]:
        self._pace()
        headers = self._stealth_headers()
        if extra_headers:
            headers.update(extra_headers)
        try:
            response = self.session.request(
                method.upper(),
                url,
                data=data,
                headers=headers,
                timeout=self.config.timeout,
                verify=self.config.verify_tls,
                allow_redirects=True,
            )
        except requests.RequestException as exc:
            self.log.debug(f"[muted]Request failed {method} {url}: {exc}[/]")
            return None

        if self.config.delay:
            time.sleep(self.config.delay)
        return response

    def get(self, url: str) -> Optional[requests.Response]:
        return self.request("GET", url)

    def post(self, url: str, data) -> Optional[requests.Response]:
        return self.request("POST", url, data=data)
