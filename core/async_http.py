from __future__ import annotations

import asyncio
import logging
import random
from typing import Optional

import httpx

from xsscane.core.config import ScanConfig
from xsscane.core.http_client import _REFERERS, _USER_AGENTS


class AsyncHttpClient:
    """Asyncio HTTP transport built on httpx for high-throughput crawling and
    fuzzing. Concurrency is bounded by a semaphore and every request carries a
    freshly rotated client fingerprint."""

    def __init__(self, config: ScanConfig, logger: logging.Logger, concurrency: Optional[int] = None):
        self.config = config
        self.log = logger
        limit = concurrency or config.concurrency
        self._semaphore = asyncio.Semaphore(limit)

        transport = httpx.AsyncHTTPTransport(
            retries=config.retries,
            verify=config.verify_tls,
            proxy=config.proxy,
            limits=httpx.Limits(max_connections=limit * 2, max_keepalive_connections=limit),
        )
        base_headers = dict(config.custom_headers)
        if config.cookies:
            base_headers["Cookie"] = config.cookies

        self._client = httpx.AsyncClient(
            transport=transport,
            headers=base_headers,
            timeout=config.timeout,
            follow_redirects=True,
        )

        # Politeness: global request pacing + Retry-After backoff.
        rate = max(0.0, getattr(config, "rate_limit", 0.0))
        self._min_interval = (1.0 / rate) if rate > 0 else 0.0
        self._rate_lock = asyncio.Lock()
        self._next_slot = 0.0

    def _stealth_headers(self) -> dict[str, str]:
        octet = lambda: random.randint(1, 254)
        spoofed_ip = f"{octet()}.{octet()}.{octet()}.{octet()}"
        return {
            "User-Agent": random.choice(_USER_AGENTS),
            "X-Forwarded-For": spoofed_ip,
            "X-Real-IP": spoofed_ip,
            "Referer": random.choice(_REFERERS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }

    async def request(self, method: str, url: str, data=None, headers=None) -> Optional[httpx.Response]:
        merged = self._stealth_headers()
        if headers:
            merged.update(headers)

        response = None
        for attempt in range(self.config.retries + 1):
            await self._pace()
            async with self._semaphore:
                try:
                    response = await self._client.request(method.upper(), url, data=data, headers=merged)
                except httpx.HTTPError as exc:
                    self.log.debug(f"[muted]Async request failed {method} {url}: {exc}[/]")
                    return None
            if response.status_code == 429 and attempt < self.config.retries:
                wait = self._retry_after(response)
                self.log.debug(f"[muted]429 from {url}; honouring Retry-After ~{wait:.1f}s[/]")
                await asyncio.sleep(wait)
                continue
            break

        if self.config.delay:
            await asyncio.sleep(self.config.delay)
        return response

    async def _pace(self) -> None:
        # Assign each request the next evenly-spaced slot, then sleep until it.
        if self._min_interval <= 0:
            return
        loop = asyncio.get_event_loop()
        async with self._rate_lock:
            slot = max(loop.time(), self._next_slot)
            self._next_slot = slot + self._min_interval
        delay = slot - loop.time()
        if delay > 0:
            await asyncio.sleep(delay)

    @staticmethod
    def _retry_after(response: httpx.Response) -> float:
        raw = response.headers.get("retry-after")
        if raw:
            try:
                return min(float(raw), 60.0)
            except ValueError:
                try:
                    from datetime import datetime
                    from email.utils import parsedate_to_datetime

                    when = parsedate_to_datetime(raw)
                    return min(max((when - datetime.now(when.tzinfo)).total_seconds(), 0.0), 60.0)
                except Exception:
                    pass
        return 5.0

    async def text(self, method: str, url: str, data=None, headers=None) -> Optional[str]:
        response = await self.request(method, url, data=data, headers=headers)
        return response.text if response is not None else None

    def set_cookie_header(self, value: str) -> None:
        """Adopt a session cookie obtained elsewhere (e.g. a browser auth flow)."""
        if value:
            self._client.headers["Cookie"] = value

    async def aclose(self) -> None:
        await self._client.aclose()
