from __future__ import annotations

import asyncio
import logging
import re
from enum import Enum
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from xsscane.core.async_http import AsyncHttpClient
from xsscane.core.config import ScanConfig
from xsscane.core.models import Confidence, Endpoint, Finding, Severity
from xsscane.payloads import occurrence
from xsscane.payloads.generator import PolymorphicPayloadGenerator
from xsscane.utils.logger import vuln

# Attributes whose value is a URL — a javascript:/data: value executes there.
_URI_ATTRS = {
    "href", "src", "action", "formaction", "data", "poster",
    "background", "cite", "longdesc", "xlink:href",
}
# Name of the attribute the reflection currently sits inside (last `name=` before it).
_CURRENT_ATTR = re.compile(r"""([a-zA-Z][\w:-]*)\s*=\s*["']?[^"'<>]*$""")


class Context(str, Enum):
    HTML = "html"
    ATTRIBUTE = "attribute"
    SCRIPT = "script"
    COMMENT = "comment"
    URI = "uri"


class AsyncFuzzer:
    """Context-aware XSS fuzzer. Per field: confirm reflection with a unique canary,
    classify the context it lands in, then fire only the breakouts for that context.
    Confirmed only when the executable breakout survives un-escaped (zero false positives)."""

    def __init__(
        self,
        config: ScanConfig,
        http: AsyncHttpClient,
        payloads: PolymorphicPayloadGenerator,
        logger: logging.Logger,
    ):
        self.config = config
        self.http = http
        self.payloads = payloads
        self.log = logger

    async def fuzz(self, endpoints: list[Endpoint], progress_cb=None) -> list[Finding]:
        tasks = []
        for endpoint in endpoints:
            for name in endpoint.params:
                tasks.append(self._fuzz_field(endpoint, name, in_body=False))
            for name in endpoint.data:
                tasks.append(self._fuzz_field(endpoint, name, in_body=True))

        if not tasks:
            self.log.info("[muted]No injectable fields discovered to fuzz[/]")
            return []

        self.log.info(f"[info]Fuzzing {len(tasks)} field(s) across the attack surface[/]")
        findings: list[Finding] = []
        done = 0
        # as_completed lets the progress bar advance live as each field finishes.
        for coro in asyncio.as_completed(tasks):
            findings.extend(await coro)
            done += 1
            if progress_cb is not None:
                progress_cb(done, len(tasks))
        return findings

    async def _fuzz_field(self, endpoint: Endpoint, name: str, in_body: bool) -> list[Finding]:
        source = endpoint.data if in_body else endpoint.params
        original = source.get(name, "")

        # Reuse captured auth headers (tokens, CSRF, cookies) so endpoints behind
        # authentication stay reachable; drop content-type so our own encoding wins.
        headers = {k: v for k, v in endpoint.headers.items() if k.lower() != "content-type"}

        # Canary detection + occurrence analysis in one probe: a unique token (rules
        # out cached/third-party responses) fenced around the structural characters,
        # so the same response tells us the context AND which characters survive.
        canary = self.payloads.token()
        probe = f"{original}{occurrence.survival_marker(canary)}"
        params, data = self._mutate(endpoint, name, in_body, probe)
        body = await self._send(endpoint.url, endpoint.method, params, data, headers)
        if not body or canary not in body:
            return []
        surviving = occurrence.surviving_chars(body, canary)

        findings: list[Finding] = []
        for context, quote in self._classify(body, canary):
            candidates = self.payloads.context_payloads(context.value, original, quote)
            viable = occurrence.select(candidates, surviving)  # drop impossible, smallest first
            if len(viable) != len(candidates):
                self.log.debug(
                    f"[muted]{name} {context.value}: {len(viable)}/{len(candidates)} breakouts "
                    f"viable (surviving: {''.join(sorted(surviving)) or 'none'})[/]"
                )
            for payload in viable:
                params, data = self._mutate(endpoint, name, in_body, payload.value)
                response = await self._send(endpoint.url, endpoint.method, params, data, headers)
                if response and payload.decoded.lower() in response.lower():
                    finding = Finding(
                        "fuzzer", endpoint.url, name, payload.value,
                        Severity.HIGH, Confidence.CONFIRMED,
                        f"{context.value} context breakout confirmed "
                        f"(canary {payload.canary}, source {endpoint.source})",
                        endpoint.method,
                    )
                    findings.append(finding)
                    vuln(finding)  # announce the hit in real time, mid-crawl
                    break
            if findings:
                break  # field proven vulnerable; stop spending requests on it
        return findings

    @staticmethod
    def _mutate(endpoint: Endpoint, name: str, in_body: bool, value: str) -> tuple[dict, dict]:
        params = dict(endpoint.params)
        data = dict(endpoint.data)
        (data if in_body else params)[name] = value
        return params, data

    # -- context analysis -----------------------------------------------------

    def _classify(self, body: str, canary: str) -> set[tuple[Context, str]]:
        contexts: set[tuple[Context, str]] = set()
        start = 0
        while True:
            index = body.find(canary, start)
            if index == -1:
                break
            context = self._context_at(body[:index])
            contexts.add(context)
            # A URL attribute is also a normal attribute: try a javascript: value
            # *and* a quote breakout, since either can yield execution.
            if context[0] is Context.URI:
                contexts.add((Context.ATTRIBUTE, context[1]))
            start = index + len(canary)
        return contexts

    def _context_at(self, prefix: str) -> tuple[Context, str]:
        """Determine the reflection context from the markup preceding the canary."""
        if prefix.rfind("<script") > prefix.rfind("</script"):
            return (Context.SCRIPT, "")
        if prefix.rfind("<!--") > prefix.rfind("-->"):
            return (Context.COMMENT, "")

        last_open = prefix.rfind("<")
        if last_open > prefix.rfind(">"):
            # Inside an unclosed tag -> attribute context. An odd number of a given
            # quote between the tag start and the canary means we are inside a value
            # delimited by that quote; otherwise the value is unquoted.
            tag = prefix[last_open:]
            quote = '"' if tag.count('"') % 2 == 1 else ("'" if tag.count("'") % 2 == 1 else "")
            match = _CURRENT_ATTR.search(tag)
            attribute = match.group(1).lower() if match else ""
            if attribute in _URI_ATTRS:
                return (Context.URI, quote)
            return (Context.ATTRIBUTE, quote)
        return (Context.HTML, "")

    # -- transport ------------------------------------------------------------

    async def _send(self, url: str, method: str, params: dict, data: dict, headers: dict | None = None) -> str | None:
        if method.upper() == "POST":
            target = self._merge_query(url, params) if params else url
            return await self.http.text("POST", target, data=data, headers=headers)
        return await self.http.text("GET", self._merge_query(url, params), headers=headers)

    @staticmethod
    def _merge_query(url: str, params: dict) -> str:
        parsed = urlparse(url)
        merged = dict(parse_qsl(parsed.query))
        merged.update(params)
        return urlunparse(parsed._replace(query=urlencode(merged)))
