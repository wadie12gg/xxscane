from __future__ import annotations

import asyncio

from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from xsscane.core.async_http import AsyncHttpClient
from xsscane.core.config import ScanConfig
from xsscane.core.models import Endpoint, Finding
from xsscane.modules.crawler import AsyncCrawler
from xsscane.modules.fuzzer import AsyncFuzzer
from xsscane.modules.navigator import DeepNavigationEngine
from xsscane.payloads.generator import PolymorphicPayloadGenerator
from xsscane.utils.logger import console, get_logger


class DeepScanEngine:
    """Two-phase asynchronous deep scan: crawl the target into a map, then fuzz
    every discovered field with context-aware payloads. Runs its own event loop so
    the synchronous CLI can call it like any other scanner."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.log = get_logger(verbose=config.verbose)
        self.payloads = PolymorphicPayloadGenerator(config.evasion_level)

    def run(self) -> list[Finding]:
        return asyncio.run(self._run())

    async def _run(self) -> list[Finding]:
        http = AsyncHttpClient(self.config, self.log)
        try:
            console.print(
                Panel(
                    f"Deep scan of [info]{self.config.url}[/]  "
                    f"depth={self.config.max_depth} pages={self.config.max_pages} "
                    f"concurrency={self.config.concurrency} "
                    f"interactions={self.config.max_interactions}",
                    title="Phase 1 / 2 — Deep Discovery",
                    border_style="cyan",
                )
            )
            with Progress(
                SpinnerColumn(),
                TextColumn("[cyan]Crawling[/]"),
                BarColumn(),
                TextColumn("[green]{task.fields[pages]}[/] pages · "
                           "[green]{task.fields[eps]}[/] endpoints"),
                TimeElapsedColumn(),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task("crawl", total=self.config.max_pages, pages=0, eps=0)

                def crawl_progress(pages: int, eps: int) -> None:
                    progress.update(task, completed=min(pages, self.config.max_pages),
                                    pages=pages, eps=eps)

                endpoints = await AsyncCrawler(self.config, http, self.log).crawl(
                    progress_cb=crawl_progress
                )

            if self.config.deep_nav:
                with console.status("[info]Deep navigation (stateful SPA exploration)...[/]", spinner="dots"):
                    engine = DeepNavigationEngine(self.config, self.log)
                    nav_endpoints = await engine.run()
                endpoints = self._merge(endpoints, nav_endpoints)
                if engine.session_cookie:
                    http.set_cookie_header(engine.session_cookie)
                    self.log.info("[info]Reusing authenticated session for fuzzing[/]")

            if self.config.mine_params:
                mined = await asyncio.to_thread(self._mine_seed)
                if mined:
                    endpoints = self._merge(endpoints, mined)

            console.print(Panel("Context-aware fuzzing", title="Phase 2 / 2", border_style="cyan"))
            with Progress(
                SpinnerColumn(),
                TextColumn("[cyan]Fuzzing[/]"),
                BarColumn(),
                TextColumn("[green]{task.completed}[/] fields probed"),
                TimeElapsedColumn(),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task("fuzz", total=None)

                def fuzz_progress(done: int, total: int) -> None:
                    progress.update(task, total=total, completed=done)

                findings = await AsyncFuzzer(self.config, http, self.payloads, self.log).fuzz(
                    endpoints, progress_cb=fuzz_progress
                )
        finally:
            await http.aclose()

        return self._dedupe(findings)

    @staticmethod
    def _merge(primary: list[Endpoint], extra: list[Endpoint]) -> list[Endpoint]:
        merged = {endpoint.key(): endpoint for endpoint in primary}
        for endpoint in extra:
            merged.setdefault(endpoint.key(), endpoint)
        return list(merged.values())

    def _mine_seed(self) -> list[Endpoint]:
        """Reflection-mine hidden parameters on the seed URL (runs in a worker
        thread so the sync miner never blocks the event loop)."""
        from urllib.parse import parse_qsl, urlparse

        from xsscane.core.http_client import HttpClient
        from xsscane.modules.paramminer import ParamMiner

        http = HttpClient(self.config, self.log)
        existing = {n for n, _ in parse_qsl(urlparse(self.config.url).query)}
        found = ParamMiner(self.config, http, self.log).mine(self.config.url, "GET", existing=existing)
        if not found:
            return []
        return [Endpoint(self.config.url, "GET", params={n: "1" for n in found}, source="mined")]

    @staticmethod
    def _dedupe(findings: list[Finding]) -> list[Finding]:
        seen = set()
        unique = []
        for finding in findings:
            if finding.key() not in seen:
                seen.add(finding.key())
                unique.append(finding)
        return unique
