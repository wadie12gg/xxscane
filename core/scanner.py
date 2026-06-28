from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from xsscane.core.config import ScanConfig
from xsscane.core.http_client import HttpClient
from xsscane.core.models import Finding
from xsscane.modules.blind import BlindXssScanner
from xsscane.modules.dom import DomScanner
from xsscane.modules.domform import DomFormScanner
from xsscane.modules.passive import PassiveScanner
from xsscane.modules.reflected import ReflectedScanner
from xsscane.modules.stored import StoredScanner
from xsscane.payloads.generator import PolymorphicPayloadGenerator
from xsscane.utils.logger import console, get_logger, vuln

_REGISTRY = {
    ReflectedScanner.name: ReflectedScanner,
    StoredScanner.name: StoredScanner,
    DomScanner.name: DomScanner,
    DomFormScanner.name: DomFormScanner,
    BlindXssScanner.name: BlindXssScanner,
    PassiveScanner.name: PassiveScanner,
}


class Scanner:
    """Top-level orchestrator: wires shared services and runs the selected modules
    behind a live progress display, aggregating de-duplicated findings."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.log = get_logger(verbose=config.verbose)
        self.http = HttpClient(config, self.log)
        self.payloads = PolymorphicPayloadGenerator(config.evasion_level)

    def run(self) -> list[Finding]:
        modules = self._select_modules()
        if not modules:
            self.log.error("[danger]No valid scan modules selected[/]")
            return []

        if self.config.mine_params:
            self._apply_param_mining()

        self.log.info(
            f"[info]Target:[/] {self.config.url}  "
            f"[info]Modules:[/] {', '.join(m.name for m in modules)}  "
            f"[info]Evasion:[/] L{self.config.evasion_level}"
        )

        findings: list[Finding] = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("Scanning", total=len(modules))
            for module in modules:
                progress.update(task, description=f"Running [info]{module.name}[/] scanner")
                try:
                    found = module.scan()
                    findings.extend(found)
                    for finding in found:
                        vuln(finding)  # surface each hit the moment the module returns it
                except Exception as exc:
                    self.log.error(f"[danger]{module.name} scanner crashed: {exc}[/]")
                progress.advance(task)

        return self._dedupe(findings)

    def _select_modules(self):
        selected = []
        for name in self.config.scan_types:
            module_cls = _REGISTRY.get(name)
            if module_cls is None:
                self.log.warning(f"[warning]Unknown scan type ignored: {name}[/]")
                continue
            selected.append(module_cls(self.config, self.http, self.payloads, self.log))
        return selected

    def _apply_param_mining(self) -> None:
        """Discover hidden parameters and fold them into the scan surface so every
        module fuzzes them too."""
        from xsscane.modules.paramminer import ParamMiner

        miner = ParamMiner(self.config, self.http, self.log)
        if self.config.method == "POST":
            existing = {n for n, _ in parse_qsl(self.config.data or "")}
            found = miner.mine(self.config.url, "POST", existing=existing)
            if found:
                extra = "&".join(f"{name}=1" for name in found)
                self.config.data = f"{self.config.data}&{extra}" if self.config.data else extra
        else:
            existing = {n for n, _ in parse_qsl(urlparse(self.config.url).query)}
            found = miner.mine(self.config.url, "GET", existing=existing)
            if found:
                self.config.url = self._append_get_params(self.config.url, found)

    @staticmethod
    def _append_get_params(url: str, names: list[str]) -> str:
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))
        for name in names:
            params.setdefault(name, "1")
        return urlunparse(parsed._replace(query=urlencode(params)))

    @staticmethod
    def _dedupe(findings: list[Finding]) -> list[Finding]:
        seen = set()
        unique = []
        for finding in findings:
            if finding.key() not in seen:
                seen.add(finding.key())
                unique.append(finding)
        return unique
