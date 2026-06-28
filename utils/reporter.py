from __future__ import annotations

from rich.panel import Panel
from rich.table import Table

from xsscane.core.models import Finding, Severity
from xsscane.utils.logger import console

_BANNER = r"""
 __  __  ____  ____    ____   ___    _    _  _
 \ \/ / / ___|/ ___|  / ___| / __|  / \  | \| |
  >  <  \___ \\___ \  \___ \| (__  / _ \ |    |
 /_/\_\  ____) |___) |  ___) |\___|/_/ \_\|_|\_|
        |____/|____/  |____/   modular xss engine
"""

_SEVERITY_STYLE = {
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def print_banner() -> None:
    from xsscane import __version__

    console.print(f"[bold magenta]{_BANNER}[/]")
    console.print(
        f"[dim]   v{__version__}[/]  [white]·[/]  [cyan]modular XSS detection suite[/]"
        f"  [white]·[/]  [yellow]authorised testing only[/]\n"
    )


def print_waf_result(result) -> None:
    if not result.detected:
        console.print(Panel("No WAF detected", title="WAF", border_style="green"))
        return
    body = f"[danger]{result.name}[/]  (confidence {result.confidence:.2f})"
    if result.indicators:
        body += "\n[muted]indicators:[/] " + ", ".join(result.indicators)
    console.print(Panel(body, title="WAF detected", border_style="yellow"))


def print_report(findings: list[Finding], target: str) -> None:
    if not findings:
        console.print(
            Panel(
                f"No XSS vulnerabilities detected on [info]{target}[/]",
                title="Result",
                border_style="green",
            )
        )
        return

    table = Table(title=f"XSS Findings - {target}", show_lines=True, header_style="bold white")
    table.add_column("#", justify="right", style="dim")
    table.add_column("Type")
    table.add_column("Parameter")
    table.add_column("Severity")
    table.add_column("Confidence")
    table.add_column("Payload", overflow="fold", max_width=44)
    table.add_column("Evidence", overflow="fold", max_width=38)

    for index, finding in enumerate(findings, 1):
        style = _SEVERITY_STYLE[finding.severity]
        table.add_row(
            str(index),
            finding.scanner,
            finding.parameter,
            f"[{style}]{finding.severity.value}[/]",
            finding.confidence.value,
            finding.payload,
            finding.evidence,
        )

    console.print(table)
    high = sum(1 for f in findings if f.severity == Severity.HIGH)
    console.print(
        Panel(
            f"[bold]{len(findings)}[/] finding(s)  -  [bold red]{high}[/] high severity",
            title="Summary",
            border_style="red" if high else "yellow",
        )
    )
