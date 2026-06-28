from __future__ import annotations

import logging

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

_THEME = Theme(
    {
        "info": "cyan",
        "success": "bold green",
        "warning": "yellow",
        "danger": "bold red",
        "muted": "dim",
    }
)

# Single shared console so log output, status lines and the rich report never
# fight over the TTY.
console = Console(theme=_THEME)

# Severity -> colour for the real-time vulnerability lines.
_SEV_COLOR = {"HIGH": "bold red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim"}


def _emit(icon: str, message: str) -> None:
    # The icon brackets are escaped (\[) so rich renders a literal "[+]" etc.
    console.print(f"{icon} {message}", highlight=False)


def good(message: str) -> None:
    """A positive result / completed milestone."""
    _emit(r"[bold green]\[+][/]", message)


def info(message: str) -> None:
    """An informational step."""
    _emit(r"[bold cyan]\[*][/]", message)


def warn(message: str) -> None:
    _emit(r"[bold yellow]\[!][/]", message)


def bad(message: str) -> None:
    _emit(r"[bold red]\[-][/]", message)


def vuln(finding) -> None:
    """Print a vulnerability the moment it is confirmed (pentest-style `[+]`)."""
    sev = finding.severity.value
    color = _SEV_COLOR.get(sev, "white")
    _emit(
        r"[bold green]\[+][/]",
        f"[{color}]{sev}[/] XSS  ·  [bold]{finding.scanner}[/]  ·  "
        f"param=[cyan]{finding.parameter}[/]  ·  {finding.url}",
    )


class _IconFormatter(logging.Formatter):
    """Prefix every log line with a coloured status icon instead of a timestamp /
    level word, for a clean security-tool look."""

    _ICON = {
        logging.DEBUG: r"[dim]\[~][/]",
        logging.INFO: r"[bold cyan]\[*][/]",
        logging.WARNING: r"[bold yellow]\[!][/]",
        logging.ERROR: r"[bold red]\[-][/]",
        logging.CRITICAL: r"[bold red]\[x][/]",
    }

    def format(self, record: logging.LogRecord) -> str:
        icon = self._ICON.get(record.levelno, r"[bold cyan]\[*][/]")
        return f"{icon} {record.getMessage()}"


def get_logger(name: str = "xsscane", verbose: bool = False) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        logger.setLevel(logging.DEBUG if verbose else logging.INFO)
        return logger

    handler = RichHandler(
        console=console,
        show_time=False,
        show_level=False,
        show_path=False,
        rich_tracebacks=True,
        markup=True,
    )
    handler.setFormatter(_IconFormatter())
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.propagate = False
    return logger
