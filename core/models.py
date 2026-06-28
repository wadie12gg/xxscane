from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    CONFIRMED = "CONFIRMED"
    PROBABLE = "PROBABLE"
    POSSIBLE = "POSSIBLE"


@dataclass
class Finding:
    """A single vulnerability observation produced by a scanner module."""

    scanner: str
    url: str
    parameter: str
    payload: str
    severity: Severity
    confidence: Confidence
    evidence: str = ""
    method: str = "GET"

    def key(self) -> tuple:
        """Identity used to de-duplicate findings across modules."""
        return (self.scanner, self.url, self.parameter, self.payload)


@dataclass
class InputField:
    name: str
    type: str = "text"
    value: str = ""


@dataclass
class Form:
    """An HTML form discovered by the crawler and fuzzed as a single unit."""

    action: str
    method: str = "GET"
    inputs: list[InputField] = field(default_factory=list)

    def key(self) -> tuple:
        return (self.action, self.method, tuple(sorted(i.name for i in self.inputs)))


@dataclass
class Endpoint:
    """An injectable request discovered during crawling.

    ``params`` are query-string fields; ``data`` are form/body fields. ``source``
    records how it was found (link, form, xhr, hook, state)."""

    url: str
    method: str = "GET"
    params: dict[str, str] = field(default_factory=dict)
    data: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    source: str = "link"

    def key(self) -> tuple:
        from urllib.parse import urlsplit

        parts = urlsplit(self.url)
        return (
            parts.netloc,
            parts.path,
            self.method,
            tuple(sorted(self.params)),
            tuple(sorted(self.data)),
        )
