from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from xsscane.core.config import ScanConfig
from xsscane.core.http_client import HttpClient
from xsscane.core.models import Finding
from xsscane.payloads.generator import PolymorphicPayloadGenerator


class BaseScanner(ABC):
    """Common plumbing shared by every detection module: parameter discovery and
    injection-point construction."""

    name = "base"

    def __init__(
        self,
        config: ScanConfig,
        http: HttpClient,
        payloads: PolymorphicPayloadGenerator,
        logger: logging.Logger,
    ):
        self.config = config
        self.http = http
        self.payloads = payloads
        self.log = logger

    @abstractmethod
    def scan(self) -> list[Finding]:
        ...

    def _injection_points(self) -> list[tuple[str, str]]:
        """Discover (parameter, method) pairs from the URL query and POST body."""
        points: list[tuple[str, str]] = []
        query = parse_qsl(urlparse(self.config.url).query)
        points.extend((name, "GET") for name, _ in query)
        if self.config.data:
            points.extend((name, "POST") for name, _ in parse_qsl(self.config.data))
        return points

    def _inject(self, parameter: str, method: str, value: str):
        """Return (url, data) with `value` placed into `parameter`."""
        if method == "POST":
            data = dict(parse_qsl(self.config.data or ""))
            data[parameter] = value
            return self.config.url, data

        parsed = urlparse(self.config.url)
        params = dict(parse_qsl(parsed.query))
        params[parameter] = value
        return urlunparse(parsed._replace(query=urlencode(params))), None
