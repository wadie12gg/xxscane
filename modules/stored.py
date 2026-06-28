from __future__ import annotations

from xsscane.core.models import Confidence, Finding, Severity
from xsscane.modules.base import BaseScanner


class StoredScanner(BaseScanner):
    """Detects stored/persistent XSS: submit a payload through each parameter, then
    re-fetch the rendering endpoint and confirm the payload survived round-trip."""

    name = "stored"

    def scan(self) -> list[Finding]:
        points = self._injection_points()
        if not points:
            self.log.info("[muted]No parameters available for stored scan[/]")
            return []

        view_url = self.config.stored_view_url or self.config.url
        findings: list[Finding] = []
        for parameter, method in points:
            for payload in self.payloads.base_payloads():
                if not self._submit(parameter, method, payload.value):
                    continue
                body = self._fetch(view_url)
                if body and payload.decoded.lower() in body.lower():
                    findings.append(
                        Finding(
                            self.name, view_url, parameter, payload.value,
                            Severity.HIGH, Confidence.CONFIRMED,
                            f"Payload persisted and rendered at {view_url}", method,
                        )
                    )
                    break  # parameter proven vulnerable, move on
        return findings

    def _submit(self, parameter: str, method: str, value: str) -> bool:
        url, data = self._inject(parameter, method, value)
        return self.http.request(method, url, data=data) is not None

    def _fetch(self, url: str):
        response = self.http.request("GET", url)
        return response.text if response is not None else None
