from __future__ import annotations

import re

from bs4 import BeautifulSoup

from xsscane.core.models import Confidence, Finding, Severity
from xsscane.modules.base import BaseScanner

# Security headers whose absence weakens a site's defence against XSS.
_SECURITY_HEADERS = [
    ("content-security-policy", Severity.LOW, "No Content-Security-Policy (the strongest XSS mitigation)"),
    ("x-content-type-options", Severity.INFO, "No X-Content-Type-Options: nosniff"),
    ("x-frame-options", Severity.INFO, "No X-Frame-Options (clickjacking exposure)"),
]

# Attacker-controllable sources that taint a value once read.
_SOURCES = (
    "location.hash", "location.search", "location.href", "location.pathname",
    "document.url", "document.documenturi", "document.referrer", "window.name",
    "document.cookie", "localstorage", "sessionstorage", "event.data",
)

# Dangerous sinks: a tainted value reaching one of these can execute script.
_SINKS = [
    ("innerHTML", r"\.innerhtml\s*[=+]"),
    ("outerHTML", r"\.outerhtml\s*[=+]"),
    ("document.write", r"document\.write(?:ln)?\s*\("),
    ("insertAdjacentHTML", r"\.insertadjacenthtml\s*\("),
    ("eval", r"\beval\s*\("),
    ("setTimeout", r"\bsettimeout\s*\("),
    ("setInterval", r"\bsetinterval\s*\("),
    ("Function", r"\bfunction\s*\("),
    ("jQuery.html", r"\.html\s*\("),
    ("location assign", r"location\s*(?:\.href|\.assign|\.replace)\s*[=(]"),
]


class PassiveScanner(BaseScanner):
    """Payload-free pre-pass: one benign GET, then a static survey for missing
    security headers and DOM source->sink flows. Findings are advisory (INFO/LOW)."""

    name = "passive"

    def scan(self) -> list[Finding]:
        response = self.http.request("GET", self.config.url)
        if response is None:
            return []
        return self._headers(response) + self._dom_flows(response.text)

    def _headers(self, response) -> list[Finding]:
        present = {name.lower() for name in response.headers}
        findings = []
        for header, severity, description in _SECURITY_HEADERS:
            if header not in present:
                findings.append(
                    Finding(self.name, self.config.url, f"header:{header}", "-",
                            severity, Confidence.CONFIRMED, description, "GET")
                )
        return findings

    def _dom_flows(self, html: str) -> list[Finding]:
        scripts = [s.get_text() for s in BeautifulSoup(html, "html.parser").find_all("script")
                   if not s.get("src")]
        js = "\n".join(scripts).lower()
        findings, seen = [], set()
        for sink_name, sink_pattern in _SINKS:
            for match in re.finditer(sink_pattern, js):
                # Look at the value flowing into the sink (its RHS / argument).
                window = js[match.end():match.end() + 140]
                source = next((s for s in _SOURCES if s in window), None)
                key = (sink_name, source)
                if source and key not in seen:
                    seen.add(key)
                    findings.append(
                        Finding(
                            self.name, self.config.url, f"sink:{sink_name}", "-",
                            Severity.LOW, Confidence.POSSIBLE,
                            f"Potential DOM XSS: tainted source '{source}' flows into {sink_name}",
                            "DOM",
                        )
                    )
        return findings
