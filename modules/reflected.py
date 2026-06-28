from __future__ import annotations

import concurrent.futures as futures

from xsscane.core.evasion import AdaptiveEvader
from xsscane.core.models import Confidence, Finding, Severity
from xsscane.modules.base import BaseScanner

# Characters that must survive un-escaped for HTML/JS breakout to be possible.
_SPECIAL = "<>\"'"


class ReflectedScanner(BaseScanner):
    """Reflected XSS: profiles each parameter's reflection, fires only payloads whose
    breakout characters survive the filter, and—when a WAF blocks a payload—runs an
    adaptive evasion loop that learns which encoding gets through."""

    name = "reflected"

    def scan(self) -> list[Finding]:
        points = self._injection_points()
        if not points:
            self.log.info("[muted]No injectable parameters for reflected scan[/]")
            return []

        self._evader = AdaptiveEvader(self.log, getattr(self.config, "detected_waf", None))
        findings: list[Finding] = []
        with futures.ThreadPoolExecutor(max_workers=self.config.threads) as pool:
            for batch in pool.map(lambda p: self._test_parameter(*p), points):
                findings.extend(batch)
        if self._evader.bypasses:
            self.log.info(
                f"[info]Adaptive evasion: bypassed the WAF {self._evader.bypasses} time(s) "
                f"(learned transform: {self._evader.preferred})[/]"
            )
        return findings

    def _test_parameter(self, parameter: str, method: str) -> list[Finding]:
        allowed = self._reflection_profile(parameter, method)
        if allowed is None:
            return []

        findings: list[Finding] = []
        for payload in self.payloads.base_payloads():
            required = {c for c in payload.value if c in _SPECIAL}
            # If the raw breakout chars are filtered, escalate to the evasion engine.
            variants = [payload] if required.issubset(allowed) else self.payloads.mutate(payload)
            for variant in variants:
                finding = self._probe(parameter, method, variant)
                if finding:
                    findings.append(finding)
                    break

        confirmed = [f for f in findings if f.confidence == Confidence.CONFIRMED]
        if confirmed:
            return confirmed[:3]  # a few working vectors is enough; avoid flooding
        return findings[:1]

    def _reflection_profile(self, parameter: str, method: str):
        """Send a benign marker and record which special characters are reflected
        without encoding — this dictates which payloads are even worth sending.

        The probe characters are fenced between two unique sentinels so the survey
        reads only our reflection and never bleeds into the page's own markup."""
        head, tail = self.payloads.token(), self.payloads.token()
        response = self._send(parameter, method, f"{head}<\"'>{tail}")
        body = response.text if response is not None else None
        if not body or head not in body:
            return None
        start = body.find(head) + len(head)
        end = body.find(tail, start)
        region = body[start:end] if end != -1 else body[start:start + 8]
        allowed = {c for c in _SPECIAL if c in region}
        self.log.debug(
            f"[muted]{parameter}: raw chars reflected -> {''.join(sorted(allowed)) or 'none'}[/]"
        )
        return allowed

    def _probe(self, parameter: str, method: str, payload) -> Finding | None:
        response = self._send(parameter, method, payload.value)
        if response is None:
            return None
        if self._evader.is_blocked(response.status_code, response.text):
            return self._evade(parameter, method, payload)
        return self._classify_reflection(payload, response.text, method, parameter)

    def _evade(self, parameter: str, method: str, payload) -> Finding | None:
        """The payload was blocked by a WAF; try encoding transforms until one gets
        through, confirm against the response, and remember what worked so the next
        blocked payload starts with the winner."""
        self._evader.blocks += 1
        passed_through = None
        for name, variant in self._evader.variants(payload.value):
            response = self._send(parameter, method, variant)
            if response is None or self._evader.is_blocked(response.status_code, response.text):
                continue
            passed_through = passed_through or name
            finding = self._classify_reflection(payload, response.text, method, parameter,
                                                via=f", waf-bypass:{name}")
            if finding:
                self._evader.learn(name)
                self.log.debug(f"[muted]{parameter}: WAF bypass via {name}[/]")
                return finding
        if passed_through:
            self._evader.learn(passed_through)  # got through but didn't confirm here
        return None

    def _classify_reflection(self, payload, body: str, method: str, parameter: str,
                             via: str = "") -> Finding | None:
        # CONFIRMED only when the executable markup itself lands un-escaped. For an
        # encoded variant this is true only if the app decoded it back to live
        # markup, which is precisely the filter bypass we want to flag.
        if payload.decoded.lower() in body.lower():
            return Finding(
                self.name, self.config.url, parameter, payload.value,
                Severity.HIGH, Confidence.CONFIRMED,
                f"Executable markup reflected unescaped ({payload.technique}{via})", method,
            )
        if payload.canary in body:
            return Finding(
                self.name, self.config.url, parameter, payload.value,
                Severity.LOW, Confidence.POSSIBLE,
                f"Input reflected but markup neutralised ({payload.technique}{via})", method,
            )
        return None

    def _send(self, parameter: str, method: str, value: str):
        url, data = self._inject(parameter, method, value)
        return self.http.request(method, url, data=data)
