from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from xsscane.core.models import Confidence, Finding, Severity
from xsscane.modules.base import BaseScanner

# Injected before any page script. Wraps the dangerous DOM sinks so we can observe
# tainted data reaching them even when execution is suppressed or obfuscated, and
# records the call without breaking the original behaviour.
_SINK_HOOK = """
(() => {
  window.__xss_hits = [];
  const record = (sink, data) => { try { window.__xss_hits.push({sink, data: String(data)}); } catch (e) {} };

  const realWrite = document.write.bind(document);
  document.write = function (html) { record('document.write', html); return realWrite(html); };

  const realEval = window.eval;
  window.eval = function (code) { record('eval', code); return realEval(code); };

  const realSetTimeout = window.setTimeout;
  window.setTimeout = function (fn, t) { if (typeof fn === 'string') record('setTimeout', fn); return realSetTimeout(fn, t); };

  const desc = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
  if (desc && desc.set) {
    Object.defineProperty(Element.prototype, 'innerHTML', {
      configurable: true,
      get() { return desc.get.call(this); },
      set(value) { record('innerHTML', value); return desc.set.call(this, value); },
    });
  }
})();
"""

_FRAGMENT = "__fragment__"


class DomScanner(BaseScanner):
    """Detects DOM-based XSS by driving a real Chromium engine via Playwright,
    instrumenting the dangerous sinks and watching for actual JS execution."""

    name = "dom"

    def scan(self) -> list[Finding]:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.log.warning(
                "[warning]Playwright not installed - skipping DOM scan "
                "(pip install playwright && playwright install chromium)[/]"
            )
            return []

        findings: list[Finding] = []
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=self.config.headless)
            context = browser.new_context(ignore_https_errors=not self.config.verify_tls)
            context.add_init_script(_SINK_HOOK)
            try:
                for parameter in self._dom_points():
                    findings.extend(self._test(context, parameter))
            finally:
                browser.close()
        return findings

    def _dom_points(self) -> list[str]:
        params = [name for name, method in self._injection_points() if method == "GET"]
        params.append(_FRAGMENT)  # always probe location.hash sinks
        return params

    def _test(self, context, parameter: str) -> list[Finding]:
        findings: list[Finding] = []
        for payload in self.payloads.base_payloads():
            url = self._build_url(parameter, payload.value)
            evidence = self._execute(context, url, payload.canary)
            if evidence:
                label = "fragment" if parameter == _FRAGMENT else parameter
                findings.append(
                    Finding(
                        self.name, url, label, payload.value,
                        Severity.HIGH, Confidence.CONFIRMED,
                        f"Client-side execution via {evidence}", "GET",
                    )
                )
                break
        return findings

    def _build_url(self, parameter: str, value: str) -> str:
        parsed = urlparse(self.config.url)
        if parameter == _FRAGMENT:
            return urlunparse(parsed._replace(fragment=value))
        params = dict(parse_qsl(parsed.query))
        params[parameter] = value
        return urlunparse(parsed._replace(query=urlencode(params)))

    def _execute(self, context, url: str, canary: str):
        page = context.new_page()
        result = {"evidence": None}

        def on_dialog(dialog):
            if canary in (dialog.message or ""):
                result["evidence"] = f"alert('{dialog.message}')"
            dialog.dismiss()

        page.on("dialog", on_dialog)
        try:
            page.goto(url, timeout=int(self.config.timeout * 1000), wait_until="load")
            page.wait_for_timeout(800)
            if not result["evidence"]:
                for hit in page.evaluate("window.__xss_hits || []"):
                    if canary in hit.get("data", ""):
                        result["evidence"] = f"sink {hit.get('sink')}"
                        break
        except Exception as exc:
            self.log.debug(f"[muted]DOM navigation error {url}: {exc}[/]")
        finally:
            page.close()
        return result["evidence"]
