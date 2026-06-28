from __future__ import annotations

from xsscane.core.models import Confidence, Finding, Severity
from xsscane.modules.base import BaseScanner
from xsscane.modules.dom import _SINK_HOOK

# Event-handler payloads: these fire through `innerHTML` (where <script> never
# runs), which is exactly how client-side stored XSS like xss-game level 2 works.
_FORM_PAYLOADS = [
    "<img src=x onerror=alert('{c}')>",
    "<svg onload=alert('{c}')>",
    "\"><img src=x onerror=alert('{c}')>",
    "'><img src=x onerror=alert('{c}')>",
]

_TEXT_FIELDS = ("input:not([type]), input[type=text], input[type=search], "
                "input[type=email], input[type=url], input[type=tel], textarea")


class DomFormScanner(BaseScanner):
    """Client-side stored / DOM XSS that only triggers through form interaction:
    fills each form's text fields with an event-handler payload in a real browser,
    submits, and confirms on execution (alert with the canary) or the canary reaching
    a sink like innerHTML — the input is never reflected by the server."""

    name = "domform"

    def scan(self) -> list[Finding]:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.log.warning(
                "[warning]Playwright not installed - skipping DOM form scan "
                "(pip install playwright && playwright install chromium)[/]"
            )
            return []

        findings: list[Finding] = []
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=self.config.headless)
            context = browser.new_context(ignore_https_errors=not self.config.verify_tls)
            context.add_init_script(_SINK_HOOK)
            try:
                count = self._form_count(context)
                if not count:
                    self.log.debug("[muted]No forms found for DOM form scan[/]")
                for index in range(count):
                    finding = self._fuzz_form(context, index)
                    if finding:
                        findings.append(finding)
            finally:
                browser.close()
        return findings

    def _form_count(self, context) -> int:
        page = context.new_page()
        try:
            page.goto(self.config.url, timeout=int(self.config.timeout * 1000), wait_until="load")
            return int(page.evaluate("document.querySelectorAll('form').length"))
        except Exception as exc:
            self.log.debug(f"[muted]DOM form load error {self.config.url}: {exc}[/]")
            return 0
        finally:
            page.close()

    def _fuzz_form(self, context, index: int) -> Finding | None:
        for template in _FORM_PAYLOADS:
            canary = self.payloads.token()
            payload = template.format(c=canary)
            evidence = self._submit_and_watch(context, index, payload, canary)
            if evidence:
                return Finding(
                    self.name, self.config.url, f"form#{index}", payload,
                    Severity.HIGH, Confidence.CONFIRMED,
                    f"Client-side execution after form submission via {evidence}", "FORM",
                )
        return None

    def _submit_and_watch(self, context, index: int, payload: str, canary: str):
        page = context.new_page()
        result = {"evidence": None}

        def on_dialog(dialog):
            if canary in (dialog.message or ""):
                result["evidence"] = f"alert('{dialog.message}')"
            dialog.dismiss()

        page.on("dialog", on_dialog)
        try:
            page.goto(self.config.url, timeout=int(self.config.timeout * 1000), wait_until="load")
            if not self._fill(page, index, payload):
                return None  # this form has no text fields to inject into
            self._submit(page, index)
            page.wait_for_timeout(1500)  # allow async storage/render (e.g. XHR) to run
            if not result["evidence"]:
                for hit in page.evaluate("window.__xss_hits || []"):
                    if canary in hit.get("data", ""):
                        result["evidence"] = f"sink {hit.get('sink')}"
                        break
        except Exception as exc:
            self.log.debug(f"[muted]DOM form submit error: {exc}[/]")
        finally:
            page.close()
        return result["evidence"]

    def _fill(self, page, index: int, payload: str) -> int:
        form = page.locator("form").nth(index)
        fields = form.locator(_TEXT_FIELDS)
        filled = 0
        for i in range(fields.count()):
            try:
                fields.nth(i).fill(payload, timeout=2000)
                filled += 1
            except Exception:
                continue
        return filled

    def _submit(self, page, index: int) -> None:
        form = page.locator("form").nth(index)
        button = form.locator("button[type=submit], input[type=submit], button")
        try:
            if button.count():
                # A real click fires the page's onsubmit handler (where the storage
                # and rendering happen); form.submit() would bypass it.
                button.first.click(timeout=3000, no_wait_after=True)
                return
        except Exception:
            pass
        try:
            page.evaluate(
                "(i) => { const f = document.querySelectorAll('form')[i];"
                " if (f) { f.requestSubmit ? f.requestSubmit() : f.submit(); } }",
                index,
            )
        except Exception:
            pass
