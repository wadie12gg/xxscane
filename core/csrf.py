from __future__ import annotations

import logging
import math
from collections import Counter
from urllib.parse import urljoin

from bs4 import BeautifulSoup

_TOKEN_KEYWORDS = (
    "csrf", "xsrf", "token", "nonce", "authenticity",
    "verification", "_token", "requestverificationtoken",
)
_NON_INPUT_TYPES = {"submit", "button", "image", "file", "reset"}


class CsrfManager:
    """Extracts anti-CSRF tokens and hidden form state so a state-changing request
    carries a valid, *fresh* token; without it a protected endpoint rejects every
    probe and the scan misses the vulnerability."""

    def __init__(self, http, logger: logging.Logger):
        self.http = http
        self.log = logger

    # -- token heuristics -----------------------------------------------------

    @staticmethod
    def _entropy(value: str) -> float:
        if not value:
            return 0.0
        length = len(value)
        return -sum((c / length) * math.log2(c / length) for c in Counter(value).values())

    @classmethod
    def is_token(cls, name: str, value: str) -> bool:
        name = (name or "").lower()
        if any(keyword in name for keyword in _TOKEN_KEYWORDS):
            return True
        return bool(value) and len(value) >= 16 and cls._entropy(value) > 3.5

    # -- form discovery -------------------------------------------------------

    def forms(self, url: str) -> list[dict]:
        """Fetch `url` and return one descriptor per form:
        {index, action, method, text_fields, hidden, has_token}."""
        response = self.http.request("GET", url)
        if response is None:
            return []
        return self._parse(response.text, url)

    def _parse(self, html: str, base_url: str) -> list[dict]:
        soup = BeautifulSoup(html, "html.parser")
        forms = []
        for index, form in enumerate(soup.find_all("form")):
            action = urljoin(base_url, form.get("action") or base_url)
            method = (form.get("method") or "GET").upper()
            text_fields, hidden, has_token = {}, {}, False
            for element in form.find_all(["input", "textarea", "select"]):
                name = element.get("name")
                if not name:
                    continue
                field_type = (element.get("type") or "text").lower()
                value = element.get("value") or ""
                if field_type == "hidden":
                    hidden[name] = value
                    if self.is_token(name, value):
                        has_token = True
                elif field_type not in _NON_INPUT_TYPES:
                    text_fields[name] = value or "test"
            forms.append({
                "index": index,
                "action": action,
                "method": method if method in ("GET", "POST") else "GET",
                "text_fields": text_fields,
                "hidden": hidden,
                "has_token": has_token,
            })
        return forms

    def fresh_hidden(self, url: str, index: int) -> dict:
        """Re-fetch the page and return the current hidden fields for form #index, so
        a single-use CSRF token is still valid at submission time."""
        for form in self.forms(url):
            if form["index"] == index:
                return form["hidden"]
        return {}
