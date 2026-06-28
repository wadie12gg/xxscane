from __future__ import annotations

import logging
import secrets
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from xsscane.core.config import ScanConfig

# Common parameter names worth probing when a target exposes none. Curated from
# real-world reflected inputs: search boxes, redirects, debug toggles, callbacks.
WORDLIST = (
    "q", "query", "search", "s", "keyword", "keywords", "term", "name", "id",
    "page", "p", "view", "action", "do", "cmd", "command", "func", "function",
    "redirect", "redirect_uri", "redirecturl", "redir", "return", "returnurl",
    "return_url", "next", "url", "uri", "link", "goto", "dest", "destination",
    "continue", "callback", "jsonp", "cb", "ref", "referer", "referrer", "from",
    "debug", "test", "demo", "preview", "lang", "language", "locale", "country",
    "file", "filename", "path", "dir", "folder", "doc", "document", "template",
    "tpl", "theme", "skin", "style", "include", "inc", "load", "module", "content",
    "data", "value", "val", "input", "output", "msg", "message", "text", "title",
    "subject", "body", "comment", "description", "desc", "note", "email", "user",
    "username", "account", "profile", "uid", "userid", "user_id", "token", "key",
    "code", "hash", "format", "type", "mode", "sort", "order", "orderby", "filter",
    "category", "cat", "tag", "tags", "date", "start", "end", "limit", "offset",
    "count", "num", "number", "size", "width", "height", "color", "show", "hide",
    "display", "echo", "render", "html", "xml", "json", "status", "state", "step",
    "tab", "section", "src", "source", "target", "host", "domain", "site", "city",
    "address", "phone", "first_name", "last_name", "fullname",
)


class ParamMiner:
    """Discovers hidden query/body parameters by reflection: submits a batch of
    candidate names, each carrying a unique token, and keeps the names whose token
    comes back in the response. Surfaces inputs that are never linked or in a form —
    a frequent home for reflected XSS (Arjun / ParamMiner style)."""

    _CHUNK = 40

    def __init__(self, config: ScanConfig, http, logger: logging.Logger):
        self.config = config
        self.http = http
        self.log = logger

    def mine(self, url: str, method: str = "GET", existing=None) -> list[str]:
        existing = set(existing or ())
        candidates = [w for w in dict.fromkeys(WORDLIST) if w not in existing]
        found: list[str] = []
        for start in range(0, len(candidates), self._CHUNK):
            chunk = candidates[start:start + self._CHUNK]
            tokens = {name: self._token() for name in chunk}
            # Two control names that don't exist: if their tokens reflect, the server
            # echoes arbitrary params and reflection-mining can't be trusted here.
            controls = {f"zzc{secrets.token_hex(5)}": self._token() for _ in range(2)}
            body = self._probe(url, method, {**tokens, **controls})
            if not body or any(tok in body for tok in controls.values()):
                continue
            found.extend(name for name, tok in tokens.items() if tok in body)

        if found:
            self.log.info(
                f"[success]Parameter mining: {len(found)} hidden param(s) reflected: "
                f"{', '.join(found)}[/]"
            )
        else:
            self.log.info("[muted]Parameter mining: no hidden parameters reflected[/]")
        return found

    @staticmethod
    def _token() -> str:
        return "z" + secrets.token_hex(4)

    def _probe(self, url: str, method: str, params: dict) -> str | None:
        if method.upper() == "POST":
            base = dict(parse_qsl(self.config.data or ""))
            base.update(params)
            response = self.http.request("POST", url, data=base)
        else:
            response = self.http.request("GET", self._merge_query(url, params))
        return response.text if response is not None else None

    @staticmethod
    def _merge_query(url: str, params: dict) -> str:
        parsed = urlparse(url)
        merged = dict(parse_qsl(parsed.query))
        merged.update(params)
        return urlunparse(parsed._replace(query=urlencode(merged)))
