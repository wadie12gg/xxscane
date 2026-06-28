"""End-to-end integration tests: real engines against an in-process vulnerable
server. Browser-free (no Playwright), so they run in CI."""

import re
import socket
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from xsscane.core.config import ScanConfig
from xsscane.core.deep_engine import DeepScanEngine
from xsscane.core.http_client import HttpClient
from xsscane.core.models import Confidence
from xsscane.core.scanner import Scanner
from xsscane.modules.paramminer import ParamMiner
from xsscane.utils.logger import get_logger

_COMMENTS: list[str] = []


def _page(body: str) -> bytes:
    return f"<!doctype html><html><body>{body}</body></html>".encode()


class _Vuln(BaseHTTPRequestHandler):
    def _send(self, body: bytes, code: int = 200):
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()  # deliberately no security headers (for the passive engine)
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        if u.path == "/":
            q = qs.get("q", [""])[0]
            self._send(_page(f"<div>Results for: {q}</div><a href='/search?name=x'>s</a>"))
        elif u.path == "/search":
            self._send(_page(f"<p>Hello {qs.get('name', [''])[0]}</p>"))
        elif u.path == "/hidden":
            self._send(_page(f"<p>debug={qs.get('debug', [''])[0]}</p>"))  # only 'debug' reflects
        elif u.path == "/comment":
            stored = "".join(f"<div>{c}</div>" for c in _COMMENTS)
            self._send(_page(f"<form method=post action=/comment>"
                             f"<textarea name=text></textarea></form>{stored}"))
        elif u.path == "/blind":
            self._send(_page("<form method=post action=/blind><textarea name=text></textarea></form>"))
        else:
            self._send(_page("404"), code=404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        u = urlparse(self.path)
        if u.path == "/comment":
            _COMMENTS.append(body.get("text", [""])[0])
            self._send(_page("saved"))
        elif u.path == "/blind":
            text = body.get("text", [""])[0]
            # Act as a victim browser: load any embedded resource (incl. protocol-
            # relative //host/path), firing the out-of-band callback.
            for url in re.findall(r"(?:https?:)?//[^\s\"'<>]+", text):
                try:
                    urllib.request.urlopen("http:" + url if url.startswith("//") else url, timeout=3)
                except Exception:
                    pass
            self._send(_page("thanks"))
        else:
            self._send(_page("404"), code=404)

    def log_message(self, *a):
        pass


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="module")
def server():
    port = _free_port()
    httpd = ThreadingHTTPServer(("127.0.0.1", port), _Vuln)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()
    httpd.server_close()


def _cfg(url, **kw):
    base = dict(waf_detect=False, retries=1, timeout=6, threads=4)
    base.update(kw)
    return ScanConfig(url=url, **base)


def _confirmed(findings):
    return [f for f in findings if f.confidence == Confidence.CONFIRMED]


def test_reflected_engine(server):
    findings = Scanner(_cfg(f"{server}/?q=test", scan_types=["reflected"])).run()
    assert _confirmed(findings), "reflected XSS should be confirmed on ?q"


def test_stored_engine(server):
    findings = Scanner(_cfg(f"{server}/comment", scan_types=["stored"], method="POST",
                            data="text=test", stored_view_url=f"{server}/comment")).run()
    assert _confirmed(findings), "stored XSS should be confirmed on the comment form"


def test_passive_engine(server):
    findings = Scanner(_cfg(f"{server}/", scan_types=["passive"])).run()
    assert findings, "passive engine should flag the missing security headers"


def test_deep_crawl_and_fuzz(server):
    cfg = _cfg(f"{server}/", scan_types=[], deep_scan=True, render_limit=0,
               max_pages=8, max_depth=2, concurrency=4, jitter_min=0.0, jitter_max=0.0)
    findings = DeepScanEngine(cfg).run()
    assert _confirmed(findings), "crawl+fuzz should reach /search?name and confirm XSS"


def test_blind_oast_engine(server):
    port = _free_port()
    cfg = _cfg(f"{server}/blind", scan_types=["blind"], oast_url=f"http://127.0.0.1:{port}",
               oast_listen=f"127.0.0.1:{port}", oast_wait=6)
    findings = Scanner(cfg).run()
    assert _confirmed(findings), "blind XSS should be confirmed via the OAST callback"


def test_param_mining_unit(server):
    cfg = _cfg(f"{server}/hidden")
    found = ParamMiner(cfg, HttpClient(cfg, get_logger()), get_logger()).mine(f"{server}/hidden")
    assert "debug" in found, "the hidden 'debug' parameter should be discovered"


def test_param_mining_end_to_end(server):
    findings = Scanner(_cfg(f"{server}/hidden", scan_types=["reflected"], mine_params=True)).run()
    assert any(f.parameter == "debug" for f in _confirmed(findings)), \
        "mining should surface 'debug' and the reflected engine should confirm XSS in it"
