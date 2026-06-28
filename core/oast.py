from __future__ import annotations

import logging
import secrets
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

# 1x1 transparent GIF returned to every probe so an injected <img>/<script> that
# loads our callback resolves cleanly instead of erroring loudly on the victim.
_PIXEL = bytes.fromhex("47494638396101000100800000000000ffffff21f90401000000002c00000000010001000002024401003b")


@dataclass
class Interaction:
    """A single out-of-band hit recorded by the listener."""

    token: str
    remote_ip: str
    method: str
    path: str
    user_agent: str
    at: float


class _OastHandler(BaseHTTPRequestHandler):
    def _handle(self) -> None:
        # The correlation token is the first path segment: /<token>[/...]
        token = self.path.strip("/").split("/")[0].split("?")[0]
        self.server.oast.record(  # type: ignore[attr-defined]
            Interaction(
                token=token,
                remote_ip=self.client_address[0],
                method=self.command,
                path=self.path,
                user_agent=self.headers.get("User-Agent", ""),
                at=time.time(),
            )
        )
        self.send_response(200)
        self.send_header("Content-Type", "image/gif")
        self.send_header("Content-Length", str(len(_PIXEL)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(_PIXEL)
            except Exception:
                pass

    do_GET = do_POST = do_HEAD = do_OPTIONS = _handle

    def log_message(self, *args) -> None:  # silence the default stderr logging
        pass


class OastServer:
    """Self-hosted out-of-band listener. Records every inbound request keyed by the
    correlation token in its path, so a stored/blind payload that later loads
    `//<host>/<token>` from any victim browser proves execution."""

    def __init__(self, host: str, port: int, logger: logging.Logger):
        self.host = host
        self.port = port
        self.log = logger
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._interactions: dict[str, list[Interaction]] = {}
        self.total = 0

    def start(self) -> bool:
        try:
            self._server = ThreadingHTTPServer((self.host, self.port), _OastHandler)
        except OSError as exc:
            self.log.warning(f"[warning]Could not bind OAST listener on {self.host}:{self.port}: {exc}[/]")
            return False
        self._server.oast = self  # type: ignore[attr-defined]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self.log.info(f"[info]OAST listener up on {self.host}:{self.port}[/]")
        return True

    def stop(self) -> None:
        if self._server is not None:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:
                pass
            self._server = None

    def record(self, interaction: Interaction) -> None:
        with self._lock:
            self._interactions.setdefault(interaction.token, []).append(interaction)
            self.total += 1

    def hits(self, token: str) -> list[Interaction]:
        with self._lock:
            return list(self._interactions.get(token, []))


class OastSession:
    """Mints correlation tokens and builds the scheme-relative callback target the
    payloads embed (`//<host>[/<base path>]/<token>`)."""

    def __init__(self, base_url: str, server: OastServer):
        raw = base_url if "://" in base_url else f"http://{base_url}"
        parsed = urlparse(raw)
        self._netloc = parsed.netloc
        self._path = parsed.path.rstrip("/")
        self.server = server

    @staticmethod
    def token() -> str:
        return secrets.token_hex(8)

    def callback(self, token: str) -> str:
        """Host[/path]/token — embedded as `//{callback}` so it works under both
        http and https targets."""
        return f"{self._netloc}{self._path}/{token}"

    def hits(self, token: str) -> list[Interaction]:
        return self.server.hits(token)
