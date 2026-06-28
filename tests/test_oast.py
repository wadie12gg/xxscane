import logging
import socket
import time

import requests

from xsscane.core.oast import OastServer, OastSession


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_oast_records_callback():
    port = _free_port()
    server = OastServer("127.0.0.1", port, logging.getLogger("t"))
    assert server.start()
    try:
        session = OastSession(f"http://127.0.0.1:{port}", server)
        token = session.token()
        assert session.callback(token) == f"127.0.0.1:{port}/{token}"

        requests.get(f"http://{session.callback(token)}", timeout=5)
        time.sleep(0.3)

        hits = server.hits(token)
        assert len(hits) == 1 and hits[0].token == token
        assert server.hits("never-seen") == []
    finally:
        server.stop()
