"""TE.CL desync oracle: a ghost request must answer on the same socket."""

import asyncio
import socketserver
import sys
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.http_smuggling import HTTPSmuggling
from state.manager import StateManager


class _Backend(socketserver.StreamRequestHandler):
    """A back end that frames by Content-Length (the TE.CL victim side)."""

    def handle(self):
        if self.server.strict:
            head = b""
            while b"\r\n\r\n" not in head and len(head) < 65536:
                chunk = self.rfile.readline()
                if not chunk:
                    return
                head += chunk
            if b"transfer-encoding" in head.lower() and \
                    b"content-length" in head.lower():
                self._reply(400, b"strict parser")
                return
            self._reply(200, b"ok")
            return
        while True:
            line = self.rfile.readline()
            if not line:
                return
            if not line.strip():
                continue
            parts = line.decode("latin-1").split()
            if len(parts) < 2:
                return
            path = parts[1]
            headers = {}
            while True:
                raw = self.rfile.readline()
                if raw in (b"\r\n", b"\n", b""):
                    break
                key, _, value = raw.decode("latin-1").partition(":")
                headers.setdefault(key.strip().lower(), []).append(
                    value.strip())
            length = int(headers.get("content-length", ["0"])[0])
            self.rfile.read(length)
            if "hopefully404" in path:
                self._reply(404, path.encode())
            else:
                self._reply(200, b"ok")

    def _reply(self, status: int, body: bytes):
        self.wfile.write(
            f"HTTP/1.1 {status} X\r\nContent-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n".encode() + body)
        self.wfile.flush()


def _serve(strict: bool):
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Backend)
    server.daemon_threads = True
    server.strict = strict
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


_REAL_READ = HTTPSmuggling._read_response


def _fast_read(sock):
    return _REAL_READ(sock, timeout=1)


def _module(port: int):
    config = {
        "target": {"domain": "acme.com"},
        "modules": {"http_smuggling": {"te_cl": True}},
        "waf": {},
        "paths": {}, "auth": {},
    }
    return HTTPSmuggling(
        StateManager(str(Path(tempfile.mkdtemp()) / "acme.com")), config)


def test_te_cl_prefix_keeps_the_framing_disagreement():
    prefix = HTTPSmuggling._smuggle_prefix(
        "te_cl", "acme.com", "/", "marker123")
    assert "Content-Length: 6\r\n" in prefix
    assert "Transfer-Encoding: chunked\r\n" in prefix
    assert "0\r\n\r\nGPOST /marker123" in prefix
    cl_te = HTTPSmuggling._smuggle_prefix(
        "cl_te", "acme.com", "/", "marker123")
    assert "Content-Length: 4\r\n" in cl_te and "5c\r\n" in cl_te


def test_te_cl_backend_answering_the_ghost_is_confirmed(monkeypatch):
    monkeypatch.setattr(
        HTTPSmuggling, "_read_response",
        staticmethod(lambda sock, timeout=10: _fast_read(sock)))
    server = _serve(strict=False)
    try:
        module = _module(server.server_address[1])
        target = f"http://127.0.0.1:{server.server_address[1]}/"
        proven = asyncio.run(module._desync_oracle(target, "te_cl"))
    finally:
        server.shutdown()
        server.server_close()
    assert proven is True
    finding = module.state.findings["findings"][0]
    assert finding["title"].startswith("HTTP Request Desync Confirmed (TE.CL)")
    assert finding["verification"]["method"] == "te_cl_desync_oracle"


def test_strict_backend_does_not_produce_a_finding(monkeypatch):
    monkeypatch.setattr(
        HTTPSmuggling, "_read_response",
        staticmethod(lambda sock, timeout=10: _fast_read(sock)))
    server = _serve(strict=True)
    try:
        module = _module(server.server_address[1])
        target = f"http://127.0.0.1:{server.server_address[1]}/"
        proven = asyncio.run(module._desync_oracle(target, "te_cl"))
    finally:
        server.shutdown()
        server.server_close()
    assert proven is False
    assert module.state.findings["findings"] == []
