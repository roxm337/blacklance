"""Raw-socket desync primitives (no network)."""

import asyncio

from core import http_smuggle


class FakeSocket:
    def __init__(self, chunks=None):
        self.chunks = list(chunks or [])
        self.sent = b""
        self.closed = False

    def sendall(self, data):
        self.sent += data

    def recv(self, size):
        return self.chunks.pop(0) if self.chunks else b""

    def settimeout(self, timeout):
        pass

    def close(self):
        self.closed = True


def test_prefixes_carry_conflicting_framing_and_the_marker():
    te_cl = http_smuggle.smuggle_prefix("te_cl", "t.test", "/", "M")
    assert "Transfer-Encoding: chunked" in te_cl
    assert "Content-Length: 6" in te_cl
    assert "GET /M" not in te_cl
    assert "GPOST /M" in te_cl

    cl_te = http_smuggle.smuggle_prefix("cl_te", "t.test", "/", "M")
    assert "Content-Length: 4" in cl_te
    assert "GPOST /M" in cl_te


def test_strict_rejection_is_not_ambiguous():
    assert http_smuggle.is_ambiguous(400) == (False, "strict rejection (HTTP 400)")
    assert http_smuggle.is_ambiguous(501)[0] is False
    assert http_smuggle.is_ambiguous(200)[0] is True


def test_read_response_consumes_the_declared_body():
    sock = FakeSocket([b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhe",
                       b"llo"])
    status, text = http_smuggle.read_response(sock)
    assert status == 200
    assert text.endswith("hello")


def _probe(reads, sent=None):
    class Sock(FakeSocket):
        def __init__(self):
            super().__init__()
            self.sent = sent or b""

    sock = Sock()

    def connect(url, timeout=20):
        return sock, "t.test"

    def read(s, timeout=10):
        return reads.pop(0) if reads else (0, "")

    return asyncio.run(http_smuggle.desync_probe(
        "http://t.test/", "cl_te", connect=connect, read=read)), sock


def test_ghost_echo_proves_desync(monkeypatch):
    monkeypatch.setattr(http_smuggle.secrets, "token_hex",
                        lambda n: "deadbeef")
    outcome, sock = _probe([(200, "ok"), (200, "hopefully404-deadbeef")])
    proven, note, marker = outcome
    assert proven is True
    assert "own request" in note
    assert marker in sock.sent.decode("latin-1")


def test_three_responses_prove_desync_without_an_echo():
    outcome, _ = _probe([(200, "a"), (200, "b"), (404, "c")])
    proven, note, _marker = outcome
    assert proven is True
    assert "3 responses for 2 requests" in note


def test_clean_endpoint_is_negative():
    outcome, _ = _probe([(200, "a"), (0, "")])
    proven, note, _marker = outcome
    assert proven is False
    assert "responses" in note


def test_connect_failure_is_a_negative_not_an_exception():
    def connect(url, timeout=20):
        raise OSError("nope")

    proven, note, _marker = asyncio.run(http_smuggle.desync_probe(
        "http://t.test/", "cl_te", connect=connect, read=lambda *a, **k: (0, "")))
    assert proven is False
    assert "connect failed" in note
