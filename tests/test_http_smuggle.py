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


# ── TE obfuscation variants ─────────────────────────────────────

def test_plain_variant_is_the_historical_byte_sequence():
    for mode in ("cl_te", "te_cl"):
        default = http_smuggle.smuggle_prefix(mode, "t.test", "/", "M")
        pinned = http_smuggle.smuggle_prefix(mode, "t.test", "/", "M",
                                             variant="plain")
        assert default == pinned
        assert "Transfer-Encoding: chunked\r\n" in default


def test_every_te_variant_keeps_the_framing_disagreement():
    expected_cl = {"cl_te": "Content-Length: 4", "te_cl": "Content-Length: 6"}
    for variant in http_smuggle.DEFAULT_TE_VARIANTS:
        if variant == "plain":
            continue
        for mode, cl in expected_cl.items():
            request = http_smuggle.smuggle_prefix(
                mode, "t.test", "/", "M", variant=variant)
            assert cl in request
            assert "GPOST /M HTTP/1.1" in request
            # The point of the variant: the chunked line is spelled so one
            # parser accepts it and the other does not.
            assert request.count("\r\n") > 6
            assert request != http_smuggle.smuggle_prefix(
                mode, "t.test", "/", "M")


def test_variants_are_capped_before_plain():
    assert http_smuggle.variants(1) == ["plain"]
    assert http_smuggle.variants(3) == ["plain", "xchunked",
                                        "space_before_colon"]
    assert http_smuggle.variants(0) == list(http_smuggle.DEFAULT_TE_VARIANTS)
    assert len(http_smuggle.variants(0)) == len(
        http_smuggle.DEFAULT_TE_VARIANTS)


def test_desync_probe_writes_the_variant_it_was_given():
    outcome, sock = _probe_with_variant("dup_x_chunked")
    proven, _note, _marker = outcome
    assert proven is False
    sent = sock.sent.decode("latin-1")
    assert "Transfer-Encoding: x\r\n" in sent
    assert "Transfer-Encoding: chunked\r\n" in sent


def _probe_with_variant(variant):
    sock = FakeSocket()

    def connect(url, timeout=20):
        return sock, "t.test"

    def read(s, timeout=10):
        return reads.pop(0) if reads else (0, "")

    reads = [(400, "")]
    return asyncio.run(http_smuggle.desync_probe(
        "http://t.test/", "cl_te", connect=connect, read=read,
        variant=variant)), sock


# ── h2c ────────────────────────────────────────────────────────

def test_h2c_probe_skips_tls_without_a_connection(monkeypatch):
    calls = []
    monkeypatch.setattr(http_smuggle, "connection",
                        lambda *a, **k: calls.append(a))
    assert asyncio.run(http_smuggle.h2c_supported("https://t.test/")) == (
        False, "not_cleartext")
    assert calls == []


def test_h2c_probe_recognises_a_settings_frame(monkeypatch):
    sock = FakeSocket([b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"])
    monkeypatch.setattr(http_smuggle, "connection",
                        lambda url, timeout=10: (sock, "t.test"))
    supported, note = asyncio.run(http_smuggle.h2c_supported(
        "http://t.test/"))
    assert supported is True
    assert "SETTINGS" in note
    assert sock.sent.startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
    assert sock.closed is True


def test_h2c_probe_rejects_a_non_settings_frame(monkeypatch):
    sock = FakeSocket([b"\x00\x00\x00\x03\x00\x00\x00\x00\x00"])
    monkeypatch.setattr(http_smuggle, "connection",
                        lambda url, timeout=10: (sock, "t.test"))
    assert asyncio.run(http_smuggle.h2c_supported("http://t.test/")) == (
        False, "unexpected frame type 3")


def test_h2c_probe_reports_a_silent_peer(monkeypatch):
    sock = FakeSocket([])
    monkeypatch.setattr(http_smuggle, "connection",
                        lambda url, timeout=10: (sock, "t.test"))
    assert asyncio.run(http_smuggle.h2c_supported("http://t.test/")) == (
        False, "no frame header")
