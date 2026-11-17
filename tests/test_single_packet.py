"""Tests for core/single_packet.py.

The module's contract is narrow on purpose: it changes *delivery*, never
grading. These tests pin the wire behaviour (one sync flush, h2 framing,
withheld last byte) and the failure contract (`in_flight == 0` plus an error
so the caller grades `untested/no_overlap` instead of a clean run).
"""

import asyncio

import pytest

from core import single_packet


class FakeSock:
    def __init__(self, chunks=()):
        self.sent = []
        self.chunks = list(chunks)
        self.timeouts = []
        self.closed = False

    def sendall(self, data):
        self.sent.append(bytes(data))

    def settimeout(self, value):
        self.timeouts.append(value)

    def recv(self, size):
        return self.chunks.pop(0) if self.chunks else b""

    def close(self):
        self.closed = True


def _requests(count, body="", method="POST"):
    return [{"method": method, "path": f"/coupon/{index}", "query": "",
             "headers": {"X-Run": "1"}, "body": body}
            for index in range(count)]


# ── request shaping ──────────────────────────────────────────────

def test_h2_headers_strip_forbidden_and_pseudo_headers():
    headers = single_packet.build_h2_headers(
        "post", "https", "api.test", "/x?y=1",
        {"Host": "evil.test", "Connection": "keep-alive",
         "Transfer-Encoding": "chunked", "TE": "trailers",
         "Upgrade": "h2c", "X-Custom": " yes ", "Empty": ""})
    names = [name for name, _ in headers]
    assert names[:4] == [b":method", b":path", b":scheme", b":authority"]
    assert (b":method", b"POST") in headers
    assert dict(headers)[b":path"] == b"/x?y=1"
    for forbidden in (b"host", b"connection", b"transfer-encoding", b"te",
                      b"upgrade"):
        assert forbidden not in names
    assert dict(headers)[b"x-custom"] == b" yes "
    assert b"empty" not in names


def test_request_path_keeps_query_and_forces_leading_slash():
    assert single_packet.request_path({"path": "/a", "query": "b=1"}) == "/a?b=1"
    assert single_packet.request_path({"path": "a"}) == "/a"
    assert single_packet.request_path({}, "/fallback") == "/fallback"


def test_build_h1_request_adds_default_connection_only_when_absent():
    built = single_packet.build_h1_request(
        "POST", "/x", "h.test", {"X-A": "1"}, "a=1").decode()
    assert built.startswith("POST /x HTTP/1.1\r\nHost: h.test\r\n")
    assert "Connection: close\r\n" in built
    explicit = single_packet.build_h1_request(
        "GET", "/x", "h.test", {"Connection": "keep-alive"}, "").decode()
    assert explicit.count("Connection:") == 1


# ── h2 event ingestion ───────────────────────────────────────────

def test_ingest_h2_folds_status_body_and_end():
    import h2.events

    responses = {1: {"status": 0, "body": ""},
                 3: {"status": 0, "body": ""}}
    ended = set()
    single_packet.ingest_h2([
        h2.events.ResponseReceived(stream_id=1, headers=[(b":status", b"204")]),
        h2.events.DataReceived(stream_id=1, data=b"hi",
                               flow_controlled_length=2),
        h2.events.StreamEnded(stream_id=1),
        h2.events.ResponseReceived(stream_id=3, headers=[(b":status", b"x")]),
        h2.events.DataReceived(stream_id=99, data=b"ignored",
                               flow_controlled_length=7),
        h2.events.StreamReset(stream_id=3, error_code=8),
    ], responses, ended)
    assert responses[1] == {"status": 204, "body": "hi"}
    # An unparseable status is "no status", never a crash.
    assert responses[3] == {"status": 0, "body": ""}
    assert ended == {1, 3}


# ── h1 last-byte sync ────────────────────────────────────────────

def test_h1_withholds_last_byte_then_flushes_together():
    socks = []

    def connect(url, timeout=15):
        sock = FakeSock()
        socks.append(sock)
        return sock, "h.test"

    result = single_packet.h1_last_byte(
        "http://h.test/", _requests(3, body="a=1"),
        connect=connect, read=lambda sock, timeout=15: (200, "ok"))

    assert result["transport"] == "h1"
    assert result["in_flight"] == 3
    assert result["statuses"] == [200, 200, 200]
    for index, sock in enumerate(socks):
        assert len(sock.sent) == 2
        withheld, last = sock.sent
        expected = (
            f"POST /coupon/{index} HTTP/1.1\r\nHost: h.test\r\n"
            "X-Run: 1\r\nConnection: close\r\nContent-Length: 3\r\n\r\n"
            "a=1").encode()
        # The request is complete only once the withheld byte is written.
        assert withheld == expected[:-1]
        assert last == expected[-1:]
        assert last == b"1"
    assert all(sock.closed for sock in socks)


# ── h2 single packet ────────────────────────────────────────────

class FakeH2:
    def __init__(self, config=None):
        self.calls = []
        self._pending = [b"PREFACE"]

    def initiate_connection(self):
        self.calls.append(("init",))

    def data_to_send(self):
        out = b"".join(self._pending)
        self._pending = []
        return out

    def send_headers(self, stream_id, headers, end_stream=False):
        self.calls.append(("headers", stream_id, headers, end_stream))
        self._pending.append(b"H")

    def send_data(self, stream_id, data, end_stream=False):
        self.calls.append(("data", stream_id, data, end_stream))
        self._pending.append(b"D")

    def receive_data(self, data):
        return []


def test_h2_single_packet_sends_all_triggers_in_one_flush():
    sock = FakeSock()
    fake = FakeH2()

    result = single_packet.h2_single_packet(
        "https://api.test/", _requests(3, body="a=1"),
        connect=lambda url, timeout=15, alpn=None: (sock, "api.test"),
        h2_factory=lambda config=None: fake)

    assert result["transport"] == "h2"
    assert result["in_flight"] == 3
    assert sock.sent[0] == b"PREFACE"
    # Requests are opened (headers + body) without ending the stream, so the
    # server cannot act on any of them until the trigger flush.
    assert fake.calls[0] == ("init",)
    opened = fake.calls[1:-3]
    assert [call[0] for call in opened] == ["headers", "data"] * 3
    assert all(call[3] is False for call in opened)
    # The sync packet carries every END_STREAM trigger, back to back.
    triggers = fake.calls[-3:]
    assert [call[:2] for call in triggers] == [("data", 1), ("data", 3),
                                               ("data", 5)]
    assert all(call[2] == b"" and call[3] is True for call in triggers)
    assert sock.sent[-1] == b"DDD"


# ── failure contract ────────────────────────────────────────────

def test_send_returns_zero_in_flight_when_connect_fails():
    def connect(url, timeout=15, **kwargs):
        raise OSError("refused")

    result = single_packet.send("http://h.test/", _requests(2),
                                transport="h1", connect=connect)
    assert result["in_flight"] == 0
    assert result["requests"] == 2
    assert "OSError" in result["error"]


def test_send_zeroes_in_flight_when_a_response_never_arrives():
    def connect(url, timeout=15):
        return FakeSock(), "h.test"

    result = single_packet.send(
        "http://h.test/", _requests(2), transport="h1",
        connect=connect, read=lambda sock, timeout=15: (0, ""))
    assert result["in_flight"] == 0
    assert result["error"] == "incomplete_batch"


def test_send_empty_batch_is_not_a_delivery():
    result = single_packet.send("http://h.test/", [])
    assert result == {"transport": "auto", "statuses": [], "bodies": [],
                      "in_flight": 0, "requests": 0,
                      "error": "no_requests"}


def test_send_rejects_unknown_transport():
    result = single_packet.send("http://h.test/", _requests(1),
                                transport="quic")
    assert result["in_flight"] == 0
    assert "unknown transport quic" in result["error"]


def test_auto_picks_h1_for_cleartext_targets():
    def connect(url, timeout=15, **kwargs):
        assert kwargs.get("alpn") is None
        return FakeSock(), "h.test"

    result = single_packet.send(
        "http://h.test/", _requests(2), transport="auto",
        connect=connect, read=lambda sock, timeout=15: (201, "ok"))
    assert result["transport"] == "h1"
    assert result["in_flight"] == 2
    assert result["statuses"] == [201, 201]


def test_send_async_runs_off_the_loop():
    async def go():
        def connect(url, timeout=15, **kwargs):
            return FakeSock(), "h.test"
        return await single_packet.send_async(
            "http://h.test/", _requests(1), transport="h1",
            connect=connect, read=lambda sock, timeout=15: (200, "ok"))

    result = asyncio.run(go())
    assert result["in_flight"] == 1
    assert result["statuses"] == [200]


def test_split_target_defaults_ports_by_scheme():
    http = single_packet.split_target("http://h.test/a?b=1")
    https = single_packet.split_target("https://h.test")
    assert (http["port"], http["path"], http["query"]) == (80, "/a", "b=1")
    assert (https["port"], https["path"]) == (443, "/")


def test_build_h1_request_frames_a_body_exactly_once():
    built = single_packet.build_h1_request(
        "POST", "/x", "h.test", {"Content-Length": "3"}, "a=1") \
        .decode()
    assert built.count("Content-Length:") == 1
    # A caller-supplied framing wins; we never rewrite its body.
    assert built.endswith("\r\n\r\na=1")
    chunked = single_packet.build_h1_request(
        "POST", "/x", "h.test", {"Transfer-Encoding": "chunked"},
        "3\r\na=1\r\n0\r\n\r\n").decode()
    assert "Content-Length:" not in chunked
