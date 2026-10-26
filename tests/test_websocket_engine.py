"""I7 WebSocket engine tests: URL resolution, header composition, captured
message templates, frame extraction, and a real loopback handshake/frame
round-trip through aiohttp. No external network."""

from __future__ import annotations

import asyncio
import json

from aiohttp import web

from tools import websocket_engine as ws


class FakeIdentity:
    def __init__(self, name="alice", cookies=None, headers=None):
        self.name = name
        self.cookies = cookies or {}
        self.headers = headers or {}

    def request_headers(self):
        return {"Authorization": f"Bearer {self.name}", **self.headers}


def test_ws_url_resolution():
    assert ws.ws_url("https://x.example", "/ws") == "wss://x.example/ws"
    assert ws.ws_url("http://127.0.0.1:8503", "ws") == "ws://127.0.0.1:8503/ws"
    assert ws.ws_url("https://x.example", "wss://other.example/s") \
        == "wss://other.example/s"
    assert ws.ws_url("", "") == ""


def test_build_headers_cookie_origin_and_extra():
    ident = FakeIdentity(cookies={"sid": "abc"})
    headers = ws.build_headers(ident, origin="https://evil.example",
                               extra={"X-Trace": "1"})
    assert headers["Authorization"] == "Bearer alice"
    assert headers["Cookie"] == "sid=abc"
    assert headers["Origin"] == "https://evil.example"
    assert headers["X-Trace"] == "1"

    bare = ws.build_headers(None)
    assert bare == {}


def test_captured_sockets_groups_and_drops_redacted():
    events = [
        {"kind": "ws_open", "url": "wss://x/ws", "page_url": "https://x/",
         "identity": {"name": "alice"}},
        {"kind": "ws_frame", "url": "wss://x/ws", "direction": "sent",
         "payload": '{"type":"read","id":1}', "opcode": "text"},
        {"kind": "ws_frame", "url": "wss://x/ws", "direction": "sent",
         "payload": '{"token":"<redacted>"}', "opcode": "text"},
        {"kind": "ws_frame", "url": "wss://x/ws", "direction": "sent",
         "payload": "<binary 4 bytes>", "opcode": "binary"},
        {"kind": "ws_frame", "url": "wss://x/ws", "direction": "received",
         "payload": '{"name":"secret"}', "opcode": "text"},
    ]
    sockets = ws.captured_sockets(events)
    assert len(sockets) == 1
    assert sockets[0]["url"] == "wss://x/ws"
    assert sockets[0]["identity"]["name"] == "alice"
    assert sockets[0]["messages"] == ['{"type":"read","id":1}']


def test_socket_session_first_value_traverses_frames():
    session = ws.SocketSession(url="wss://x/ws", status=101, accepted=True,
                               frames=[
                                   ws.Frame("received", '{"status":"ok"}'),
                                   ws.Frame("received",
                                            '{"data":{"name":"seed-1"}}'),
                               ])
    extract = {"type": "jsonpath", "path": "data.name"}
    assert session.first_value(extract) == "seed-1"
    assert session.first_value({"type": "jsonpath", "path": "missing"}) is None


def _make_handler():
    async def handler(request):
        if request.headers.get("Origin") == "https://evil.example":
            return web.Response(status=403, text="foreign origin")
        socket = web.WebSocketResponse()
        await socket.prepare(request)
        async for message in socket:
            if message.type == web.WSMsgType.TEXT:
                payload = json.loads(message.data)
                await socket.send_str(json.dumps(
                    {"type": "read_result", "name": "seed-123",
                     "id": payload.get("id")}))
        return socket
    return handler


def test_loopback_handshake_session_and_origin_rejection():
    async def scenario():
        app = web.Application()
        app.router.add_get("/ws", _make_handler())
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        try:
            host, port = runner.addresses[0][:2]
            url = f"ws://{host}:{port}/ws"

            handshake = await ws.probe_handshake(url, timeout=3)
            assert handshake.accepted is True
            assert handshake.status == 101

            session = await ws.run_session(
                url, send=['{"type":"read","id":"7"}'],
                stop_on={"contains": "seed-123"},
                connect_timeout=3, read_timeout=1, window=3)
            assert session.accepted is True
            assert session.sent == 1
            assert session.received >= 1
            assert session.first_value(
                {"type": "jsonpath", "path": "name"}) == "seed-123"

            rejected = await ws.probe_handshake(
                url, origin="https://evil.example", timeout=3)
            assert rejected.accepted is False
            assert rejected.status == 403
        finally:
            await runner.cleanup()

    asyncio.run(scenario())
