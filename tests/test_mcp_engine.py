"""I8 MCP engine tests: JSON-RPC framing, session headers, SSE/JSON
parsing, extraction and caps. Transport is faked — no network."""

from __future__ import annotations

import asyncio
import json

from tools import mcp_engine as mcp


def _json(payload, status=200, headers="Content-Type: application/json"):
    return {"status": status, "body": json.dumps(payload),
            "headers": headers, "url": ""}


def _fake_curl(responses, calls):
    async def fake(url, **kwargs):
        payload = json.loads(kwargs["data"]) if kwargs.get("data") else None
        method = (payload or {}).get("method") or kwargs.get("method")
        responder = responses.get(method)
        if responder is None:
            result = {"status": 404, "body": "", "headers": "", "url": url}
        elif callable(responder):
            result = responder(payload, kwargs)
        else:
            result = dict(responder)
        result.setdefault("url", url)
        calls.append({"method": method, "kwargs": kwargs, "payload": payload})
        return result
    return fake


def test_helpers_parse_headers_sse_and_join_text():
    headers = mcp.parse_header_block(
        "Content-Type: application/json\nMcp-Session-Id: sid-9\n")
    assert headers["mcp-session-id"] == "sid-9"
    events = mcp.parse_sse(
        'event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{}}\n\n')
    assert events == [{"jsonrpc": "2.0", "id": 1, "result": {}}]
    text = mcp.joined_text({
        "content": [{"type": "text", "text": "a"},
                    {"type": "image", "data": "x"}],
        "contents": [{"text": "b"}]})
    assert text == "a\nb"
    assert mcp.endpoint_url("https://x.example", "/mcp") \
        == "https://x.example/mcp"
    assert mcp.endpoint_url("https://x.example",
                            "https://y.example/mcp") \
        == "https://y.example/mcp"


def test_initialize_captures_session_and_subsequent_headers(monkeypatch):
    calls = []
    responses = {
        "initialize": _json(
            {"jsonrpc": "2.0", "id": 1,
             "result": {"protocolVersion": "2025-03-26",
                        "serverInfo": {"name": "twin"}}},
            headers=("Content-Type: application/json\n"
                     "Mcp-Session-Id: sid-1\n")),
        "notifications/initialized": {"status": 202, "body": "",
                                      "headers": ""},
        "tools/list": _json({"jsonrpc": "2.0", "id": 2,
                             "result": {"tools": [{"name": "read_note"},
                                                  {"name": "create_note"}]}}),
    }
    monkeypatch.setattr(mcp, "curl", _fake_curl(responses, calls))

    client = mcp.McpClient("https://x.example/mcp")
    init = asyncio.run(client.initialize())
    assert init.ok is True
    assert init.session_id == "sid-1"
    assert client.initialized is True
    assert calls[0]["payload"]["params"]["protocolVersion"] \
        == mcp.DEFAULT_PROTOCOL_VERSION
    assert calls[0]["payload"]["params"]["clientInfo"]["name"]

    listing = asyncio.run(client.list_tools())
    assert listing.ok is True
    assert mcp.tool_names(listing.result["tools"]) \
        == ["read_note", "create_note"]
    headers = calls[-1]["kwargs"]["headers"]
    assert headers["Mcp-Session-Id"] == "sid-1"
    assert headers["MCP-Protocol-Version"] == mcp.DEFAULT_PROTOCOL_VERSION
    assert calls[-1]["payload"]["jsonrpc"] == "2.0"


def test_call_tool_and_resource_read_join_text(monkeypatch):
    calls = []
    responses = {
        "initialize": _json({"jsonrpc": "2.0", "id": 1, "result": {}}),
        "notifications/initialized": {"status": 202, "body": "",
                                      "headers": ""},
        "tools/call": _json({"jsonrpc": "2.0", "id": 2, "result": {
            "content": [{"type": "text", "text": "hello"}],
            "structuredContent": {"id": 7, "text": "hello"}}}),
        "resources/read": _json({"jsonrpc": "2.0", "id": 3, "result": {
            "contents": [{"uri": "note://7", "text": "resource text"}]}}),
    }
    monkeypatch.setattr(mcp, "curl", _fake_curl(responses, calls))

    client = mcp.McpClient("https://x.example/mcp")
    asyncio.run(client.initialize())
    call = asyncio.run(client.call_tool("read_note", {"id": 7}))
    assert call.ok is True
    assert call.text == "hello"
    assert call.value({"type": "jsonpath",
                       "path": "structuredContent.id"}) == "7"
    assert call.contains("hello") is True

    read = asyncio.run(client.read_resource("note://7"))
    assert read.text == "resource text"
    assert calls[-1]["payload"]["params"] == {"uri": "note://7"}


def test_sse_response_is_parsed(monkeypatch):
    calls = []

    def sse(payload, kwargs):
        body = ("event: message\ndata: " + json.dumps({
            "jsonrpc": "2.0", "id": payload["id"],
            "result": {"content": [{"type": "text",
                                    "text": "from-sse"}]}}) + "\n\n")
        return {"status": 200, "body": body,
                "headers": "Content-Type: text/event-stream", "url": ""}

    responses = {
        "tools/call": sse,
    }
    monkeypatch.setattr(mcp, "curl", _fake_curl(responses, calls))
    client = mcp.McpClient("https://x.example/mcp", initialized=True,
                           session_id="sid-2")
    result = asyncio.run(client.call_tool("read_note", {"id": 1}))
    assert result.ok is True
    assert result.text == "from-sse"


def test_jsonrpc_error_and_transport_failure(monkeypatch):
    calls = []
    responses = {
        "tools/call": _json({"jsonrpc": "2.0", "id": 1,
                             "error": {"code": -32601,
                                       "message": "method not found"}}),
    }
    monkeypatch.setattr(mcp, "curl", _fake_curl(responses, calls))
    client = mcp.McpClient("https://x.example/mcp", initialized=True,
                           session_id="sid-3")
    result = asyncio.run(client.call_tool("nope", {}))
    assert result.ok is False
    assert result.error["code"] == -32601
    assert "method not found" in result.error_text

    async def failing(url, **kwargs):
        return {"status": 0, "body": "", "headers": "",
                "error": "connection_error", "url": url}

    monkeypatch.setattr(mcp, "curl", failing)
    failed = asyncio.run(client.call_tool("nope", {}))
    assert failed.ok is False
    assert failed.status == 0


def test_reused_session_skips_initialize_and_sends_session_header(monkeypatch):
    calls = []
    responses = {
        "tools/call": _json({"jsonrpc": "2.0", "id": 1, "result": {
            "content": [{"type": "text", "text": "shared"}]}}),
    }
    monkeypatch.setattr(mcp, "curl", _fake_curl(responses, calls))
    client = mcp.McpClient("https://x.example/mcp", identity="alice",
                           headers={"Authorization": "Bearer alice"},
                           session_id="sid-owner", initialized=True)
    result = asyncio.run(client.call_tool("read_note", {"id": 3}))
    assert result.ok is True
    assert all(call["method"] != "initialize" for call in calls)
    headers = calls[0]["kwargs"]["headers"]
    assert headers["Mcp-Session-Id"] == "sid-owner"
    assert headers["Authorization"] == "Bearer alice"
    assert calls[0]["kwargs"]["identity"] == "alice"


def test_close_session_sends_delete(monkeypatch):
    calls = []

    async def fake(url, **kwargs):
        calls.append((kwargs.get("method"), kwargs.get("headers")))
        return {"status": 204, "body": "", "headers": "", "url": url}

    monkeypatch.setattr(mcp, "curl", fake)
    client = mcp.McpClient("https://x.example/mcp", session_id="sid-9",
                           initialized=True)
    result = asyncio.run(client.close_session())
    assert result == {"status": 204, "attempted": True}
    method, headers = calls[0]
    assert method == "DELETE"
    assert headers["Mcp-Session-Id"] == "sid-9"


def test_oversized_tool_text_is_capped():
    text = "x" * (mcp.MAX_TEXT + 1000)
    result = mcp.McpResult(method="tools/call", ok=True,
                           result={"content": [{"type": "text",
                                                "text": text}]},
                           text=mcp.joined_text({"content": [
                               {"type": "text", "text": text}]}))
    assert len(result.text) == mcp.MAX_TEXT
