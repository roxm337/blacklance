"""Bounded MCP (Model Context Protocol) JSON-RPC client (I8).

Speaks the streamable-HTTP transport through the framework's sanctioned
HTTP transport, so deadlines, request budgets, rate limiting, identity
isolation and R7 wire accounting apply exactly as they do to every other
adapter. No external SDK and no model provider is required.

The client is intentionally minimal and defensive:

- responses may be ``application/json`` or ``text/event-stream``; both are
  parsed, anything else becomes an explicit unsupported result;
- request/response bodies and tool text are capped; tool descriptions and
  resource contents are DATA, never instructions — nothing here evaluates
  or acts on target-supplied text;
- ``Mcp-Session-Id`` is kept in memory only; it is a credential and is
  never written to evidence or the report.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional
from urllib.parse import urljoin, urlparse, urlunparse

from core.workflows import _extract
from tools.wrappers import curl

DEFAULT_PROTOCOL_VERSION = "2025-03-26"
DEFAULT_TIMEOUT = 15
MAX_BODY = 256 * 1024
MAX_TEXT = 8192
MAX_PAGES = 3


@dataclass
class McpResult:
    method: str
    url: str = ""
    status: int = 0
    ok: bool = False
    result: Any = None
    error: dict = field(default_factory=dict)
    session_id: str = ""
    text: str = ""
    error_text: str = ""

    def value(self, spec: dict):
        """Extract from the JSON-RPC result first, then from joined text."""
        if self.result is not None:
            value = _extract(spec or {}, json.dumps(self.result, default=str))
            if value is not None:
                return value
        return _extract(spec or {}, self.text or "")

    def contains(self, needle: str) -> bool:
        if not needle:
            return False
        haystack = self.text or ""
        if self.result is not None:
            haystack += "\n" + json.dumps(self.result, default=str)
        return str(needle) in haystack


def endpoint_url(base_url: str, value: str) -> str:
    value = str(value or "").strip()
    if not value:
        return ""
    parsed = urlparse(value)
    if parsed.scheme in ("http", "https"):
        return value
    base = str(base_url or "").strip()
    if not base:
        return value
    return urljoin(base.rstrip("/") + "/", value.lstrip("/"))


def parse_header_block(block: str) -> dict:
    headers = {}
    for line in str(block or "").splitlines():
        key, sep, value = line.partition(":")
        if sep and key.strip():
            headers[key.strip().lower()] = value.strip()
    return headers


def parse_sse(body: str) -> list[dict]:
    """JSON payloads from an event-stream body (multi-line data joined)."""
    payloads = []
    text = str(body or "").replace("\r\n", "\n")
    for block in text.split("\n\n"):
        data = [line[5:].lstrip() for line in block.splitlines()
                if line.startswith("data:")]
        if not data:
            continue
        raw = "\n".join(data)
        try:
            payloads.append(json.loads(raw))
        except (ValueError, TypeError):
            continue
    return payloads


def joined_text(result: Any) -> str:
    """Text from tools/call ``content`` or resources/read ``contents``."""
    if not isinstance(result, dict):
        return ""
    chunks = []
    for item in result.get("content") or []:
        if isinstance(item, dict) and item.get("type") == "text":
            chunks.append(str(item.get("text") or ""))
    for item in result.get("contents") or []:
        if isinstance(item, dict) and isinstance(item.get("text"), str):
            chunks.append(item["text"])
    return "\n".join(chunks)[:MAX_TEXT]


class McpClient:
    """One MCP endpoint and its session (kept in memory only)."""

    def __init__(self, url: str, *, identity: Optional[str] = None,
                 headers: Optional[dict] = None,
                 protocol_version: str = DEFAULT_PROTOCOL_VERSION,
                 timeout: float = DEFAULT_TIMEOUT,
                 session_id: str = "", initialized: bool = False,
                 client_name: str = "osint-agent"):
        self.url = url
        self.identity = identity or ""
        self.headers = {str(k): str(v) for k, v in (headers or {}).items()}
        self.protocol_version = str(protocol_version or "")
        self.timeout = max(1.0, float(timeout))
        self.session_id = str(session_id or "")
        self.initialized = bool(initialized)
        self.client_name = client_name
        self._next_id = 0
        self.last_error = ""

    # ── Protocol ─────────────────────────────────────────────────

    async def initialize(self) -> McpResult:
        payload = {
            "protocolVersion": self.protocol_version or DEFAULT_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": self.client_name, "version": "0.1"},
        }
        result = await self._send("initialize", payload)
        if result.ok:
            if result.session_id:
                self.session_id = result.session_id
            self.initialized = True
            await self._send("notifications/initialized",
                             notification=True)
            result.session_id = self.session_id
        return result

    async def list_tools(self) -> McpResult:
        return await self._paged("tools/list", "tools")

    async def list_resources(self) -> McpResult:
        return await self._paged("resources/list", "resources")

    async def call_tool(self, name: str, arguments: Optional[dict] = None):
        result = await self._send("tools/call",
                                  {"name": str(name),
                                   "arguments": dict(arguments or {})})
        if result.ok:
            result.text = joined_text(result.result)
        return result

    async def read_resource(self, uri: str) -> McpResult:
        result = await self._send("resources/read", {"uri": str(uri)})
        if result.ok:
            result.text = joined_text(result.result)
        return result

    async def close_session(self) -> dict:
        """Best-effort DELETE of the session; a failure is not an error."""
        if not self.session_id:
            return {"status": 0, "attempted": False}
        result = await self._http("DELETE", include_session=True)
        return {"status": int(result.get("status", 0) or 0),
                "attempted": True}

    async def _paged(self, method: str, key: str) -> McpResult:
        merged: list = []
        cursor = None
        final: Optional[McpResult] = None
        for _ in range(MAX_PAGES):
            params = {"cursor": cursor} if cursor else {}
            final = await self._send(method, params)
            if not final.ok or not isinstance(final.result, dict):
                return final
            items = final.result.get(key)
            if isinstance(items, list):
                merged.extend(item for item in items
                              if isinstance(item, dict))
            cursor = final.result.get("nextCursor")
            if not cursor:
                break
        if final is not None:
            final.result = {key: merged}
        return final or McpResult(method=method, url=self.url)

    async def _send(self, method: str, params: Optional[dict] = None, *,
                    notification: bool = False) -> McpResult:
        request_id = None
        payload: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params:
            payload["params"] = params
        if not notification:
            self._next_id += 1
            request_id = self._next_id
            payload["id"] = request_id
        http = await self._http("POST", body=json.dumps(payload))
        result = McpResult(method=method, url=self.url,
                           status=int(http.get("status", 0) or 0),
                           session_id=self._session_from(http))
        if result.status == 0:
            result.error = {"code": 0,
                            "message": str(http.get("error") or "transport")}
            result.error_text = result.error["message"]
            return result
        headers = parse_header_block(str(http.get("headers") or ""))
        content_type = headers.get("content-type", "")
        body = str(http.get("body") or "")[:MAX_BODY]
        payloads: list[dict] = []
        if "text/event-stream" in content_type or body.lstrip().startswith("data:"):
            payloads = parse_sse(body)
        else:
            stripped = body.strip()
            if stripped.startswith(("{", "[")):
                try:
                    parsed = json.loads(stripped)
                except (ValueError, TypeError):
                    parsed = None
                if isinstance(parsed, dict):
                    payloads = [parsed]
                elif isinstance(parsed, list):
                    payloads = [p for p in parsed if isinstance(p, dict)]
        if notification:
            # 202 Accepted is the spec response; some servers reply with JSON.
            result.ok = result.status in (200, 202, 204)
            result.error_text = "" if result.ok else body[:500]
            return result
        response = None
        for candidate in payloads:
            if request_id is not None and candidate.get("id") == request_id:
                response = candidate
                break
        if response is None and payloads:
            response = payloads[-1]
        if response is None:
            result.error = {
                "code": result.status,
                "message": ("unsupported response body"
                            if body else "empty response body")}
            result.error_text = body[:500]
            return result
        error = response.get("error")
        if isinstance(error, dict):
            result.error = error
            result.error_text = str(error.get("message") or "")[:500]
            return result
        if "result" not in response:
            result.error = {"code": -32603, "message": "missing result"}
            return result
        result.result = response.get("result")
        result.ok = 200 <= result.status < 300
        return result

    async def _http(self, method: str, *, body: str = "",
                    include_session: bool = False) -> dict:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        headers.update(self.headers)
        if include_session or self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        if self.initialized and self.protocol_version:
            headers["MCP-Protocol-Version"] = self.protocol_version
        kwargs: dict[str, Any] = {
            "method": method,
            "headers": headers,
            "output": "full",
            "timeout": int(max(1, round(self.timeout))),
            "follow_redirects": False,
        }
        if body:
            kwargs["data"] = body
        if self.identity:
            kwargs["identity"] = self.identity
        else:
            kwargs["no_session"] = True
        try:
            return await curl(self.url, **kwargs)
        except Exception as exc:
            self.last_error = str(exc)
            return {"status": 0, "body": "", "error": str(exc),
                    "headers": ""}

    def _session_from(self, http: dict) -> str:
        headers = parse_header_block(str(http.get("headers") or ""))
        return headers.get("mcp-session-id", "")


def value_of(result: McpResult, spec: dict):
    return result.value(spec) if result is not None else None


def tool_names(tools: Iterable[dict], limit: int = 50) -> list[str]:
    return [str(t.get("name") or "") for t in list(tools or [])[:limit]
            if isinstance(t, dict) and t.get("name")]


def resource_uris(resources: Iterable[dict], limit: int = 50) -> list[str]:
    return [str(r.get("uri") or "") for r in list(resources or [])[:limit]
            if isinstance(r, dict) and r.get("uri")]
