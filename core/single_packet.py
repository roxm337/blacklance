"""Single-packet race delivery.

A race-condition oracle proves a defect by contrast — the operation behaves
when replayed serially, but a concurrent batch produces more accepted effects
than the invariant allows. That proof never depends on timing. Delivery does.

With one request per connection, the kernel, the TLS stack and the server's
accept loop spread a batch across milliseconds, and a back end that serialises
per connection turns a genuinely racy endpoint into a clean run. Single-packet
delivery removes that variable: every request's final byte is written into one
TCP segment, so the server reads them together.

This module changes **delivery only**. It does not grade, and callers must not
let it: `in_flight` is reported as the number of requests actually written in
one sync batch, so a failed batch reports 0 and the caller's overlap guard
grades the invariant `untested / no_overlap` rather than "clean".

Two transports:

``h2``
    One TLS+ALPN h2 connection. Every request is sent as HEADERS plus its body
    with ``end_stream=False``; the empty DATA frame that ends each stream is
    then flushed in a single ``sendall``. That flush is the packet that lands
    together.

``h1``
    One connection per request, HTTP/1.1 last-byte sync: write everything but
    the final byte, then flush the final bytes together.

Scope admission and target policy belong to the caller; this module opens the
socket it is handed and nothing else.
"""

from __future__ import annotations

import asyncio
import socket
import time
from typing import Callable, Optional
from urllib.parse import urlparse

from core import http_smuggle

# RFC 7540 §8.1.2.2: connection-specific headers are a protocol error in h2.
_H2_FORBIDDEN = frozenset({
    "connection", "keep-alive", "proxy-connection", "transfer-encoding",
    "upgrade", "host", "te", "trailer",
})


class SinglePacketError(RuntimeError):
    """The batch could not be delivered; the caller must fall back."""


def h2_available() -> bool:
    try:
        import h2.connection  # noqa: F401
        return True
    except Exception:  # pragma: no cover - import guard
        return False


def split_target(url: str) -> dict:
    parsed = urlparse(url)
    scheme = (parsed.scheme or "http").lower()
    return {
        "scheme": scheme,
        "host": parsed.hostname or "",
        "port": parsed.port or (443 if scheme == "https" else 80),
        "path": parsed.path or "/",
        "query": parsed.query,
    }


def request_path(request: dict, default: str = "/") -> str:
    """Absolute-form path for one request, keeping its query string."""
    path = str(request.get("path") or default)
    query = str(request.get("query") or "")
    if query and "?" not in path:
        path = f"{path}?{query}"
    if not path.startswith("/"):
        path = "/" + path
    return path


def build_h2_headers(method: str, scheme: str, host: str, path: str,
                     headers: Optional[dict]) -> list:
    out = [
        (b":method", str(method or "GET").upper().encode()),
        (b":path", path.encode()),
        (b":scheme", scheme.encode()),
        (b":authority", host.encode()),
    ]
    for name, value in (headers or {}).items():
        lowered = str(name).strip().lower()
        if not lowered or lowered.startswith(":"):
            continue
        if lowered in _H2_FORBIDDEN:
            continue
        if value is None or str(value) == "":
            continue
        out.append((lowered.encode(), str(value).encode()))
    return out


def ingest_h2(events, responses: dict, ended: set) -> None:
    """Fold h2 events into per-stream status/body state.

    Split out from the socket loop so the parser is testable without a server.
    """
    import h2.events

    for event in events:
        if isinstance(event, h2.events.ResponseReceived):
            entry = responses.get(event.stream_id)
            if entry is None:
                continue
            for name, value in event.headers:
                if name == b":status":
                    try:
                        entry["status"] = int(value)
                    except (TypeError, ValueError):
                        entry["status"] = 0
        elif isinstance(event, h2.events.DataReceived):
            entry = responses.get(event.stream_id)
            if entry is not None:
                entry["body"] += event.data.decode("utf-8", errors="replace")
        elif isinstance(event, (h2.events.StreamEnded,
                                h2.events.StreamReset)):
            ended.add(event.stream_id)


def h2_single_packet(
    url: str,
    requests: list,
    timeout: int = 15,
    connect: Optional[Callable] = None,
    h2_factory: Optional[Callable] = None,
    h2_config: Optional[Callable] = None,
) -> dict:
    """Deliver every request on one h2 connection, then flush all triggers."""
    import h2.config
    import h2.connection

    connect = connect or http_smuggle.connection
    h2_factory = h2_factory or h2.connection.H2Connection
    h2_config = h2_config or (lambda: h2.config.H2Configuration(
        client_side=True, header_encoding="utf-8",
        validate_outbound_headers=False,
        normalize_outbound_headers=False))

    target = split_target(url)
    if not target["host"]:
        raise SinglePacketError("no host in target")

    sock, host = connect(url, timeout=timeout, alpn=["h2"])
    conn = h2_factory(config=h2_config())
    responses = {stream: {"status": 0, "body": ""}
                 for stream in range(1, 2 * len(requests), 2)}
    ended: set = set()
    try:
        conn.initiate_connection()
        sock.sendall(conn.data_to_send())

        for index, request in enumerate(requests):
            stream_id = 2 * index + 1
            path = request_path(request, target["path"])
            headers = build_h2_headers(
                request.get("method", "GET"), target["scheme"], host, path,
                request.get("headers") or {})
            body = str(request.get("body") or "").encode()
            conn.send_headers(stream_id, headers, end_stream=False)
            if body:
                conn.send_data(stream_id, body, end_stream=False)
        sock.sendall(conn.data_to_send())

        # The sync packet: one empty DATA(END_STREAM) frame per stream.
        for index in range(len(requests)):
            conn.send_data(2 * index + 1, b"", end_stream=True)
        sock.sendall(conn.data_to_send())

        deadline = time.time() + timeout
        while time.time() < deadline and len(ended) < len(requests):
            sock.settimeout(max(0.5, deadline - time.time()))
            try:
                data = sock.recv(65535)
            except (socket.timeout, OSError):
                break
            if not data:
                break
            events = conn.receive_data(data)
            ingest_h2(events, responses, ended)
            pending = conn.data_to_send()
            if pending:
                sock.sendall(pending)
    finally:
        try:
            sock.close()
        except OSError:
            pass

    ordered = [responses[2 * index + 1] for index in range(len(requests))]
    return {
        "transport": "h2",
        "statuses": [entry["status"] for entry in ordered],
        "bodies": [entry["body"] for entry in ordered],
        # Every stream's final frame was written in one sendall; that is the
        # honest definition of "in flight together" for this transport.
        "in_flight": len(requests),
        "requests": len(requests),
        "error": "",
    }


def build_h1_request(method: str, path: str, host: str,
                     headers: Optional[dict], body: str) -> bytes:
    """One HTTP/1.1 request, with framing left exactly as the caller set it.

    A body with no declared length would be unreadable to the server, so
    Content-Length is added when the caller did not already frame the request
    (explicit Content-Length or chunked).
    """
    lines = [f"{str(method or 'GET').upper()} {path} HTTP/1.1",
             f"Host: {host}"]
    lower = {str(name).lower() for name in (headers or {})}
    for name, value in (headers or {}).items():
        if name and value is not None:
            lines.append(f"{name}: {value}")
    if "connection" not in lower:
        lines.append("Connection: close")
    payload = str(body or "").encode()
    if payload and "content-length" not in lower and \
            "transfer-encoding" not in lower:
        lines.append(f"Content-Length: {len(payload)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + payload


def h1_last_byte(
    url: str,
    requests: list,
    timeout: int = 15,
    connect: Optional[Callable] = None,
    read: Optional[Callable] = None,
) -> dict:
    """HTTP/1.1 last-byte sync across one connection per request."""
    connect = connect or http_smuggle.connection
    read = read or http_smuggle.read_response

    target = split_target(url)
    if not target["host"]:
        raise SinglePacketError("no host in target")

    opened: list = []
    try:
        for request in requests:
            sock, host = connect(url, timeout=timeout)
            payload = build_h1_request(
                request.get("method", "GET"),
                request_path(request, target["path"]), host,
                request.get("headers") or {},
                str(request.get("body") or ""))
            # Withhold the final byte so the request is not complete yet.
            sock.sendall(payload[:-1])
            opened.append((sock, payload[-1:]))

        # The sync burst: every withheld byte, back to back.
        for sock, last in opened:
            sock.sendall(last)

        statuses, bodies = [], []
        for sock, _ in opened:
            status, text = read(sock, timeout=timeout)
            statuses.append(status)
            bodies.append(text)
    finally:
        for sock, _ in opened:
            try:
                sock.close()
            except OSError:
                pass

    return {
        "transport": "h1",
        "statuses": statuses,
        "bodies": bodies,
        "in_flight": len(requests),
        "requests": len(requests),
        "error": "",
    }


def send(
    url: str,
    requests: list,
    transport: str = "auto",
    timeout: int = 15,
    connect: Optional[Callable] = None,
    read: Optional[Callable] = None,
    h2_factory: Optional[Callable] = None,
) -> dict:
    """Deliver one batch through the best available transport.

    ``transport`` is ``auto`` (h2 over TLS when importable, else h1),
    ``h2`` or ``h1``. Any failure returns a zero ``in_flight`` result and an
    ``error`` — the caller decides whether to fall back, and a zero overlap
    must never be read as a clean target.
    """
    requests = list(requests or [])
    if not requests:
        return {"transport": transport, "statuses": [], "bodies": [],
                "in_flight": 0, "requests": 0, "error": "no_requests"}

    chosen = transport
    if chosen == "auto":
        target = split_target(url)
        chosen = "h2" if (target["scheme"] == "https" and h2_available()) \
            else "h1"

    try:
        if chosen == "h2":
            result = h2_single_packet(
                url, requests, timeout=timeout, connect=connect,
                h2_factory=h2_factory)
        elif chosen == "h1":
            result = h1_last_byte(
                url, requests, timeout=timeout, connect=connect, read=read)
        else:
            raise SinglePacketError(f"unknown transport {chosen}")
    except Exception as exc:  # noqa: BLE001 - delivery failure is a fallback
        return {"transport": chosen, "statuses": [], "bodies": [],
                "in_flight": 0, "requests": len(requests),
                "error": f"{type(exc).__name__}: {exc}"}

    if any(not status for status in result.get("statuses", [])):
        # A connection that answered nothing did not overlap; report zero so
        # the caller grades untested/no_overlap instead of a clean run.
        result["in_flight"] = 0
        result["error"] = result.get("error") or "incomplete_batch"
    return result


async def send_async(url: str, requests: list, **kwargs) -> dict:
    """Run `send` off the event loop. Socket writes are blocking by design."""
    return await asyncio.to_thread(send, url, requests, **kwargs)
