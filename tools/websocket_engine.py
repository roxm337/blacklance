"""Bounded WebSocket client for capture replay and authorization probes (I7).

Built on aiohttp, which is already a core dependency. No browser and no
extra package is required: the audit module never speaks WebSocket itself.

Every connection is bounded (connect timeout, per-receive idle timeout,
total read window, frame cap, payload cap) and every connection is reported
to the R7 wire recorder. Sent and received payloads are redacted before
they are stored, so evidence never carries credentials.

``captured_sockets`` turns I1 ``ws_open``/``ws_frame`` traffic events into
socket endpoints plus client-to-server message templates. Templates are
shapes, not credentials: values redacted at capture time are dropped rather
than replayed.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional
from urllib.parse import urljoin, urlparse, urlunparse

from core.redaction import redact_body
from core.results import note_wire
from core.workflows import _extract

DEFAULT_CONNECT_TIMEOUT = 10.0
DEFAULT_READ_TIMEOUT = 2.0
DEFAULT_MAX_FRAMES = 50
DEFAULT_MAX_PAYLOAD = 8192


@dataclass
class HandshakeResult:
    url: str
    status: int          # 101 accepted; an HTTP status when rejected; 0 on transport error
    accepted: bool
    error: str = ""
    subprotocol: str = ""


@dataclass
class Frame:
    direction: str       # sent | received
    payload: str         # redacted, capped
    binary: bool = False
    truncated: bool = False


@dataclass
class SocketSession:
    url: str
    status: int = 0
    accepted: bool = False
    error: str = ""
    frames: list[Frame] = field(default_factory=list)
    sent: int = 0
    received: int = 0

    def received_text(self) -> list[str]:
        return [f.payload for f in self.frames
                if f.direction == "received" and not f.binary]

    def first_value(self, spec: dict, frames: Optional[Iterable[str]] = None):
        texts = list(frames) if frames is not None else self.received_text()
        for text in texts:
            value = _extract(spec or {}, str(text))
            if value is not None:
                return value
        return None


def ws_url(base_url: str, value: str) -> str:
    """Resolve a configured/captured socket reference to a ws(s) URL."""
    value = str(value or "").strip()
    if not value:
        return ""
    parsed = urlparse(value)
    if parsed.scheme in ("ws", "wss"):
        return value
    base = str(base_url or "").strip()
    if not base:
        return value
    joined = urljoin(base.rstrip("/") + "/", value)
    parsed = urlparse(joined)
    scheme = {"http": "ws", "https": "wss"}.get(parsed.scheme)
    if not scheme:
        return joined
    return urlunparse(parsed._replace(scheme=scheme))


def cookie_header(identity) -> str:
    cookies = getattr(identity, "cookies", None) or {}
    if not isinstance(cookies, dict):
        return ""
    return "; ".join(f"{k}={v}" for k, v in cookies.items() if k)


def build_headers(identity, *, origin: str = "",
                  extra: Optional[dict] = None) -> dict:
    """Identity auth (headers + cookies) plus explicit overrides."""
    headers: dict[str, str] = {}
    if identity is not None:
        try:
            headers.update(identity.request_headers() or {})
        except Exception:
            pass
        cookie = cookie_header(identity)
        if cookie and not any(k.lower() == "cookie" for k in headers):
            headers["Cookie"] = cookie
    headers.update({str(k): str(v) for k, v in (extra or {}).items()})
    if origin:
        headers.setdefault("Origin", origin)
    return headers


def _stop_matches(spec: Optional[dict], text: str) -> bool:
    if not spec:
        return False
    needle = spec.get("contains")
    if needle and str(needle) in text:
        return True
    extract = spec.get("extract")
    if extract:
        value = _extract(extract, text)
        if value is not None and "equals" in spec \
                and str(value) == str(spec.get("equals")):
            return True
    return False


class SocketClient:
    """One live socket with bounded send/read primitives.

    ``async with`` opens and closes; ``send`` then ``read_until`` may be
    interleaved with external actions (the revocation probe logs the
    session out between two sends on the same connection).
    """

    def __init__(self, url: str, *, headers: Optional[dict] = None,
                 origin: str = "", subprotocols: Iterable[str] = (),
                 connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
                 read_timeout: float = DEFAULT_READ_TIMEOUT,
                 max_frames: int = DEFAULT_MAX_FRAMES,
                 max_payload: int = DEFAULT_MAX_PAYLOAD,
                 verify_tls: bool = True):
        self.url = url
        self.headers = dict(headers or {})
        self.origin = origin
        self.subprotocols = tuple(subprotocols or ())
        self.connect_timeout = max(0.5, float(connect_timeout))
        self.read_timeout = max(0.1, float(read_timeout))
        self.max_frames = max(1, int(max_frames))
        self.max_payload = max(256, int(max_payload))
        self.verify_tls = verify_tls
        self.status = 0
        self.accepted = False
        self.error = ""
        self.subprotocol = ""
        self.frames: list[Frame] = []
        self._session = None
        self._ws = None
        self._attempted = False
        self._accounted = False

    async def __aenter__(self) -> "SocketClient":
        await self.connect()
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.close()

    async def connect(self) -> bool:
        import aiohttp

        headers = dict(self.headers)
        if self.origin:
            headers.setdefault("Origin", self.origin)
        timeout = aiohttp.ClientTimeout(
            total=None, sock_connect=self.connect_timeout)
        self._session = aiohttp.ClientSession(timeout=timeout)
        self._attempted = True
        kwargs: dict[str, Any] = {
            "headers": headers or None,
            "protocols": self.subprotocols or None,
        }
        if not self.verify_tls:
            kwargs["ssl"] = False
        ws_timeout = getattr(aiohttp, "ClientWSTimeout", None)
        if ws_timeout is not None:
            kwargs["timeout"] = ws_timeout(ws_receive=self.read_timeout)
        else:  # aiohttp < 3.9
            kwargs["receive_timeout"] = self.read_timeout
        try:
            self._ws = await asyncio.wait_for(
                self._session.ws_connect(self.url, **kwargs),
                timeout=self.connect_timeout)
            self.status = 101
            self.accepted = True
            self.subprotocol = str(getattr(self._ws, "protocol", "") or "")
        except Exception as exc:
            self.status = int(getattr(exc, "status", 0) or 0)
            self.accepted = False
            self.error = f"{type(exc).__name__}: {exc}"
        return self.accepted

    async def send(self, text: str) -> bool:
        if self._ws is None or not self.accepted:
            return False
        try:
            await self._ws.send_str(str(text))
        except Exception as exc:
            self.error = f"send failed: {exc}"
            return False
        payload = redact_body(str(text))
        self.frames.append(Frame(
            "sent", payload[:self.max_payload],
            truncated=len(payload) > self.max_payload))
        return True

    async def read_until(self, *, stop_on: Optional[dict] = None,
                         max_frames: Optional[int] = None,
                         window: float = 10.0) -> list[str]:
        """Collect received text frames until idle, cap or stop condition."""
        import aiohttp

        if self._ws is None or not self.accepted:
            return []
        out: list[str] = []
        limit = self.max_frames if max_frames is None else max(1, int(max_frames))
        loop = asyncio.get_running_loop()
        deadline = loop.time() + max(0.2, float(window))
        while len(out) < limit and loop.time() < deadline:
            try:
                message = await asyncio.wait_for(
                    self._ws.receive(), timeout=self.read_timeout)
            except asyncio.TimeoutError:
                break
            except Exception as exc:
                self.error = f"receive failed: {exc}"
                break
            if message.type == aiohttp.WSMsgType.TEXT:
                text = str(message.data)
                out.append(text)
                payload = redact_body(text)
                self.frames.append(Frame(
                    "received", payload[:self.max_payload],
                    truncated=len(payload) > self.max_payload))
                if _stop_matches(stop_on, text):
                    break
            elif message.type == aiohttp.WSMsgType.BINARY:
                data = message.data or b""
                self.frames.append(Frame(
                    "received", f"<binary {len(data)} bytes>", binary=True))
            elif message.type in (aiohttp.WSMsgType.ERROR,
                                  aiohttp.WSMsgType.CLOSE,
                                  aiohttp.WSMsgType.CLOSING,
                                  aiohttp.WSMsgType.CLOSED):
                if message.type == aiohttp.WSMsgType.ERROR:
                    self.error = f"error frame: {getattr(message, 'data', '')}"
                break
        return out

    async def close(self) -> None:
        try:
            if self._ws is not None and not self._ws.closed:
                await self._ws.close()
        except Exception:
            pass
        try:
            if self._session is not None:
                await self._session.close()
        except Exception:
            pass
        self._account()

    def _account(self) -> None:
        if self._accounted or not self._attempted:
            return
        self._accounted = True
        note_wire({"transport": "websocket", "requests": 1,
                   "messages": len(self.frames)})

    @property
    def sent(self) -> int:
        return sum(1 for f in self.frames if f.direction == "sent")

    @property
    def received(self) -> int:
        return sum(1 for f in self.frames if f.direction == "received")

    def first_value(self, spec: dict, frames: Optional[Iterable[str]] = None):
        texts = list(frames) if frames is not None else [
            f.payload for f in self.frames
            if f.direction == "received" and not f.binary]
        for text in texts:
            value = _extract(spec or {}, str(text))
            if value is not None:
                return value
        return None

    def received_text(self) -> list[str]:
        return [f.payload for f in self.frames
                if f.direction == "received" and not f.binary]


async def probe_handshake(url: str, *, headers: Optional[dict] = None,
                          origin: str = "",
                          subprotocols: Iterable[str] = (),
                          timeout: float = DEFAULT_CONNECT_TIMEOUT,
                          verify_tls: bool = True) -> HandshakeResult:
    """Open one socket and report only the handshake outcome."""
    client = SocketClient(
        url, headers=headers, origin=origin, subprotocols=subprotocols,
        connect_timeout=timeout, read_timeout=0.3, verify_tls=verify_tls)
    async with client:
        pass
    return HandshakeResult(url=url, status=client.status,
                           accepted=client.accepted, error=client.error,
                           subprotocol=client.subprotocol)


async def run_session(url: str, *, headers: Optional[dict] = None,
                      origin: str = "",
                      subprotocols: Iterable[str] = (),
                      send: Iterable[str] = (),
                      stop_on: Optional[dict] = None,
                      connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
                      read_timeout: float = DEFAULT_READ_TIMEOUT,
                      window: float = 10.0,
                      max_frames: int = DEFAULT_MAX_FRAMES,
                      max_payload: int = DEFAULT_MAX_PAYLOAD,
                      verify_tls: bool = True) -> SocketSession:
    """Connect, send the given messages, collect replies, disconnect."""
    client = SocketClient(
        url, headers=headers, origin=origin, subprotocols=subprotocols,
        connect_timeout=connect_timeout, read_timeout=read_timeout,
        max_frames=max_frames, max_payload=max_payload,
        verify_tls=verify_tls)
    async with client:
        if client.accepted:
            for message in send:
                if not await client.send(str(message)):
                    break
            await client.read_until(stop_on=stop_on, window=window)
    return SocketSession(
        url=url, status=client.status, accepted=client.accepted,
        error=client.error, frames=list(client.frames),
        sent=client.sent, received=client.received)


def captured_sockets(events: Iterable[dict], *, max_sockets: int = 8,
                     max_messages: int = 10) -> list[dict]:
    """Group captured WS traffic into endpoints + client message templates.

    Captured payloads were redacted before persistence; templates containing
    a redaction marker are dropped instead of replayed.
    """
    sockets: dict[str, dict] = {}
    for event in events or []:
        kind = str(event.get("kind") or "")
        if kind not in ("ws_open", "ws_frame"):
            continue
        url = str(event.get("url") or "")
        if not url:
            continue
        entry = sockets.setdefault(url, {
            "url": url,
            "page_url": str(event.get("page_url") or ""),
            "identity": dict(event.get("identity") or {}),
            "messages": [],
        })
        if kind != "ws_frame" or event.get("direction") != "sent":
            continue
        if len(entry["messages"]) >= max_messages:
            continue
        if event.get("opcode") == "binary":
            continue
        payload = str(event.get("payload") or "")
        if not payload or "<redacted" in payload:
            continue
        entry["messages"].append(payload)
    return list(sockets.values())[:max(1, int(max_sockets))]
