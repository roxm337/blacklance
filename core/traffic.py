"""Replayable browser traffic capture (I1).

Captures the XHR/fetch traffic a real browser session produces, links every
response to its initiating request, tags each event with the identity that
produced it, and persists a redacted, capped JSONL stream that a later run
can replay with fresh credentials.

Redaction happens AT CAPTURE TIME: credential headers are dropped, bodies
pass through the shared redaction pipeline, JWT-shaped strings are scrubbed,
and bodies are capped. Nothing sensitive is ever written to disk.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

from core.redaction import (RESPONSE_HEADER_ALLOWLIST, redact_body,
                            redact_headers)
from core.validators import redact_for_log

DEFAULT_MAX_EVENTS = 2000
DEFAULT_MAX_REQUEST_BODY = 8 * 1024
DEFAULT_MAX_RESPONSE_BODY = 32 * 1024

# Resource types worth replaying. Fonts/images/media are skipped by default;
# the interesting traffic is API-shaped.
CAPTURED_RESOURCE_TYPES = frozenset({"xhr", "fetch", "document"})


@dataclass
class TrafficEvent:
    kind: str                    # xhr | fetch | navigation | response
    request_id: str
    url: str
    method: str = ""
    resource_type: str = ""
    status: int = 0
    initiator: str = ""          # script URL or frame URL that issued it
    page_url: str = ""
    identity: dict = field(default_factory=dict)
    request_headers: dict = field(default_factory=dict)
    request_body: str = ""
    response_headers: dict = field(default_factory=dict)
    response_body: str = ""
    parent_request_id: str = ""  # response → its request
    timestamp: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class TrafficCapture:
    """Playwright-backed capture. No playwright import at module import."""

    def __init__(self, *, identity: Optional[dict] = None,
                 capture_documents: bool = True,
                 max_events: int = DEFAULT_MAX_EVENTS,
                 max_request_body: int = DEFAULT_MAX_REQUEST_BODY,
                 max_response_body: int = DEFAULT_MAX_RESPONSE_BODY):
        self.events: list[TrafficEvent] = []
        self._lock = threading.Lock()
        self._identity = identity or {"name": "anonymous",
                                      "source": "anonymous", "verified": False}
        self._capture_documents = capture_documents
        self.max_events = max_events
        self.max_request_body = max_request_body
        self.max_response_body = max_response_body
        self.requests_seen = 0
        self._page = None

    def set_identity(self, identity: dict) -> None:
        self._identity = identity or {}

    def _count(self) -> None:
        self.requests_seen += 1

    def settle_budget(self, budget=None) -> int:
        """Post-hoc budget consumption for browser requests.

        Playwright traffic cannot be reserved pre-dispatch, so the module
        counts completed requests and settles them here (observe-then-count,
        recorded in the operations ledger as browser transport).
        """
        from core.results import note_wire
        count = self.requests_seen
        self.requests_seen = 0
        if count:
            note_wire({"transport": "browser", "requests": count})
        if budget is not None and count:
            try:
                budget.consume_request(count)
            except Exception:
                # The budget manager raises when over; the caller decides
                # whether to stop navigating.
                self.requests_seen += count
                raise
        return count

    # ── Playwright wiring ─────────────────────────────────────────

    def attach(self, page) -> None:
        """Hook a live Playwright page. Response handlers run per request."""
        self._page = page
        page.on("request", self._on_request)
        page.on("response", self._on_response)

    def _wanted(self, resource_type: str, kind: str) -> bool:
        if kind == "navigation":
            return self._capture_documents
        return resource_type in CAPTURED_RESOURCE_TYPES

    def _on_request(self, request) -> None:
        try:
            resource_type = str(getattr(request, "resource_type", "") or "")
            kind = "navigation" if resource_type == "document" \
                else str(getattr(request, "resource_type", "") or "")
            if not self._wanted(resource_type, kind):
                return
            headers = {}
            try:
                headers = dict(request.headers or {})
            except Exception:
                pass
            body = ""
            if getattr(request, "post_data", None):
                body = redact_body(str(request.post_data or "") or "")
            self._count()
            with self._lock:
                if len(self.events) >= self.max_events:
                    return
                self.events.append(TrafficEvent(
                    kind=kind,
                    request_id=self._request_id(request),
                    url=redact_for_log(str(request.url)),
                    method=str(getattr(request, "method", "") or ""),
                    resource_type=resource_type,
                    initiator=self._initiator(request),
                    page_url=str(getattr(request, "frame", None).url
                                 if getattr(request, "frame", None) else ""),
                    identity=dict(self._identity),
                    request_headers=redact_headers(headers),
                    request_body=body[:self.max_request_body],
                    timestamp=_now(),
                ))
        except Exception:
            pass

    async def _on_response(self, response) -> None:
        try:
            request = getattr(response, "request", None)
            if request is None:
                return
            resource_type = str(getattr(request, "resource_type", "") or "")
            if not self._wanted(resource_type,
                                "navigation" if resource_type == "document"
                                else resource_type):
                return
            body = ""
            try:
                text = getattr(response, "text", None)
                if callable(text):
                    body = str(await text() or "")
            except Exception:
                pass
            headers = {}
            try:
                headers = {str(k).lower(): str(v)
                           for k, v in (response.headers or {}).items()
                           if str(k).lower() in RESPONSE_HEADER_ALLOWLIST}
            except Exception:
                pass
            with self._lock:
                if len(self.events) >= self.max_events:
                    return
                self.events.append(TrafficEvent(
                    kind="response",
                    request_id="",
                    url=redact_for_log(str(response.url)),
                    status=int(getattr(response, "status", 0) or 0),
                    resource_type=resource_type,
                    page_url=str(getattr(request, "frame", None).url
                                 if getattr(request, "frame", None) else ""),
                    identity=dict(self._identity),
                    response_headers=headers,
                    response_body=redact_body(body)[:self.max_response_body],
                    parent_request_id=self._request_id(request),
                    timestamp=_now(),
                ))
        except Exception:
            pass

    def _request_id(self, request) -> str:
        try:
            return f"{request.method} {request.url}"
        except Exception:
            return str(request)

    def _initiator(self, request) -> str:
        frame = getattr(request, "frame", None)
        if frame is not None:
            url = getattr(frame, "url", "")
            if url:
                return str(url)
        return ""


class TrafficStore:
    """Append-only redacted traffic JSONL with size caps."""

    def __init__(self, path: str | Path, *,
                 max_events: int = DEFAULT_MAX_EVENTS,
                 max_body_bytes: int = DEFAULT_MAX_RESPONSE_BODY,
                 verify_existing: bool = True):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_events = max_events
        self.max_body_bytes = max_body_bytes
        self._lock = threading.Lock()
        self._count = 0
        if verify_existing and self.path.exists():
            self._count = self.count()

    def append(self, event: TrafficEvent) -> bool:
        with self._lock:
            if self._count >= self.max_events:
                return False
            line = json.dumps(event.to_dict(), sort_keys=True,
                              default=str) + "\n"
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line)
            self._count += 1
            return True

    def append_many(self, events: list[TrafficEvent]) -> int:
        written = 0
        with self._lock:
            with self.path.open("a", encoding="utf-8") as fh:
                for event in events:
                    if self._count >= self.max_events:
                        break
                    fh.write(json.dumps(event.to_dict(), sort_keys=True,
                                        default=str) + "\n")
                    self._count += 1
                    written += 1
        return written

    def load(self) -> list[dict]:
        if not self.path.exists():
            return []
        events = []
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return events

    def count(self) -> int:
        if not self.path.exists():
            return 0
        total = 0
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    total += 1
        return total

    def digest(self) -> str:
        """SHA-256 of the file for the evidence chain."""
        import hashlib
        if not self.path.exists():
            return ""
        h = hashlib.sha256()
        with self.path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
