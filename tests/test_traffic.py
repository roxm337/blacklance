"""I1 traffic-capture tests: redaction, capping, event linking, workflow
building. Playwright itself is not needed — events come from fakes."""

from __future__ import annotations

import json

import pytest

from core.traffic import (DEFAULT_MAX_EVENTS, TrafficCapture, TrafficEvent,
                          TrafficStore)
from core.workflows import build_workflow


class FakeResponse:
    def __init__(self, url, status, body, request, headers=None):
        self.url = url
        self.status = status
        self._body = body
        self.request = request
        self.headers = headers or {}

    async def text(self):
        return self._body


class FakeRequest:
    def __init__(self, url, method="GET", resource_type="xhr",
                 headers=None, post_data=None, frame=None):
        self.url = url
        self.method = method
        self.resource_type = resource_type
        self.headers = headers or {}
        self.post_data = post_data
        self.frame = frame


class FakeFrame:
    def __init__(self, url):
        self.url = url


class FakePage:
    def __init__(self):
        self.handlers = {}

    def on(self, event, handler):
        self.handlers[event] = handler

    def emit(self, event, *args):
        if event in self.handlers:
            result = self.handlers[event](*args)
            import inspect
            if inspect.isawaitable(result):
                import asyncio
                asyncio.run(result)


def test_store_roundtrip_and_caps(tmp_path):
    store = TrafficStore(tmp_path / "traffic.jsonl", max_events=2)
    assert store.append(TrafficEvent(kind="xhr", request_id="a", url="https://x/1")) is True
    assert store.append(TrafficEvent(kind="xhr", request_id="b", url="https://x/2")) is True
    assert store.append(TrafficEvent(kind="xhr", request_id="c", url="https://x/3")) is False
    assert store.count() == 2
    loaded = store.load()
    assert [e["url"] for e in loaded] == ["https://x/1", "https://x/2"]
    assert len(store.digest()) == 64


def test_capture_redacts_credentials_at_capture_time():
    page = FakePage()
    capture = TrafficCapture(identity={"name": "user_a", "source": "auth_harness",
                                       "verified": True})
    capture.attach(page)
    request = FakeRequest(
        "https://x/api/me", method="POST",
        headers={"Authorization": "Bearer sekret123", "Cookie": "session=abc",
                 "Content-Type": "application/json"},
        post_data='{"password": "hunter2", "token": "eyJhbGciOiJIUzI1NiJ9.abc.def"}',
        frame=FakeFrame("https://x/app"))
    response = FakeResponse(
        "https://x/api/me", 200,
        '{"ok": true, "token": "eyJhbGciOiJIUzI1NiJ9.abc.def"}',
        request, headers={"Content-Type": "application/json", "Set-Cookie": "s=1"})
    page.emit("request", request)
    page.emit("response", response)

    assert len(capture.events) == 2
    req_event, resp_event = capture.events
    assert "Authorization" not in json.dumps(req_event.request_headers)
    assert "Cookie" not in json.dumps(req_event.request_headers)
    assert "Content-Type" in req_event.request_headers
    assert "hunter2" not in json.dumps(req_event.to_dict())
    assert "sekret123" not in json.dumps(req_event.to_dict())
    assert "<redacted>" in req_event.request_body
    assert "eyJ" not in req_event.request_body
    assert "<redacted>" in resp_event.response_body
    assert "eyJ" not in resp_event.response_body
    assert "Set-Cookie" not in json.dumps(resp_event.response_headers)
    assert "content-type" in resp_event.response_headers
    assert resp_event.parent_request_id == f"{request.method} {request.url}"
    assert req_event.identity["name"] == "user_a"
    assert capture.requests_seen == 1


def test_capture_filters_static_assets():
    page = FakePage()
    capture = TrafficCapture()
    capture.attach(page)
    page.emit("request", FakeRequest("https://x/logo.png", resource_type="image"))
    page.emit("request", FakeRequest("https://x/api/items", resource_type="fetch"))
    assert [e.url for e in capture.events] == ["https://x/api/items"]


def test_capture_event_cap():
    page = FakePage()
    capture = TrafficCapture(max_events=2)
    capture.attach(page)
    for i in range(5):
        page.emit("request", FakeRequest(f"https://x/api/{i}"))
    assert len(capture.events) == 2


def test_bodies_are_capped():
    page = FakePage()
    capture = TrafficCapture(max_response_body=64)
    capture.attach(page)
    request = FakeRequest("https://x/api", resource_type="xhr")
    page.emit("response", FakeResponse("https://x/api", 200, "a" * 1000, request))
    assert len(capture.events[0].response_body) <= 64


def test_settle_budget_counts_requests_once():
    page = FakePage()
    capture = TrafficCapture()
    capture.attach(page)
    page.emit("request", FakeRequest("https://x/a"))
    page.emit("request", FakeRequest("https://x/b"))

    class FakeBudget:
        def __init__(self):
            self.consumed = 0

        def consume_request(self, count=1):
            self.consumed += count

    budget = FakeBudget()
    settled = capture.settle_budget(budget)
    assert settled == 2
    assert budget.consumed == 2
    assert capture.settle_budget(budget) == 0


def test_build_workflow_orders_by_capture_and_skips_assets():
    events = [
        {"kind": "xhr", "url": "https://x/api/2", "method": "GET",
         "resource_type": "xhr",
         "identity": {"name": "user_a"}, "request_headers": {},
         "request_body": ""},
        {"kind": "xhr", "url": "https://x/logo.png", "method": "GET",
         "resource_type": "image", "identity": {"name": "user_a"},
         "request_headers": {}, "request_body": ""},
        {"kind": "xhr", "url": "https://x/api/1", "method": "POST",
         "resource_type": "fetch",
         "identity": {"name": "anonymous"}, "request_headers": {},
         "request_body": '{"a": 1}'},
        {"kind": "response", "url": "https://x/api/2", "status": 200},
    ]
    workflow = build_workflow(events, source="test")
    assert [s.url for s in workflow.steps] == ["https://x/api/2", "https://x/api/1"]
    assert workflow.steps[0].identity_ref == "user_a"
    assert workflow.steps[1].body == '{"a": 1}'
    assert workflow.identity_order == ["user_a", "anonymous"]
