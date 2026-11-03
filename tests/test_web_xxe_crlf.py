"""XXE and CRLF proving actions.

Both classes used to fall into the generic `injection` token and arm the SQLi
oracle. These tests pin what each one actually requires: XXE needs disclosed
file content (not a DOCTYPE echo), and CRLF needs the probe in the response
*headers* (a body reflection is explicitly rejected).
"""

import asyncio
from urllib.parse import unquote, urlsplit

import pytest

from actions.registry import ActionContext
from actions.web import crlf as crlf_action
from actions.web import xxe as xxe_action


def _ctx(action_id, url="https://t.test/x", **params):
    return ActionContext(action_id=action_id,
                         params={"url": url, **params}, target=url)


# ── XXE ─────────────────────────────────────────────────────────────────

@pytest.fixture
def xxe_curl(monkeypatch):
    calls = []
    replies = []

    async def fake(url, **kwargs):
        calls.append(kwargs)
        return replies.pop(0)

    monkeypatch.setattr(xxe_action, "curl", fake)
    return calls, replies


def _resp(body="", status=200, headers=""):
    return {"status": status, "body": body, "headers": headers}


def test_xxe_requires_file_content_not_a_doctype_echo(xxe_curl):
    calls, replies = xxe_curl
    replies.extend([
        _resp("<ok>ok</ok>"),
        _resp("root:x:0:0:root:/root:/bin/bash"),
        _resp("root:x:0:0:root:/root:/bin/bash"),
    ])

    result = asyncio.run(xxe_action.xxe_detect(_ctx("web.xxe.detect")))

    assert result.success is True
    assert result.confidence == "CONFIRMED"
    assert result.data["findings"][0]["marker"] == "root:x:0:0:"
    assert calls[0]["method"] == "POST"
    assert all("Content-Type" in c["headers"] for c in calls)


def test_xxe_echoed_payload_is_not_expansion(xxe_curl):
    _, replies = xxe_curl
    # The endpoint reflects the request body; the marker never appears.
    replies.extend([
        _resp("<ok>ok</ok>"),
        _resp('<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>'),
        _resp('<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>'),
    ])

    result = asyncio.run(xxe_action.xxe_detect(_ctx("web.xxe.detect")))

    assert result.success is False
    assert "no external entity expansion" in result.error


def test_xxe_marker_already_on_baseline_is_skipped(xxe_curl):
    _, replies = xxe_curl
    replies.append(_resp(
        "root:x:0:0: root:*:0:0: daemon:x: nobody:x: "
        "[extensions] [fonts] for 16-bit app support"))

    result = asyncio.run(xxe_action.xxe_detect(_ctx("web.xxe.detect")))

    assert result.success is False
    assert "no external entity expansion" in result.error


# ── CRLF ────────────────────────────────────────────────────────────────

@pytest.fixture
def crlf_curl(monkeypatch):
    replies = []

    async def fake(url, **kwargs):
        query = unquote(urlsplit(url).query)
        if "X-Bhs-Probe:" in query:
            token = query.split("X-Bhs-Probe:", 1)[1].split("&")[0].strip()
            return _resp(headers=f"HTTP/1.1 200 OK\r\nX-Bhs-Probe: {token}\r\n")
        return _resp(headers="HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n")

    monkeypatch.setattr(crlf_action, "curl", fake)
    return replies


def test_crlf_header_injection_is_confirmed(crlf_curl):
    result = asyncio.run(
        crlf_action.crlf_detect(_ctx("web.crlf.detect", param="next")))

    assert result.success is True
    assert result.confidence == "CONFIRMED"
    assert result.data["header"] == "X-Bhs-Probe"


def test_crlf_body_reflection_is_not_splitting(monkeypatch):
    async def fake(url, **kwargs):
        query = unquote(urlsplit(url).query)
        token = query.split("X-Bhs-Probe:", 1)[1].split("&")[0].strip() \
            if "X-Bhs-Probe:" in query else ""
        return _resp(body=f"<p>{token}</p>",
                     headers="HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n")

    monkeypatch.setattr(crlf_action, "curl", fake)
    result = asyncio.run(
        crlf_action.crlf_detect(_ctx("web.crlf.detect", param="next")))

    assert result.success is False
    assert "not response splitting" in result.error
    assert result.evidence["body_reflected"] is True


def test_crlf_baseline_already_sets_probe_header(monkeypatch):
    async def fake(url, **kwargs):
        return _resp(headers="HTTP/1.1 200 OK\r\nX-Bhs-Probe: fixed\r\n")

    monkeypatch.setattr(crlf_action, "curl", fake)
    result = asyncio.run(
        crlf_action.crlf_detect(_ctx("web.crlf.detect", param="next")))

    assert result.success is False
    assert "not injectable" in result.error


def test_crlf_requires_a_parameter(crlf_curl):
    result = asyncio.run(crlf_action.crlf_detect(_ctx("web.crlf.detect")))

    assert result.success is False
    assert "url and param are required" in result.error
