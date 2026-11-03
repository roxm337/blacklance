"""`recon.security_headers` — re-read the live headers, twice.

The threshold is deliberate: one missing header is configuration taste, so the
action must not promote it. A set that changes between fetches is reported at
FIRM, not confirmed.
"""

import asyncio

import pytest

from actions.recon import headers as headers_action
from actions.registry import ActionContext

_BARE = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: nginx\r\n"
_FULL = ("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
         "Strict-Transport-Security: max-age=63072000\r\n"
         "Content-Security-Policy: default-src 'self'\r\n"
         "X-Content-Type-Options: nosniff\r\n"
         "X-Frame-Options: DENY\r\n"
         "Referrer-Policy: no-referrer\r\n"
         "Permissions-Policy: geolocation=()\r\n")


def _ctx(url="https://t.test/"):
    return ActionContext(action_id="recon.security_headers",
                         params={"url": url}, target=url)


@pytest.fixture
def curl_replies(monkeypatch):
    replies = []

    async def fake(url, **kwargs):
        return replies.pop(0)

    monkeypatch.setattr(headers_action, "curl", fake)
    return replies


def _resp(blob, status=200):
    return {"status": status, "body": "<html></html>", "headers": blob}


def test_three_missing_headers_confirm(curl_replies):
    curl_replies.extend([_resp(_BARE), _resp(_BARE)])

    result = asyncio.run(headers_action.security_headers(_ctx()))

    assert result.success is True
    assert result.confidence == "CONFIRMED"
    assert len(result.data["missing"]) >= 3


def test_one_or_two_missing_headers_are_not_promoted(curl_replies):
    only_hsts_missing = _FULL.replace(
        "Strict-Transport-Security: max-age=63072000\r\n", "")
    curl_replies.append(_resp(only_hsts_missing))

    result = asyncio.run(headers_action.security_headers(_ctx()))

    assert result.success is False
    assert result.data["missing"] == ["strict-transport-security"]


def test_fully_hardened_endpoint_is_not_a_finding(curl_replies):
    curl_replies.append(_resp(_FULL))

    result = asyncio.run(headers_action.security_headers(_ctx()))

    assert result.success is False
    assert result.data["missing"] == []


def test_changing_header_set_is_refused(curl_replies):
    without_csp = _BARE
    with_csp = _BARE + "Content-Security-Policy: default-src 'self'\r\n"
    curl_replies.extend([_resp(without_csp), _resp(with_csp)])

    result = asyncio.run(headers_action.security_headers(_ctx()))

    assert result.success is False
    assert result.confidence == "FIRM"
    assert "changed between fetches" in result.error


def test_unreachable_endpoint_is_reported(curl_replies):
    curl_replies.append(_resp("", status=0))

    result = asyncio.run(headers_action.security_headers(_ctx()))

    assert result.success is False
    assert "unreachable" in result.error
