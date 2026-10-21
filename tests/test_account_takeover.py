"""Account-takeover primitives: password-reset host poisoning."""

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import modules.account_takeover as at
from modules.account_takeover import AccountTakeover, _marker_in_url_context
from state.manager import StateManager


def test_marker_in_url_context():
    assert _marker_in_url_context('<a href="https://evil.example/r">x</a>', "evil.example")
    assert _marker_in_url_context("reset at https://evil.example/t", "evil.example")
    # plain-text echo (not in a URL) is not actionable
    assert not _marker_in_url_context("your host is evil.example today", "evil.example")
    assert not _marker_in_url_context("nothing here", "evil.example")


def _state():
    st = StateManager(str(Path(tempfile.mkdtemp()) / "acme.com"))
    st.add_asset("webapp", "webapp:https://acme.com", "https://acme.com",
                 confidence="CONFIRMED", sources=["t"], attrs={})
    return st


def test_inert_reflection_lead_without_sending_email(monkeypatch):
    st = _state()
    posted = {"n": 0}

    async def fake_curl(url, method="GET", output="status", headers=None,
                        data=None, timeout=12, **kw):
        if method == "POST":
            posted["n"] += 1
        marker = (headers or {}).get("X-Forwarded-Host", "")
        # Reset page reflects the forwarded host into a link.
        body = (f'<form>reset your password</form>'
                f'<a href="https://{marker}/reset">link</a>') if marker else \
               "reset your password"
        return {"status": 200, "headers": "HTTP/1.1 200\n", "body": body}

    async def fake_cws(url, **kw):
        if url.endswith("/forgot-password"):
            return {"status": 200, "body": "reset your password here",
                    "content_type": "text/html"}
        return {"status": 404, "body": "", "content_type": ""}

    monkeypatch.setattr(at, "curl", fake_curl)
    monkeypatch.setattr(at, "curl_with_status", fake_cws)

    # No test_email configured → confirmation POST must NOT be sent.
    m = AccountTakeover(st, {"target": {"domain": "acme.com", "active": True},
                             "modules": {}, "paths": {}})
    m.domain = "acme.com"
    assert asyncio.run(m.run()) == "done"
    titles = [f["title"] for f in st.findings["findings"]]
    assert "Password-reset host reflection (poisoning lead)" in titles
    assert posted["n"] == 0, "must not POST a reset without a configured mailbox"


def test_confirmation_only_with_test_email(monkeypatch):
    st = _state()
    posted = {"n": 0}

    async def fake_curl(url, method="GET", output="status", headers=None,
                        data=None, timeout=12, **kw):
        marker = (headers or {}).get("X-Forwarded-Host", "")
        if method == "POST":
            posted["n"] += 1
            return {"status": 200, "headers": "HTTP/1.1 200\n",
                    "body": f'reset link https://{marker}/r'}
        return {"status": 200, "headers": "HTTP/1.1 200\n",
                "body": "reset your password"}

    async def fake_cws(url, **kw):
        if url.endswith("/forgot-password"):
            return {"status": 200, "body": "reset your password",
                    "content_type": "text/html"}
        return {"status": 404, "body": "", "content_type": ""}

    monkeypatch.setattr(at, "curl", fake_curl)
    monkeypatch.setattr(at, "curl_with_status", fake_cws)

    m = AccountTakeover(st, {
        "target": {"domain": "acme.com", "active": True},
        "modules": {"account_takeover": {"test_email": "me@mybox.test"}},
        "paths": {}})
    m.domain = "acme.com"
    assert asyncio.run(m.run()) == "done"
    titles = [f["title"] for f in st.findings["findings"]]
    assert "Password-reset poisoning via Host header (confirmed)" in titles
    assert posted["n"] >= 1


def test_no_reset_endpoint_skips(monkeypatch):
    st = _state()

    async def fake_curl(url, **kw):
        return {"status": 404, "headers": "", "body": "nope"}

    async def fake_cws(url, **kw):
        return {"status": 404, "body": "not found", "content_type": ""}

    monkeypatch.setattr(at, "curl", fake_curl)
    monkeypatch.setattr(at, "curl_with_status", fake_cws)

    m = AccountTakeover(st, {"target": {"domain": "acme.com", "active": True},
                             "modules": {}, "paths": {}})
    m.domain = "acme.com"
    assert asyncio.run(m.run()) == "skipped"
