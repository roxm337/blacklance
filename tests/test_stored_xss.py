"""Stored / persistent XSS."""

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import modules.stored_xss as sx
from modules.stored_xss import StoredXSS, stored_reflection
from state.manager import StateManager


def test_stored_reflection_only_on_unescaped():
    m = "abc123"
    assert stored_reflection(f'...<img src=x onerror=xss{m}>...', m)
    # entity-encoded echo = storage working correctly, not a finding
    assert not stored_reflection(f'...&lt;img src=x onerror=xss{m}&gt;...', m)
    assert not stored_reflection("nothing here", m)


def _state():
    st = StateManager(str(Path(tempfile.mkdtemp()) / "acme.com"))
    st.add_asset("webapp", "webapp:https://acme.com", "https://acme.com",
                 confidence="CONFIRMED", sources=["t"], attrs={})
    st.add_asset("api_endpoint", "api_endpoint:https://acme.com/api/Feedbacks",
                 "https://acme.com/api/Feedbacks", confidence="FIRM", sources=["t"], attrs={})
    return st


def test_stored_xss_confirmed(monkeypatch):
    st = _state()
    stored = {"payload": ""}

    async def fake_curl(url, method="GET", output="status", data=None, timeout=12, headers=None, **kw):
        # POST stores whatever payload was sent.
        if method == "POST" and data and "onerror=xss" in data:
            import json
            stored["payload"] = json.loads(data).get("comment", "")
            return {"status": 201, "body": "created"}
        return {"status": 200, "body": "ok"}

    async def fake_cws(url, timeout=12, headers=None, **kw):
        # GET renders the stored payload verbatim.
        return {"status": 200, "body": f'[{{"comment":"{stored["payload"]}"}}]'}

    monkeypatch.setattr(sx, "curl", fake_curl)
    monkeypatch.setattr(sx, "curl_with_status", fake_cws)
    m = StoredXSS(st, {"target": {"domain": "acme.com", "active": True},
                       "modules": {}, "paths": {}, "auth": {}})
    m.domain = "acme.com"
    assert asyncio.run(m.run()) == "done"
    titles = [f["title"] for f in st.findings["findings"]]
    assert "Stored / persistent XSS" in titles


def test_escaped_storage_not_flagged(monkeypatch):
    st = _state()
    stored = {"payload": ""}

    async def fake_curl(url, method="GET", output="status", data=None, timeout=12, headers=None, **kw):
        if method == "POST" and data and "onerror=xss" in data:
            import json
            stored["payload"] = json.loads(data).get("comment", "")
        return {"status": 200, "body": "ok"}

    async def fake_cws(url, timeout=12, headers=None, **kw):
        # Rendered HTML-escaped (safe).
        safe = stored["payload"].replace("<", "&lt;").replace(">", "&gt;")
        return {"status": 200, "body": f'[{{"comment":"{safe}"}}]'}

    monkeypatch.setattr(sx, "curl", fake_curl)
    monkeypatch.setattr(sx, "curl_with_status", fake_cws)
    m = StoredXSS(st, {"target": {"domain": "acme.com", "active": True},
                       "modules": {}, "paths": {}, "auth": {}})
    m.domain = "acme.com"
    asyncio.run(m.run())
    assert st.findings["findings"] == []
