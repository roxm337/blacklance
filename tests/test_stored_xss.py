"""Stored / persistent XSS."""

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import modules.stored_xss as sx
from modules.stored_xss import StoredXSS, stored_reflection, is_html_response, payload_for
from state.manager import StateManager


def test_stored_reflection_only_on_unescaped():
    m = "abc123"
    assert stored_reflection(f"...<img src=x onerror=alert('xss{m}')>...", m)
    # entity-encoded echo = storage working correctly, not a finding
    assert not stored_reflection(f"...&lt;img src=x onerror=alert('xss{m}')&gt;...", m)
    assert not stored_reflection("nothing here", m)


def test_payload_fires_cleanly_and_carries_marker():
    p = payload_for("mk99")
    assert "alert('xssmk99')" in p and "onerror=xss" not in p


def test_is_html_response():
    assert is_html_response("HTTP/1.1 200\nContent-Type: text/html; charset=utf-8")
    assert not is_html_response("Content-Type: application/json")


def _state():
    st = StateManager(str(Path(tempfile.mkdtemp()) / "acme.com"))
    st.add_asset("webapp", "webapp:https://acme.com", "https://acme.com",
                 confidence="CONFIRMED", sources=["t"], attrs={})
    st.add_asset("api_endpoint", "api_endpoint:https://acme.com/api/Feedbacks",
                 "https://acme.com/api/Feedbacks", confidence="FIRM", sources=["t"], attrs={})
    return st


def _run(monkeypatch, render_ctype, escape=False):
    st = _state()
    stored = {"payload": ""}

    async def fake_curl(url, method="GET", output="status", data=None, timeout=12, headers=None, **kw):
        if method == "POST" and data and "onerror=alert" in data:
            import json
            stored["payload"] = json.loads(data).get("comment", "")
            return {"status": 201, "headers": "", "body": "created"}
        # GET re-read (output="full") → headers + body, verbatim or escaped.
        val = stored["payload"]
        if escape:
            val = val.replace("<", "&lt;").replace(">", "&gt;")
        body = (f'<html><div>{val}</div></html>' if "html" in render_ctype
                else f'[{{"comment":"{val}"}}]')
        return {"status": 200,
                "headers": f"HTTP/1.1 200 OK\nContent-Type: {render_ctype}\n",
                "body": body}

    monkeypatch.setattr(sx, "curl", fake_curl)
    m = StoredXSS(st, {"target": {"domain": "acme.com", "active": True},
                       "modules": {}, "paths": {}, "auth": {}})
    m.domain = "acme.com"
    asyncio.run(m.run())
    return st


def test_html_render_is_confirmed_and_verified(monkeypatch):
    st = _run(monkeypatch, "text/html; charset=utf-8")
    f = [x for x in st.findings["findings"] if x["title"] == "Stored / persistent XSS"]
    assert f, "HTML-context unescaped reflection must be CONFIRMED stored XSS"
    assert f[0]["confidence"] == "CONFIRMED" and f[0]["verified"] is True


def test_json_echo_is_firm_not_confirmed(monkeypatch):
    st = _run(monkeypatch, "application/json")
    titles = [x["title"] for x in st.findings["findings"]]
    # Must NOT over-claim CONFIRMED stored XSS on a JSON echo.
    assert "Stored / persistent XSS" not in titles
    f = [x for x in st.findings["findings"]
         if x["title"].startswith("Stored input reflected unescaped")]
    assert f and f[0]["confidence"] == "FIRM" and not f[0]["verified"]


def test_escaped_storage_not_flagged(monkeypatch):
    st = _run(monkeypatch, "text/html", escape=True)
    assert st.findings["findings"] == []
