"""CRLF / header injection + HPP."""

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import modules.crlf_audit as cr
from modules.crlf_audit import CRLFAudit, header_injected
from state.manager import StateManager


def test_header_injected_detects_real_header_only():
    m = "deadbeef12"
    assert header_injected(f"HTTP/1.1 200\nX-CRLF-{m}: {m}\n", m)
    assert header_injected(f"Set-Cookie: crlf={m}", m)
    # marker only in body-ish text, not as a header line → not injected
    assert header_injected("HTTP/1.1 200\nContent-Type: text/html", m) == ""
    assert header_injected(f"X-Other: value with {m} inside", m) == ""


def _state(param):
    st = StateManager(str(Path(tempfile.mkdtemp()) / "acme.com"))
    st.add_asset("webapp", "webapp:https://acme.com", "https://acme.com",
                 confidence="CONFIRMED", sources=["t"], attrs={})
    st.add_asset("parameter", f"param:https://acme.com/r:{param}", param,
                 confidence="FIRM", sources=["t"],
                 attrs={"url": "https://acme.com/r", "parameter": param})
    return st


def test_crlf_injection_confirmed(monkeypatch):
    st = _state("redirect")

    async def fake_curl(url, output="status", follow_redirects=True, timeout=12, **kw):
        # Server decodes CRLF and reflects the injected header.
        marker = ""
        if "X-CRLF-" in url:
            marker = url.split("X-CRLF-", 1)[1].split(":", 1)[0]
        hdr = f"HTTP/1.1 302\nX-CRLF-{marker}: {marker}\n" if marker else "HTTP/1.1 200\n"
        return {"status": 302 if marker else 200, "headers": hdr, "body": ""}

    monkeypatch.setattr(cr, "curl", fake_curl)
    m = CRLFAudit(st, {"target": {"domain": "acme.com", "active": True},
                       "modules": {}, "paths": {}})
    m.domain = "acme.com"
    assert asyncio.run(m.run()) == "done"
    titles = [f["title"] for f in st.findings["findings"]]
    assert "CRLF / HTTP response header injection" in titles


def test_hpp_lead_when_both_values_reflected(monkeypatch):
    st = _state("q")

    async def fake_curl(url, output="status", follow_redirects=True, timeout=12, **kw):
        if output == "full" or "X-CRLF-" in url:
            # No CRLF reflection.
            return {"status": 200, "headers": "HTTP/1.1 200\n", "body": ""}
        # HPP probe: echo both values.
        body = url.split("?", 1)[1] if "?" in url else ""
        vals = [kv.split("=", 1)[1] for kv in body.split("&") if "=" in kv]
        return {"status": 200, "headers": "", "body": " ".join(vals)}

    monkeypatch.setattr(cr, "curl", fake_curl)
    m = CRLFAudit(st, {"target": {"domain": "acme.com", "active": True},
                       "modules": {}, "paths": {}})
    m.domain = "acme.com"
    asyncio.run(m.run())
    titles = [f["title"] for f in st.findings["findings"]]
    assert "HTTP parameter pollution (both values reflected)" in titles
