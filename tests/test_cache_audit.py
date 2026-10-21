"""Web cache poisoning probe."""

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import modules.cache_audit as ca
from modules.cache_audit import CacheAudit, cacheable_signals
from state.manager import StateManager


def test_cacheable_signals_detects_cdn_and_cache_control():
    assert "x-cache" in cacheable_signals("X-Cache: HIT\nServer: x")
    assert "cf-cache-status" in cacheable_signals("cf-cache-status: HIT")
    assert cacheable_signals("Server: nginx\nContent-Type: text/html") == []


def _state():
    st = StateManager(str(Path(tempfile.mkdtemp()) / "acme.com"))
    st.add_asset("webapp", "webapp:https://acme.com", "https://acme.com",
                 confidence="CONFIRMED", sources=["t"], attrs={})
    return st


def test_unkeyed_reflection_on_cacheable_response_is_high(monkeypatch):
    st = _state()

    async def fake_curl(url, output="status", headers=None, timeout=12, **kw):
        marker = ""
        if headers:
            for v in headers.values():
                if str(v).startswith("wcp"):
                    marker = v
        hdr = "HTTP/1.1 200 OK\nX-Cache: HIT\nCache-Control: public, max-age=60\n"
        body = f'<link href="https://{marker}/style.css">' if marker else "<html>home</html>"
        return {"status": 200, "headers": hdr, "body": body}

    async def fake_cws(url, **kw):
        return {"status": 404, "body": "", "content_type": ""}

    monkeypatch.setattr(ca, "curl", fake_curl)
    monkeypatch.setattr(ca, "curl_with_status", fake_cws)

    m = CacheAudit(st, {"target": {"domain": "acme.com", "active": False},
                        "modules": {}, "paths": {}})
    m.domain = "acme.com"
    assert asyncio.run(m.run()) == "done"
    titles = [f["title"] for f in st.findings["findings"]]
    assert "Web cache poisoning via unkeyed header" in titles


def test_reflection_without_cacheability_is_not_reported(monkeypatch):
    st = _state()

    async def fake_curl(url, output="status", headers=None, timeout=12, **kw):
        # Reflects the header, but the response is NOT cacheable.
        marker = ""
        if headers:
            for v in headers.values():
                if str(v).startswith("wcp"):
                    marker = v
        return {"status": 200, "headers": "HTTP/1.1 200\nCache-Control: no-store\n",
                "body": f"https://{marker}/" if marker else "home"}

    async def fake_cws(url, **kw):
        return {"status": 404, "body": "", "content_type": ""}

    monkeypatch.setattr(ca, "curl", fake_curl)
    monkeypatch.setattr(ca, "curl_with_status", fake_cws)

    m = CacheAudit(st, {"target": {"domain": "acme.com", "active": False},
                        "modules": {}, "paths": {}})
    m.domain = "acme.com"
    asyncio.run(m.run())
    assert st.findings["findings"] == []   # not cacheable → no finding
