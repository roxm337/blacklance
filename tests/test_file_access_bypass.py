"""File-serving filter bypass (null byte / double extension)."""

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import modules.file_access_bypass as fb
from modules.file_access_bypass import FileAccessBypass
from state.manager import StateManager


def _state():
    st = StateManager(str(Path(tempfile.mkdtemp()) / "acme.com"))
    st.add_asset("webapp", "webapp:https://acme.com", "https://acme.com",
                 confidence="CONFIRMED", sources=["t"], attrs={})
    return st


def test_null_byte_bypass_confirmed(monkeypatch):
    st = _state()

    async def fake_cws(url, timeout=10, follow_redirects=False, **kw):
        if url.endswith("/ftp"):
            return {"status": 200, "content_type": "text/html",
                    "body": '<a href="ftp/package-lock.json.bak">x</a>'}
        if url.endswith("package-lock.json.bak%2500.md"):
            return {"status": 200, "content_type": "application/json",
                    "body": '{"name":"juice-shop","lockfileVersion":2, ...lots of content...}' * 3}
        if url.endswith("package-lock.json.bak"):
            return {"status": 403, "content_type": "text/html", "body": "Forbidden"}
        return {"status": 404, "content_type": "text/html", "body": "not found"}

    monkeypatch.setattr(fb, "curl_with_status", fake_cws)
    m = FileAccessBypass(st, {"target": {"domain": "acme.com", "active": True},
                              "modules": {}, "paths": {}})
    m.domain = "acme.com"
    assert asyncio.run(m.run()) == "done"
    titles = [f["title"] for f in st.findings["findings"]]
    assert "File-serving filter bypass (restricted file served)" in titles


def test_no_bypass_when_still_blocked(monkeypatch):
    st = _state()

    async def fake_cws(url, timeout=10, follow_redirects=False, **kw):
        if url.endswith("/ftp"):
            return {"status": 200, "content_type": "text/html",
                    "body": '<a href="ftp/secret.bak">x</a>'}
        if "secret.bak" in url:
            return {"status": 403, "content_type": "text/html", "body": "Forbidden"}
        return {"status": 404, "content_type": "text/html", "body": "nf"}

    monkeypatch.setattr(fb, "curl_with_status", fake_cws)
    m = FileAccessBypass(st, {"target": {"domain": "acme.com", "active": True},
                              "modules": {}, "paths": {}})
    m.domain = "acme.com"
    asyncio.run(m.run())
    assert st.findings["findings"] == []
