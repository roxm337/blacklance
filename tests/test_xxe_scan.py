"""XXE injection scan."""

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import modules.xxe_scan as xx
from modules.xxe_scan import XXEScan, _oob_payload
from state.manager import StateManager


def test_oob_payload_embeds_callback():
    p = _oob_payload("http://oob.test/x")
    assert "http://oob.test/x" in p and "<!DOCTYPE" in p and "SYSTEM" in p


def _state():
    st = StateManager(str(Path(tempfile.mkdtemp()) / "acme.com"))
    st.add_asset("webapp", "webapp:https://acme.com", "https://acme.com",
                 confidence="CONFIRMED", sources=["t"], attrs={})
    st.add_asset("api_endpoint", "api_endpoint:https://acme.com/api/xmlparse",
                 "https://acme.com/api/xmlparse", confidence="FIRM",
                 sources=["t"], attrs={})
    return st


def test_inband_file_read_confirmed(monkeypatch):
    st = _state()

    async def fake_curl(url, method="GET", output="status", data=None,
                        headers=None, timeout=12, **kw):
        if method == "POST" and "xmlparse" in url and "file:///etc/passwd" in (data or ""):
            return {"status": 200, "headers": "", "body": "root:x:0:0:root:/root:/bin/sh"}
        return {"status": 400, "headers": "", "body": "bad request"}

    monkeypatch.setattr(xx, "curl", fake_curl)
    m = XXEScan(st, {"target": {"domain": "acme.com", "active": True},
                     "modules": {}, "paths": {}})
    m.domain = "acme.com"
    monkeypatch.setattr(m, "oob", lambda: None)   # no OOB channel
    assert asyncio.run(m.run()) == "done"
    titles = [f["title"] for f in st.findings["findings"]]
    assert "XXE: local file read (in-band)" in titles


def test_no_xml_signature_no_finding(monkeypatch):
    st = _state()

    async def fake_curl(url, method="GET", output="status", data=None,
                        headers=None, timeout=12, **kw):
        # Reflects nothing useful; just an error page.
        return {"status": 400, "headers": "", "body": "XML parse error"}

    monkeypatch.setattr(xx, "curl", fake_curl)
    m = XXEScan(st, {"target": {"domain": "acme.com", "active": True},
                     "modules": {}, "paths": {}})
    m.domain = "acme.com"
    monkeypatch.setattr(m, "oob", lambda: None)
    assert asyncio.run(m.run()) == "done"
    assert st.findings["findings"] == []


def test_blind_oob_confirmed(monkeypatch):
    st = _state()

    async def fake_curl(url, method="GET", output="status", data=None,
                        headers=None, timeout=12, **kw):
        return {"status": 200, "headers": "", "body": "ok"}

    class FakeOOB:
        poll_timeout = 8
        poll_interval = 2
        async def register_callback(self, note): return "corr1234"
        def callback_url(self, corr, tag): return f"http://oob.test/{corr}{tag}"
        async def poll(self, corr):
            # First drain empty, then report an interaction.
            if not getattr(self, "_drained", False):
                self._drained = True
                return []
            return [{"protocol": "dns"}]

    monkeypatch.setattr(xx, "curl", fake_curl)
    m = XXEScan(st, {"target": {"domain": "acme.com", "active": True},
                     "modules": {}, "paths": {}})
    m.domain = "acme.com"
    monkeypatch.setattr(m, "oob", lambda: FakeOOB())
    assert asyncio.run(m.run()) == "done"
    titles = [f["title"] for f in st.findings["findings"]]
    assert "XXE: blind out-of-band interaction" in titles
