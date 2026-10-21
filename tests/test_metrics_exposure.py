"""Observability / metrics endpoint exposure."""

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import modules.metrics_exposure as me
from modules.metrics_exposure import MetricsExposure
from state.manager import StateManager


def _state():
    st = StateManager(str(Path(tempfile.mkdtemp()) / "acme.com"))
    st.add_asset("webapp", "webapp:https://acme.com", "https://acme.com",
                 confidence="CONFIRMED", sources=["t"], attrs={})
    return st


def test_prometheus_metrics_flagged(monkeypatch):
    st = _state()

    async def fake_cws(url, timeout=10, follow_redirects=False, **kw):
        if url.endswith("/metrics"):
            return {"status": 200, "content_type": "text/plain",
                    "body": "# HELP app_requests_total Total\n# TYPE app_requests_total counter\napp_requests_total 5\n"}
        return {"status": 404, "content_type": "text/html", "body": "nf"}

    monkeypatch.setattr(me, "curl_with_status", fake_cws)
    m = MetricsExposure(st, {"target": {"domain": "acme.com", "active": False},
                             "modules": {}, "paths": {}})
    m.domain = "acme.com"
    assert asyncio.run(m.run()) == "done"
    titles = [f["title"] for f in st.findings["findings"]]
    assert "Observability endpoint exposed: /metrics" in titles


def test_generic_200_not_flagged(monkeypatch):
    st = _state()

    async def fake_cws(url, timeout=10, follow_redirects=False, **kw):
        # /metrics exists but returns an HTML page, not metrics format.
        if url.endswith("/metrics"):
            return {"status": 200, "content_type": "text/html", "body": "<html>dashboard</html>"}
        return {"status": 404, "content_type": "text/html", "body": "nf"}

    monkeypatch.setattr(me, "curl_with_status", fake_cws)
    m = MetricsExposure(st, {"target": {"domain": "acme.com", "active": False},
                             "modules": {}, "paths": {}})
    m.domain = "acme.com"
    asyncio.run(m.run())
    assert st.findings["findings"] == []
