"""Broken authorization — unauthenticated API data exposure."""

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import modules.bfla_audit as bf
from modules.bfla_audit import BFLAAudit, returns_records, is_sensitive_collection
from state.manager import StateManager


def test_returns_records_shapes():
    assert returns_records('[{"a":1},{"b":2}]') == 2
    assert returns_records('{"status":"success","data":[{"id":1}]}') == 1
    assert returns_records('{"data":[]}') == 0
    assert returns_records("<html>page</html>") == 0


def test_sensitivity_classification():
    assert is_sensitive_collection("/api/Feedbacks")
    assert is_sensitive_collection("/rest/user")
    assert not is_sensitive_collection("/api/Products")


def test_flags_unauth_sensitive_collection(monkeypatch):
    st = StateManager(str(Path(tempfile.mkdtemp()) / "acme.com"))
    st.add_asset("webapp", "webapp:https://acme.com", "https://acme.com",
                 confidence="CONFIRMED", sources=["t"], attrs={})
    for coll in ("/api/Feedbacks", "/api/Products", "/api/Users"):
        st.add_asset("api_endpoint", f"api_endpoint:https://acme.com{coll}",
                     f"https://acme.com{coll}", confidence="FIRM", sources=["t"], attrs={})

    async def fake_cws(url, no_session=False, follow_redirects=False, timeout=10, **kw):
        if url.endswith("/api/Feedbacks"):
            return {"status": 200, "body": '{"status":"success","data":[{"UserId":1,"comment":"x"}]}', "content_type": "application/json"}
        if url.endswith("/api/Products"):
            return {"status": 200, "body": '{"data":[{"id":1,"name":"Juice"}]}', "content_type": "application/json"}
        if url.endswith("/api/Users"):
            return {"status": 401, "body": "Unauthorized", "content_type": "text/html"}
        # baseline control paths → 404 (so not a catch-all)
        return {"status": 404, "body": "not found", "content_type": "text/html"}

    monkeypatch.setattr(bf, "curl_with_status", fake_cws)
    m = BFLAAudit(st, {"target": {"domain": "acme.com", "active": False},
                       "modules": {}, "paths": {}})
    m.domain = "acme.com"
    assert asyncio.run(m.run()) == "done"

    findings = {f["title"]: f for f in st.findings["findings"]}
    assert "Unauthenticated API data exposure: /api/Feedbacks" in findings
    assert findings["Unauthenticated API data exposure: /api/Feedbacks"]["severity"] == "HIGH"
    # Products is public data → LOW, not suppressed but not alarming
    assert findings["Unauthenticated API data exposure: /api/Products"]["severity"] == "LOW"
    # Users is protected → no finding
    assert "Unauthenticated API data exposure: /api/Users" not in findings
