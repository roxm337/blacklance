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


def test_cross_identity_pass_flags_other_identity_records(monkeypatch):
    """I3: an open collection returning another identity's markers in a
    given identity's session is a cross-identity leak."""
    st = StateManager(str(Path(tempfile.mkdtemp()) / "acme.com"))
    st.add_asset("api_endpoint", "api_endpoint:https://acme.com/api/Feedbacks",
                 "https://acme.com/api/Feedbacks", confidence="FIRM",
                 sources=["t"], attrs={})

    async def fake_cws(url, no_session=False, follow_redirects=False, timeout=10, **kw):
        return {"status": 200,
                "body": '{"status":"success","data":[{"UserId":1,"comment":"x"}]}',
                "content_type": "application/json"}

    class FakeIdentity:
        def __init__(self, name, markers):
            self.name = name
            self.verified = True
            self.privileged = False
            self.verification_note = "ok"

    class FakeHarness:
        def __init__(self):
            self.mutations = None
            self.identities = {"alice": FakeIdentity("alice", ()),
                               "bob": FakeIdentity("bob", ())}

        def adopt_discovered(self, state, log=None):
            return 0

        async def establish_all(self, base_url=""):
            return [self.identities["alice"], self.identities["bob"]]

        async def request(self, identity, url, method="GET", **kwargs):
            if identity == "alice":
                return {"status": 200,
                        "body": '{"data":[{"UserId":1,"owner_email":"alice@x.com"},{"UserId":2,"owner_email":"bob@x.com"}]}'}
            return {"status": 200,
                    "body": '{"data":[{"UserId":2,"owner_email":"bob@x.com"}]}'}

    monkeypatch.setattr(bf, "curl_with_status", fake_cws)
    monkeypatch.setattr(bf, "AuthHarness", lambda config: FakeHarness())
    m = BFLAAudit(st, {"target": {"domain": "acme.com", "active": False},
                       "modules": {"bfla_audit": {"matrix": {"enabled": True}}},
                       "paths": {}})
    m.domain = "acme.com"
    assert asyncio.run(m.run()) == "done"
    titles = [f["title"] for f in st.findings["findings"]]
    assert any("Cross-identity collection leak" in t for t in titles)


def test_cross_identity_pass_opt_in_off_by_default(monkeypatch):
    st = StateManager(str(Path(tempfile.mkdtemp()) / "acme.com"))
    st.add_asset("api_endpoint", "api_endpoint:https://acme.com/api/Feedbacks",
                 "https://acme.com/api/Feedbacks", confidence="FIRM",
                 sources=["t"], attrs={})

    async def fake_cws(url, no_session=False, follow_redirects=False, timeout=10, **kw):
        return {"status": 200,
                "body": '{"status":"success","data":[{"UserId":1}]}',
                "content_type": "application/json"}

    monkeypatch.setattr(bf, "curl_with_status", fake_cws)
    m = BFLAAudit(st, {"target": {"domain": "acme.com", "active": False},
                       "modules": {}, "paths": {}})
    m.domain = "acme.com"
    assert asyncio.run(m.run()) == "done"
    titles = [f["title"] for f in st.findings["findings"]]
    assert not any("Cross-identity collection leak" in t for t in titles)
