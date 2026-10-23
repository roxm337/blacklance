"""Auth-bypass via SQLi on login."""

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import modules.auth_bypass as ab
from modules.auth_bypass import AuthBypass, auth_success
from state.manager import StateManager

_JWT = ("eyJhbGciOiAiSFMyNTYifQ."
        "eyJkYXRhIjogeyJyb2xlIjogImFkbWluIiwgImVtYWlsIjogImFkbWluQGFjbWUuY29tIn19."
        "sig123456")


def test_auth_success_signals():
    assert auth_success("", f'{{"authentication":{{"token":"{_JWT}"}}}}')
    assert auth_success("Set-Cookie: session=abcdefgh12345; Path=/", "")
    assert not auth_success("", '{"error":"Invalid email or password"}')


def _state():
    st = StateManager(str(Path(tempfile.mkdtemp()) / "acme.com"))
    st.add_asset("webapp", "webapp:https://acme.com", "https://acme.com",
                 confidence="CONFIRMED", sources=["t"], attrs={})
    return st


def test_sqli_login_bypass_confirmed(monkeypatch):
    st = _state()

    async def fake_cws(url, method="GET", data=None, timeout=10, **kw):
        # Endpoint discovery: /rest/user/login answers POST (not 404).
        if url.endswith("/rest/user/login"):
            return {"status": 401, "body": '{"error":"invalid"}'}
        return {"status": 404, "body": "nope"}

    async def fake_curl(url, method="POST", output="full", data=None, timeout=10, headers=None, **kw):
        # Injection payload authenticates; bad creds fail.
        if data and "OR 1=1" in data:
            return {"status": 200, "headers": "HTTP/1.1 200\n",
                    "body": f'{{"authentication":{{"token":"{_JWT}"}}}}'}
        return {"status": 401, "headers": "HTTP/1.1 401\n",
                "body": '{"error":"Invalid email or password"}'}

    monkeypatch.setattr(ab, "curl_with_status", fake_cws)
    monkeypatch.setattr(ab, "curl", fake_curl)
    m = AuthBypass(st, {"target": {"domain": "acme.com", "active": True},
                        "modules": {}, "paths": {}})
    m.domain = "acme.com"
    assert asyncio.run(m.run()) == "done"
    f = [x for x in st.findings["findings"] if x["title"].startswith("Authentication bypass")]
    assert f and f[0]["severity"] == "CRITICAL"
    assert f[0]["verified"] is True
    assert f[0]["verification"]["token_captured"] is True
    identities = st.get_assets_by_type("identity_credential")
    assert identities and identities[0]["attrs"]["technique"] == "sqli_auth_bypass"
    assert identities[0]["attrs"]["role"] == "admin"


def test_no_bypass_when_payload_also_fails(monkeypatch):
    st = _state()

    async def fake_cws(url, method="GET", data=None, timeout=10, **kw):
        return {"status": 401, "body": "invalid"} if url.endswith("/rest/user/login") else {"status": 404, "body": ""}

    async def fake_curl(url, method="POST", output="full", data=None, timeout=10, headers=None, **kw):
        return {"status": 401, "headers": "", "body": '{"error":"invalid"}'}

    monkeypatch.setattr(ab, "curl_with_status", fake_cws)
    monkeypatch.setattr(ab, "curl", fake_curl)
    m = AuthBypass(st, {"target": {"domain": "acme.com", "active": True},
                        "modules": {}, "paths": {}})
    m.domain = "acme.com"
    asyncio.run(m.run())
    assert st.findings["findings"] == []
