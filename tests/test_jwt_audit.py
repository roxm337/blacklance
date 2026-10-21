"""JWT harvest & analysis."""

import asyncio
import base64
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import modules.jwt_audit as jw
from modules.jwt_audit import JWTAudit, decode_jwt, extract_jwts
from state.manager import StateManager


def _mk_jwt(header, payload):
    def seg(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{seg(header)}.{seg(payload)}.sigpart123"


def test_decode_and_extract():
    tok = _mk_jwt({"alg": "RS256", "typ": "JWT"},
                  {"data": {"role": "admin", "password": "0192023a7bbd7325"}})
    h, p = decode_jwt(tok)
    assert h["alg"] == "RS256" and p["data"]["role"] == "admin"
    assert tok in extract_jwts(f"set-cookie: token={tok}; Path=/")
    assert extract_jwts("no token here") == set()


def _state():
    st = StateManager(str(Path(tempfile.mkdtemp()) / "acme.com"))
    st.add_asset("webapp", "webapp:https://acme.com", "https://acme.com",
                 confidence="CONFIRMED", sources=["t"], attrs={})
    return st


def test_payload_sensitive_and_alg_surface(monkeypatch):
    st = _state()
    tok = _mk_jwt({"alg": "RS256", "typ": "JWT"},
                  {"data": {"email": "admin@x", "role": "admin",
                            "password": "0192023a7bbd73250516f069df18b500"}})

    async def fake_curl(url, method="GET", output="status", data=None, timeout=12, headers=None, **kw):
        # Homepage issues the token as a cookie.
        if method == "GET":
            return {"status": 200, "headers": f"Set-Cookie: token={tok}; Path=/",
                    "body": "<html>home</html>"}
        return {"status": 401, "headers": "", "body": "invalid"}

    monkeypatch.setattr(jw, "curl", fake_curl)
    m = JWTAudit(st, {"target": {"domain": "acme.com", "active": True},
                     "modules": {}, "paths": {}})
    m.domain = "acme.com"
    assert asyncio.run(m.run()) == "done"
    titles = [f["title"] for f in st.findings["findings"]]
    assert "JWT payload exposes sensitive data" in titles
    assert any(t.startswith("JWT algorithm forgery surface") for t in titles)


def test_no_jwt_skips(monkeypatch):
    st = _state()

    async def fake_curl(url, method="GET", output="status", data=None, timeout=12, headers=None, **kw):
        return {"status": 200, "headers": "", "body": "no tokens"} if method == "GET" \
            else {"status": 404, "headers": "", "body": "nf"}

    monkeypatch.setattr(jw, "curl", fake_curl)
    m = JWTAudit(st, {"target": {"domain": "acme.com", "active": True},
                     "modules": {}, "paths": {}})
    m.domain = "acme.com"
    assert asyncio.run(m.run()) == "skipped"
