"""CSRF / cookie posture."""

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import modules.csrf_audit as ca
from modules.csrf_audit import CSRFAudit, cookie_csrf_issues
from state.manager import StateManager


def test_cookie_csrf_issues():
    issues = cookie_csrf_issues(
        ["Set-Cookie: sessionid=abc; Path=/; SameSite=None"], https=True)
    kinds = [i[2] for i in issues]
    assert any("SameSite=None" in k for k in kinds)
    assert any("HttpOnly" in k for k in kinds)   # none set
    assert any("Secure" in k for k in kinds)     # https but no Secure
    # A hardened cookie yields nothing.
    assert cookie_csrf_issues(
        ["Set-Cookie: sessionid=abc; HttpOnly; Secure; SameSite=Strict"],
        https=True) == []
    # Non-session cookie ignored.
    assert cookie_csrf_issues(["Set-Cookie: theme=dark"], https=True) == []


def test_flags_samesite_none(monkeypatch):
    st = StateManager(str(Path(tempfile.mkdtemp()) / "acme.com"))
    st.add_asset("webapp", "webapp:https://acme.com", "https://acme.com",
                 confidence="CONFIRMED", sources=["t"], attrs={})

    async def fake_curl(url, output="status", timeout=10, **kw):
        return {"status": 200,
                "headers": "HTTP/1.1 200\nSet-Cookie: connect.sid=xyz; Path=/; SameSite=None\n",
                "body": "home"}

    monkeypatch.setattr(ca, "curl", fake_curl)
    m = CSRFAudit(st, {"target": {"domain": "acme.com", "active": False},
                       "modules": {}, "paths": {}})
    m.domain = "acme.com"
    assert asyncio.run(m.run()) == "done"
    titles = [f["title"] for f in st.findings["findings"]]
    assert any("connect.sid" in t for t in titles)


def test_hardened_cookies_skip(monkeypatch):
    st = StateManager(str(Path(tempfile.mkdtemp()) / "acme.com"))
    st.add_asset("webapp", "webapp:https://acme.com", "https://acme.com",
                 confidence="CONFIRMED", sources=["t"], attrs={})

    async def fake_curl(url, output="status", timeout=10, **kw):
        return {"status": 200,
                "headers": "HTTP/1.1 200\nSet-Cookie: sid=x; HttpOnly; Secure; SameSite=Lax\n",
                "body": "home"}

    monkeypatch.setattr(ca, "curl", fake_curl)
    m = CSRFAudit(st, {"target": {"domain": "acme.com", "active": False},
                       "modules": {}, "paths": {}})
    m.domain = "acme.com"
    assert asyncio.run(m.run()) == "skipped"
