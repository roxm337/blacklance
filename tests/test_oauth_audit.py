"""OAuth/OIDC flow audit."""

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import modules.oauth_audit as oa
from modules.oauth_audit import OAuthAudit, parse_oidc_config, redirect_uri_mutations
from state.manager import StateManager


def test_parse_oidc_config():
    cfg = parse_oidc_config({
        "authorization_endpoint": "https://a/authorize",
        "token_endpoint": "https://a/token",
        "response_types_supported": ["code", "token"],
        "code_challenge_methods_supported": ["S256"]})
    assert cfg["authorization_endpoint"] == "https://a/authorize"
    assert "token" in cfg["response_types"]
    assert cfg["pkce"] == ["S256"]


def test_redirect_uri_mutations_carry_marker():
    muts = redirect_uri_mutations("https://acme.com", "MK.example")
    labels = {l for l, _ in muts}
    assert "arbitrary host" in labels and "userinfo trick" in labels
    assert all("MK.example" in ru for _, ru in muts)


def test_redirect_uri_open_is_high_finding(monkeypatch):
    st = StateManager(str(Path(tempfile.mkdtemp()) / "acme.com"))
    st.add_asset("webapp", "webapp:https://acme.com", "https://acme.com",
                 confidence="CONFIRMED", sources=["t"], attrs={})

    async def fake_json_status(url, **kw):
        if "openid-configuration" in url:
            return (200, {"authorization_endpoint": "https://acme.com/authorize",
                          "response_types_supported": ["code"]})
        return (404, None)

    async def fake_curl(url, output="status", **kw):
        # The authorize endpoint reflects the attacker redirect_uri into Location.
        if "/authorize" in url and "redirect_uri=" in url:
            ru = url.split("redirect_uri=", 1)[1]
            return {"status": 302, "headers": f"HTTP/1.1 302\nLocation: {ru}\n",
                    "body": ""}
        return {"status": 200, "headers": "", "body": "home"}

    async def fake_curl_with_status(url, **kw):
        return {"status": 404, "body": "", "content_type": ""}

    monkeypatch.setattr(oa, "curl_json_with_status", fake_json_status)
    monkeypatch.setattr(oa, "curl", fake_curl)
    monkeypatch.setattr(oa, "curl_with_status", fake_curl_with_status)

    m = OAuthAudit(st, {"target": {"domain": "acme.com", "active": False},
                        "modules": {}, "paths": {}})
    m.domain = "acme.com"
    assert asyncio.run(m.run()) == "done"

    titles = [f["title"] for f in st.findings["findings"]]
    assert "OAuth redirect_uri accepts attacker-controlled host" in titles
    f = next(x for x in st.findings["findings"] if x["title"].startswith("OAuth redirect_uri"))
    assert f["severity"] == "HIGH"


def test_no_oauth_endpoints_is_clean(monkeypatch):
    st = StateManager(str(Path(tempfile.mkdtemp()) / "acme.com"))
    st.add_asset("webapp", "webapp:https://acme.com", "https://acme.com",
                 confidence="CONFIRMED", sources=["t"], attrs={})

    async def fake_json_status(url, **kw):
        return (404, None)

    async def fake_curl(url, output="status", **kw):
        # Nothing reflects; common authorize paths 404.
        return {"status": 404, "headers": "", "body": "not found"}

    async def fake_cws(url, **kw):
        return {"status": 404, "body": "", "content_type": ""}

    monkeypatch.setattr(oa, "curl_json_with_status", fake_json_status)
    monkeypatch.setattr(oa, "curl", fake_curl)
    monkeypatch.setattr(oa, "curl_with_status", fake_cws)

    m = OAuthAudit(st, {"target": {"domain": "acme.com", "active": False},
                        "modules": {}, "paths": {}})
    m.domain = "acme.com"
    assert asyncio.run(m.run()) == "done"
    assert st.findings["findings"] == []   # no false positives
