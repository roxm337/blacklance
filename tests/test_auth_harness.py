"""Identity session lifecycle regression: logout must clear every copy of
the session material so a later re-establishment does not keep sending the
revoked token (found by the I7 revocation lab probe)."""

from __future__ import annotations

import asyncio

import core.auth_harness as mod
from core.auth_harness import Identity


def test_logout_clears_authorization_header_for_fresh_login(monkeypatch):
    identity = Identity(name="alice", bearer_token="old-token")
    identity.headers["Authorization"] = "Bearer old-token"
    identity.cookies = {"sid": "old"}

    async def fake_curl(url, **kwargs):
        return {"status": 200}

    monkeypatch.setattr(mod, "curl", fake_curl)
    assert asyncio.run(identity.logout("https://x.example")) is True
    assert identity.bearer_token == ""
    assert identity.cookies == {}
    assert "Authorization" not in identity.headers
    assert identity.verified is False


def test_identity_resolves_secret_references(monkeypatch):
    monkeypatch.setenv("OSINT_APP_TOKEN", "tok-123")
    harness = mod.AuthHarness({"auth": {"identities": [{
        "name": "alice",
        "bearer_token": "env:OSINT_APP_TOKEN",
    }]}})
    identity = harness.identities["alice"]
    assert identity.bearer_token == "tok-123"
    assert identity.credential_error == ""


def test_missing_secret_reference_is_unusable(monkeypatch):
    monkeypatch.delenv("OSINT_APP_MISSING", raising=False)
    harness = mod.AuthHarness({"auth": {"identities": [{
        "name": "alice",
        "bearer_token": "env:OSINT_APP_MISSING",
    }]}})
    identity = harness.identities["alice"]
    assert asyncio.run(identity.establish("https://x.example")) is False
    assert "OSINT_APP_MISSING" in identity.verification_note


def test_expired_and_revoked_credentials_are_refused():
    expired = Identity(name="a", bearer_token="tok",
                       expires_at="2020-01-01T00:00:00Z")
    assert asyncio.run(expired.establish("https://x.example")) is False
    assert "expired" in expired.verification_note

    revoked = Identity(name="b", bearer_token="tok", revoked=True)
    assert asyncio.run(revoked.establish("https://x.example")) is False
    assert "revoked" in revoked.verification_note
