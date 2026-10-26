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
