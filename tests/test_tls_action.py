"""`network.tls.cert` — prove a TLS weakness from the handshake itself.

`_probe_tls` is injected so the tests never open a socket; the action's
classification logic (which finding counts as proof) is what is pinned.
"""

import asyncio

import pytest

from actions.network import tls as tls_action
from actions.registry import ActionContext


def _ctx(url):
    return ActionContext(action_id="network.tls.cert", params={"url": url},
                         target=url)


def _probe(**overrides):
    info = {"host": "t.test", "port": 443, "version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384", "verified": True,
            "not_after": "Nov  3 12:00:00 2027 GMT", "error": "",
            "expired": False, "self_signed": False,
            "hostname_mismatch": False, "weak_protocol": False}
    info.update(overrides)
    return info


def _patch(monkeypatch, info):
    async def fake(host, port, timeout=10):
        fake.seen = (host, port)
        return info

    monkeypatch.setattr(tls_action, "_probe_tls", fake)
    return fake


def test_expired_certificate_is_confirmed(monkeypatch):
    _patch(monkeypatch, _probe(verified=False, expired=True,
                               error="certificate has expired"))
    result = asyncio.run(tls_action.tls_cert(_ctx("https://t.test/")))

    assert result.success is True
    assert result.confidence == "CONFIRMED"
    assert result.data["issues"] == ["expired"]


def test_self_signed_certificate_is_confirmed(monkeypatch):
    _patch(monkeypatch, _probe(verified=False, self_signed=True))
    result = asyncio.run(tls_action.tls_cert(_ctx("https://t.test/")))

    assert result.success is True
    assert result.data["issues"] == ["self_signed"]


def test_hostname_mismatch_and_legacy_protocol_are_both_reported(monkeypatch):
    _patch(monkeypatch, _probe(hostname_mismatch=True, weak_protocol=True))
    result = asyncio.run(tls_action.tls_cert(_ctx("https://t.test/")))

    assert result.success is True
    assert set(result.data["issues"]) == {"hostname_mismatch", "weak_protocol"}


def test_valid_certificate_is_not_a_finding(monkeypatch):
    _patch(monkeypatch, _probe())
    result = asyncio.run(tls_action.tls_cert(_ctx("https://t.test/")))

    assert result.success is False
    assert result.data["issues"] == []
    assert "within baseline" in result.error


def test_handshake_failure_is_reported_as_such(monkeypatch):
    _patch(monkeypatch, _probe(version="", error="connection refused"))
    result = asyncio.run(tls_action.tls_cert(_ctx("https://t.test/")))

    assert result.success is False
    assert "handshake failed" in result.error


def test_plain_http_is_not_probed_as_tls(monkeypatch):
    fake = _patch(monkeypatch, _probe())
    result = asyncio.run(tls_action.tls_cert(_ctx("http://t.test/")))

    assert result.success is False
    assert "not a TLS endpoint" in result.error
    assert not hasattr(fake, "seen")


def test_custom_tls_port_is_probed(monkeypatch):
    fake = _patch(monkeypatch, _probe(expired=True))
    asyncio.run(tls_action.tls_cert(_ctx("https://t.test:8443/api")))
    assert fake.seen == ("t.test", 8443)


def test_invalid_port_is_reported_not_raised():
    result = asyncio.run(tls_action.tls_cert(_ctx("https://t.test:notaport/")))
    assert result.success is False
    assert "invalid port" in (result.error or "")
