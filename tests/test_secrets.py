"""R10 tests: credential references, expiry/revocation and KeyVault refs."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from core import secrets
from core.keyvault import KeyVault


def test_env_reference_resolves(monkeypatch):
    monkeypatch.setenv("OSINT_TEST_TOKEN", "tok-123")
    assert secrets.resolve("env:OSINT_TEST_TOKEN") == "tok-123"
    assert secrets.resolve_tree({"a": "env:OSINT_TEST_TOKEN",
                                 "b": ["env:OSINT_TEST_TOKEN"]}) == {
        "a": "tok-123", "b": ["tok-123"]}


def test_missing_env_reference_raises(monkeypatch):
    monkeypatch.delenv("OSINT_TEST_MISSING", raising=False)
    with pytest.raises(secrets.SecretError):
        secrets.resolve("env:OSINT_TEST_MISSING")
    assert secrets.resolve("env:OSINT_TEST_MISSING", required=False) == ""


def test_file_reference_resolves_and_errors(tmp_path):
    path = tmp_path / "token.txt"
    path.write_text("file-token\n", encoding="utf-8")
    assert secrets.resolve(f"file:{path}") == "file-token"
    with pytest.raises(secrets.SecretError):
        secrets.resolve(f"file:{tmp_path / 'missing.txt'}")


def test_literal_values_and_descriptions():
    assert secrets.resolve("plain-token") == "plain-token"
    assert secrets.describe("env:NAME") == "env:NAME"
    assert secrets.describe("plain-token") == "literal"
    assert secrets.describe("") == "missing"


def test_expiry_and_revocation_states():
    now = datetime.now(timezone.utc)
    future = secrets.credential_state(
        (now + timedelta(hours=1)).isoformat())
    assert future["usable"] is True and future["expired"] is False
    past = secrets.credential_state(
        (now - timedelta(hours=1)).isoformat())
    assert past["usable"] is False and past["expired"] is True
    revoked = secrets.credential_state(None, True)
    assert revoked["usable"] is False and revoked["revoked"] is True
    with pytest.raises(secrets.SecretError):
        secrets.parse_expiry("not-a-date")


def test_keyvault_resolves_references(monkeypatch):
    monkeypatch.setenv("OSINT_TEST_VT", "vt-secret")
    vault = KeyVault({"api_keys": {"virustotal": "env:OSINT_TEST_VT"}})
    assert vault.has("virustotal") is True
    assert vault.get("virustotal") == "vt-secret"


def test_literal_secret_fields_detects_plaintext():
    entry = {
        "name": "alice",
        "bearer_token": "env:APP_TOKEN",
        "cookies": {"session": "plain-cookie"},
        "expires_at": "2030-01-01T00:00:00Z",
    }
    assert secrets.literal_secret_fields(entry) == ["cookies"]
    assert [name for name, _ in secrets.credential_fields(entry)] \
        == ["bearer_token", "cookies"]
