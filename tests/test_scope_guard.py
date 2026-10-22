"""Scope file enforcement: deny wins, unknown hosts fail closed."""

import asyncio
import json
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tools.wrappers as wrappers
from core.scope_guard import (
    ScopeGuard, from_config, host_matches, load_scope)


def test_apex_rule_covers_subdomains_but_wildcard_does_not_cover_apex():
    assert host_matches("acme.com", "acme.com")
    assert host_matches("acme.com", "api.acme.com")
    assert host_matches("*.acme.com", "api.acme.com")
    assert not host_matches("*.acme.com", "acme.com")
    assert not host_matches("acme.com", "evil-acme.com")


def test_deny_beats_allow_and_unknown_hosts_fail_closed():
    guard = ScopeGuard(allow=["acme.com"], deny=["admin.acme.com"],
                       allow_external=False)
    assert guard.check("https://api.acme.com/x") == (True, "in scope")
    ok, reason = guard.check("https://admin.acme.com/")
    assert ok is False and "denied" in reason
    ok, reason = guard.check("https://elsewhere.test/")
    assert ok is False and "allow list" in reason
    ok, reason = guard.check("ftp://acme.com/")
    assert ok is False and "http(s)" in reason


def test_external_is_allowed_only_when_opted_in():
    open_guard = ScopeGuard(allow=["acme.com"], allow_external=True)
    assert open_guard.check("https://api.nvd.nist.gov/")[0] is True
    closed = ScopeGuard(allow=["acme.com"], allow_external=False)
    assert closed.check("https://api.nvd.nist.gov/")[0] is False


def _write_scope(payload):
    path = Path(tempfile.mkdtemp()) / "scope.json"
    path.write_text(json.dumps(payload))
    return path


def test_no_file_means_no_enforcement():
    assert from_config({"scope": {"file": "/nonexistent/scope.json"}}) is None


def test_a_malformed_file_fails_closed():
    path = Path(tempfile.mkdtemp()) / "scope.json"
    path.write_text("{not json")
    guard = from_config({"scope": {"file": str(path)}})
    assert guard is not None
    assert guard.check("https://acme.com/")[0] is False


def test_the_file_is_read_with_config_override():
    path = _write_scope({"allow": ["acme.com"], "deny": [],
                         "allow_external": False})
    guard = from_config({"scope": {"file": str(path)}})
    assert guard.check("https://api.acme.com/")[0] is True
    override = from_config({"scope": {"file": str(path),
                                      "allow_external": True}})
    assert override.check("https://example.org/")[0] is True


def test_blocked_requests_never_leave_the_process():
    guard = ScopeGuard(allow=["acme.com"], allow_external=False)
    wrappers.set_scope_guard(guard)
    try:
        result = asyncio.run(wrappers.curl("http://evil.test/"))
    finally:
        wrappers.set_scope_guard(None)
    assert result["status"] == 0
    assert result["error"].startswith("blocked_by_scope")
    assert result["body"] == ""
