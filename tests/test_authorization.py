"""I3 authorization-matrix engine tests: cell classification gates,
field diffs, revocation protocol, sharing, canary PROOF path with R8."""

from __future__ import annotations

import asyncio

import pytest

from core.authorization import (AuthorizationMatrix, MatrixCell, _field_diff,
                                _identity_markers, _looks_like_owner_key,
                                _maybe_json)
from state.manager import StateManager


class FakeIdentity:
    def __init__(self, name, markers=(), logout="POST", logout_url=""):
        self.name = name
        self.verified = True
        self._markers = tuple(markers)
        self.logout_method = logout
        self.logout_url = logout_url
        self.logout_calls = 0
        self.established = 0

    def own_markers(self):
        return set(self._markers)

    async def establish(self, base_url=""):
        self.established += 1
        self.verified = True
        return True

    async def logout(self, base_url=""):
        self.logout_calls += 1
        return True


class FakeHarness:
    def __init__(self, responder):
        self.identities = {}
        self.responder = responder
        self.calls = []

    async def request(self, identity, url, method="GET", headers=None,
                      data=None, **kwargs):
        self.calls.append((identity, url, method, data))
        return self.responder(identity, url, method, data)

    async def request_anonymous(self, url, method="GET", headers=None,
                                data=None, **kwargs):
        self.calls.append(("anonymous", url, method, data))
        return self.responder("anonymous", url, method, data)


def _matrix(responder, tmp_path, cfg=None, identities=None):
    state = StateManager(str(tmp_path / "run" / "example.com"))
    harness = FakeHarness(responder)
    for identity in (identities or []):
        harness.identities[identity.name] = identity
    matrix = AuthorizationMatrix(harness, "https://x", cfg or {}, state)
    return matrix, state, harness


# ── pure helpers ──────────────────────────────────────────────────

def test_field_diff_reports_only_differing_leaves():
    a = '{"id": 1, "customer": {"email": "a@x.com", "name": "A"}, "ts": 1}'
    b = '{"id": 1, "customer": {"email": "b@x.com", "name": "B"}, "ts": 2}'
    diffs = _field_diff(a, b)
    assert "customer.email" in diffs
    assert "customer.name" in diffs
    assert "id" not in diffs
    assert "ts" in diffs  # caller filters noise


def test_field_diff_non_json_fallback():
    assert _field_diff("same", "same") == []
    assert _field_diff("same", "other") == ["<root>"]


def test_identity_markers_attribution():
    body = '{"UserId": 26, "email": "bob@example.com", "status": "active"}'
    markers = _identity_markers(body)
    assert "26" in markers
    assert "bob@example.com" in markers
    assert "active" not in markers


def test_owner_key_flattening():
    assert _looks_like_owner_key("userid")
    assert _looks_like_owner_key("customer_email")
    assert not _looks_like_owner_key("status")


def test_maybe_json():
    assert _maybe_json('{"a": 1}') == {"a": 1}
    assert _maybe_json("plain text") is None
    assert _maybe_json("") is None


# ── cell classification ──────────────────────────────────────────

def test_denied_and_absent_are_healthy(tmp_path):
    async def go():
        matrix, state, harness = _matrix(
            lambda i, u, m, d: {"status": 403, "body": "forbidden"},
            tmp_path)
        victim = FakeIdentity("user_b", markers=("bob@x.com",))
        cell = await matrix._cell(FakeIdentity("user_a"), victim,
                                  "/api/x/{id}", "5")
        assert cell.outcome == "denied"
        matrix2, _, _ = _matrix(
            lambda i, u, m, d: {"status": 404, "body": "{}"},
            tmp_path)
        cell2 = await matrix2._cell(FakeIdentity("user_a"), victim,
                                    "/api/x/{id}", "5")
        assert cell2.outcome == "absent"

    return asyncio.run(go())


def test_ambiguous_when_indistinguishable_from_missing(tmp_path):
    async def go():
        def responder(identity, url, method, data):
            if "1000005" in url or "zzz" in url:
                return {"status": 200, "body": '{"empty": true}'}
            return {"status": 200, "body": '{"empty": true}'}

        matrix, _, _ = _matrix(responder, tmp_path)
        victim = FakeIdentity("user_b", markers=("bob@x.com",))
        cell = await matrix._cell(FakeIdentity("user_a"), victim,
                                  "/api/x/{id}", "5")
        assert cell.outcome == "ambiguous"

    return asyncio.run(go())


def test_leak_when_attributed_to_victim(tmp_path):
    async def go():
        def responder(identity, url, method, data):
            if "1000007" in url:
                return {"status": 200, "body": '{"id": 1000007}'}
            if identity == "user_a":
                return {"status": 200,
                        "body": '{"UserId": 7, "email": "bob@x.com"}'}
            return {"status": 200,
                    "body": '{"UserId": 7, "email": "bob@x.com"}'}

        matrix, _, _ = _matrix(responder, tmp_path)
        victim = FakeIdentity("user_b", markers=("bob@x.com",))
        cell = await matrix._cell(FakeIdentity("user_a"), victim,
                                  "/api/invoices/{id}", "7")
        assert cell.outcome == "leak"

    return asyncio.run(go())


def test_ownership_matrix_and_violations(tmp_path):
    async def go():
        def responder(identity, url, method, data):
            if "1000007" in url:
                return {"status": 200, "body": '{"id": 1000007}'}
            if identity == "user_a":
                return {"status": 200,
                        "body": '{"UserId": 7, "email": "bob@x.com"}'}
            return {"status": 200,
                    "body": '{"UserId": 7, "email": "bob@x.com"}'}

        victim = FakeIdentity("user_b", markers=("bob@x.com",))
        attacker = FakeIdentity("user_a")
        matrix, state, harness = _matrix(
            responder, tmp_path, identities=[victim, attacker])
        await matrix.run_ownership(
            [{"template": "/api/invoices/{id}", "ref": "7",
              "owner": victim}],
            [(attacker, victim)])
        violations = matrix.report.violations()
        assert len(violations) == 1
        assert violations[0].outcome == "leak"
        assert violations[0].attribution["owner"] == "user_b"

    return asyncio.run(go())


# ── revocation ───────────────────────────────────────────────────

def test_revocation_untested_without_logout(tmp_path):
    async def go():
        identity = FakeIdentity("user_a", logout_url="")
        matrix, _, _ = _matrix(lambda i, u, m, d: {"status": 200, "body": ""},
                               tmp_path, identities=[identity])
        await matrix.run_revocation(identity)
        assert matrix.report.checks["revocation"]["status"] == "untested"

    return asyncio.run(go())


def test_revocation_protocol_proven(tmp_path):
    async def go():
        state = {"logged_out": False}

        def responder(identity, url, method, data):
            if method == "POST" and url.endswith("/logout"):
                state["logged_out"] = True
                return {"status": 200, "body": ""}
            if state["logged_out"]:
                return {"status": 403, "body": "login"}
            return {"status": 200, "body": "ok"}

        identity = FakeIdentity("user_a", logout_url="/logout")
        matrix, _, harness = _matrix(responder, tmp_path,
                                     identities=[identity])

        async def fake_logout(base_url=""):
            await harness.request("user_a", base_url + "/logout",
                                  method="POST")
            return True

        identity.logout = fake_logout
        await matrix.run_revocation(identity)
        check = matrix.report.checks["revocation"]
        assert check["status"] == "proven"
        assert check["after_logout"] == "denied"
        assert check["reestablished"] == "allowed"

    return asyncio.run(go())


# ── sharing ──────────────────────────────────────────────────────

def test_sharing_ok_and_regression(tmp_path):
    async def go():
        def responder(identity, url, method, data):
            if identity == "user_b":
                return {"status": 403, "body": ""}
            return {"status": 200, "body": '{"shared": 1}'}

        victim = FakeIdentity("user_a")
        attacker = FakeIdentity("user_b")
        matrix, _, _ = _matrix(responder, tmp_path,
                               identities=[victim, attacker])
        await matrix.run_sharing(
            [{"read_probe": "/api/shared/{id}", "ids": [9]}],
            {"user_a": victim, "user_b": attacker})
        check = matrix.report.checks["sharing"]
        assert check["ok"] == 0
        assert len(check["regressions"]) == 1

    return asyncio.run(go())


# ── canaries (PROOF path + R8) ───────────────────────────────────

def test_canary_proven_with_verified_cleanup(tmp_path):
    async def go():
        orders = {}

        def responder(identity, url, method, data):
            if method == "POST" and url.endswith("/api/orders"):
                orders["9"] = {"id": 9, "note": "osint-canary-abc"}
                return {"status": 201, "body": '{"id": 9}'}
            if method == "DELETE":
                orders.pop("9", None)
                return {"status": 200, "body": ""}
            if url.endswith("/api/orders/9"):
                if "9" not in orders:
                    return {"status": 404, "body": ""}
                return {"status": 200,
                        "body": f'{{"id": 9, "note": "{orders["9"]["note"]}"}}'}
            return {"status": 200, "body": "{}"}

        owner = FakeIdentity("user_b")
        attacker = FakeIdentity("user_a")
        matrix, state, _ = _matrix(responder, tmp_path,
                                   identities=[owner, attacker])
        results = await matrix.run_canaries([{
            "name": "order-read",
            "owner_identity": "user_b",
            "forbidden_identity": "user_a",
            "seed": "osint-canary-abc",
            "create": {"method": "POST", "url_template": "/api/orders",
                       "body_template": '{"note": "osint-canary-abc"}',
                       "extract_id": {"type": "jsonpath", "path": "id"}},
            "read_probe": {"url_template": "/api/orders/{id}",
                           "extract": {"type": "jsonpath", "path": "note"},
                           "expect": {"op": "eq", "value": "osint-canary-abc"}},
            "cleanup": {"method": "DELETE",
                        "url_template": "/api/orders/{id}",
                        "verify": {"method": "http_get",
                                   "expect_status": [404]}},
        }])
        assert results[0]["proven"] is True
        assert results[0]["observed"] == "osint-canary-abc"
        assert results[0]["cleanup_status"] == "verified"
        assert state.mutations.outstanding() == []
        rows = matrix.finding_rows("test")
        proofs = [r for r in rows if r["tier"] == "proof"]
        assert len(proofs) == 1
        assert proofs[0]["verified"] is True

    return asyncio.run(go())


def test_canary_denied_read_is_not_proof(tmp_path):
    """A denied read is healthy — the canary must only prove LEAKS."""
    async def go():
        def responder(identity, url, method, data):
            if method == "POST":
                return {"status": 201, "body": '{"id": 9}'}
            if identity == "user_a" and url.endswith("/api/orders/9"):
                return {"status": 403, "body": "forbidden"}
            if url.endswith("/api/orders/9"):
                return {"status": 200, "body": '{"id": 9, "note": "seed"}'}
            if method == "DELETE":
                return {"status": 200, "body": ""}
            return {"status": 200, "body": "{}"}

        owner = FakeIdentity("user_b")
        attacker = FakeIdentity("user_a")
        matrix, state, _ = _matrix(responder, tmp_path,
                                   identities=[owner, attacker])
        results = await matrix.run_canaries([{
            "name": "order-read",
            "owner_identity": "user_b",
            "forbidden_identity": "user_a",
            "seed": "seed",
            "create": {"method": "POST", "url_template": "/api/orders",
                       "body_template": '{"note": "seed"}',
                       "extract_id": {"type": "jsonpath", "path": "id"}},
            "read_probe": {"url_template": "/api/orders/{id}",
                           "extract": {"type": "jsonpath", "path": "note"},
                           "expect": {"op": "eq", "value": "seed"}},
            "cleanup": {"method": "DELETE",
                        "url_template": "/api/orders/{id}",
                        "verify": {"method": "http_get",
                                   "expect_status": [404]}},
        }])
        assert results[0]["proven"] is False
        assert matrix.finding_rows("test") == [] or all(
            r["tier"] != "proof" for r in matrix.finding_rows("test"))

    return asyncio.run(go())
