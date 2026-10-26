"""I2 api_workflows module tests: discovery, skip paths, tier grading,
R8 mutation flow, impact re-verification, and path-param binding. The
schemathesis adapter is monkeypatched — no real tool runs here."""

from __future__ import annotations

import asyncio
import json

import pytest

from modules.api_workflows import APIWorkflows
from state.manager import StateManager


class FakeHarness:
    def __init__(self, responses=None):
        self.identities = {}
        self.responses = responses or {}
        self.established = 0

    def adopt_discovered(self, state, log=None):
        return 0

    async def establish_all(self, base_url=""):
        self.established += 1
        return list(self.identities.values())

    async def request(self, identity, url, method="GET", headers=None,
                      data=None, **kwargs):
        return self.responses.get(url, {"status": 200, "body": "{}"})

    async def request_anonymous(self, url, method="GET", headers=None,
                                data=None, **kwargs):
        return self.responses.get(url, {"status": 200, "body": "{}"})


def _module(tmp_path, cfg=None, assets=None, responses=None,
            fake_result=None):
    state = StateManager(str(tmp_path / "run" / "example.com"))
    for asset_type, value, attrs in (assets or []):
        state.add_asset(asset_type, f"{asset_type}:{value}", value,
                        confidence="FIRM", sources=["test"], attrs=attrs)
    config = {"target": {"domain": "example.com",
                         "base_url": "https://example.com"},
              "modules": {"api_workflows": dict(cfg or {})}}
    module = APIWorkflows(state, config)
    module._fake_result = fake_result
    return module, state


def _run(module, monkeypatch, fake_harness=None, fake_result=None,
         probe=None):
    import modules.api_workflows as mod

    if fake_result is None:
        fake_result = {"available": True, "backend": "local",
                       "version": "3.41.2", "exit_code": 1,
                       "records": [], "failures": [],
                       "unsupported": False, "error": None,
                       "report_path": "", "cassette_dir": "",
                       "workdir": "", "tool_output_tail": ""}
    fake_result = dict(fake_result)

    async def fake_run_schemathesis(spec_path, base_url, **kwargs):
        fake_result["_kwargs"] = kwargs
        return fake_result

    monkeypatch.setattr(mod, "schemathesis_available",
                        probe or (lambda: {"available": True,
                                           "backend": "local",
                                           "version": "3.41.2",
                                           "unsupported": False}))
    monkeypatch.setattr(mod, "run_schemathesis", fake_run_schemathesis)
    monkeypatch.setattr(mod, "AuthHarness",
                        lambda config: fake_harness or FakeHarness())
    monkeypatch.setattr(mod, "curl", _fake_curl({}))
    return asyncio.run(module.run())


def _fake_curl(responses):
    async def curl(url, **kwargs):
        if url.endswith(".json"):
            return {"status": 200, "body": SPEC}
        return responses.get(url, {"status": 404, "body": ""})
    return curl


SPEC = '{"openapi": "3.0.0", "paths": {"/api/orders": {"post": {}}}}'


def test_skips_when_disabled(monkeypatch, tmp_path):
    module, _ = _module(tmp_path, cfg={"enabled": False})
    result = _run(module, monkeypatch)
    assert result == "skipped"
    assert "disabled" in module.state.module["skipped"][-1]["reason"]


def test_skips_when_no_schema_assets(monkeypatch, tmp_path):
    module, _ = _module(tmp_path, cfg={"enabled": True})
    result = _run(module, monkeypatch)
    assert result == "skipped"
    assert "no OpenAPI" in module.state.module["skipped"][-1]["reason"]


def test_skips_when_tool_missing(monkeypatch, tmp_path):
    module, _ = _module(
        tmp_path, cfg={"enabled": True},
        assets=[("api_endpoint", "https://example.com/openapi.json",
                 {"type": "openapi", "endpoint_count": 3})])
    result = _run(
        module, monkeypatch,
        probe=lambda: {"available": False, "version": "3.20.0",
                       "unsupported": True,
                       "reason": "schemathesis 3.20.0 < 3.21.0"})
    assert result == "skipped"
    assert "3.20.0" in module.state.module["skipped"][-1]["reason"]


def test_schema_assets_sorted_by_endpoint_count_and_capped(monkeypatch,
                                                           tmp_path):
    module, _ = _module(
        tmp_path, cfg={"enabled": True, "max_schemas": 2},
        assets=[
            ("api_endpoint", "https://example.com/small.json",
             {"type": "openapi", "endpoint_count": 2}),
            ("api_endpoint", "https://example.com/big.json",
             {"type": "openapi", "endpoint_count": 10}),
            ("api_endpoint", "https://example.com/mid.json",
             {"type": "openapi", "endpoint_count": 5}),
        ])
    schemas = module._schema_assets(module._cfg())
    assert schemas == ["https://example.com/big.json",
                       "https://example.com/mid.json"]


def test_fetch_spec_rejects_non_spec_bodies(monkeypatch, tmp_path):
    module, _ = _module(tmp_path, cfg={"enabled": True})
    assert module._looks_like_spec("<html>docs</html>") is False
    assert module._looks_like_spec('{"paths": {}}') is True
    assert module._looks_like_spec('{"swagger": "2.0"}') is True


def test_grading_observation_and_candidate(monkeypatch, tmp_path):
    failures = [
        {"path": "/api/o", "method": "POST", "check": "not_a_server_error",
         "count": 1, "seeds": [1], "min_interactions": 2,
         "message": "500", "fingerprint": "fp-server-error-1"},
        {"path": "/api/o", "method": "POST",
         "check": "response_schema_conformance", "count": 2,
         "seeds": [2], "min_interactions": 1, "message": "schema drift",
         "fingerprint": "fp-schema-1"},
    ]
    fake_result = {"available": True, "backend": "local", "version": "3.41.2",
                   "exit_code": 1, "records": [], "failures": failures,
                   "unsupported": False, "error": None,
                   "report_path": "", "cassette_dir": "",
                   "workdir": "", "tool_output_tail": ""}
    module, state = _module(
        tmp_path, cfg={"enabled": True},
        assets=[("api_endpoint", "https://example.com/openapi.json",
                 {"type": "openapi", "endpoint_count": 3})])
    _run(module, monkeypatch, fake_result=fake_result)

    findings = state.findings["findings"]
    titles = [f["title"] for f in findings]
    assert any("API schema violations" in t for t in titles)
    assert any("API state violation" in t for t in titles)
    candidate = next(f for f in findings
                     if "API state violation" in f["title"])
    assert candidate["verified"] is False
    assert candidate["severity"] == "MEDIUM"
    low = next(f for f in findings if "API schema violations" in f["title"])
    assert low["severity"] == "LOW"


def test_impact_reverification_promotes_to_proof(monkeypatch, tmp_path):
    failures = [
        {"path": "/api/orders/9/pay", "method": "POST",
         "check": "not_a_server_error", "count": 1, "seeds": [1],
         "min_interactions": 3, "message": "500",
         "fingerprint": "fp-pay-1"},
    ]
    fake_result = {"available": True, "backend": "local", "version": "3.41.2",
                   "exit_code": 1, "records": [], "failures": failures,
                   "unsupported": False, "error": None,
                   "report_path": "", "cassette_dir": "",
                   "workdir": "", "tool_output_tail": ""}
    harness = FakeHarness(responses={
        "https://example.com/api/orders/9":
            {"status": 200, "body": '{"id": 9, "total": -1000, "status": "paid"}'},
    })

    class NamedIdentity:
        name = "lab_user"
        verified = True

        def request_headers(self):
            return {"Authorization": "Bearer tok"}

    harness.identities = {"lab_user": NamedIdentity()}
    module, state = _module(
        tmp_path,
        cfg={"enabled": True,
             "impact_probe": {
                 "url_template": "/api/orders/{order_id}",
                 "extract": {"type": "jsonpath", "path": "total"},
                 "expect": {"op": "lt", "value": 0}}},
        assets=[("api_endpoint", "https://example.com/openapi.json",
                 {"type": "openapi", "endpoint_count": 3})])
    _run(module, monkeypatch, fake_harness=harness,
         fake_result=fake_result)

    candidate = next(f for f in state.findings["findings"]
                     if "API state violation" in f["title"])
    assert candidate["verified"] is True
    assert candidate["confidence"] == "CONFIRMED"
    assert candidate["severity"] == "HIGH"
    # The impact probe re-read is recorded as evidence.
    evidence_types = [e.get("type") for e in state.evidence["items"]]
    assert "schemathesis_impact" in evidence_types


def test_mutation_ledger_not_required_without_cleanup_spec(monkeypatch,
                                                           tmp_path):
    module, state = _module(
        tmp_path, cfg={"enabled": True},
        assets=[("api_endpoint", "https://example.com/openapi.json",
                 {"type": "openapi", "endpoint_count": 3})])
    _run(module, monkeypatch)
    outstanding = state.mutations.outstanding()
    assert outstanding == []
    records = state.mutations.read_records()
    assert records, "fuzzer launch not recorded"
    current = state.mutations.current(records[0]["id"])
    assert current["cleanup"]["status"] == "not_required"


def test_mutation_ledger_verified_cleanup(monkeypatch, tmp_path):
    harness = FakeHarness(responses={
        "https://example.com/api/orders/9":
            {"status": 404, "body": ""},
    })

    class NamedIdentity:
        name = "lab_user"
        verified = True

        def request_headers(self):
            return {"Authorization": "Bearer tok"}

    harness.identities = {"lab_user": NamedIdentity()}
    failures = [
        {"path": "/api/orders/9/pay", "method": "POST",
         "check": "not_a_server_error", "count": 1, "seeds": [1],
         "min_interactions": 3, "message": "500",
         "fingerprint": "fp-pay-cleanup"},
    ]
    fake_result = {"available": True, "backend": "local", "version": "3.41.2",
                   "exit_code": 1, "records": [], "failures": failures,
                   "unsupported": False, "error": None,
                   "report_path": "", "cassette_dir": "",
                   "workdir": "", "tool_output_tail": ""}
    module, state = _module(
        tmp_path,
        cfg={"enabled": True,
             "cleanup": {"method": "DELETE",
                         "url_template": "/api/orders/{order_id}",
                         "verify": {"method": "http_get",
                                    "expect_status": [404]}}},
        assets=[("api_endpoint", "https://example.com/openapi.json",
                 {"type": "openapi", "endpoint_count": 3})])
    _run(module, monkeypatch, fake_harness=harness,
         fake_result=fake_result)

    records = state.mutations.read_records()
    current = state.mutations.current(records[0]["id"])
    assert current["cleanup"]["status"] == "verified"
    assert state.mutations.outstanding() == []


def test_bind_path_params(monkeypatch, tmp_path):
    module, _ = _module(tmp_path, cfg={"enabled": True})
    bound = module._bind_path_params(
        "/api/orders/9/pay", "/api/orders/{order_id}")
    assert bound == "/api/orders/9"
    assert module._bind_path_params("/api/orders/9/pay",
                                    "/api/users/{user_id}") is None


def test_expect_holds(monkeypatch, tmp_path):
    module, _ = _module(tmp_path, cfg={"enabled": True})
    assert module._expect_holds("-1000", {"op": "lt", "value": 0})
    assert not module._expect_holds("500", {"op": "lt", "value": 0})
    assert module._expect_holds("paid", {"op": "eq", "value": "paid"})
    assert module._expect_holds("state: paid", {"op": "contains",
                                                "value": "paid"})
