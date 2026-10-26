"""I5 ORM/filter audit tests: skip paths, vector classification, the
seeded-record PROOF protocol, candidate caps, and the no-timing-promotion
rule. Transport is faked — no network."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from modules.orm_filter_audit import (ORMFilterAudit, param_vector,
                                      rows_of, with_param)
from state.manager import StateManager


class FakeIdentity:
    def __init__(self, name, markers=()):
        self.name = name
        self.verified = True
        self._markers = tuple(markers)

    def own_markers(self):
        return set(self._markers)

    def request_headers(self):
        return {"Authorization": f"Bearer {self.name}"}


class FakeHarness:
    def __init__(self, responder=None, identities=None):
        self.mutations = None
        self.responder = responder or (lambda i, u, m, d: {"status": 404, "body": ""})
        self.identities = {i.name: i for i in (identities or [])}
        self.calls = []

    def adopt_discovered(self, state, log=None):
        return 0

    async def establish_all(self, base_url=""):
        return list(self.identities.values())

    async def request(self, identity, url, method="GET", headers=None,
                      data=None, **kwargs):
        self.calls.append((identity, method, url, data))
        return self.responder(identity, url, method, data)

    async def request_anonymous(self, url, method="GET", headers=None,
                                data=None, **kwargs):
        self.calls.append(("anonymous", method, url, data))
        return self.responder("anonymous", url, method, data)


SURFACE = {"url": "https://x/api/items", "filter_params": ["q", "owner_id"]}


def _cfg(**overrides):
    cfg = {
        "enabled": True,
        "surfaces": [SURFACE],
        "traffic_surfaces": False,
        "augment_collections": False,
        "canary": {
            "enabled": True,
            "owner_identity": "bob",
            "forbidden_identity": "alice",
            "max": 2,
            "record": {"method": "POST", "url_template": "/api/items",
                       "body_template": '{"name": "{run}"}',
                       "extract_id": {"type": "jsonpath", "path": "id"}},
            "read": {"direct_url_template": "/api/items/{id}",
                     "extract": {"type": "jsonpath", "path": "name"}},
            "probes": [{"name": "items-q", "url_template": "/api/items",
                        "param": "q", "bind": "seed",
                        "extract": {"type": "jsonpath", "path": "data.0.name"}}],
            "cleanup": {"method": "DELETE",
                        "url_template": "/api/items/{id}",
                        "verify": {"method": "http_get",
                                   "expect_status": [404]}},
        },
    }
    cfg.update(overrides)
    return cfg


def _module(tmp_path, cfg=None, identities=None):
    state = StateManager(str(tmp_path / "run" / "example.com"))
    config = {"target": {"domain": "example.com",
                         "base_url": "https://x"},
              "modules": {"orm_filter_audit": cfg if cfg is not None
                          else _cfg()}}
    module = ORMFilterAudit(state, config)
    if identities is None:
        identities = [FakeIdentity("alice", markers=("alice@x.com",)),
                      FakeIdentity("bob", markers=("bob@x.com",))]
    harness = FakeHarness(identities=identities)
    return module, state, harness


def _run(module, monkeypatch, harness):
    import modules.orm_filter_audit as mod
    monkeypatch.setattr(mod, "AuthHarness", lambda config: harness)
    return asyncio.run(module.run())


# ── pure helpers ─────────────────────────────────────────────────

def test_param_vector_classification():
    assert param_vector("q") == "inclusion"
    assert param_vector("filter[owner_id]") == "inclusion"
    assert param_vector("search") == "inclusion"
    assert param_vector("include") == "field"
    assert param_vector("fields") == "field"
    assert param_vector("sort") == "ordering"
    assert param_vector("page") == ""


def test_rows_of_envelopes():
    assert rows_of('[{"a":1},{"b":2}]') == [{"a": 1}, {"b": 2}]
    assert rows_of('{"data":[{"id":1}]}') == [{"id": 1}]
    assert rows_of('{"hydra:member":[{"id":1}]}') == [{"id": 1}]
    assert rows_of('<html>') == []


def test_with_param_preserves_other_params():
    url = with_param("https://x/api/items?page=2#frag", "q", "seed")
    parsed = urlparse(url)
    assert parse_qs(parsed.query) == {"page": ["2"], "q": ["seed"]}
    assert parsed.fragment == "frag"


# ── skips ────────────────────────────────────────────────────────

def test_skips_when_disabled(monkeypatch, tmp_path):
    module, state, harness = _module(tmp_path, cfg={"enabled": False})
    assert _run(module, monkeypatch, harness) == "skipped"


def test_skips_without_identities(monkeypatch, tmp_path):
    module, state, harness = _module(tmp_path, identities=[])
    assert _run(module, monkeypatch, harness) == "skipped"
    assert "no verified identities" in state.module["skipped"][-1]["reason"]


def test_skips_without_surfaces(monkeypatch, tmp_path):
    module, state, harness = _module(
        tmp_path, cfg=_cfg(surfaces=[], augment_collections=False,
                           traffic_surfaces=False))
    assert _run(module, monkeypatch, harness) == "skipped"
    assert "no filter/search surfaces" in state.module["skipped"][-1]["reason"]


# ── canary PROOF protocol ────────────────────────────────────────

def _seed_store():
    return {"orders": {}, "ref": [0], "seed": None}


def _vuln_responder(store, *, filter_leaks=True, seed=None):
    def responder(identity, url, method, data):
        parsed = urlparse(url)
        q = parse_qs(parsed.query).get("q", [""])[0]
        if method == "POST" and parsed.path == "/api/items":
            body = json.loads(data or "{}")
            store["ref"][0] += 1
            ref = store["ref"][0]
            store["orders"][ref] = {"id": ref, "name": body.get("name", ""),
                                    "owner": "bob"}
            return {"status": 201, "body": json.dumps({"id": ref})}
        if method == "DELETE":
            store["orders"].pop(int(parsed.path.rsplit("/", 1)[-1]), None)
            return {"status": 200, "body": ""}
        if parsed.path.startswith("/api/items/"):
            ref = int(parsed.path.rsplit("/", 1)[-1])
            record = store["orders"].get(ref)
            if not record:
                return {"status": 404, "body": ""}
            if identity != "bob":
                return {"status": 404, "body": ""}  # direct read denied
            return {"status": 200, "body": json.dumps(record)}
        if parsed.path == "/api/items":
            if not q or q.startswith("zz-absent"):
                return {"status": 200, "body": json.dumps({"data": []})}
            rows = ([r for r in store["orders"].values() if r["name"] == q]
                    if filter_leaks else [])
            return {"status": 200, "body": json.dumps({"data": rows})}
        return {"status": 404, "body": ""}
    return responder


def _run_canary(monkeypatch, tmp_path, responder):
    module, state, harness = _module(tmp_path)
    harness.responder = responder
    result = _run(module, monkeypatch, harness)
    return result, module, state


def test_canary_proves_filter_leak_with_verified_cleanup(monkeypatch, tmp_path):
    store = _seed_store()
    result, module, state = _run_canary(
        monkeypatch, tmp_path, _vuln_responder(store))

    assert result == "done"
    proofs = [f for f in state.findings["findings"] if f.get("verified") is True]
    assert len(proofs) == 1
    assert proofs[0]["verification"]["method"] == "filter_canary_observed"
    assert proofs[0]["verification"]["param"] == "q"
    assert state.mutations.outstanding() == []
    records = state.evidence["items"]
    report_item = next(e for e in records if e["type"] == "orm_filter_report")
    report = json.loads((Path(state.output_dir) / report_item["path"])
                        .read_text(encoding="utf-8"))["data"]
    assert report["state_counts"]["proof"] == 1
    canary = report["canaries"][0]
    assert canary["proven"] is True
    assert canary["direct_read_status"] == 404
    assert canary["seed_intact"] is True
    assert canary["cleanup_status"] == "verified"


def test_fixed_filter_misses_are_not_proof(monkeypatch, tmp_path):
    store = _seed_store()
    result, module, state = _run_canary(
        monkeypatch, tmp_path, _vuln_responder(store, filter_leaks=False))

    assert result == "done"
    assert not [f for f in state.findings["findings"]
                if f.get("verified") is True]
    report_item = next(e for e in state.evidence["items"]
                       if e["type"] == "orm_filter_report")
    report = json.loads((Path(state.output_dir) / report_item["path"])
                        .read_text(encoding="utf-8"))["data"]
    assert report["state_counts"]["proof"] == 0
    assert state.mutations.outstanding() == []


def test_direct_read_allowed_is_idor_lane_not_filter_proof(monkeypatch, tmp_path):
    def responder(identity, url, method, data):
        parsed = urlparse(url)
        if method == "POST" and parsed.path == "/api/items":
            return {"status": 201, "body": '{"id": 1}'}
        if parsed.path.startswith("/api/items/"):
            return {"status": 200, "body": '{"id": 1, "name": "ofseeded"}'}
        if method == "DELETE":
            return {"status": 200, "body": ""}
        return {"status": 200, "body": '{"data": []}'}

    result, module, state = _run_canary(monkeypatch, tmp_path, responder)
    assert result == "done"
    assert not [f for f in state.findings["findings"]
                if f.get("verified") is True]
    report_item = next(e for e in state.evidence["items"]
                       if e["type"] == "orm_filter_report")
    report = json.loads((Path(state.output_dir) / report_item["path"])
                        .read_text(encoding="utf-8"))["data"]
    canary = report["canaries"][0]
    assert canary["proven"] is False
    assert "prerequisite" in canary.get("reason", "")
    assert state.mutations.outstanding() == []


def test_baseline_containing_seed_blocks_proof(monkeypatch, tmp_path):
    """Baseline already exposes the record → collection-level exposure,
    not a filter leak; the module must not claim proof."""
    store = _seed_store()
    base = _vuln_responder(store)

    def responder(identity, url, method, data):
        parsed = urlparse(url)
        if parsed.path == "/api/items" and "q=" not in url:
            rows = list(store["orders"].values())
            return {"status": 200, "body": json.dumps({"data": rows})}
        return base(identity, url, method, data)

    result, module, state = _run_canary(monkeypatch, tmp_path, responder)
    assert result == "done"
    assert not [f for f in state.findings["findings"]
                if f.get("verified") is True]
    assert state.mutations.outstanding() == []


def test_cleanup_failure_blocks_proof_and_stays_failed(monkeypatch, tmp_path):
    store = _seed_store()
    base = _vuln_responder(store)

    def responder(identity, url, method, data):
        parsed = urlparse(url)
        if method == "DELETE":
            return {"status": 200, "body": ""}
        if parsed.path.startswith("/api/items/") and identity == "bob":
            # Verification re-read still finds the record (cleanup failed).
            return {"status": 200, "body": '{"id": 1, "name": "still-here"}'}
        return base(identity, url, method, data)

    result, module, state = _run_canary(monkeypatch, tmp_path, responder)
    assert result == "done"
    assert not [f for f in state.findings["findings"]
                if f.get("verified") is True]
    records = state.mutations.read_records()
    statuses = [(r.get("cleanup") or {}).get("status")
                for r in records if r.get("kind") == "cleanup"]
    assert "failed" in statuses
    assert "verified" not in statuses


# ── candidates + no-timing-promotion ────────────────────────────

def test_candidate_from_other_identity_records_without_proof(monkeypatch,
                                                             tmp_path):
    def responder(identity, url, method, data):
        parsed = urlparse(url)
        q = parse_qs(parsed.query).get("q", [""])[0]
        if parsed.path == "/api/items":
            # The module probes as the LAST identity (bob); leak alice's row.
            if identity == "bob" and q and not q.startswith("zz-absent"):
                return {"status": 200, "body": json.dumps({"data": [
                    {"id": 9, "owner_email": "alice@x.com"}]})}
            return {"status": 200, "body": '{"data": []}'}
        return {"status": 404, "body": ""}

    module, state, harness = _module(
        tmp_path, cfg=_cfg(vector_values=["2"], canary={"enabled": False}),
        identities=[FakeIdentity("alice", markers=("alice@x.com",)),
                    FakeIdentity("bob", markers=("bob@x.com",))])
    harness.responder = responder
    result = _run(module, monkeypatch, harness)
    assert result == "done"
    findings = state.findings["findings"]
    assert findings and findings[0]["verified"] is False
    assert "candidate" in findings[0]["title"].lower()
    report_item = next(e for e in state.evidence["items"]
                       if e["type"] == "orm_filter_report")
    report = json.loads((Path(state.output_dir) / report_item["path"])
                        .read_text(encoding="utf-8"))["data"]
    probe = report["probes"][0]
    assert probe["state"] == "candidate"
    assert "body" not in json.dumps(probe)  # values are never stored


def test_timing_alone_never_promotes(monkeypatch, tmp_path):
    import time

    def responder(identity, url, method, data):
        parsed = urlparse(url)
        if parsed.path == "/api/items":
            time.sleep(0.002)  # delay with no seeded content
            return {"status": 200, "body": '{"data": []}'}
        return {"status": 404, "body": ""}

    module, state, harness = _module(
        tmp_path, cfg=_cfg(canary={"enabled": False}, vector_values=["1"]))
    harness.responder = responder
    result = _run(module, monkeypatch, harness)
    assert result == "done"
    assert not [f for f in state.findings["findings"]
                if f.get("verified") is True]
