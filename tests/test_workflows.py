"""I1 workflow-replay tests: fresh identity establishment, value bindings,
assertion semantics, and the rule that captured credentials are never
replayed."""

from __future__ import annotations

import asyncio

from core.workflows import (ReplayReport, StepOutcome, Workflow,
                            WorkflowStep, build_workflow, replay_workflow)


class FakeIdentity:
    def __init__(self, name):
        self.name = name
        self.established = 0

    async def establish(self, base_url=""):
        self.established += 1
        return True


class FakeHarness:
    def __init__(self, responses=None):
        self.identities = {"user_a": FakeIdentity("user_a")}
        self.responses = responses or {}
        self.calls = []

    async def request(self, identity, url, method="GET", headers=None,
                      data=None, **kwargs):
        self.calls.append({"identity": identity, "url": url,
                           "method": method, "headers": headers, "data": data})
        return self.responses.get(url, {"status": 200, "body": "{}"})

    async def request_anonymous(self, url, method="GET", headers=None,
                                data=None, **kwargs):
        self.calls.append({"identity": "anonymous", "url": url,
                           "method": method, "headers": headers, "data": data})
        return self.responses.get(url, {"status": 200, "body": "{}"})


def test_replay_reestablishes_identity_once():
    harness = FakeHarness()
    workflow = Workflow()
    workflow.add(WorkflowStep(index=0, url="https://x/api/a", identity_ref="user_a"))
    workflow.add(WorkflowStep(index=1, url="https://x/api/b", identity_ref="user_a"))
    report = asyncio.run(replay_workflow(workflow, harness, base_url="https://x"))
    assert harness.identities["user_a"].established == 1
    assert len(report.steps) == 2
    assert all(s.ok for s in report.steps)
    assert report.error == ""


def test_unestablished_identity_is_not_replayed_anonymously():
    class FailingIdentity(FakeIdentity):
        async def establish(self, base_url=""):
            self.established += 1
            return False

    class Harness(FakeHarness):
        def __init__(self):
            super().__init__()
            self.identities = {"user_a": FailingIdentity("user_a")}

    harness = Harness()
    workflow = Workflow()
    workflow.add(WorkflowStep(index=0, url="https://x/api/private",
                              identity_ref="user_a"))
    report = asyncio.run(replay_workflow(workflow, harness))

    assert harness.calls == []
    assert report.steps[0].result_kind == "error"
    assert "did not establish" in report.error


def test_anonymous_steps_use_anonymous_transport():
    harness = FakeHarness()
    workflow = Workflow()
    workflow.add(WorkflowStep(index=0, url="https://x/api/pub"))
    asyncio.run(replay_workflow(workflow, harness))
    assert harness.calls[0]["identity"] == "anonymous"


def test_captured_credentials_never_replayed():
    harness = FakeHarness()
    workflow = Workflow()
    # A capture would never contain these (redacted at capture time), but if
    # one did, replay must not re-transmit them: the harness receives exactly
    # what the step carries and nothing fabricates an Authorization header.
    workflow.add(WorkflowStep(index=0, url="https://x/api/me",
                              identity_ref="user_a",
                              headers={"Accept": "application/json"}))
    asyncio.run(replay_workflow(workflow, harness))
    call = harness.calls[0]
    assert "Authorization" not in (call["headers"] or {})
    assert call["headers"] == {"Accept": "application/json"}


def test_bindings_substitute_into_later_steps():
    harness = FakeHarness(responses={
        "https://x/api/token": {"status": 200,
                                "body": '{"csrf": "tok-123"}'},
        "https://x/api/create": {"status": 201, "body": "{}"},
    })
    workflow = Workflow()
    workflow.add(WorkflowStep(
        index=0, url="https://x/api/token", identity_ref="user_a",
        binds_from=[{"step": 0, "extract": {"type": "jsonpath", "path": "csrf"},
                     "to": "csrf"}]))
    workflow.add(WorkflowStep(
        index=1, url="https://x/api/create", method="POST",
        identity_ref="user_a",
        headers={"X-CSRF-Token": "{csrf}"}))
    report = asyncio.run(replay_workflow(workflow, harness))
    create_call = harness.calls[1]
    assert create_call["headers"]["X-CSRF-Token"] == "tok-123"
    assert report.steps[1].ok


def test_mutation_spec_records_and_verifies_cleanup(tmp_path):
    from core.mutations import MutationLedger

    responses = {
        "https://x/api/items": {"status": 200,
                                "body": '{"data": {"id": 42}}'},
        "https://x/api/items/42": {"status": 404, "body": ""},
    }
    harness = FakeHarness(responses=responses)
    ledger = MutationLedger(tmp_path / "mutations.jsonl")
    workflow = Workflow()
    workflow.add(WorkflowStep(
        index=0, url="https://x/api/items", method="POST",
        identity_ref="user_a",
        binds_from=[{"step": 0,
                     "extract": {"type": "jsonpath", "path": "data.id"},
                     "to": "item_id"}]))
    workflow.add(WorkflowStep(
        index=1, url="https://x/api/items/{item_id}",
        method="DELETE", identity_ref="user_a",
        mutation={
            "kind": "object_create",
            "owned_objects": [{"type": "resource",
                               "identifier": "{item_id}"}],
            "cleanup": {"method": "DELETE",
                        "url_template": "https://x/api/items/{item_id}",
                        "verify": {"method": "http_get",
                                   "expect_status": [404]}},
        }))
    report = asyncio.run(replay_workflow(
        workflow, harness, mutations=ledger))
    assert report.cleanup_status["1"]["status"] == "verified"
    assert ledger.outstanding() == []
    record = ledger.current(report.cleanup_status["1"]["mut_id"])
    assert record["cleanup"]["status"] == "verified"
    assert record["owned_objects"][0]["identifier"] == "42"


def test_mutation_cleanup_failure_is_honest(tmp_path):
    from core.mutations import MutationLedger

    harness = FakeHarness(responses={
        "https://x/api/items": {"status": 200, "body": '{"id": 7}'},
        # Cleanup DELETE succeeds but the object still reads back 200.
        "https://x/api/items/7": {"status": 200, "body": "still here"},
    })
    ledger = MutationLedger(tmp_path / "mutations.jsonl")
    workflow = Workflow()
    workflow.add(WorkflowStep(
        index=0, url="https://x/api/items", method="POST",
        identity_ref="user_a", mutation={
            "kind": "object_create",
            "owned_objects": [{"type": "resource", "identifier": "7"}],
            "cleanup": {"method": "DELETE",
                        "url_template": "https://x/api/items/7",
                        "verify": {"method": "http_get",
                                   "expect_status": [404]}},
        }))
    report = asyncio.run(replay_workflow(workflow, harness, mutations=ledger))
    assert report.cleanup_status["0"]["status"] == "failed"
    assert ledger.current(report.cleanup_status["0"]["mut_id"])[
        "cleanup"]["status"] == "failed"


def test_assertion_failure_yields_candidate_never_proof():
    harness = FakeHarness(responses={
        "https://x/api/flag": {"status": 200, "body": "no flag here"}})
    workflow = Workflow()
    workflow.add(WorkflowStep(
        index=0, url="https://x/api/flag",
        assertions=[{"type": "body_contains", "value": "FLAG{owned}"}]))
    report = asyncio.run(replay_workflow(workflow, harness))
    step = report.steps[0]
    assert step.ok is False
    assert step.result_kind == "candidate"


def test_http_error_records_failed_step_and_stops():
    harness = FakeHarness(responses={
        "https://x/api/broken": {"status": 500, "body": "boom"}})
    workflow = Workflow()
    workflow.add(WorkflowStep(index=0, url="https://x/api/broken"))
    report = asyncio.run(replay_workflow(workflow, harness))
    assert report.steps[0].status == 500
    assert report.steps[0].ok is False


def test_replay_report_equivalence():
    a = ReplayReport(steps=[StepOutcome(0, "u", 200, True, "observation"),
                            StepOutcome(1, "u", 201, True, "observation")])
    b = ReplayReport(steps=[StepOutcome(0, "u", 200, True, "observation"),
                            StepOutcome(1, "u", 204, True, "observation")])
    c = ReplayReport(steps=[StepOutcome(0, "u", 500, False, "error")])
    assert a.equivalent(b) is True
    assert a.equivalent(c) is False


def test_replay_records_operations_ledger_rows(tmp_path):
    from core.results import OperationsLedger
    harness = FakeHarness()
    ledger = OperationsLedger(tmp_path / "ops.jsonl")
    workflow = Workflow()
    workflow.add(WorkflowStep(index=0, url="https://x/api/a", identity_ref="user_a"))
    asyncio.run(replay_workflow(workflow, harness, operations=ledger))
    records = ledger.read_records()
    assert len(records) == 2
    assert records[0]["phase"] == "started"
    assert records[1]["outcome"] == "completed"
    assert records[1]["caller"] == {"kind": "workflow_step", "id": "0"}
