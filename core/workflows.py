"""Workflow replay for captured browser traffic (I1).

Turns a redacted capture into an ordered, per-identity step list and replays
it through the framework HTTP transport with FRESH credentials: identity
names are re-established (re-running the login flow) and captured credential
values are never replayed — only identity references survive capture.

Each replayed step is a typed operation in the R7 ledger; assertion failures
yield ``candidate`` results, never ``proof``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from core.results import Outcome, ResultKind, reset_op_context, set_op_context


@dataclass
class WorkflowStep:
    index: int
    url: str
    method: str = "GET"
    identity_ref: str = "anonymous"
    headers: dict = field(default_factory=dict)
    body: str = ""
    # Extraction bindings: values pulled from an earlier step's response.
    # {"step": <index>, "extract": {"type": "regex", "pattern": ...} |
    #                            {"type": "jsonpath", "path": "a.b.c"},
    #  "to": "<binding name>"}
    # A later step references the value as "{<binding name>}" in url,
    # headers or body.
    binds_from: list = field(default_factory=list)
    assertions: list = field(default_factory=list)
    # Explicit mutation spec (R8): when set and a MutationLedger is passed to
    # replay_workflow, the step is recorded before dispatch and its cleanup
    # is executed and verified afterwards.
    # {"kind": "object_create",
    #  "owned_objects": [{"type": "resource", "identifier": "{item_id}"}],
    #  "cleanup": {"method": "DELETE", "url_template": "/api/items/{item_id}",
    #              "verify": {"method": "http_get", "expect_status": [404]}}}
    mutation: Optional[dict] = None


@dataclass
class Workflow:
    steps: list[WorkflowStep] = field(default_factory=list)
    source: str = ""          # capture id or provenance note
    identity_order: list = field(default_factory=list)

    def add(self, step: WorkflowStep) -> None:
        step.index = len(self.steps)
        self.steps.append(step)


@dataclass
class StepOutcome:
    index: int
    url: str
    status: int
    ok: bool
    result_kind: str
    detail: str = ""
    evidence_refs: list = field(default_factory=list)


@dataclass
class ReplayReport:
    steps: list[StepOutcome] = field(default_factory=list)
    cleanup_status: dict = field(default_factory=dict)
    error: str = ""

    def equivalent(self, other: "ReplayReport") -> bool:
        """Same step outcomes (status class + ok), used by lab acceptance."""
        if len(self.steps) != len(other.steps):
            return False
        for mine, theirs in zip(self.steps, other.steps):
            if _status_class(mine.status) != _status_class(theirs.status):
                return False
            if mine.ok != theirs.ok:
                return False
        return True


def _status_class(status: int) -> int:
    if status < 200:
        return 1
    if status < 300:
        return 2
    if status < 400:
        return 3
    return 4


def build_workflow(events: list[dict], *,
                   source: str = "",
                   skip_assets: bool = True) -> Workflow:
    """Linearize captured request events into a replayable workflow.

    Order is capture order (timestamp). Static assets are dropped; the
    response events only carry linkage, not steps.
    """
    workflow = Workflow(source=source)
    identity_order: list = []
    for event in events:
        if event.get("kind") == "response":
            continue
        # WebSocket events are replayed by tools/websocket_engine, not as
        # HTTP workflow steps.
        if str(event.get("kind") or "").startswith("ws_"):
            continue
        url = str(event.get("url") or "")
        resource_type = str(event.get("resource_type") or "")
        if skip_assets and resource_type not in ("xhr", "fetch", "document"):
            continue
        identity = event.get("identity") or {}
        name = str(identity.get("name") or "anonymous")
        if name not in identity_order:
            identity_order.append(name)
        workflow.add(WorkflowStep(
            index=0,
            url=url,
            method=str(event.get("method") or "GET").upper() or "GET",
            identity_ref=name,
            headers=dict(event.get("request_headers") or {}),
            body=str(event.get("request_body") or ""),
        ))
    workflow.identity_order = identity_order
    return workflow


async def replay_workflow(workflow: Workflow, harness, *,
                          base_url: str = "",
                          budget=None,
                          operations=None,
                          mutations=None,
                          max_steps: int = 100) -> ReplayReport:
    """Replay every step with a fresh identity session.

    ``harness`` is an AuthHarness. Each named identity is re-established
    before its first use (fresh cookies/bearer), anonymous steps use
    ``request_anonymous``. Captured headers/bodies are replayed verbatim —
    they were redacted at capture time, so credential values never appear.

    ``mutations`` (a MutationLedger) enables R8 accounting for steps that
    declare a mutation spec: the step is recorded before dispatch, its
    cleanup executed afterwards, and cleanup is only marked verified after
    the verify check succeeds.
    """
    report = ReplayReport()
    bindings: dict[str, str] = {}
    established: set = set()
    step: WorkflowStep
    for step in workflow.steps[:max_steps]:
        url = _substitute(step.url, bindings)
        headers = {k: _substitute(str(v), bindings)
                   for k, v in step.headers.items()}
        body = _substitute(step.body, bindings)

        identity = step.identity_ref
        if identity not in ("anonymous", "") and identity not in established:
            try:
                await harness.identities[identity].establish(base_url)
            except (KeyError, Exception):
                pass
            established.add(identity)

        mut_id = None
        if step.mutation and mutations is not None:
            mut_id = _begin_mutation(mutations, step, url, bindings)

        op = None
        op_token = None
        if operations is not None:
            op = operations.start(
                {"kind": "workflow_step", "id": str(step.index)},
                transport="http", target=url,
                provenance={"identity": identity})
            op_token = set_op_context(op)

        try:
            if identity in ("anonymous", ""):
                result = await harness.request_anonymous(
                    url, method=step.method, headers=headers or None,
                    data=body or None)
            else:
                result = await harness.request(
                    identity, url, method=step.method, headers=headers or None,
                    data=body or None)
        except Exception as exc:
            report.steps.append(StepOutcome(
                index=step.index, url=url, status=0, ok=False,
                result_kind="error", detail=str(exc)))
            if op is not None:
                op.finish(Outcome.FAILED, ResultKind.ERROR,
                          error={"code": "workflow_step_error",
                                 "message": str(exc)})
            if mut_id is not None:
                mutations.mark_failed(mut_id, f"request raised: {exc}")
            report.error = str(exc)
            return report
        finally:
            if op_token is not None:
                reset_op_context(op_token)

        status = int(result.get("status", 0) or 0)
        ok = 200 <= status < 400
        kind = ResultKind.OBSERVATION.value
        detail = ""
        if step.assertions:
            passed = _check_assertions(step.assertions, result)
            if not passed:
                ok = False
                kind = ResultKind.CANDIDATE.value
                detail = "assertion failed"
        if op is not None:
            if ok:
                op.finish(Outcome.COMPLETED, ResultKind(kind))
            else:
                op.finish(Outcome.FAILED, ResultKind(kind),
                          error={"code": "assertion_failed" if detail
                                 else f"http_{status}", "message": detail})
        report.steps.append(StepOutcome(
            index=step.index, url=url, status=status, ok=ok,
            result_kind=kind, detail=detail))

        # Extraction bindings for later steps.
        response_body = str(result.get("body") or "")
        for binding in step.binds_from:
            value = _extract(binding.get("extract") or {}, response_body)
            if value is not None:
                bindings[str(binding.get("to")
                             or f"step:{binding.get('step')}")] = value

        # R8: execute and verify the declared cleanup.
        if mut_id is not None:
            report.cleanup_status[str(step.index)] = await _run_cleanup(
                mutations, mut_id, step, harness, identity, bindings)
    return report


def _begin_mutation(mutations, step: WorkflowStep, url: str,
                    bindings: dict[str, str]) -> Optional[str]:
    from core.mutations import OwnedObject
    spec = step.mutation
    owned = [
        OwnedObject(
            type=str(obj.get("type") or "resource"),
            identifier=_substitute(str(obj.get("identifier") or ""),
                                   bindings),
            probe_value=obj.get("probe_value"),
            neutral_value=obj.get("neutral_value"),
        )
        for obj in (spec.get("owned_objects") or [])
    ]
    return mutations.begin(
        "workflow_replay", str(spec.get("kind") or "http_write"),
        {"url": url, "method": step.method},
        identity=step.identity_ref,
        owned_objects=owned,
    )


async def _run_cleanup(mutations, mut_id: str, step: WorkflowStep,
                       harness, identity: str,
                       bindings: dict[str, str]) -> dict:
    cleanup = (step.mutation or {}).get("cleanup") or {}
    method = str(cleanup.get("method") or "DELETE").upper()
    template = _substitute(str(cleanup.get("url_template") or ""), bindings)
    if not template:
        mutations.mark_not_required(mut_id, "no cleanup template declared")
        return {"status": "not_required", "mut_id": mut_id}
    try:
        if identity in ("anonymous", ""):
            result = await harness.request_anonymous(
                template, method=method)
        else:
            result = await harness.request(identity, template, method=method)
    except Exception as exc:
        mutations.mark_failed(mut_id, f"cleanup request raised: {exc}")
        return {"status": "failed", "mut_id": mut_id}
    verify = cleanup.get("verify") or {}
    verification = {"method": str(verify.get("method") or "http_get"),
                    "cleanup_status": result.get("status", 0)}
    # Fresh check: re-read the owned location and require it to be gone.
    try:
        if identity in ("anonymous", ""):
            check = await harness.request_anonymous(template, method="GET")
        else:
            check = await harness.request(identity, template, method="GET")
    except Exception as exc:
        mutations.mark_failed(mut_id, f"verify request raised: {exc}")
        return {"status": "failed", "mut_id": mut_id}
    check_status = int(check.get("status", 0) or 0)
    verification["check_status"] = check_status
    expect = list(verify.get("expect_status") or [404, 410])
    gone = check_status in expect or check_status >= 400
    mutations.record_rollback(
        mut_id, "verified" if gone else "failed", verification=verification)
    if gone:
        mutations.verify_cleanup(mut_id, verification)
        return {"status": "verified", "mut_id": mut_id}
    mutations.mark_failed(mut_id, f"verify read returned {check_status}")
    return {"status": "failed", "mut_id": mut_id}


def _substitute(text: str, bindings: dict[str, str]) -> str:
    out = str(text or "")
    for key, value in bindings.items():
        out = out.replace("{" + key + "}", str(value))
    return out


def _extract(spec: dict, body: str) -> Optional[str]:
    if spec.get("type") == "regex":
        pattern = str(spec.get("pattern") or "")
        if not pattern:
            return None
        match = re.search(pattern, body)
        return match.group(1) if match and match.groups() else (match.group(0) if match else None)
    if spec.get("type") == "jsonpath":
        try:
            import json
            obj = json.loads(body)
        except (ValueError, TypeError):
            return None
        current: Any = obj
        for part in str(spec.get("path") or "").split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            elif isinstance(current, list) and part.isdigit() \
                    and int(part) < len(current):
                current = current[int(part)]
            else:
                return None
        return None if isinstance(current, (dict, list)) else str(current)
    return None


def _check_assertions(assertions: list, result: dict) -> bool:
    for assertion in assertions:
        kind = assertion.get("type")
        if kind == "status_in":
            if int(result.get("status", 0)) not in assertion.get("values", []):
                return False
        elif kind == "body_contains":
            needle = str(assertion.get("value") or "")
            if needle and needle not in str(result.get("body") or ""):
                return False
    return True
