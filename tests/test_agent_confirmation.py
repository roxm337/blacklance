"""Confirmation must reach the finding the report reads.

The agent lifecycle filed a finding from the exploitation result, then
verified it only on the blackboard. The console said CONFIRMED while
`findings.json` still held an unverified claim, so the report, SARIF and
DefectDojo export all disagreed with the engagement summary.
"""

import asyncio
import tempfile

import pytest

from actions.registry import ActionMeta, ActionRegistry, ActionResult, RiskLevel
from agents.agent_supervisor import AgentSupervisor
from agents.blackboard import Hypothesis
from core.budget_manager import BudgetManager
from state.manager import StateManager


@pytest.fixture(autouse=True)
def _clean_registry():
    saved = dict(ActionRegistry._actions)
    yield
    ActionRegistry._actions.clear()
    ActionRegistry._actions.update(saved)


def _register(action_id, confidence):
    async def fn(ctx):
        return ActionResult(
            success=True, confidence=confidence,
            evidence={"impact": "marker", "url": ctx.params.get("url", "")},
            data={"sampled": "value"},
        )

    ActionRegistry.register(
        ActionMeta(id=action_id, risk=RiskLevel.LOW, detectability="low",
                   description="fake", category="test",
                   requires=["url"], produces="Finding"),
        fn,
    )


def _supervisor(tmp_path):
    state = StateManager(str(tmp_path / "run"))
    return state, AgentSupervisor(
        state, {}, budget=BudgetManager({}), execute=True,
        max_risk=RiskLevel.LOW,
    )


def _hypothesis(action_id):
    return Hypothesis(
        id="HYP-0001", title="Reflected XSS", description="",
        likelihood=0.8, impact=0.7, target="https://example.test/?q=1",
        technique="xss", action_id=action_id,
        params={"url": "https://example.test/?q=1", "param": "q"},
    )


def test_confirmed_verification_updates_the_finding(tmp_path):
    _register("test.confirm", "CONFIRMED")
    state, supervisor = _supervisor(tmp_path)
    hyp = _hypothesis("test.confirm")

    asyncio.run(supervisor.agents["exploitation"].test_hypothesis(hyp))
    assert hyp.finding_id
    finding = next(f for f in state.findings["findings"]
                   if f["id"] == hyp.finding_id)
    assert finding["verified"] is False, "exploitation alone is not proof"

    result = asyncio.run(
        supervisor.agents["verification"].verify_finding(hyp))

    assert result["status"] == "CONFIRMED"
    assert hyp.status == "confirmed"
    finding = next(f for f in state.findings["findings"]
                   if f["id"] == hyp.finding_id)
    assert finding["verified"] is True
    assert finding["confidence"] == "CONFIRMED"
    assert finding["verification"]["method"] == "test.confirm"
    assert finding["verification"]["url"] == "https://example.test/?q=1"
    assert finding["verification"]["param"] == "q"


def test_firm_verification_is_not_promoted_to_confirmed(tmp_path):
    _register("test.firm", "FIRM")
    state, supervisor = _supervisor(tmp_path)
    hyp = _hypothesis("test.firm")

    asyncio.run(supervisor.agents["exploitation"].test_hypothesis(hyp))
    result = asyncio.run(
        supervisor.agents["verification"].verify_finding(hyp))

    assert result["status"] == "FIRM", "success alone must not mean CONFIRMED"
    assert hyp.status == "testing"
    finding = next(f for f in state.findings["findings"]
                   if f["id"] == hyp.finding_id)
    assert finding["verified"] is False
