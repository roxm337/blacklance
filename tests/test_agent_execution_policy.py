"""Autonomous execution uses the same explicit risk policy as chain execution."""

import asyncio

from actions.registry import ActionRegistry, RiskLevel
from agents.agent_supervisor import AgentSupervisor
from agents.base_agent import BaseAgent
from agents.blackboard import Hypothesis
from core.budget_manager import BudgetManager
from state.manager import StateManager


def test_agent_action_respects_default_low_risk_ceiling(tmp_path, monkeypatch):
    state = StateManager(str(tmp_path / "run"))
    agent = BaseAgent(state, {}, object())
    called = False

    async def should_not_run(*args, **kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(ActionRegistry, "execute", should_not_run)
    result = asyncio.run(agent.execute_action(
        "web.xss.reflected",
        {"url": "https://example.com/?q=x", "param": "q"},
        "https://example.com/?q=x",
    ))
    assert result["blocked"] is True
    assert "blocked_risk" in result["error"]
    assert called is False


def test_agent_exploit_phase_requires_execute(tmp_path):
    state = StateManager(str(tmp_path / "run"))
    supervisor = AgentSupervisor(
        state, {}, budget=BudgetManager({}), execute=False,
        max_risk=RiskLevel.LOW,
    )
    result = asyncio.run(supervisor.run_single_phase("exploit"))
    assert result == {
        "phase": "exploit",
        "error": "phase requires --execute",
        "blocked": True,
    }


def test_unregistered_agent_probe_stays_manual_review(tmp_path, monkeypatch):
    state = StateManager(str(tmp_path / "run"))
    supervisor = AgentSupervisor(
        state, {}, budget=BudgetManager({}), execute=True,
        max_risk=RiskLevel.HIGH,
    )
    agent = supervisor.agents["exploitation"]
    called = False

    async def must_not_fallback(*args, **kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(agent, "_fallback_test", must_not_fallback)
    hypothesis = Hypothesis(
        id="hyp-1", title="Unclassified probe", description="",
        likelihood=0.5, impact=0.5, target="https://example.com",
        technique="custom_unknown", action_id="manual_review",
    )
    result = asyncio.run(agent.test_hypothesis(hypothesis))
    assert result["blocked"] is True
    assert "manual_review" in result["error"]
    assert called is False


def test_verification_reuses_registry_and_enforces_risk_ceiling(tmp_path,
                                                                monkeypatch):
    state = StateManager(str(tmp_path / "run"))
    supervisor = AgentSupervisor(
        state, {}, budget=BudgetManager({}), execute=True,
        max_risk=RiskLevel.LOW,
    )
    called = False

    async def must_not_execute(*args, **kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(ActionRegistry, "execute", must_not_execute)
    hypothesis = Hypothesis(
        id="hyp-xss", title="Reflected XSS", description="",
        likelihood=0.8, impact=0.7,
        target="https://example.com/?q=1", technique="xss",
        action_id="web.xss.reflected", params={
            "url": "https://example.com/?q=1", "param": "q",
        }, status="testing",
    )
    result = asyncio.run(
        supervisor.agents["verification"].verify_finding(hypothesis))
    assert result["status"] == "BLOCKED"
    assert result["blocked"] is True
    assert called is False
    assert hypothesis.status == "testing"
