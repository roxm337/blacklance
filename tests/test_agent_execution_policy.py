"""Autonomous execution uses the same explicit risk policy as chain execution."""

import asyncio

from actions.registry import ActionRegistry, RiskLevel
from agents.agent_supervisor import AgentSupervisor
from agents.base_agent import BaseAgent
from agents.blackboard import Hypothesis
from agents.supervisor import SupervisorAgent
from core.attack_graph import AttackEdge, AttackNode, AttackPath
from core.budget_manager import BudgetManager
from state.manager import StateManager


def test_agent_action_respects_explicit_low_risk_ceiling(tmp_path, monkeypatch):
    state = StateManager(str(tmp_path / "run"))
    agent = BaseAgent(state, {}, object(), max_risk=RiskLevel.LOW)
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


def test_agent_action_blocks_out_of_scope_hypothesis(tmp_path, monkeypatch):
    """A model-proposed URL must not turn an allow-listed action into a
    request against someone else's host."""
    state = StateManager(str(tmp_path / "run"))
    agent = BaseAgent(
        state,
        {"target": {"domain": "example.com",
                    "raw_url": "https://example.com"}},
        object(), max_risk=RiskLevel.HIGH,
    )
    called = False

    async def should_not_run(*args, **kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(ActionRegistry, "execute", should_not_run)
    result = asyncio.run(agent.execute_action(
        "web.ssrf.oob_detect",
        {"url": "https://attacker.example/fetch?url=x", "param": "url"},
        "https://attacker.example/fetch?url=x",
    ))
    assert result["blocked"] is True
    assert "blocked_scope" in result["error"]
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


def test_unregistered_agent_probe_uses_generic_probes(tmp_path, monkeypatch):
    state = StateManager(str(tmp_path / "run"))
    supervisor = AgentSupervisor(
        state, {}, budget=BudgetManager({}), execute=True,
        max_risk=RiskLevel.HIGH,
    )
    agent = supervisor.agents["exploitation"]
    called = False

    async def generic(hypothesis):
        nonlocal called
        called = True
        return {"success": False, "error": "nothing proved"}

    monkeypatch.setattr(agent, "_generic_probe", generic)
    hypothesis = Hypothesis(
        id="hyp-1", title="Unclassified probe", description="",
        likelihood=0.5, impact=0.5, target="https://example.com/?q=1",
        technique="custom_unknown", action_id="manual_review",
    )
    result = asyncio.run(agent.test_hypothesis(hypothesis))
    assert called is True
    assert result["success"] is False


def test_explicit_probe_failure_is_not_masked_by_generic_probe(tmp_path,
                                                              monkeypatch):
    state = StateManager(str(tmp_path / "run"))
    supervisor = AgentSupervisor(
        state, {}, budget=BudgetManager({}), execute=True,
        max_risk=RiskLevel.HIGH,
    )
    agent = supervisor.agents["exploitation"]

    async def explicit(*args, **kwargs):
        return {"success": False, "action_id": "auth.jwt.none_alg",
                "error": "none-alg token was rejected"}

    async def generic(*args, **kwargs):
        return {"success": False, "action_id": "web.ssrf.oob_detect",
                "error": "OOB not configured"}

    monkeypatch.setattr(agent, "execute_action", explicit)
    monkeypatch.setattr(agent, "_generic_probe", generic)
    hypothesis = Hypothesis(
        id="hyp-jwt", title="JWT none algorithm", description="",
        likelihood=0.5, impact=0.5, target="https://example.com/",
        technique="jwt_none", action_id="auth.jwt.none_alg",
        params={"url": "https://example.com/", "param": "q"},
    )
    result = asyncio.run(agent.test_hypothesis(hypothesis))
    assert result["action_id"] == "auth.jwt.none_alg"
    assert "none-alg" in result["error"]


def test_generic_probe_reports_every_failure(tmp_path, monkeypatch):
    state = StateManager(str(tmp_path / "run"))
    supervisor = AgentSupervisor(
        state, {}, budget=BudgetManager({}), execute=True,
        max_risk=RiskLevel.HIGH,
    )
    agent = supervisor.agents["exploitation"]

    async def fail(action_id, params, target):
        return {"success": False, "action_id": action_id,
                "error": f"{action_id} failed"}

    monkeypatch.setattr(agent, "execute_action", fail)
    hypothesis = Hypothesis(
        id="hyp-generic", title="Unclassified probe", description="",
        likelihood=0.5, impact=0.5, target="https://example.com/?q=1",
        technique="custom_unknown", action_id="",
        params={"url": "https://example.com/?q=1", "param": "q"},
    )
    result = asyncio.run(agent._generic_probe(hypothesis))
    assert result["success"] is False
    assert len(result["attempts"]) >= 2
    assert "web.sqli.detect" in result["error"]
    assert "web.ssrf.oob_detect" in result["error"]


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


def test_fallback_plan_uses_chain_source_url_and_skips_dead_targets(tmp_path):
    state = StateManager(str(tmp_path / "run"))
    config = {"target": {"domain": "example.com",
                         "raw_url": "https://example.com"}}
    agent = SupervisorAgent(state, config, object())

    private = AttackNode(
        id="bucket:s3:mediaads", label="mediaads", node_type="bucket",
        attrs={"url": "https://mediaads.s3.amazonaws.com",
               "status": 403, "private": True},
    )
    private_goal = AttackNode(
        id="goal:bucket_access_bucket:s3:mediaads",
        label="Bucket data access", node_type="goal",
    )
    private_chain = AttackPath(
        nodes=[private, private_goal],
        edges=[AttackEdge(private.id, private_goal.id, "exploit")],
        score=0.35, summary="private bucket",
    )

    source = AttackNode(
        id="url:https://example.com/search?q=1",
        label="https://example.com/search?q=1", node_type="url",
        attrs={"url": "https://example.com/search?q=1", "status": 200},
    )
    goal = AttackNode(id="goal:rce", label="Remote code execution",
                      node_type="goal")
    chain = AttackPath(
        nodes=[source, goal],
        edges=[AttackEdge(source.id, goal.id, "exploit")],
        score=0.6, summary="search --[exploit]--> RCE",
    )

    plan = agent._fallback_plan([private_chain, chain, chain])
    targets = [h["target"] for h in plan["hypotheses"]]
    assert targets == ["https://example.com/search?q=1"]
    assert "Bucket data access" not in targets


def test_invalid_web_target_is_not_executed(tmp_path, monkeypatch):
    state = StateManager(str(tmp_path / "run"))
    supervisor = AgentSupervisor(
        state, {}, budget=BudgetManager({}), execute=True,
        max_risk=RiskLevel.HIGH,
    )
    agent = supervisor.agents["exploitation"]
    called = False

    async def should_not_run(*args, **kwargs):
        nonlocal called
        called = True
        return {"success": False, "error": "should not run"}

    monkeypatch.setattr(agent, "execute_action", should_not_run)
    hypothesis = Hypothesis(
        id="hyp-bad-target", title="Bucket pivot", description="",
        likelihood=0.5, impact=0.5, target="Bucket data access",
        technique="sqli", action_id="web.sqli.detect",
    )
    result = asyncio.run(agent.test_hypothesis(hypothesis))
    assert result["status"] == "unsupported"
    assert "invalid web target" in result["error"]
    assert called is False

    generic = Hypothesis(
        id="hyp-bad-generic", title="Bucket pivot", description="",
        likelihood=0.5, impact=0.5, target="Bucket data access",
        technique="unknown", action_id="manual_review",
    )
    result = asyncio.run(agent._generic_probe(generic))
    assert result["status"] == "unsupported"
    assert called is False

    manual = Hypothesis(
        id="hyp-manual-bucket", title="Public bucket", description="",
        likelihood=0.5, impact=0.5,
        target="https://storage.googleapis.com/mediaads",
        technique="cloud storage exposure", action_id="manual_review",
    )
    result = asyncio.run(agent.test_hypothesis(manual))
    assert result["status"] == "unsupported"
    assert "manual review" in result["error"]
    assert called is False
