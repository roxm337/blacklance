"""Behavioral regressions reproduced during the professional-readiness review."""

import asyncio
import base64
import json
import sys
from unittest.mock import AsyncMock

import pytest

from actions.registry import RiskLevel
from agents.blackboard import Blackboard, Hypothesis
from agents.exploitation_agent import ExploitationAgent
from agents.verification_agent import VerificationAgent
from core.attack_graph import AttackGraph, AttackNode, AttackEdge
from state.manager import StateManager
from tools import wrappers, external


def _hypothesis(action_id="", technique="unknown"):
    return Hypothesis(id="review", title="Review probe", description="fixture",
                      likelihood=0.5, impact=0.5, target="https://example.test/?q=1",
                      technique=technique, action_id=action_id)


def _agent(tmp_path):
    state = StateManager(str(tmp_path))
    config = {"target": {"domain": "example.test", "raw_url": "https://example.test"},
              "oob": {"enabled": False}}
    board = Blackboard(state, config)
    return state, config, board, ExploitationAgent(state, config, board, max_risk=RiskLevel.SAFE)


def test_blocked_generic_probes_do_not_fall_through_to_direct_http(tmp_path, monkeypatch):
    _, _, _, agent = _agent(tmp_path)
    direct = AsyncMock()
    monkeypatch.setattr(wrappers, "curl", direct)
    monkeypatch.setattr("core.verification_oracle.curl", direct)
    result = asyncio.run(agent.test_hypothesis(_hypothesis()))
    assert result["blocked"]
    assert not result["success"]
    direct.assert_not_awaited()
    assert agent.budget.state.actions_used == 0


def test_jwt_discovery_is_an_observation_in_exploitation_and_verification(tmp_path, monkeypatch):
    state, config, board, agent = _agent(tmp_path)
    encode = lambda value: base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")
    token = encode({"alg": "HS256"}) + "." + encode({"sub": "test-user"}) + ".fixture"
    monkeypatch.setattr("actions.auth.jwt.curl", AsyncMock(return_value={
        "status": 200, "body": json.dumps({"token": token}), "headers": ""}))
    hyp = _hypothesis("auth.jwt.detect", "jwt")
    asyncio.run(agent.test_hypothesis(hyp))
    assert hyp.status == "observed"
    verifier = VerificationAgent(state, config, board, max_risk=RiskLevel.SAFE)
    result = asyncio.run(verifier.verify_finding(hyp))
    assert result["status"] == "OBSERVED"
    assert not state.findings["findings"]
    assert state.get_assets_by_type("observation")


def test_llm_cannot_enable_an_active_module(tmp_path, monkeypatch):
    from orchestrator import Orchestrator
    run = Orchestrator("example.test", str(tmp_path), mode="llm")
    selected = AsyncMock(side_effect=["RUN_MODULE:nuclei_scan", "COMPLETE"])
    monkeypatch.setattr("agents.orchestrator_agent.LLMOrchestrator.decide_next", selected)
    module = AsyncMock()
    monkeypatch.setattr(run, "_run_module", module)
    asyncio.run(run.run_llm())
    module.assert_not_awaited()
    assert run.state.summary()["modules_skipped"] == ["nuclei_scan"]


def test_graph_preserves_stronger_alternate_path(tmp_path):
    graph = AttackGraph(StateManager(str(tmp_path)))
    graph.nodes = {key: AttackNode(id=key, label=key,
                   node_type="goal" if key == "goal" else "url")
                   for key in ("start", "middle", "goal")}
    graph.edges = [AttackEdge("start", "goal", "probe", likelihood=0.1, impact=1),
                   AttackEdge("start", "middle", "probe", likelihood=0.9, impact=1),
                   AttackEdge("middle", "goal", "probe", likelihood=0.9, impact=1),
                   AttackEdge("middle", "start", "probe", likelihood=1, impact=1)]
    chains = graph.find_chains(min_score=0.3)
    assert any([node.id for node in chain.nodes] == ["start", "middle", "goal"]
               and chain.score == 0.81 for chain in chains)
    assert all(len({node.id for node in chain.nodes}) == len(chain.nodes) for chain in chains)


@pytest.mark.parametrize("transport", ["command", "shell", "curl"])
def test_cancellation_reaps_the_child_process(tmp_path, monkeypatch, transport):
    async def scenario():
        original = asyncio.create_subprocess_exec
        launched = asyncio.Event()
        children = []

        async def launch(*args, **kwargs):
            proc = await original(sys.executable, "-c", "import time; time.sleep(30)",
                                  stdout=asyncio.subprocess.PIPE,
                                  stderr=asyncio.subprocess.PIPE, start_new_session=True)
            children.append(proc)
            launched.set()
            return proc

        monkeypatch.setattr(asyncio, "create_subprocess_exec", launch)
        monkeypatch.setattr(asyncio, "create_subprocess_shell", launch)
        monkeypatch.setattr(external, "_docker_wants", lambda args: False)
        monkeypatch.setattr(wrappers, "docker_wrap_shell", lambda command: command)
        external.configure_tool_budget(None)
        if transport == "command":
            operation = external.run_command(["fixture"], timeout=40)
        elif transport == "shell":
            operation = wrappers.bash("fixture", timeout=40)
        else:
            operation = wrappers._curl_subprocess("https://example.test", timeout=40)
        task = asyncio.create_task(operation)
        await launched.wait()
        task.cancel()
        try:
            with pytest.raises(asyncio.CancelledError):
                await task
            assert children[0].returncode is not None
        finally:
            if children[0].returncode is None:
                await external.terminate_process_tree(children[0])

    asyncio.run(scenario())


def test_source_map_can_be_fetched_without_forwarding_session_credentials(tmp_path, monkeypatch):
    from modules.js_analysis import JSAnalysis
    captured = []
    map_url = "https://outside.invalid/source.map"

    class Engine:
        async def request(self, url, *args, **kwargs):
            captured.append((url, kwargs.get("headers", {})))
            if url == "https://example.test":
                body = '<script src="/main.js"></script>'
            elif url == "https://example.test/main.js":
                body = "const x = 'fixture';" * 5 + "\n//# sourceMappingURL=" + map_url
            elif url == map_url:
                body = json.dumps({"version": 3, "sources": ["x.js"]})
            else:
                return {"status": 404, "body": "missing", "headers": "Content-Type: text/plain"}
            return {"status": 200, "body": body, "headers": "Content-Type: text/javascript"}

    state, config, _, _ = _agent(tmp_path)
    config["auth"] = {"bearer_token": "synthetic-review-token", "headers": {"X-Custom-Session": "private"}}
    monkeypatch.setattr(wrappers, "get_engine", lambda: Engine())
    monkeypatch.setattr("modules.js_analysis.tool_available", lambda tool: False)
    wrappers.configure_http_budget(None)
    wrappers.configure_http_limiter(max_per_minute=10000)
    try:
        asyncio.run(JSAnalysis(state, config).run())
        target = next(headers for url, headers in captured if url == "https://example.test")
        outside = next(headers for url, headers in captured if url == map_url)
        assert target["Authorization"] == "Bearer synthetic-review-token"
        assert "Authorization" not in outside
        assert "X-Custom-Session" not in outside
    finally:
        wrappers.configure_http_session({})
        wrappers.configure_request_observer(None)
        wrappers.configure_http_limiter()


def test_legacy_html_reflection_never_claims_execution(monkeypatch):
    from core.verification_oracle import VerificationOracle, Confidence
    payload = "<script>alert(1)</script>"
    monkeypatch.setattr("core.verification_oracle.curl", AsyncMock(return_value={
        "status": 200, "body": f"<textarea>{payload}</textarea>",
        "headers": "Content-Type: text/html", "time_ms": 1}))
    verdict = asyncio.run(VerificationOracle().verify_xss("https://example.test/?q=1", "q", payload))
    assert verdict.confidence != Confidence.CONFIRMED


def test_evidence_digest_detects_changed_bytes(tmp_path):
    state = StateManager(str(tmp_path))
    reference = state.add_evidence("fixture", "http", "https://example.test", {"marker": "original"})
    assert state.verify_evidence(reference)["ok"]
    state.save()
    reloaded = StateManager(str(tmp_path))
    assert reloaded.verify_evidence(reference)["ok"]
    item = reloaded.evidence["items"][0]
    path = tmp_path / item["path"]
    path.write_text(path.read_text().replace("original", "tampered"))
    assert not reloaded.verify_evidence(reference)["ok"]


def test_confirmation_without_proof_stays_inconclusive(tmp_path, monkeypatch):
    state, config, board, _ = _agent(tmp_path)
    verifier = VerificationAgent(state, config, board)
    monkeypatch.setattr(verifier, "execute_action", AsyncMock(return_value={
        "success": True, "confidence": "CONFIRMED", "evidence": {}}))
    hyp = _hypothesis("web.xss.reflected", "xss")
    result = asyncio.run(verifier.verify_finding(hyp))
    assert result["status"] == "INCONCLUSIVE"
    assert not result["success"]
    assert hyp.status == "testing"


def test_firm_chain_candidate_is_not_counted_as_proven(tmp_path):
    from actions.registry import ActionResult
    from core.chain_executor import ChainExecutor, PlannedEdge, ExecutionReport
    state = StateManager(str(tmp_path))
    executor = ChainExecutor(state)
    planned = PlannedEdge(edge=AttackEdge("a", "b", "probe"),
                          action_id="web.xss.reflected", risk="MEDIUM",
                          url="https://example.test", reason="fixture", params={})
    outcome = executor._promote(planned, ActionResult(
        True, confidence="FIRM", evidence={"reflection": "fixture"}))
    assert not state.findings["findings"][0]["verified"]
    assert ExecutionReport(ran=[outcome]).proven == 0


@pytest.mark.parametrize("transport", ["engine", "curl"])
def test_redirects_continue_without_credentials_at_other_origin(monkeypatch, transport):
    import shutil
    if transport == "curl" and not shutil.which("curl"):
        pytest.skip("curl unavailable")
    from aiohttp import web
    from tools.http_engine import HttpEngine

    async def scenario():
        first_headers = []
        first = web.Application()
        second = web.Application()

        async def echo(request):
            return web.json_response(dict(request.headers))

        second.router.add_get("/", echo)
        second_runner = web.AppRunner(second)
        await second_runner.setup()
        second_site = web.TCPSite(second_runner, "127.0.0.1", 0)
        await second_site.start()
        destination = f"http://127.0.0.1:{second_site._server.sockets[0].getsockname()[1]}/"

        async def redirect(request):
            first_headers.append(dict(request.headers))
            raise web.HTTPFound(destination)

        first.router.add_get("/", redirect)
        first_runner = web.AppRunner(first)
        await first_runner.setup()
        first_site = web.TCPSite(first_runner, "127.0.0.1", 0)
        await first_site.start()
        url = f"http://127.0.0.1:{first_site._server.sockets[0].getsockname()[1]}/"
        headers = {"Authorization": "Bearer fixture", "Cookie": "sid=fixture",
                   "X-Custom-Session": "fixture"}
        engine = HttpEngine()
        try:
            if transport == "engine":
                result = await engine.request(url, headers=headers, output="full")
            else:
                wrappers.configure_http_budget(None)
                wrappers.configure_request_observer(None)
                result = await wrappers._curl_subprocess(url, output="full", session_headers=headers)
            assert result["status"] == 200, result
            assert first_headers[0]["X-Custom-Session"] == "fixture"
            received = {name.lower() for name in json.loads(result["body"])}
            assert not received.intersection({"authorization", "cookie", "x-custom-session"})
            assert len(result["history"]) == 1
        finally:
            await engine.close()
            await first_runner.cleanup()
            await second_runner.cleanup()
            wrappers.reset_cookie_jar()

    asyncio.run(scenario())
