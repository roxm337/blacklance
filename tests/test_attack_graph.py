"""Tests for attack graph engine."""

import sys, json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.attack_graph import AttackGraph, AttackNode, AttackEdge, AttackPath
from state.manager import StateManager


def test_empty_graph():
    state = StateManager("/tmp/_test_ag_empty")
    graph = AttackGraph(state)
    graph.build()
    assert len(graph.nodes) == 0
    assert len(graph.edges) == 0
    assert len(graph.find_chains()) == 0


def test_asset_nodes_become_attack_nodes():
    import tempfile, shutil
    tmpdir = tempfile.mkdtemp()
    state = StateManager(tmpdir)
    state.add_asset("domain", "domain:test.com", "test.com", confidence="CONFIRMED")
    state.add_asset("url", "url:https://test.com", "https://test.com", confidence="CONFIRMED")
    state.save()

    graph = AttackGraph(state)
    graph.build()
    assert len(graph.nodes) == 2
    assert "domain:test.com" in graph.nodes
    assert graph.nodes["domain:test.com"].node_type == "domain"

    shutil.rmtree(tmpdir)


def test_finding_creates_vuln_node():
    import tempfile, shutil
    tmpdir = tempfile.mkdtemp()
    state = StateManager(tmpdir)
    state.add_asset("url", "url:https://test.com", "https://test.com", confidence="CONFIRMED")
    fid = state.add_finding(
        "Test SQLi", "HIGH", "FIRM", "SQL Injection",
        "Found SQL injection", asset_keys=["url:https://test.com"]
    )
    state.save()

    graph = AttackGraph(state)
    graph.build()
    vuln_key = f"vuln:{fid}"
    assert vuln_key in graph.nodes
    assert graph.nodes[vuln_key].node_type == "vuln"

    shutil.rmtree(tmpdir)


def test_login_panel_creates_goal():
    import tempfile, shutil
    tmpdir = tempfile.mkdtemp()
    state = StateManager(tmpdir)
    state.add_asset("url", "url:https://test.com/login",
                    "https://test.com/login", confidence="CONFIRMED")
    state.save()

    graph = AttackGraph(state)
    graph.build()
    goals = [n for n in graph.nodes.values() if n.node_type == "goal"]
    assert len(goals) >= 1
    assert "login" in goals[0].label.lower() or "access" in goals[0].label.lower()

    shutil.rmtree(tmpdir)


def test_find_chains_with_vuln_and_login():
    import tempfile, shutil
    tmpdir = tempfile.mkdtemp()
    state = StateManager(tmpdir)
    state.add_asset("url", "url:https://test.com/login",
                    "https://test.com/login", confidence="CONFIRMED")
    state.add_finding(
        "SQLi", "HIGH", "FIRM", "SQL Injection",
        "Found SQLi", asset_keys=["url:https://test.com/login"]
    )
    state.save()

    graph = AttackGraph(state)
    graph.build()
    chains = graph.find_chains(min_score=0.1)
    assert len(chains) >= 1

    shutil.rmtree(tmpdir)


def test_to_dict():
    import tempfile, shutil
    tmpdir = tempfile.mkdtemp()
    state = StateManager(tmpdir)
    state.add_asset("domain", "domain:x.com", "x.com", confidence="CONFIRMED")
    state.save()

    graph = AttackGraph(state)
    graph.build()
    d = graph.to_dict()
    assert "nodes" in d
    assert "edges" in d
    assert len(d["nodes"]) >= 1

    shutil.rmtree(tmpdir)


def test_save_load_graph():
    import tempfile, shutil
    tmpdir = tempfile.mkdtemp()
    state = StateManager(tmpdir)
    state.add_asset("domain", "domain:x.com", "x.com", confidence="CONFIRMED")
    state.save()

    graph = AttackGraph(state)
    graph.build()
    path = f"{tmpdir}/graph.json"
    graph.save(path)
    loaded = json.loads(Path(path).read_text())
    assert "nodes" in loaded
    assert "edges" in loaded

    shutil.rmtree(tmpdir)


def test_ssrf_finding_reaches_a_cloud_metadata_goal():
    import tempfile, shutil
    tmpdir = tempfile.mkdtemp()
    state = StateManager(tmpdir)
    url = "https://test.com/fetch?url=1"
    state.add_asset("url", f"url:{url}", url, confidence="FIRM")
    fid = state.add_finding(
        "SSRF", "HIGH", "FIRM", "SSRF",
        "Parameter fetches arbitrary URLs", asset_keys=[f"url:{url}"],
    )
    graph = AttackGraph(state)
    graph.build()

    assert "goal:cloud_metadata" in graph.nodes
    chained = [e for e in graph.edges
               if e.target_id == "goal:cloud_metadata"]
    assert len(chained) == 1
    assert chained[0].action_id == "web.ssrf.cloud_metadata"
    assert chained[0].attrs["via"] == fid

    chains = graph.find_chains()
    assert any(n.id == "goal:cloud_metadata"
               for c in chains for n in c.nodes)

    shutil.rmtree(tmpdir)


def test_a_non_ssrf_finding_does_not_invent_a_metadata_chain():
    import tempfile, shutil
    tmpdir = tempfile.mkdtemp()
    state = StateManager(tmpdir)
    url = "https://test.com/search?q=1"
    state.add_asset("url", f"url:{url}", url, confidence="FIRM")
    state.add_finding(
        "SQLi", "HIGH", "FIRM", "SQL Injection",
        "Union based", asset_keys=[f"url:{url}"],
    )
    graph = AttackGraph(state)
    graph.build()

    assert "goal:cloud_metadata" not in graph.nodes

    shutil.rmtree(tmpdir)


def test_ssrf_finding_without_a_testable_surface_is_not_chained():
    import tempfile, shutil
    tmpdir = tempfile.mkdtemp()
    state = StateManager(tmpdir)
    state.add_asset("domain", "domain:test.com", "test.com",
                    confidence="CONFIRMED")
    state.add_finding(
        "SSRF", "HIGH", "FIRM", "SSRF", "x", asset_keys=["domain:test.com"],
    )
    graph = AttackGraph(state)
    graph.build()

    assert "goal:cloud_metadata" in graph.nodes
    assert [e for e in graph.edges
            if e.target_id == "goal:cloud_metadata"] == []

    shutil.rmtree(tmpdir)


def test_configured_chain_adds_a_declared_payoff_edge():
    import tempfile, shutil
    tmpdir = tempfile.mkdtemp()
    state = StateManager(tmpdir)
    url = "https://api.test/orders/17"
    state.add_asset("url", f"url:{url}", url, confidence="FIRM")
    state.add_finding("IDOR", "HIGH", "FIRM", "IDOR",
                      "reads another user's order", asset_keys=[f"url:{url}"])
    graph = AttackGraph(state, config={"chains": {"edges": [
        {"category": "idor", "goal": "Account takeover",
         "action": "test.session_replay", "edge_type": "escalate"}]}})
    graph.build()

    goal = "goal:account-takeover"
    assert goal in graph.nodes
    edge = next(e for e in graph.edges if e.target_id == goal)
    assert edge.action_id == "test.session_replay"
    assert edge.edge_type == "escalate"
    assert edge.attrs["configured"] is True

    shutil.rmtree(tmpdir)


def test_configured_chain_respects_asset_hint_and_category():
    import tempfile, shutil
    tmpdir = tempfile.mkdtemp()
    state = StateManager(tmpdir)
    wanted = "https://api.test/admin/users/7"
    other = "https://api.test/public/7"
    state.add_asset("url", f"url:{wanted}", wanted, confidence="FIRM")
    state.add_asset("url", f"url:{other}", other, confidence="FIRM")
    state.add_finding("IDOR", "HIGH", "FIRM", "IDOR",
                      "x", asset_keys=[f"url:{wanted}", f"url:{other}"])
    state.add_finding("XSS", "HIGH", "FIRM", "XSS",
                      "x", asset_keys=[f"url:{wanted}"])
    graph = AttackGraph(state, config={"chains": {"edges": [
        {"category": "idor", "goal": "Admin", "action": "test.replay",
         "asset_hint": "/admin/"}]}})
    graph.build()

    sources = [e.source_id for e in graph.edges if e.target_id == "goal:admin"]
    assert sources == [f"url:{wanted}"]

    shutil.rmtree(tmpdir)


def _ssrf_finding(url, param="url"):
    return {
        "title": "Blind SSRF Confirmed via OOB Callback",
        "severity": "HIGH",
        "confidence": "CONFIRMED",
        "category": "SSRF",
        "verified": True,
        "description": "server fetched our callback",
        "asset_keys": [f"url:{url}"],
        "verification": {"method": "oob_callback", "url": url, "param": param},
    }


def test_ssrf_finding_uses_parameter_asset_when_page_asset_is_missing():
    """parameter_discovery writes `param:` assets, not `url:` ones.

    ssrf_scan then files its finding against `url:<page>`, which may not
    exist. The chain must be built from the parameter asset that was
    actually tested, or confirmed SSRF never reaches an exploitation goal.
    """
    import tempfile, shutil
    tmpdir = tempfile.mkdtemp()
    state = StateManager(tmpdir)
    url = "https://t.test/fetch"
    state.add_asset("parameter", f"param:{url}:url", "url",
                    confidence="FIRM", attrs={"url": url, "parameter": "url"})
    state.add_finding(**_ssrf_finding(url))
    graph = AttackGraph(state)
    graph.build()

    edges = [e for e in graph.edges if e.target_id == "goal:cloud_metadata"]
    assert len(edges) == 1
    assert edges[0].source_id == f"param:{url}:url"
    assert edges[0].action_id == "web.ssrf.cloud_metadata"

    from core.chain_executor import ChainExecutor
    chains = graph.find_chains()
    planned = [p for c in chains for p in ChainExecutor(state, {}).plan(c)]
    assert any(p.action_id == "web.ssrf.cloud_metadata"
               and p.params.get("param") == "url" for p in planned)

    shutil.rmtree(tmpdir)


def test_ssrf_finding_uses_verification_param_on_a_bare_url():
    """A URL asset without a query string still has a known parameter."""
    import tempfile, shutil
    tmpdir = tempfile.mkdtemp()
    state = StateManager(tmpdir)
    url = "https://t.test/fetch"
    state.add_asset("url", f"url:{url}", url, confidence="FIRM")
    state.add_finding(**_ssrf_finding(url))
    graph = AttackGraph(state)
    graph.build()

    edges = [e for e in graph.edges if e.target_id == "goal:cloud_metadata"]
    assert len(edges) == 1
    assert graph.nodes[edges[0].source_id].attrs["param"] == "url"

    shutil.rmtree(tmpdir)


def test_ssrf_finding_without_any_asset_uses_verification_surface():
    """A pruned asset must not erase a confirmed finding's exploit surface."""
    import tempfile, shutil
    tmpdir = tempfile.mkdtemp()
    state = StateManager(tmpdir)
    url = "https://t.test/fetch"
    state.add_finding(**_ssrf_finding(url))
    graph = AttackGraph(state)
    graph.build()

    edges = [e for e in graph.edges if e.target_id == "goal:cloud_metadata"]
    assert len(edges) == 1
    assert edges[0].source_id == f"url:{url}"

    shutil.rmtree(tmpdir)


def test_configured_chain_uses_verification_url_when_asset_missing():
    import tempfile, shutil
    tmpdir = tempfile.mkdtemp()
    state = StateManager(tmpdir)
    url = "https://api.test/orders/17"
    state.add_finding("IDOR", "HIGH", "FIRM", "IDOR", "x",
                      asset_keys=[f"url:{url}"],
                      verification={"url": url})
    graph = AttackGraph(state, config={"chains": {"edges": [
        {"category": "idor", "goal": "ATO", "action": "test.replay"}]}})
    graph.build()

    sources = [e.source_id for e in graph.edges if e.target_id == "goal:ato"]
    assert sources == [f"url:{url}"]

    shutil.rmtree(tmpdir)
