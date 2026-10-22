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
