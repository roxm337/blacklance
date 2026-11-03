"""Goal inference: which findings become proving edges, and which must not.

The generic tier arms any category that routes to a registered action. The
tests here pin the two failure modes that creates: an observation category
must not borrow a curated token from its name ("Client-Side Path Traversal"
must not become a server-side LFI edge), and XXE must aim its own prover
rather than the SSRF metadata action.
"""

import tempfile

from core.attack_graph import AttackGraph
from state.manager import StateManager


def _graph(category, url="https://t.test/item?q=1"):
    state = StateManager(tempfile.mkdtemp())
    state.add_asset("url", f"url:{url}", url, confidence="CONFIRMED")
    state.add_finding(
        title=f"{category} finding", severity="MEDIUM", confidence="FIRM",
        category=category, description="d", asset_keys=[f"url:{url}"])
    graph = AttackGraph(state, {"target": {"domain": "t.test"}})
    graph.build()
    return graph


def _actions(graph):
    return {(e.target_id, e.action_id, e.edge_type) for e in graph.edges}


def test_tls_finding_is_armed_with_the_tls_prover():
    edges = _actions(_graph("TLS Configuration"))
    assert ("goal:proven:network.tls.cert", "network.tls.cert", "exploit") in edges


def test_hardening_finding_is_armed_with_the_header_prover():
    edges = _actions(_graph("Hardening Deficiency"))
    assert any(action == "recon.security_headers" for _, action, _ in edges)


def test_cloud_exposure_is_armed_with_bucket_listing():
    edges = _actions(_graph("Cloud Exposure", "https://b.s3.amazonaws.com/"))
    assert any(action == "cloud.bucket.list" for _, action, _ in edges)


def test_xxe_aims_file_disclosure_not_ssrf_metadata():
    edges = _actions(_graph("XXE"))
    assert ("goal:sensitive_file", "web.xxe.detect", "extract") in edges
    assert not any(action == "web.ssrf.cloud_metadata" for _, action, _ in edges)


def test_crlf_aims_its_own_prover():
    edges = _actions(_graph("CRLF Injection"))
    assert any(action == "web.crlf.detect" for _, action, _ in edges)


def test_observation_categories_get_no_proving_edge():
    for category in ("Client-Side Path Traversal", "Information Disclosure",
                     "File Upload", "HTTP Request Smuggling"):
        graph = _graph(category)
        proving = [e for e in graph.edges
                   if e.action_id or e.target_id.startswith("goal:")]
        assert proving == [], category


def test_broad_category_falls_back_to_a_routable_title():
    """Several GraphQL classes share the "API Security" category.

    Without the title fallback the category matches no prover and the finding
    never gets an edge, even though its title names the class exactly.
    """
    url = "https://t.test/graphql"
    state = StateManager(tempfile.mkdtemp())
    state.add_asset("url", f"url:{url}", url, confidence="CONFIRMED")
    state.add_finding(
        title="GraphQL Introspection Enabled: https://t.test/graphql",
        severity="LOW", confidence="CONFIRMED", category="API Security",
        description="d", asset_keys=[f"url:{url}"])
    graph = AttackGraph(state, {"target": {"domain": "t.test"}})
    graph.build()

    assert any(e.action_id == "api.graphql.introspect" for e in graph.edges)


def test_broad_category_without_a_routable_title_stays_unarmed():
    url = "https://t.test/swagger.json"
    state = StateManager(tempfile.mkdtemp())
    state.add_asset("url", f"url:{url}", url, confidence="CONFIRMED")
    state.add_finding(
        title="API Documentation Exposed: /swagger.json",
        severity="MEDIUM", confidence="CONFIRMED", category="API Security",
        description="d", asset_keys=[f"url:{url}"])
    graph = AttackGraph(state, {"target": {"domain": "t.test"}})
    graph.build()

    assert not any(e.action_id for e in graph.edges)
