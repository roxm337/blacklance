"""Category routing: separators, substring traps, and the new seams.

Routing is first-match-wins over a free-text category, so two classes of bug
hide in it: a category written with hyphens never matches a spaced token, and
a short token matches inside a longer unrelated word ("injection" inside
"integer injection" is fine, "orm" inside "information" is not). Both used to
fail silently — the finding simply had no proving action.
"""

import pytest

from core.action_routing import (action_for_category, is_observation,
                                 normalize_category)


@pytest.mark.parametrize("category,expected", [
    ("GraphQL Introspection Enabled", "api.graphql.introspect"),
    ("GraphQL field leak: user.email", "api.graphql.introspect"),
    ("Broken Access Control", "auth.bypass.probe"),
    ("broken-access-control", "auth.bypass.probe"),
    ("Broken_Access_Control", "auth.bypass.probe"),
    ("Authorization Matrix", "auth.bypass.probe"),
    ("ORM Filter Leak", "web.nosql.detect"),
    ("orm-leak in Sequelize", "web.nosql.detect"),
    ("Server-side template injection", "web.ssti.detect"),
    ("ssti", "web.ssti.detect"),
    ("Path Traversal", "web.lfi.detect"),
    ("Local File Inclusion", "web.lfi.detect"),
    ("NoSQL Operator Injection", "web.nosql.detect"),
    ("server-side-request-forgery", "web.ssrf.oob_detect"),
    ("Open Redirect", "web.redirect.probe"),
    ("TLS Configuration", "network.tls.cert"),
    ("Weak TLS protocols", "network.tls.cert"),
    ("Hardening Deficiency", "recon.security_headers"),
    ("Security Misconfiguration", "recon.security_headers"),
    ("XXE", "web.xxe.detect"),
    ("XML External Entity", "web.xxe.detect"),
    ("CRLF Injection", "web.crlf.detect"),
    ("HTTP Response Splitting", "web.crlf.detect"),
    ("Cloud Exposure", "cloud.bucket.list"),
    ("Public bucket listing", "cloud.bucket.list"),
])
def test_category_routes_to_prover(category, expected):
    assert action_for_category(category) == expected


@pytest.mark.parametrize("category", [
    "Information Disclosure",
    "Attack Surface",
    "Threat Intelligence",
    "Email Security",
    "Client-Side Path Traversal",
    "File Upload",
    "HTTP Request Smuggling",
    "Credential Exposure",
    "Web Cache Deception",
    "",
    None,
])
def test_unrelated_categories_do_not_borrow_a_prover(category):
    assert action_for_category(category) == ""


def test_normalize_folds_separators_and_case():
    assert normalize_category("Broken-Access_Control") == "broken access control"
    assert normalize_category("  GraphQL  ") == "graphql"
    assert normalize_category(None) == ""


@pytest.mark.parametrize("category", [
    "Information Disclosure",
    "Credential Exposure",
    "Attack Surface",
    "Threat Intelligence",
    "Client-Side Prototype Pollution",
    "Client-Side Path Traversal",
    "Known Exploited Vulnerability",
    "File Upload",
    "HTTP Request Smuggling",
    "Web Cache Deception",
])
def test_observation_categories_are_labelled(category):
    assert is_observation(category) is True
    assert action_for_category(category) == ""


@pytest.mark.parametrize("category", [
    "TLS Configuration",
    "Hardening Deficiency",
    "XXE",
    "Cloud Exposure",
    "Broken Access Control",
    "GraphQL Introspection Enabled",
])
def test_provable_categories_are_not_observations(category):
    assert is_observation(category) is False
