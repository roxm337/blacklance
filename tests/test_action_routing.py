"""Category routing: separators, substring traps, and the new seams.

Routing is first-match-wins over a free-text category, so two classes of bug
hide in it: a category written with hyphens never matches a spaced token, and
a short token matches inside a longer unrelated word ("injection" inside
"integer injection" is fine, "orm" inside "information" is not). Both used to
fail silently — the finding simply had no proving action.
"""

import pytest

from core.action_routing import action_for_category, normalize_category


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
])
def test_category_routes_to_prover(category, expected):
    assert action_for_category(category) == expected


@pytest.mark.parametrize("category", [
    "Information Disclosure",
    "TLS Configuration",
    "Attack Surface",
    "Threat Intelligence",
    "Email Security",
    "",
    None,
])
def test_unrelated_categories_do_not_borrow_a_prover(category):
    assert action_for_category(category) == ""


def test_normalize_folds_separators_and_case():
    assert normalize_category("Broken-Access_Control") == "broken access control"
    assert normalize_category("  GraphQL  ") == "graphql"
    assert normalize_category(None) == ""
