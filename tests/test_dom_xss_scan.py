"""DOM XSS route/payload shaping, without launching a browser."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.dom_xss_scan import injection_templates


def test_hash_route_gets_router_shaped_injection_points():
    base, templates = injection_templates("https://app.test/#/search?term=a")
    assert base == "https://app.test/#/search"
    assert "https://app.test/#/search?q={P}" in templates
    assert "https://app.test/#/search/{P}" in templates
    assert "https://app.test/#/search?term={P}" in templates


def test_plain_page_keeps_query_and_fragment_candidates():
    base, templates = injection_templates("https://app.test/search?q=a")
    assert base == "https://app.test/search"
    assert "https://app.test/search?q={P}" in templates
    assert "https://app.test/search#q={P}" in templates


def test_operator_routes_are_added_and_deduplicated():
    base, templates = injection_templates(
        "https://app.test/#/item/7",
        ["https://app.test/#/item/{P}?tab=1",
         "https://app.test/#/item/7?q={P}"])
    assert "https://app.test/#/item/{P}?tab=1" in templates
    assert templates.count("https://app.test/#/item/7?q={P}") == 1
    assert base == "https://app.test/#/item/7"


def test_routes_without_a_placeholder_are_ignored():
    _, templates = injection_templates(
        "https://app.test/", ["https://app.test/static", 42, None])
    assert "https://app.test/static" not in templates
