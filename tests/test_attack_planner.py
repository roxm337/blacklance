"""Tests for LLM attack planning fallback behavior."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.attack_planner import _build_user_prompt, fallback_plan, render_attack_plan


def test_attack_planner_fallback_ranks_existing_findings():
    bundle = {
        "risk": {
            "top_findings": [
                {
                    "id": "FINDING-0001",
                    "title": "Open API metadata",
                    "severity": "HIGH",
                    "risk_score": 80,
                    "category": "API",
                }
            ]
        },
        "assets": {"counts_by_type": {"api_endpoint": 2, "webapp": 1}},
        "patterns": [{"title": "API-heavy surface"}],
    }

    plan = fallback_plan(bundle)
    markdown = render_attack_plan(plan, "example.com")

    assert plan["top_hypotheses"][0]["recommended_module"] == "rest_api_audit"
    assert "parameter_discovery" in plan["module_sequence"]
    assert "Authorized Testing Plan: example.com" in markdown


def test_attack_planner_prompt_renders_json_schema_without_format_error():
    prompt = _build_user_prompt({"metadata": {"target": "example.com"}})

    assert '"executive_focus": "one concise paragraph"' in prompt
    assert '"target": "example.com"' in prompt


def test_planner_routes_new_categories_and_skips_observations():
    from agents.attack_planner import _action_for_category

    assert _action_for_category("TLS Configuration") == \
        ("network.tls.cert", "SAFE")
    assert _action_for_category("XXE") == ("web.xxe.detect", "MEDIUM")
    assert _action_for_category("CRLF Injection") == \
        ("web.crlf.detect", "MEDIUM")
    assert _action_for_category("Cloud Exposure") == \
        ("cloud.bucket.list", "SAFE")
    assert _action_for_category("Hardening Deficiency") == \
        ("recon.security_headers", "SAFE")
    # Observations are reported, not armed.
    assert _action_for_category("Information Disclosure") == ("", "")
    assert _action_for_category("Client-Side Path Traversal") == ("", "")
