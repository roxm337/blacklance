"""LLM plan output is untrusted data until schema-normalized."""

from agents.attack_planner import _parse_plan
from agents.plan_validation import (
    parse_json_object,
    validate_attack_plan,
    validate_supervisor_plan,
)


def test_json_parser_decodes_one_object_without_greedy_trailing_content():
    parsed = parse_json_object('prefix {"focus": "safe"} trailing {bad}')
    assert parsed == {"focus": "safe"}


def test_supervisor_plan_bounds_types_scores_actions_and_modules():
    plan = validate_supervisor_plan({
        "focus": ["wrong type"],
        "hypotheses": [
            {
                "title": "A" * 500,
                "description": {"not": "text"},
                "likelihood": 4.2,
                "impact": "high",
                "target": "https://example.test",
                "technique": "xss",
                "action_id": "invented.shell",
                "assigned_to": "root",
            },
            "not-an-object",
            {"title": ""},
        ],
        "module_sequence": ["known", "invented", {"bad": True}],
        "watch_items": ["watch", {"bad": True}],
    }, action_ids={"web.xss.reflected"}, module_ids={"known"})

    assert plan is not None
    assert plan["focus"] == "Testing target"
    assert len(plan["hypotheses"]) == 1
    hypothesis = plan["hypotheses"][0]
    assert len(hypothesis["title"]) == 200
    assert hypothesis["description"] == ""
    assert hypothesis["likelihood"] == 1.0
    assert hypothesis["impact"] == 0.5
    assert hypothesis["action_id"] == "manual_review"
    assert hypothesis["assigned_to"] == "exploitation"
    assert plan["module_sequence"] == ["known"]
    assert plan["watch_items"] == ["watch"]


def test_attack_plan_drops_invalid_hypotheses_and_unknown_modules():
    plan = validate_attack_plan({
        "executive_focus": "focus",
        "top_hypotheses": [
            {
                "title": "Valid",
                "likelihood": "HIGH",
                "impact": "medium",
                "why": "evidence",
                "recommended_module": "invented_module",
                "validation": "repeat",
                "confirming_evidence": "same result",
            },
            {"title": "Wrong", "likelihood": 1, "impact": "high"},
        ],
        "module_sequence": ["rest_api_audit", "invented_module"],
        "watch_items": "wrong-type",
    }, module_ids={"rest_api_audit"})

    assert len(plan["top_hypotheses"]) == 1
    assert plan["top_hypotheses"][0]["recommended_module"] == "manual_review"
    assert plan["module_sequence"] == ["rest_api_audit"]
    assert plan["watch_items"] == []


def test_attack_planner_parser_validates_before_attaching_actions():
    plan = _parse_plan('''```json
    {
      "executive_focus": "Validate XSS",
      "top_hypotheses": [{
        "title": "Reflected XSS candidate",
        "likelihood": "high",
        "impact": "high",
        "why": "reflection",
        "recommended_module": "xss_scan",
        "suggested_action": "invented.shell",
        "validation": "inject marker",
        "confirming_evidence": "verbatim HTML reflection"
      }],
      "module_sequence": ["xss_scan", "invented_module"],
      "watch_items": []
    }
    ```''')

    hypothesis = plan["top_hypotheses"][0]
    assert hypothesis["suggested_action"] == "web.xss.reflected"
    assert plan["module_sequence"] == ["xss_scan"]
