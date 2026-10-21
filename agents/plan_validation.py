"""Strict normalization for untrusted LLM-generated execution plans."""

from __future__ import annotations

import json
from typing import Any


_LIKELIHOODS = {"high", "medium", "low"}
_IMPACTS = {"critical", "high", "medium", "low", "info"}
_ROLES = {"recon", "vuln_analyst", "exploitation", "verification"}


def parse_json_object(text: str) -> dict:
    """Decode the first complete JSON object without greedy brace matching.

    LLMs that hit their token cap return JSON cut off mid-string or mid-array
    — `raw_decode` then raises and the whole plan is lost to the fallback.
    When the clean decode fails, recover the largest valid object by closing
    the open string and brackets, so a truncated plan still yields the
    hypotheses that did arrive rather than nothing.
    """
    if not isinstance(text, str):
        raise ValueError("planner response was not text")
    start = text.find("{")
    if start < 0:
        raise ValueError("planner response contained no JSON object")
    body = text[start:]
    try:
        value, _end = json.JSONDecoder().raw_decode(body)
    except json.JSONDecodeError:
        value = _recover_truncated_json(body)
    if not isinstance(value, dict):
        raise ValueError("planner response was not a JSON object")
    return value


def _recover_truncated_json(body: str) -> Any:
    """Best-effort decode of a truncated JSON object: close the dangling
    string and any open brackets, drop a trailing comma, and parse."""
    stack = []
    in_str = False
    escaped = False
    for ch in body:
        if in_str:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            stack.append("}")
        elif ch == "[":
            stack.append("]")
        elif ch in "}]":
            if stack:
                stack.pop()
    repaired = body
    if in_str:
        repaired += '"'
    repaired = repaired.rstrip()
    if repaired.endswith(","):
        repaired = repaired[:-1]
    repaired += "".join(reversed(stack))
    return json.loads(repaired)


def _text(value: Any, *, limit: int, default: str = "") -> str:
    if not isinstance(value, str):
        return default
    return value.strip()[:limit]


def _score(value: Any, default: float = 0.5) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return default
    return max(0.0, min(1.0, float(value)))


def _string_list(value: Any, *, allowed: set[str] | None = None,
                 limit: int = 20, item_limit: int = 200) -> list[str]:
    if not isinstance(value, list):
        return []
    result = []
    for item in value:
        text = _text(item, limit=item_limit)
        if not text or (allowed is not None and text not in allowed):
            continue
        if text not in result:
            result.append(text)
        if len(result) >= limit:
            break
    return result


def validate_supervisor_plan(value: Any, *, action_ids: set[str],
                             module_ids: set[str]) -> dict | None:
    """Return a bounded supervisor plan, or None for a wrong top-level shape."""
    if not isinstance(value, dict):
        return None
    raw_hypotheses = value.get("hypotheses", [])
    if not isinstance(raw_hypotheses, list):
        return None

    hypotheses = []
    for raw in raw_hypotheses[:25]:
        if not isinstance(raw, dict):
            continue
        title = _text(raw.get("title"), limit=200)
        if not title:
            continue
        action_id = _text(raw.get("action_id"), limit=120,
                          default="manual_review")
        if action_id not in action_ids and action_id != "manual_review":
            action_id = "manual_review"
        assigned_to = _text(raw.get("assigned_to"), limit=32,
                            default="exploitation")
        if assigned_to not in _ROLES:
            assigned_to = "exploitation"
        hypotheses.append({
            "title": title,
            "description": _text(raw.get("description"), limit=2000),
            "likelihood": _score(raw.get("likelihood")),
            "impact": _score(raw.get("impact")),
            "target": _text(raw.get("target"), limit=2048),
            "technique": _text(raw.get("technique"), limit=200),
            "action_id": action_id,
            "assigned_to": assigned_to,
        })
        if len(hypotheses) >= 10:
            break

    return {
        "focus": _text(value.get("focus"), limit=1000,
                       default="Testing target"),
        "hypotheses": hypotheses,
        "module_sequence": _string_list(
            value.get("module_sequence"), allowed=module_ids, limit=20,
            item_limit=100),
        "watch_items": _string_list(
            value.get("watch_items"), limit=20, item_limit=500),
    }


def validate_attack_plan(value: Any, *, module_ids: set[str]) -> dict:
    """Normalize the report-oriented planner schema and reject type confusion."""
    if not isinstance(value, dict):
        raise ValueError("planner response was not a JSON object")
    raw_hypotheses = value.get("top_hypotheses", [])
    if not isinstance(raw_hypotheses, list):
        raise ValueError("top_hypotheses must be an array")

    hypotheses = []
    for raw in raw_hypotheses[:25]:
        if not isinstance(raw, dict):
            continue
        title = _text(raw.get("title"), limit=200)
        likelihood = _text(raw.get("likelihood"), limit=16).lower()
        impact = _text(raw.get("impact"), limit=16).lower()
        if not title or likelihood not in _LIKELIHOODS or impact not in _IMPACTS:
            continue
        recommended = _text(raw.get("recommended_module"), limit=100,
                            default="manual_review")
        if recommended not in module_ids and recommended != "manual_review":
            recommended = "manual_review"
        hypothesis = {
            "rank": len(hypotheses) + 1,
            "title": title,
            "likelihood": likelihood,
            "impact": impact,
            "why": _text(raw.get("why"), limit=2000),
            "recommended_module": recommended,
            "validation": _text(raw.get("validation"), limit=2000),
            "confirming_evidence": _text(
                raw.get("confirming_evidence"), limit=2000),
        }
        # These are advisory only and are revalidated by the action mapper.
        for key in ("suggested_action", "needs_ceiling", "category"):
            if key in raw:
                hypothesis[key] = _text(raw.get(key), limit=120)
        hypotheses.append(hypothesis)
        if len(hypotheses) >= 10:
            break

    return {
        "executive_focus": _text(
            value.get("executive_focus"), limit=2000),
        "top_hypotheses": hypotheses,
        "module_sequence": _string_list(
            value.get("module_sequence"), allowed=module_ids, limit=20,
            item_limit=100),
        "watch_items": _string_list(
            value.get("watch_items"), limit=20, item_limit=500),
    }
