"""DefectDojo export: Generic Findings Import shape, stable unique ids."""

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.reporting import render_defectdojo, write_report_bundle
from state.manager import StateManager


def _state():
    tmp = Path(tempfile.mkdtemp())
    return StateManager(str(tmp / "run" / "example.com"))


def test_empty_bundle_is_an_empty_import():
    doc = render_defectdojo({"findings": [], "metadata": {"target": "x"}})
    assert doc["findings"] == []


def test_finding_maps_severity_endpoint_and_verification():
    doc = render_defectdojo({"findings": [{
        "title": "SQLi", "severity": "HIGH", "confidence": "CONFIRMED",
        "category": "SQL Injection", "description": "boolean differential",
        "verified": True, "risk_score": 92,
        "asset_keys": ["url:https://example.com/search?q=1"],
        "verification": {"method": "boolean_differential",
                         "url": "https://example.com/search?q=1"},
    }], "metadata": {"target": "example.com"}})
    item = doc["findings"][0]
    assert item["severity"] == "High"
    assert item["numerical_severity"] == "S1"
    assert item["verified"] is True
    assert item["dynamic_finding"] is True
    assert item["endpoints"] == ["https://example.com/search?q=1"]
    assert "boolean_differential" in item["description"]
    assert item["unique_id_from_tool"]


def test_unique_id_is_stable_and_changes_with_title():
    base = {"title": "SSTI", "severity": "HIGH", "category": "SSTI",
            "description": "49", "asset_keys": ["url:https://a.test/x"]}
    first = render_defectdojo({"findings": [base]})["findings"][0]
    second = render_defectdojo({"findings": [base]})["findings"][0]
    other = render_defectdojo(
        {"findings": [{**base, "title": "SSTI elsewhere"}]})["findings"][0]
    assert first["unique_id_from_tool"] == second["unique_id_from_tool"]
    assert first["unique_id_from_tool"] != other["unique_id_from_tool"]


def test_report_writes_the_defectdojo_file():
    state = _state()
    state.add_finding(
        title="Open admin", severity="LOW", confidence="FIRM",
        category="Exposure", description="admin reachable",
        asset_keys=["url:https://example.com/admin"])
    paths = write_report_bundle(state, "example.com")
    assert paths["defectdojo"].endswith("example.com_defectdojo.json")
    doc = json.loads(Path(paths["defectdojo"]).read_text())
    assert doc["findings"][0]["title"] == "Open admin"
    assert doc["findings"][0]["severity"] == "Low"
