"""SARIF export: one rule per category, stable fingerprints, real locations."""

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.reporting import render_sarif, write_report_bundle
from state.manager import StateManager


def _state(findings=()):
    tmpdir = Path(tempfile.mkdtemp())
    state = StateManager(str(tmpdir / "run" / "example.com"))
    for finding in findings:
        state.add_finding(**finding)
    return state


def test_empty_state_still_produces_a_valid_run():
    doc = render_sarif({"findings": []})
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []
    assert doc["runs"][0]["results"] == []


def test_results_map_severity_and_dedupe_rules():
    doc = render_sarif({"findings": [
        {"title": "SQLi in search", "severity": "HIGH", "confidence": "CONFIRMED",
         "category": "SQL Injection", "description": "boolean differential",
         "verified": True, "asset_keys": ["url:https://example.com/search"],
         "verification": {"url": "https://example.com/search"}},
        {"title": "SQLi in login", "severity": "MEDIUM", "confidence": "FIRM",
         "category": "SQL Injection", "description": "error based"},
    ]})
    run = doc["runs"][0]
    assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == ["sql-injection"]
    high, medium = run["results"]
    assert high["level"] == "error"
    assert medium["level"] == "warning"
    assert high["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == \
        "https://example.com/search"
    assert "locations" not in medium
    assert high["properties"]["verified"] is True


def test_fingerprint_is_content_derived_and_stable():
    findings = [{"title": "SSTI", "severity": "HIGH", "category": "SSTI",
                 "description": "49", "asset_keys": ["url:https://a.test/x"],
                 "confid": "CONFIRMED"}]
    first = render_sarif({"findings": findings})
    second = render_sarif({"findings": findings})
    fp1 = first["runs"][0]["results"][0]["partialFingerprints"]["osintAgent/v1"]
    fp2 = second["runs"][0]["results"][0]["partialFingerprints"]["osintAgent/v1"]
    other = render_sarif({"findings": [
        {**findings[0], "title": "SSTI elsewhere"}]})
    fp3 = other["runs"][0]["results"][0]["partialFingerprints"]["osintAgent/v1"]
    assert fp1 == fp2 != fp3


def test_report_bundle_writes_the_sarif_file():
    state = _state([{
        "title": "Open admin", "severity": "LOW", "confidence": "FIRM",
        "category": "Exposure", "description": "admin reachable",
        "asset_keys": ["url:https://example.com/admin"],
    }])
    paths = write_report_bundle(state, "example.com")
    assert paths["sarif"].endswith("example.com.sarif")
    doc = json.loads(Path(paths["sarif"]).read_text())
    assert doc["runs"][0]["results"][0]["ruleId"] == "exposure"
