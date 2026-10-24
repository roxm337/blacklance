"""History must distinguish observations, exports, and explicit negative retests."""

import json
from pathlib import Path

import pytest

from core.fingerprints import fingerprint, finding_url
from core.history import annotate, annotate_assets, empty
from core.reporting import write_report_bundle
from state.manager import StateManager


FINDING = {"title": "private object", "category": "IDOR", "severity": "HIGH",
           "asset_keys": ["url:https://example.com/objects/1"]}


def test_absence_without_coverage_is_untested_not_resolved():
    _, history, _ = annotate([FINDING], empty(), run_id="first")
    _, history, diff = annotate([], history, run_id="partial")
    assert not diff["resolved"]
    assert len(diff["untested"]) == 1
    assert next(iter(history["findings"].values()))["last_status"] == "untested"
    fp = fingerprint(FINDING, finding_url(FINDING))
    _, history, diff = annotate([], history, run_id="negative-retest", retested={fp})
    assert len(diff["resolved"]) == 1
    assert not diff["untested"]
    _, _, again = annotate([], history, run_id="later")
    assert not again["resolved"]


def test_duplicate_rows_and_exports_count_one_observation():
    _, history, diff = annotate([FINDING, FINDING], empty(), run_id="first")
    assert len(diff["new"]) == 1
    _, history, _ = annotate([FINDING], history, run_id="first")
    assert next(iter(history["findings"].values()))["occurrences"] == 1
    _, history, diff = annotate([FINDING], history, run_id="second")
    assert len(diff["recurring"]) == 1
    assert next(iter(history["findings"].values()))["occurrences"] == 2


def test_missing_assets_are_not_resolved_by_an_incomplete_crawl():
    asset = {"key": "url:https://example.com/a", "type": "url", "value": "a"}
    history, _ = annotate_assets([asset, asset], empty(), run_id="first")
    history, diff = annotate_assets([], history, run_id="partial")
    assert len(diff["untested"]) == 1
    assert not diff["resolved"]
    _, diff = annotate_assets([], history, run_id="verified-absent", retested={asset["key"]})
    assert len(diff["resolved"]) == 1


def test_report_annotations_and_occurrences_are_consistent(tmp_path):
    state = StateManager(str(tmp_path))
    state.add_finding(**FINDING, confidence="FIRM", description="fixture")
    paths = write_report_bundle(state, "example.com")
    summary = json.loads(Path(paths["summary"]).read_text())
    exported = json.loads(Path(paths["findings"]).read_text())
    assert summary["findings"][0]["history"] == exported["findings"][0]["history"]
    before = json.loads((tmp_path / "findings_history.json").read_text())
    # Report-only module runs do not constitute a new target observation.
    run = state.begin_module_run("reporting")
    state.finish_module_run(run, "done")
    write_report_bundle(state, "example.com")
    after = json.loads((tmp_path / "findings_history.json").read_text())
    assert before == after


def test_corrupt_history_is_not_overwritten_by_report(tmp_path):
    state = StateManager(str(tmp_path))
    path = tmp_path / "findings_history.json"
    path.write_text("{broken")
    with pytest.raises(ValueError, match="baseline"):
        write_report_bundle(state, "example.com")
    assert path.read_text() == "{broken"


def test_unrelated_surface_update_does_not_reobserve_old_findings(tmp_path):
    state = StateManager(str(tmp_path))
    state.add_finding(**FINDING, confidence="FIRM", description="fixture")
    write_report_bundle(state, "example.com")
    state.add_asset("url", "url:https://example.com/other", "https://example.com/other")
    write_report_bundle(state, "example.com")
    history = json.loads((tmp_path / "findings_history.json").read_text())
    assert next(iter(history["findings"].values()))["occurrences"] == 1
    state.add_finding(**FINDING, confidence="FIRM", description="fixture")
    write_report_bundle(state, "example.com")
    history = json.loads((tmp_path / "findings_history.json").read_text())
    assert next(iter(history["findings"].values()))["occurrences"] == 2


def test_legacy_history_migrates_without_losing_first_seen():
    _, history, _ = annotate([FINDING], empty(), now="old", run_id="old")
    history["version"] = 1
    entry = next(iter(history["findings"].values()))
    entry.pop("last_run_id")
    entry.pop("history_status")
    _, updated, _ = annotate([FINDING], history, now="new", run_id="new")
    entry = next(iter(updated["findings"].values()))
    assert entry["first_seen"] == "old"
    assert entry["occurrences"] == 2
    assert updated["version"] == 2
