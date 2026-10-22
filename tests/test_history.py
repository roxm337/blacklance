"""Cross-run history: new, recurring, resolved — and persistence."""

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.history import annotate, annotate_assets, empty, load, save
from core.reporting import write_report_bundle
from state.manager import StateManager

FINDING = {
    "title": "Open admin",
    "severity": "HIGH",
    "category": "Exposure",
    "description": "admin reachable",
    "asset_keys": ["url:https://example.com/admin"],
}


def test_first_run_is_new():
    annotated, history, diff = annotate([FINDING], empty(), now="2026-01-01")
    assert annotated[0]["history"]["status"] == "new"
    assert annotated[0]["history"]["occurrences"] == 1
    assert diff["new"][0]["url"] == "https://example.com/admin"
    assert len(history["findings"]) == 1


def test_second_run_is_recurring_and_keeps_first_seen():
    _, history, _ = annotate([FINDING], empty(), now="2026-01-01")
    annotated, history, diff = annotate([FINDING], history, now="2026-02-01")
    block = annotated[0]["history"]
    assert block["status"] == "recurring"
    assert block["occurrences"] == 2
    assert block["first_seen"] == "2026-01-01"
    assert diff["recurring"]
    assert diff["new"] == []


def test_a_vanished_finding_is_resolved_relative_to_the_last_scan():
    _, history, _ = annotate([FINDING], empty(), now="2026-01-01")
    _, history, diff = annotate([], history, now="2026-02-01")
    assert [item["title"] for item in diff["resolved"]] == ["Open admin"]
    _, history, diff = annotate([], history, now="2026-03-01")
    assert diff["resolved"] == []


def test_malformed_history_starts_clean():
    path = Path(tempfile.mkdtemp()) / "history.json"
    path.write_text("{broken")
    assert load(path) == empty()
    path.write_text(json.dumps({"findings": []}))
    assert load(path) == empty()


def test_save_and_load_round_trip():
    _, history, _ = annotate([FINDING], empty(), now="2026-01-01")
    path = Path(tempfile.mkdtemp()) / "history.json"
    save(path, history)
    assert load(path) == history


def test_report_bundle_writes_regression_and_updates_history(tmp_path=None):
    root = Path(tempfile.mkdtemp())
    state = StateManager(str(root / "run" / "example.com"))
    state.add_finding(title=FINDING["title"], severity="HIGH",
                      confidence="FIRM", category="Exposure",
                      description="admin reachable",
                      asset_keys=FINDING["asset_keys"])
    first = write_report_bundle(state, "example.com")
    doc = json.loads(Path(first["regression"]).read_text())
    assert doc["counts"] == {"new": 1, "recurring": 0, "resolved": 0}
    assert Path(first["regression"]).parent == root / "run" / "example.com"

    second = write_report_bundle(state, "example.com")
    doc = json.loads(Path(second["regression"]).read_text())
    assert doc["counts"]["recurring"] == 1
    assert doc["counts"]["new"] == 0


def _asset(key, kind="url"):
    return {"key": key, "type": kind, "value": key.split(":", 1)[-1]}


def test_asset_diff_is_new_then_recurring_then_resolved():
    history, diff = annotate_assets(
        [_asset("url:https://a.test"), _asset("url:https://b.test")],
        empty(), now="2026-01-01")
    assert diff["new"] and len(diff["new"]) == 2
    assert diff["resolved"] == []

    history, diff = annotate_assets(
        [_asset("url:https://a.test")], history, now="2026-01-02")
    assert diff["new"] == []
    assert len(diff["recurring"]) == 1
    assert [item["key"] for item in diff["resolved"]] == ["url:https://b.test"]

    # A disappearance is reported once, not every run.
    history, diff = annotate_assets(
        [_asset("url:https://a.test")], history, now="2026-01-03")
    assert diff["resolved"] == []


def test_finding_annotate_preserves_the_asset_section():
    history, _ = annotate_assets([_asset("url:https://a.test")], empty(),
                                 now="2026-01-01")
    _, history, _ = annotate([FINDING], history, now="2026-01-02")
    assert "url:https://a.test" in history["assets"]
    assert history["findings"]


def test_report_bundle_records_asset_diff(tmp_path=None):
    root = Path(tempfile.mkdtemp())
    state = StateManager(str(root / "run" / "example.com"))
    state.add_asset("url", "url:https://example.com/a",
                    "https://example.com/a", confidence="FIRM")
    first = write_report_bundle(state, "example.com")
    doc = json.loads(Path(first["regression"]).read_text())
    assert doc["assets"]["counts"]["new"] == 1

    second = write_report_bundle(state, "example.com")
    doc = json.loads(Path(second["regression"]).read_text())
    assert doc["assets"]["counts"] == {"new": 0, "recurring": 1, "resolved": 0}
    history = json.loads((Path(first["regression"]).parent /
                          "findings_history.json").read_text())
    assert "url:https://example.com/a" in history["assets"]
