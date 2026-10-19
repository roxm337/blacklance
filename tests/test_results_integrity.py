"""Regression tests for results-management integrity fixes (D1–D7).

Covers: monotonic finding/evidence IDs (no reuse after prune), atomic
state writes, corrupt-read policy (keep last good data + flag), drawable
edge counting, live risk metrics, mid-run table refresh, and the
cross-link columns (evidence backlinks, submission finding IDs,
INDEX.md exclusion, show-in-assets, multi-ref evidence picker).
"""

import json
import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("QTWEBENGINE_DISABLE_SANDBOX", "1")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QApplication

from gui.app import MainWindow
from gui.graph import build_graph, count_relations
from state.manager import StateManager


def _window(tmp_path):
    """Isolated MainWindow: tmp output dir, controlled target, private QSettings."""
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    window.output_dir = tmp_path / "reports"
    window.output_input.setText(str(window.output_dir))
    window.target_input.setText("unit.test")
    window._settings = QSettings(str(tmp_path / "gui-test.ini"), QSettings.IniFormat)
    window._recent_targets = []
    window._triage = {}
    return window, app


def _state(tmp_path) -> StateManager:
    return StateManager(str(tmp_path / "reports" / "unit.test"))


def _add_finding(state, module_id="m", title="t", **kwargs):
    # add_finding tags findings with module["current"] (no module_id param).
    state.module["current"] = module_id
    defaults = dict(
        title=title, severity="HIGH", confidence="FIRM",
        category="Test", description="d",
    )
    defaults.update(kwargs)
    return state.add_finding(**defaults)


# ── D1: monotonic finding IDs ──────────────────────────────────────


def test_finding_ids_not_reused_after_prune(tmp_path):
    state = _state(tmp_path)
    a1 = _add_finding(state, module_id="mod_a", title="a1")
    b1 = _add_finding(state, module_id="mod_b", title="b1")
    a2 = _add_finding(state, module_id="mod_a", title="a2")
    assert (a1, b1, a2) == ("FINDING-0001", "FINDING-0002", "FINDING-0003")

    # Re-run mod_a: prune removes its two findings, mod_b's survives.
    state.begin_module_run("mod_a", "low", 1)
    surviving = [f["id"] for f in state.findings["findings"]]
    assert surviving == ["FINDING-0002"]

    new_id = _add_finding(state, module_id="mod_a", title="a-new")
    all_ids = [f["id"] for f in state.findings["findings"]]
    assert new_id == "FINDING-0004"          # never reissues 0001/0003
    assert len(all_ids) == len(set(all_ids))  # no duplicate IDs
    assert "FINDING-0002" in all_ids          # unrelated finding untouched


def test_legacy_state_migrates_id_seq_from_disk(tmp_path):
    state_dir = tmp_path / "reports" / "unit.test" / "state"
    state_dir.mkdir(parents=True)
    (state_dir / "findings.json").write_text(json.dumps({
        "findings": [{"id": "FINDING-0002", "title": "old"}],
    }))
    state = _state(tmp_path)
    new_id = _add_finding(state, title="new")
    assert new_id == "FINDING-0003"


def test_merged_finding_keeps_its_id(tmp_path):
    state = _state(tmp_path)
    first = _add_finding(state, title="Same")
    second = _add_finding(state, title="Same", severity="CRITICAL")
    assert first == second
    assert len(state.findings["findings"]) == 1


# ── D7: monotonic evidence IDs ─────────────────────────────────────


def test_evidence_ids_monotonic_after_removal(tmp_path):
    state = _state(tmp_path)
    e1 = state.add_evidence("m", "json", "s1", {"a": 1})
    e2 = state.add_evidence("m", "json", "s2", {"a": 2})
    assert (e1, e2) == ("EVIDENCE-0001", "EVIDENCE-0002")
    state.evidence["items"] = [i for i in state.evidence["items"] if i["id"] != e1]
    e3 = state.add_evidence("m", "json", "s3", {"a": 3})
    ids = [i["id"] for i in state.evidence["items"]]
    assert e3 == "EVIDENCE-0003"
    assert len(ids) == len(set(ids))


# ── D2: atomic writes ──────────────────────────────────────────────


def test_state_save_leaves_no_temp_files(tmp_path):
    state = _state(tmp_path)
    _add_finding(state)
    state.add_evidence("m", "json", "s", {"ok": True})
    state.save()
    leftovers = list(state.state_dir.glob("*.tmp"))
    assert leftovers == []
    data = json.loads((state.state_dir / "findings.json").read_text())
    assert data["findings"] and "id_seq" in data


def test_corrupt_findings_keep_previous_and_flag(tmp_path):
    window, app = _window(tmp_path)
    state = _state(tmp_path)
    _add_finding(state)
    state.save()
    window.load_results()
    assert window.findings_table.rowCount() == 1

    (tmp_path / "reports" / "unit.test" / "state" / "findings.json").write_text("{torn")
    window.load_results()
    # Previous rows kept, not silently zeroed…
    assert window.findings_table.rowCount() == 1
    assert window.findings_value.text() == "1"
    # …and the header pill says which file is broken.
    assert "Corrupt" in window.status_label.text()
    assert "findings.json" in window.status_label.text()
    window.close()
    app.processEvents()


# ── D3: drawable-only edges ────────────────────────────────────────


def test_build_graph_drops_dangling_finding_edges():
    assets = {
        "nodes": [{"key": "domain:a", "type": "domain", "value": "a"}],
        "edges": [
            {"source": "domain:a", "target": "FINDING-0001",
             "type": "AFFECTED_BY"},
            {"source": "domain:a", "target": "ip:1.2.3.4",
             "type": "RELATES_TO"},
        ],
    }
    graph = build_graph(assets)
    assert graph["edges"] == []          # both edges lack a real endpoint
    assert count_relations(assets) == 0


def test_count_relations_matches_drawable_edges():
    assets = {
        "nodes": [
            {"key": "domain:a", "type": "domain", "value": "a"},
            {"key": "ip:1.2.3.4", "type": "ip", "value": "1.2.3.4"},
        ],
        "edges": [
            {"source": "domain:a", "target": "ip:1.2.3.4", "type": "RELATES_TO"},
            {"source": "domain:a", "target": "FINDING-0009", "type": "AFFECTED_BY"},
        ],
    }
    assert count_relations(assets) == 1


# ── D4: live risk metrics ──────────────────────────────────────────


def test_risk_metrics_live_without_report_summary(tmp_path):
    window, app = _window(tmp_path)
    state = _state(tmp_path)
    _add_finding(state, title="mid", severity="MEDIUM", risk_score=40)
    _add_finding(state, title="crit", severity="CRITICAL", risk_score=90)
    _add_finding(state, title="low", severity="LOW", risk_score=10)
    state.save()
    window.load_results()
    assert window.max_risk_value.text() == "90"
    assert window.critical_high_value.text() == "1"
    window.close()
    app.processEvents()


# ── D5: mid-run table refresh ──────────────────────────────────────


def test_poll_data_tables_refreshes_tables(tmp_path):
    window, app = _window(tmp_path)
    window.load_results()
    assert window.findings_table.rowCount() == 0

    state = _state(tmp_path)
    _add_finding(state)
    state.save()
    window._poll_data_tables()
    assert window.findings_table.rowCount() == 1
    assert window.findings_value.text() == "1"
    # Default score_finding(HIGH, FIRM) with no assets.
    assert window.max_risk_value.text() == "75"
    window.close()
    app.processEvents()


# ── D6/D7: cross-links ─────────────────────────────────────────────


def test_evidence_table_shows_citing_findings(tmp_path):
    window, app = _window(tmp_path)
    state = _state(tmp_path)
    eid = state.add_evidence("m", "json", "subject", {"ok": True})
    _add_finding(state, evidence_refs=[eid])
    state.save()
    window.load_results()
    ids = [window.evidence_table.item(r, 0).text()
           for r in range(window.evidence_table.rowCount())]
    row = ids.index(eid)
    assert window.evidence_table.item(row, 5).text() == "FINDING-0001"
    window.close()
    app.processEvents()


def test_submissions_exclude_index_and_link_finding(tmp_path):
    window, app = _window(tmp_path)
    sub = tmp_path / "reports" / "unit.test" / "submissions"
    sub.mkdir(parents=True)
    (sub / "INDEX.md").write_text("# Index")
    (sub / "FINDING-0004_open-redirect.md").write_text("# Report")
    window._load_submissions()
    assert window.submissions_table.rowCount() == 1
    assert window.submissions_table.item(0, 0).text() == "FINDING-0004_open-redirect.md"
    assert window.submissions_table.item(0, 1).text() == "FINDING-0004"
    window.close()
    app.processEvents()


def test_show_in_assets_seeds_asset_filter(tmp_path):
    window, app = _window(tmp_path)
    window._load_findings([{
        "id": "F-1", "title": "t", "severity": "HIGH", "confidence": "FIRM",
        "category": "c", "module_id": "m", "description": "d",
        "asset_keys": ["domain:example.com"],
    }])
    window.findings_table.selectRow(0)
    window._show_selected_in_assets()
    assert window.screen_stack.currentIndex() == 3  # Data screen
    assert window.data_tabs.currentIndex() == 0     # Assets sub-tab
    entry = window._table_filters.get(window.assets_table)
    assert entry[0].text() == "example.com"
    window.close()
    app.processEvents()


def test_open_finding_evidence_single_ref_no_dialog(tmp_path, monkeypatch):
    window, app = _window(tmp_path)
    target_dir = window.output_dir / "unit.test"
    (target_dir / "ev").mkdir(parents=True)
    (target_dir / "ev" / "a.txt").write_text("a")
    window.current_evidence = {"items": [
        {"id": "EVIDENCE-0001", "path": "ev/a.txt"},
    ]}
    opened = []
    monkeypatch.setattr(
        "gui.app.QDesktopServices.openUrl",
        lambda url: opened.append(url.toString()) or True,
    )

    def _dialog_must_not_open(*_a, **_k):
        raise AssertionError("single ref must not open the picker")

    monkeypatch.setattr("gui.app.QInputDialog.getItem", _dialog_must_not_open)
    window._open_finding_evidence({"evidence_refs": ["EVIDENCE-0001"]})
    assert len(opened) == 1 and "a.txt" in opened[0]
    window.close()
    app.processEvents()


def test_open_finding_evidence_multi_ref_picker(tmp_path, monkeypatch):
    window, app = _window(tmp_path)
    target_dir = window.output_dir / "unit.test"
    (target_dir / "ev").mkdir(parents=True)
    (target_dir / "ev" / "a.txt").write_text("a")
    (target_dir / "ev" / "b.txt").write_text("b")
    window.current_evidence = {"items": [
        {"id": "EVIDENCE-0001", "path": "ev/a.txt"},
        {"id": "EVIDENCE-0002", "path": "ev/b.txt"},
    ]}
    opened = []
    monkeypatch.setattr(
        "gui.app.QDesktopServices.openUrl",
        lambda url: opened.append(url.toString()) or True,
    )
    # Pick the second label from the picker.
    monkeypatch.setattr(
        "gui.app.QInputDialog.getItem",
        lambda *args, **kwargs: (args[3][1], True),
    )
    window._open_finding_evidence(
        {"evidence_refs": ["EVIDENCE-0001", "EVIDENCE-0002"]})
    assert len(opened) == 1 and "b.txt" in opened[0]
    window.close()
    app.processEvents()
