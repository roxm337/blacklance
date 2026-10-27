"""Tests for the I4 client-side path traversal screen in the desktop GUI."""

import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("QTWEBENGINE_DISABLE_SANDBOX", "1")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml
from PySide6.QtWidgets import QApplication, QMessageBox

import gui.app as gui_app_module
# _browser_driver_present is resolved inside the CSPT screen mixin's own
# module namespace, so patch it there (not on gui.app's re-export).
import gui.screens.cspt as cspt_screen_module
from gui.app import MainWindow
from state.manager import StateManager


ALTERED_PROVEN = "https://shop.example.test/api/xhr/admin/secrets"
ALTERED_OPEN = "https://shop.example.test/api/xhr/internal/export"

PAIRS = [
    # The token reached an XHR and the payload escaped on a segment boundary;
    # the replay below is what promotes it.
    {"state": "path_altered", "identity": "user_a", "point": "query",
     "name": "r", "target": "https://shop.example.test/cart",
     "natural_path": "/api/xhr/cart/czabc123",
     "natural_url": "https://shop.example.test/api/xhr/cart/czabc123",
     "probe_path": "/api/xhr/admin/secrets", "probe_url": ALTERED_PROVEN,
     "prefix": ["api", "xhr", "cart"],
     "effect_segments": ["admin", "secrets"],
     "payload": "..%2f..%2fadmin%2fsecrets%3fcspt%3dczabc123", "status": 200},
    # Same escape, no replay of it: adjacent signal only.
    {"state": "path_altered", "identity": "anonymous", "point": "fragment",
     "name": "", "target": "https://shop.example.test/cart",
     "natural_path": "/api/xhr/cart/czabc123",
     "natural_url": "https://shop.example.test/api/xhr/cart/czabc123",
     "probe_path": "/api/xhr/internal/export", "probe_url": ALTERED_OPEN,
     "prefix": ["api", "xhr", "cart"],
     "effect_segments": ["internal", "export"],
     "payload": "%2e%2e%2f%2e%2e%2finternal%2fexport", "status": 404},
    # Reached the request layer and stayed under the prefix: clean.
    {"state": "unchanged", "identity": "user_a", "point": "path", "name": "",
     "target": "https://shop.example.test/cart",
     "natural_path": "/api/xhr/cart/czabc123",
     "natural_url": "https://shop.example.test/api/xhr/cart/czabc123",
     "probe_path": "", "prefix": ["api", "xhr", "cart"],
     "effect_segments": [], "payload": "", "status": 0},
    # Never appeared in a request: this inject point is unproven.
    {"state": "not_reached", "identity": "anonymous", "point": "query",
     "name": "file", "target": "https://shop.example.test/account",
     "natural_path": "", "natural_url": "", "probe_path": "", "prefix": [],
     "effect_segments": [], "payload": "", "status": 0},
]

IMPACT = {
    "natural_url": "https://shop.example.test/api/xhr/cart/czabc123",
    "probe_url": ALTERED_PROVEN,
    "resolved_path": "/api/xhr/admin/secrets",
    "observed": "lease-442", "expectation": "lease-442",
    "baseline_status": 404, "control_same_shape": False,
}

REPORT = {
    "schema_version": 1, "run_token": "czabc123",
    "targets": ["https://shop.example.test/cart"],
    "pairs": PAIRS,
    "state_counts": {"path_altered": 2, "unchanged": 1, "not_reached": 1},
    "untested": [{"target": "https://shop.example.test/checkout",
                  "reason": "time-box hit"}],
}


def _cspt_state(tmp_path):
    """One finished CSPT pass: a replay-confirmed escape, an open candidate,
    one clean inject point and one that was never reached."""
    state = StateManager(str(tmp_path / "reports" / "example.com"))
    report_id = state.add_evidence("cspt_audit", "cspt_report",
                                   "https://shop.example.test", REPORT)
    impact_id = state.add_evidence("cspt_audit", "cspt_impact",
                                   "https://shop.example.test", IMPACT)
    state.add_finding(
        title="Client-Side Path Traversal: /api/xhr/cart/{id} → "
              "/api/xhr/admin/secrets [aaaaaaaa]",
        severity="HIGH", confidence="CONFIRMED",
        category="Client-Side Path Traversal",
        description="The replayed altered URL returned the configured value.",
        evidence=[f"natural:{IMPACT['natural_url']}",
                  f"altered:{ALTERED_PROVEN}", impact_id],
        verified=True)
    state.add_finding(
        title="Client-Side Path Traversal candidate: /api/xhr/internal/export "
              "[bbbbbbbb]",
        severity="MEDIUM", confidence="FIRM",
        category="Client-Side Path Traversal",
        description="A payload resolved outside the natural prefix.",
        evidence=[f"natural:{IMPACT['natural_url']}", f"altered:{ALTERED_OPEN}"],
        verified=False)
    state.complete_module("cspt_audit")
    state.save()
    return state, report_id, impact_id


def _window(tmp_path):
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    window.output_dir = tmp_path / "reports"
    window.output_input.setText(str(window.output_dir))
    window.target_input.setText("example.com")
    window.config_path = tmp_path / "config.yaml"
    window.refresh_graph = lambda: None
    return app, window


def _write_config(tmp_path, payload: dict):
    (tmp_path / "config.yaml").write_text(
        yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def _loaded(tmp_path):
    _cspt_state(tmp_path)
    app, window = _window(tmp_path)
    window.load_results()
    return app, window


def test_cspt_screen_is_registered_on_the_rail():
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    keys = [entry[0] for entry in window.SCREEN_DEFS]
    # The full rail list is asserted once, in test_gui_app.py.
    assert "cspt" in keys
    index = MainWindow._screen_index("cspt")
    assert index == keys.index("cspt")
    assert window.screen_stack.count() == len(keys)
    assert window.screen_stack.widget(index).objectName() == "screenCspt"
    assert [window.cspt_tabs.tabText(i)
            for i in range(window.cspt_tabs.count())] == \
        ["Inject points", "Impact replays", "Coverage"]
    # Inserting a screen must not move what the graph auto-refresh watches.
    assert window.SCREEN_GRAPH_INDEX == keys.index("graph")
    window.close()
    app.processEvents()


def test_cspt_screen_grades_the_three_states(tmp_path):
    app, window = _loaded(tmp_path)

    assert window.cspt_targets_value.text() == "1"
    assert window.cspt_points_value.text() == "4"
    assert window.cspt_altered_value.text() == "2"
    assert window.cspt_proofs_value.text() == "1"
    # The unproven inject point plus the target the time-box cut off.
    assert window.cspt_look_value.text() == "2"
    assert window.cspt_gap_value.text() == "1"
    tiers = [window.cspt_pairs_table.item(row, 0).text()
             for row in range(window.cspt_pairs_table.rowCount())]
    assert tiers == ["PROOF", "CANDIDATE", "OBSERVATION", "HEALTHY"]
    assert "1 replay-confirmed escape" in window.cspt_run_label.text()
    window.close()
    app.processEvents()


def test_replay_is_what_makes_a_proof_and_the_detail_shows_it(tmp_path):
    app, window = _loaded(tmp_path)

    rows = getattr(window, "_cspt_pair_rows")
    index = next(i for i, row in enumerate(rows)
                 if row["probe_url"] == ALTERED_PROVEN)
    window.cspt_pairs_table.setCurrentCell(index, 0)
    detail = window.cspt_detail_body.toPlainText()
    assert rows[index]["tier"] == "PROOF"
    assert "Impact replay" in detail
    assert '"lease-442"' in detail
    # A proof does not ask for another proof.
    assert "Still needed" not in detail
    assert window.cspt_open_finding_button.isEnabled()
    assert window.cspt_copy_url_button.isEnabled()
    window.close()
    app.processEvents()


def test_detail_panes_put_one_field_per_line(tmp_path):
    """The detail is a record the operator reads top to bottom; joined with
    newlines it collapses into one run-on paragraph in rich text."""
    app, window = _loaded(tmp_path)

    window.cspt_pairs_table.setCurrentCell(0, 0)
    lines = [line.strip()
             for line in window.cspt_detail_body.toPlainText().splitlines()
             if line.strip()]
    assert lines[0].startswith("PROOF —")
    assert "Module cspt_audit" in lines
    assert any(line.startswith("Resolved path /api/xhr/admin/secrets")
               for line in lines)
    assert any(line.startswith("Finding FINDING-") for line in lines)
    window.close()
    app.processEvents()


def test_altered_path_without_a_replay_stays_a_candidate(tmp_path):
    app, window = _loaded(tmp_path)

    rows = getattr(window, "_cspt_pair_rows")
    index = next(i for i, row in enumerate(rows)
                 if row["probe_url"] == ALTERED_OPEN)
    window.cspt_pairs_table.setCurrentCell(index, 0)
    detail = window.cspt_detail_body.toPlainText()
    assert rows[index]["tier"] == "CANDIDATE"
    assert "Still needed" in detail
    assert "impact probe with a configured expectation" in detail
    assert "api/xhr/cart" in detail  # the natural prefix it escaped
    window.close()
    app.processEvents()


def test_unreached_inject_point_is_not_called_clean(tmp_path):
    app, window = _loaded(tmp_path)

    rows = getattr(window, "_cspt_pair_rows")
    index = next(i for i, row in enumerate(rows) if row["state"] == "not_reached")
    window.cspt_pairs_table.setCurrentCell(index, 0)
    detail = window.cspt_detail_body.toPlainText()
    assert "Unproven" in detail
    assert "never appeared in an XHR/fetch request" in detail
    # The inject surface is the point of the row: query?file, not just "query".
    assert "query?file" in window.cspt_detail_title.text()
    window.close()
    app.processEvents()


def test_impact_tab_lists_the_frameworks_own_replays(tmp_path):
    app, window = _loaded(tmp_path)

    table = window.cspt_impacts_table
    assert table.rowCount() == 1
    assert table.item(0, 0).text() == "/api/xhr/admin/secrets"
    assert table.item(0, 2).text() == '"lease-442"'
    assert table.item(0, 4).text() == "different shape"
    window.cspt_impacts_table.setCurrentCell(0, 0)
    assert "PROOF" in window.cspt_detail_body.toPlainText()
    assert window.cspt_detail_title.text().startswith("PROOF ·")
    window.close()
    app.processEvents()


def test_coverage_tab_shows_what_the_run_never_drove(tmp_path):
    app, window = _loaded(tmp_path)

    assert window.cspt_gap_table.rowCount() == 1
    assert window.cspt_gap_table.item(0, 0).text() == \
        "https://shop.example.test/checkout"
    assert window.cspt_gap_table.item(0, 1).text() == "time-box hit"
    assert "1 target(s) the last run never drove" in window.cspt_gap_note.text()
    assert window.cspt_gap_note.property("tone") == "warn"
    window.close()
    app.processEvents()


def test_cspt_filter_narrows_rows(tmp_path):
    app, window = _loaded(tmp_path)

    window.cspt_tier_combo.setCurrentText("HEALTHY")
    assert window.cspt_pairs_table.rowCount() == 1
    assert window.cspt_pairs_table.item(0, 6).text() == "unchanged"
    window._reset_cspt_filter()
    window.cspt_search.setText("secrets")
    assert window.cspt_pairs_table.rowCount() == 1
    assert window.cspt_count_label.text() == "1 of 4"
    window._reset_cspt_filter()
    assert window.cspt_pairs_table.rowCount() == 4
    window.close()
    app.processEvents()


def test_open_in_triage_routes_to_the_traversal_finding(tmp_path):
    app, window = _loaded(tmp_path)

    window.cspt_pairs_table.setCurrentCell(0, 0)
    window._open_cspt_finding()
    assert window.screen_stack.currentIndex() == MainWindow._screen_index("triage")
    assert window.finding_search.text()
    window.close()
    app.processEvents()


def test_cspt_plan_saves_and_keeps_nested_yaml(tmp_path):
    _cspt_state(tmp_path)
    _write_config(tmp_path, {
        "modules": {
            "cspt_audit": {
                "enabled": False, "max_targets": 3, "max_payloads": 6,
                "wait_ms": 1200, "inject_points": ["query"],
                "inject_names": ["fileUrl"],
                "canary_route": {"sibling_paths": ["/api/xhr/admin/secrets"],
                                 "hint_segments": ["admin"]},
                "impact_probe": {"enabled": True,
                                 "expect": {"type": "jsonpath", "path": "lease"},
                                 "equals": "lease-442"},
            },
        },
        "auth": {"identities": [{"name": "user_a"}, {"name": "user_b"}]},
    })
    app, window = _window(tmp_path)
    window._load_settings_form()

    assert window.cspt_enabled_check.isChecked() is False
    assert window.cspt_point_checks["query"].isChecked()
    assert not window.cspt_point_checks["fragment"].isChecked()
    assert "/api/xhr/admin/secrets" in window.cspt_route_label.text()
    assert "lease-442" in window.cspt_expect_label.text()
    assert window.cspt_expect_label.property("tone") == "ok"
    assert "user_a" in window.cspt_identity_label.text()

    window.cspt_enabled_check.setChecked(True)
    window.cspt_point_checks["fragment"].setChecked(True)
    window.cspt_max_targets_spin.setValue(5)
    window.cspt_wait_spin.setValue(900)
    assert window._save_cspt_plan() is True

    saved = yaml.safe_load((tmp_path / "config.yaml").read_text())
    section = saved["modules"]["cspt_audit"]
    assert section["enabled"] is True
    assert section["max_targets"] == 5
    assert section["wait_ms"] == 900
    assert section["inject_points"] == ["query", "fragment"]
    # The panel reports on these; it must never rewrite them.
    assert section["inject_names"] == ["fileUrl"]
    assert section["canary_route"]["hint_segments"] == ["admin"]
    assert section["impact_probe"]["expect"] == {"type": "jsonpath",
                                                 "path": "lease"}
    assert section["impact_probe"]["equals"] == "lease-442"
    assert "CSPT plan saved" in window.statusBar().currentMessage()
    assert "candidate" not in window.statusBar().currentMessage()
    window.close()
    app.processEvents()


def test_saving_without_an_expectation_says_nothing_can_reach_proof(tmp_path):
    _write_config(tmp_path, {"modules": {"cspt_audit": {}}})
    app, window = _window(tmp_path)
    window._load_settings_form()
    assert "nothing on this screen can reach PROOF" in \
        window.cspt_expect_label.text()
    assert window.cspt_expect_label.property("tone") == "warn"

    window.cspt_enabled_check.setChecked(True)
    assert window._save_cspt_plan() is True
    message = window.statusBar().currentMessage()
    assert "CSPT plan saved" in message
    assert "an escape stays a candidate" in message
    window.close()
    app.processEvents()


def test_saving_with_no_inject_point_is_refused(tmp_path, monkeypatch):
    _write_config(tmp_path, {"modules": {"cspt_audit": {}}})
    app, window = _window(tmp_path)
    window._load_settings_form()
    dialogs = []
    monkeypatch.setattr(QMessageBox, "warning", staticmethod(
        lambda *a, **k: dialogs.append(a[2])))
    for check in window.cspt_point_checks.values():
        check.setChecked(False)
    assert window._save_cspt_plan() is False
    assert dialogs and "silently falls back" in str(dialogs[0])
    saved = yaml.safe_load((tmp_path / "config.yaml").read_text())
    # Nothing was written: a refused save must not leave a half plan behind.
    assert saved["modules"]["cspt_audit"] == {}
    window.close()
    app.processEvents()


def test_toggling_the_probe_checkbox_updates_the_proof_state(tmp_path):
    _write_config(tmp_path, {"modules": {"cspt_audit": {"impact_probe": {
        "enabled": True, "expect": {"type": "regex", "pattern": "(x)"},
        "equals": "x"}}}})
    app, window = _window(tmp_path)
    window._load_settings_form()
    assert window.cspt_expect_label.property("tone") == "ok"
    window.cspt_probe_check.setChecked(False)
    assert "off — an altered path stays a candidate" in \
        window.cspt_expect_label.text()
    assert window.cspt_expect_label.property("tone") == "warn"
    window.close()
    app.processEvents()


def test_run_requires_the_gate_then_the_browser_then_confirmation(
        tmp_path, monkeypatch):
    _write_config(tmp_path, {"modules": {"cspt_audit": {}}})
    app, window = _window(tmp_path)
    window._load_settings_form()

    warnings = []
    monkeypatch.setattr(QMessageBox, "warning", staticmethod(
        lambda *a, **k: warnings.append(a[2])))
    window._run_cspt_pass()
    assert warnings and "enabled is off" in str(warnings[0])

    # Gate on, but the module drives a real browser that is not here.
    window.cspt_enabled_check.setChecked(True)
    warnings.clear()
    monkeypatch.setattr(cspt_screen_module, "_browser_driver_present",
                        lambda: False)
    window._run_cspt_pass()
    assert warnings and "Playwright is not installed" in str(warnings[0])

    asked = []
    monkeypatch.setattr(cspt_screen_module, "_browser_driver_present", lambda: True)

    def fake_question(*_args, **_kwargs):
        asked.append(1)
        return QMessageBox.StandardButton.Yes

    started = []
    monkeypatch.setattr(QMessageBox, "question", staticmethod(fake_question))
    monkeypatch.setattr(window, "start_scan", lambda: started.append(1))
    window._run_cspt_pass()
    assert asked == [1]
    assert started == [1]
    assert window.module_combo.currentData() == "cspt_audit"
    assert window.screen_stack.currentIndex() == MainWindow._screen_index("run")
    # The plan the dialog described is the plan on disk.
    saved = yaml.safe_load((tmp_path / "config.yaml").read_text())
    assert saved["modules"]["cspt_audit"]["enabled"] is True
    window.close()
    app.processEvents()


def test_unreadable_cspt_payload_is_reported_not_silent(tmp_path):
    state, _report_id, impact_id = _cspt_state(tmp_path)
    state.save()
    app, window = _window(tmp_path)
    window.load_results()
    victim = next(
        item for item in window.current_evidence["items"]
        if item.get("type") == "cspt_report")
    path = window._assessment_dir() / victim["path"]
    path.write_text("{not json", encoding="utf-8")

    window.load_results()
    assert window.cspt_points_value.text() == "0"
    assert window.cspt_proofs_value.text() == "0"
    assert "unreadable" in window.statusBar().currentMessage()
    # The orphan replay still shows: a proof whose report could not be read
    # is exactly what the operator needs to see, not something to drop.
    assert window.cspt_impacts_table.rowCount() == 1
    window.cspt_impacts_table.setCurrentCell(0, 0)
    detail = window.cspt_detail_body.toPlainText()
    assert "/api/xhr/admin/secrets" in detail
    assert "Impact replay" in detail
    window.close()
    app.processEvents()


def test_cspt_screen_with_no_run_data_stays_quiet(tmp_path):
    state = StateManager(str(tmp_path / "reports" / "example.com"))
    state.complete_module("seed")
    state.save()
    app, window = _window(tmp_path)
    window.load_results()

    assert window.cspt_points_value.text() == "0"
    assert window.cspt_run_label.text() == "no cspt run loaded"
    assert window.cspt_detail_body.toPlainText() == ""
    assert not window.cspt_open_evidence_button.isEnabled()
    assert not window.cspt_copy_url_button.isEnabled()
    assert window.cspt_gap_note.text() == \
        "nothing left untested by the last run"
    window.close()
    app.processEvents()


def test_a_quiet_cspt_view_leaves_the_status_bar_to_the_screen_with_a_problem(tmp_path):
    """The status bar is one shared line: a screen with nothing wrong must not
    write to it, or it overwrites the notice another screen just raised."""
    state = StateManager(str(tmp_path / "reports" / "example.com"))
    state.add_evidence("idor_differ", "matrix_report",
                       "https://api.example.test",
                       {"schema_version": 1, "cells": [], "checks": {},
                        "canaries": []})
    state.complete_module("idor_differ")
    state.save()
    app, window = _window(tmp_path)
    window.load_results()
    victim = next(item for item in window.current_evidence["items"]
                  if item.get("type") == "matrix_report")
    (window._assessment_dir() / victim["path"]).write_text(
        "{not json", encoding="utf-8")

    window.load_results()
    assert "matrix payload(s) unreadable" in window.statusBar().currentMessage()
    assert window.cspt_run_label.text() == "no cspt run loaded"
    window.close()
    app.processEvents()


def test_theme_covers_the_cspt_screen():
    qss = (Path(__file__).resolve().parent.parent / "gui"
           / "theme.qss").read_text(encoding="utf-8")
    for selector in ("#screenCspt", "#csptStrip", "#csptCaption",
                     "#csptState[state=\"ok\"]", "#csptTool",
                     "#csptLegend", "#csptWarning", "#csptResults",
                     "#csptViews", "#csptProofState", "#csptDetail",
                     "#csptDetailTitle", "#csptDetailBody",
                     "#csptSplitter"):
        assert selector in qss, f"missing QSS selector {selector}"
