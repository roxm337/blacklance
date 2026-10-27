"""Tests for the I3 authorization matrix screen in the desktop GUI."""

import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("QTWEBENGINE_DISABLE_SANDBOX", "1")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml
from PySide6.QtWidgets import QApplication, QMessageBox

from gui.app import MainWindow
from state.manager import StateManager


CELLS = [
    # A cross-identity read that carried the victim's own markers.
    {"subject": "user_a", "tenant": "t1", "operation": "read",
     "object": {"template": "/api/basket/{id}", "ref": "7", "owner": "user_b"},
     "field": "", "status": 200, "outcome": "leak",
     "attribution": {"markers": ["user_b"]}, "owner_baseline": {"status": 200},
     "diff_fields": [], "evidence_sha256": "a" * 64},
    # The same object correctly denied — coverage, not a finding.
    {"subject": "user_b", "tenant": "t1", "operation": "read",
     "object": {"template": "/api/basket/{id}", "ref": "7", "owner": "user_b"},
     "field": "", "status": 403, "outcome": "denied",
     "attribution": {}, "owner_baseline": None, "diff_fields": [],
     "evidence_sha256": "b" * 64},
    # A login page wearing a 200: proves nothing.
    {"subject": "anonymous", "tenant": "", "operation": "read",
     "object": {"template": "/api/invoices/{id}", "ref": "9", "owner": ""},
     "field": "", "status": 200, "outcome": "ambiguous",
     "attribution": {}, "owner_baseline": None, "diff_fields": [],
     "evidence_sha256": "c" * 64},
]

CANARIES = [
    {"name": "invoice-read", "created_by": "user_b", "read_by": "user_a",
     "observed": "osint-canary-x", "expected": "denied", "proven": True,
     "denied": False, "seed_intact": True, "mut_id": "MUT-1",
     "cleanup_status": "verified"},
    {"name": "basket-read", "created_by": "user_b", "read_by": "user_a",
     "observed": None, "expected": "denied", "proven": False, "denied": True,
     "seed_intact": True, "mut_id": "MUT-2", "cleanup_status": "failed"},
]

CHECKS = {
    "sharing": {"specs": 2, "ok": 1,
                "regressions": [{"template": "/api/orders/{id}", "ref": "3",
                                 "shapes": {}, "ok": False}]},
    "freshness": {"drift": [], "verified": True},
    "revocation": {"identity": "user_a", "status": "proven",
                   "after_logout": "denied", "reestablished": "allowed"},
}


def _authz_state(tmp_path):
    """One finished matrix pass: a leak candidate, a canary proof, noise."""
    state = StateManager(str(tmp_path / "reports" / "example.com"))
    evidence_id = state.add_evidence(
        "idor_differ", "matrix_report", "https://api.example.test",
        {"schema_version": 1, "cells": CELLS, "checks": CHECKS,
         "canaries": CANARIES})
    state.add_finding(
        title="Authorization matrix leak: user_a read /api/basket/{id} "
              "[aaaaaaaa]",
        severity="HIGH", confidence="FIRM",
        category="Authorization Matrix",
        description="user_a read user_b's basket.",
        evidence=[f"cell_sha256:{'a' * 64}"],
        verified=False)
    state.add_finding(
        title="Canary proof: invoice-read",
        severity="CRITICAL", confidence="CONFIRMED",
        category="Authorization Matrix",
        description="user_a read the seeded invoice note.",
        evidence=["canary:invoice-read", f"evidence:{evidence_id}"],
        verified=True)
    state.complete_module("idor_differ")
    state.save()
    return state


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


def test_authz_screen_is_registered_on_the_rail():
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    keys = [entry[0] for entry in window.SCREEN_DEFS]
    # The full rail list is asserted once, in test_gui_app.py; here only the
    # invariants matter, so adding a screen is not a second edit.
    assert "authz" in keys
    index = MainWindow._screen_index("authz")
    assert index == keys.index("authz")
    assert window.screen_stack.count() == len(keys)
    assert window.screen_stack.widget(index).objectName() == "screenAuthz"
    assert [window.authz_tabs.tabText(i)
            for i in range(window.authz_tabs.count())] == \
        ["Cells", "Matrix", "Canaries"]
    window.close()
    app.processEvents()


def test_authz_screen_grades_cells_and_canaries(tmp_path):
    _authz_state(tmp_path)
    app, window = _window(tmp_path)
    window.load_results()

    assert window.authz_cells_value.text() == "3"
    assert window.authz_leaks_value.text() == "1"
    # The ambiguous cell plus the canary whose cleanup never verified.
    assert window.authz_ambiguous_value.text() == "2"
    # The failed cleanup is the row the operator must not miss.
    assert window.authz_cleanup_value.text() == "1"
    assert window.authz_subjects_value.text() == "3"
    # One proven canary; the denied one proves the control, not a leak.
    assert window.authz_proofs_value.text() == "1"
    tiers = [window.authz_cells_table.item(row, 0).text()
             for row in range(window.authz_cells_table.rowCount())]
    assert tiers == ["CANDIDATE", "OBSERVATION", "HEALTHY"]
    assert window.authz_cells_table.rowCount() == 3
    window.close()
    app.processEvents()


def test_authz_detail_asks_for_a_canary_before_calling_it_a_leak(tmp_path):
    _authz_state(tmp_path)
    app, window = _window(tmp_path)
    window.load_results()

    window.authz_cells_table.setCurrentCell(0, 0)
    detail = window.authz_detail_body.toPlainText()
    assert "user_a" in detail and "/api/basket/{id}" in detail
    assert "Still needed" in detail
    assert window.authz_open_finding_button.isEnabled()
    window.close()
    app.processEvents()


def test_denied_canary_is_not_presented_as_a_proof(tmp_path):
    _authz_state(tmp_path)
    app, window = _window(tmp_path)
    window.load_results()

    rows = getattr(window, "_authz_canary_rows")
    index = next(i for i, row in enumerate(rows)
                 if row["name"] == "basket-read")
    window.authz_canaries_table.setCurrentCell(index, 0)
    detail = window.authz_detail_body.toPlainText()
    assert "Not a proof" in detail
    assert "proves the control works" in detail
    # A denied read is only healthy if the seeded object left the target.
    assert "Cleanup not verified" in detail
    assert rows[index]["tier"] == "OBSERVATION"
    window.close()
    app.processEvents()


def test_authz_matrix_grid_maps_a_cell_back_to_its_row(tmp_path):
    _authz_state(tmp_path)
    app, window = _window(tmp_path)
    window.load_results()

    assert window.authz_grid_table.rowCount() == 3  # user_a, user_b, anonymous
    assert window.authz_grid_table.columnCount() == 2
    # The row headers are the reading identities: hide them and the grid is
    # just coloured squares nobody can attribute.
    assert not window.authz_grid_table.verticalHeader().isHidden()
    assert [window.authz_grid_table.verticalHeaderItem(row).text()
            for row in range(window.authz_grid_table.rowCount())] == \
        ["anonymous", "user_a", "user_b"]
    target = next(key for key, row in window._authz_grid_lookup.items()
                  if row["outcome"] == "leak")
    window.authz_grid_table.cellClicked.emit(*target)
    detail = window.authz_detail_body.toPlainText()
    assert "CANDIDATE" in detail and "leak" in detail
    window.close()
    app.processEvents()


def test_authz_session_checks_panel_reports_the_engine(tmp_path):
    _authz_state(tmp_path)
    app, window = _window(tmp_path)
    window.load_results()

    assert "1/2" in window.authz_check_sharing.text()
    assert "1 regression" in window.authz_check_sharing.text()
    assert window.authz_check_freshness.text() == "Freshness: clean"
    assert "user_a: proven" in window.authz_check_revocation.text()
    window.close()
    app.processEvents()


def test_authz_filter_narrows_rows(tmp_path):
    _authz_state(tmp_path)
    app, window = _window(tmp_path)
    window.load_results()

    window.authz_tier_combo.setCurrentText("HEALTHY")
    assert window.authz_cells_table.rowCount() == 1
    assert window.authz_cells_table.item(0, 6).text() == "denied"
    window.authz_search.setText("invoice")
    assert window.authz_cells_table.rowCount() == 0
    window._reset_authz_filter()
    assert window.authz_cells_table.rowCount() == 3
    window.close()
    app.processEvents()


def test_authz_plan_saves_and_keeps_nested_specs(tmp_path):
    _authz_state(tmp_path)
    _write_config(tmp_path, {
        "modules": {
            "idor_differ": {"matrix": {
                "enabled": False, "max_cells": 200,
                "sharing": [{"template": "/api/orders/{id}", "ref": "3"}],
                "canaries": {"max": 3, "specs": [{"name": "invoice-read"}]},
            }},
            "graphql_audit": {"matrix": {"enabled": False, "max_queries": 10,
                                         "field_probes": [{"query": "{ a }"}]}},
        },
        "auth": {"identities": [
            {"name": "user_a", "logout_url": "/logout"},
            {"name": "user_b"},
        ]},
    })
    app, window = _window(tmp_path)
    window._load_settings_form()
    assert window.authz_identities_label.text().startswith("Identities: user_a")
    assert "the only path to PROOF" in window.authz_specs_label.text()

    window.authz_gate_checks["idor_differ"].setChecked(True)
    window.authz_max_cells_spin.setValue(120)
    window.authz_revocation_check.setChecked(False)
    window._save_authz_plan()

    saved = yaml.safe_load((tmp_path / "config.yaml").read_text())
    matrix = saved["modules"]["idor_differ"]["matrix"]
    assert matrix["enabled"] is True
    assert matrix["max_cells"] == 120
    assert matrix["revocation"] == {"enabled": False}
    # The panel reports on these; it must never rewrite them.
    assert matrix["sharing"] == [{"template": "/api/orders/{id}", "ref": "3"}]
    assert matrix["canaries"]["specs"] == [{"name": "invoice-read"}]
    assert saved["modules"]["graphql_audit"]["matrix"]["field_probes"] == \
        [{"query": "{ a }"}]
    assert "Matrix plan saved" in window.statusBar().currentMessage()
    window.close()
    app.processEvents()


def test_enabling_a_gate_without_canary_specs_says_so(tmp_path):
    _write_config(tmp_path, {"modules": {"idor_differ": {"matrix": {}}}})
    app, window = _window(tmp_path)
    window._load_settings_form()
    assert "nothing on this screen can reach PROOF" in \
        window.authz_specs_label.text()

    window.authz_gate_checks["bfla_audit"].setChecked(True)
    window._save_authz_plan()
    message = window.statusBar().currentMessage()
    assert "Matrix plan saved" in message
    assert "no canary specs" in message
    window.close()
    app.processEvents()


def test_run_matrix_requires_the_gate_then_confirms(tmp_path, monkeypatch):
    _write_config(tmp_path, {"modules": {"idor_differ": {"matrix": {}}}})
    app, window = _window(tmp_path)
    window._load_settings_form()

    warnings = []
    monkeypatch.setattr(QMessageBox, "warning",
                        staticmethod(lambda *a, **k: warnings.append(a[2])))
    window._run_authz_module("idor_differ")
    assert warnings and "Gate Off" in str(warnings[0]) or "gate" in str(
        warnings[0]).lower()

    asked = []

    def fake_question(*_args, **_kwargs):
        asked.append(1)
        return QMessageBox.StandardButton.Yes

    started = []
    monkeypatch.setattr(QMessageBox, "question", staticmethod(fake_question))
    monkeypatch.setattr(window, "start_scan", lambda: started.append(1))
    window.authz_gate_checks["idor_differ"].setChecked(True)
    window._run_authz_module("idor_differ")
    assert asked == [1]
    assert started == [1]
    assert window.module_combo.currentData() == "idor_differ"
    assert window.screen_stack.currentIndex() == \
        MainWindow._screen_index("run")
    window.close()
    app.processEvents()


def test_open_in_triage_routes_to_the_matrix_finding(tmp_path):
    _authz_state(tmp_path)
    app, window = _window(tmp_path)
    window.load_results()

    window.authz_cells_table.setCurrentCell(0, 0)
    window._open_authz_finding()
    assert window.screen_stack.currentIndex() == \
        MainWindow._screen_index("triage")
    assert window.finding_search.text()
    window.close()
    app.processEvents()


def test_unreadable_matrix_payload_is_reported_not_silent(tmp_path):
    state = _authz_state(tmp_path)
    state.save()
    app, window = _window(tmp_path)
    window.load_results()
    victim = next(
        item for item in window.current_evidence["items"]
        if item.get("type") == "matrix_report")
    path = window._assessment_dir() / victim["path"]
    path.write_text("{not json", encoding="utf-8")

    window.load_results()
    assert window.authz_cells_value.text() == "0"
    assert "unreadable" in window.statusBar().currentMessage()
    window.close()
    app.processEvents()


def test_authz_screen_with_no_matrix_data_stays_quiet(tmp_path):
    state = StateManager(str(tmp_path / "reports" / "example.com"))
    state.complete_module("seed")
    state.save()
    app, window = _window(tmp_path)
    window.load_results()

    assert window.authz_cells_value.text() == "0"
    assert window.authz_run_label.text() == "no matrix run loaded"
    assert window.authz_detail_body.toPlainText() == ""
    assert not window.authz_open_evidence_button.isEnabled()
    assert window.authz_check_sharing.text() == "Sharing: no specs configured"
    window.close()
    app.processEvents()


def test_theme_covers_the_authz_screen():
    qss = (Path(__file__).resolve().parent.parent / "gui"
           / "theme.qss").read_text(encoding="utf-8")
    for selector in ("#screenAuthz", "#authzStrip", "#authzCaption",
                     "#authzState[state=\"ok\"]", "#authzTool",
                     "#authzLegend", "#authzWarning", "#authzResults",
                     "#authzViews", "#authzProofState", "#authzDetail",
                     "#authzDetailTitle", "#authzDetailBody",
                     "#authzSplitter"):
        assert selector in qss, f"missing QSS selector {selector}"
