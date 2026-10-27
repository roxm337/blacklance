"""Tests for the I5 ORM / filter leak screen in the desktop GUI."""

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


ITEMS = "https://shop.example.test/api/items"
ORDERS = "https://shop.example.test/api/orders"
INVOICES = "https://shop.example.test/api/invoices"
SEED = "ofabc123"

REPORT = {
    "schema_version": 1, "run_token": SEED,
    "surfaces": [
        # Driven, and one filter value returned another identity's rows.
        {"url": ITEMS, "param": "filter[owner_id]", "vector": "inclusion",
         "source": "configured", "method": "GET"},
        # Driven against every value, nothing cross-identity came back.
        {"url": ITEMS, "param": "include", "vector": "inclusion",
         "source": "collection", "method": "GET"},
        # The probe budget ran out here: named by the engine as untested.
        {"url": ORDERS, "param": "fields", "vector": "field",
         "source": "traffic", "method": "GET"},
        # After the budget ran out the run returned, so this surface has no
        # record of its own at all — it must not read as clean.
        {"url": INVOICES, "param": "q", "vector": "inclusion",
         "source": "collection", "method": "GET"},
    ],
    "probes": [
        {"surface": ITEMS, "param": "filter[owner_id]", "identity": "user_b",
         "state": "candidate", "row_delta": 4, "attributed_markers": 2,
         "note": "real records only — values are never stored"},
    ],
    "observations": [
        {"surface": ITEMS, "param": "include", "vector": "inclusion",
         "source": "collection", "identity": "user_b", "values_tried": 3,
         "state": "no_signal"},
    ],
    "canaries": [
        # Full protocol, seed read back by the forbidden identity, cleaned up.
        {"name": "seeded_owner_filter", "created_by": "user_a",
         "read_by": "user_b", "mut_id": "MUT-0001", "proven": True,
         "observed": SEED, "direct_read_status": 403, "seed_intact": True,
         "baseline_contains": False, "absent_contains": False,
         "owner_positive": True, "cleanup_status": "verified",
         "param": "filter[owner_id]"},
        # Same protocol, seed stayed private: a real negative.
        {"name": "seeded_scope_probe", "created_by": "user_a",
         "read_by": "user_b", "mut_id": "MUT-0002", "proven": False,
         "observed": None, "direct_read_status": 404, "seed_intact": True,
         "baseline_contains": False, "absent_contains": False,
         "owner_positive": True, "cleanup_status": "verified", "param": "q"},
        # No leak, but the record this pass created is not verifiably gone.
        {"name": "seeded_unverified", "created_by": "user_a",
         "read_by": "user_b", "mut_id": "MUT-0003", "proven": False,
         "observed": None, "direct_read_status": 403, "seed_intact": True,
         "baseline_contains": False, "absent_contains": False,
         "owner_positive": True, "cleanup_status": "failed",
         "param": "include"},
        # Direct read was allowed: that is the IDOR lane, not a filter leak,
        # and the run stopped before any cleanup could be verified.
        {"name": "seeded_direct_open", "created_by": "user_a",
         "read_by": "user_b", "mut_id": "MUT-0004", "proven": False,
         "direct_read_status": 200, "seed_intact": True,
         "reason": "prerequisite failed (direct read 200)", "param": "q"},
    ],
    "state_counts": {"observation": 1, "candidate": 1, "proof": 1},
    "untested": [
        {"surface": ORDERS,
         "reason": "max_payloads reached after 0 of 3 value(s)"},
    ],
}


def _orm_state(tmp_path):
    state = StateManager(str(tmp_path / "reports" / "example.com"))
    state.add_evidence("orm_filter_audit", "orm_filter_report",
                       "https://shop.example.test", REPORT)
    canary_id = state.add_evidence(
        "orm_filter_audit", "orm_filter_canary", "https://shop.example.test",
        {"name": "seeded_owner_filter", "param": "filter[owner_id]",
         "mut_id": "MUT-0001", "cleanup_status": "verified"})
    state.add_finding(
        title="ORM filter leak candidate: inclusion 'filter[owner_id]' on "
              f"{ITEMS} [aaaaaaaa]",
        severity="MEDIUM", confidence="FIRM", category="ORM Filter Leak",
        description="Rows attributable to another identity.",
        evidence=[f"surface:{ITEMS}", "param:filter[owner_id]",
                  "vector:inclusion"],
        verified=False)
    state.add_finding(
        title=f"ORM filter leak: 'filter[owner_id]' on {ITEMS} [bbbbbbbb]",
        severity="HIGH", confidence="CONFIRMED", category="ORM Filter Leak",
        description="A seeded record came back through the filter.",
        evidence=["canary:seeded_owner_filter", canary_id], verified=True)
    state.complete_module("orm_filter_audit")
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


def _loaded(tmp_path):
    _orm_state(tmp_path)
    app, window = _window(tmp_path)
    window.load_results()
    return app, window


def _select_canary(window, name: str):
    rows = getattr(window, "_orm_canary_rows_cache")
    index = next(i for i, row in enumerate(rows) if row["name"] == name)
    window.orm_canaries_table.setCurrentCell(index, 0)
    return rows[index]


def test_orm_screen_is_registered_on_the_rail():
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    keys = [entry[0] for entry in window.SCREEN_DEFS]
    # The full rail list is asserted once, in test_gui_app.py.
    assert "orm" in keys
    index = MainWindow._screen_index("orm")
    assert index == keys.index("orm")
    assert window.screen_stack.count() == len(keys)
    assert window.screen_stack.widget(index).objectName() == "screenOrm"
    assert [window.orm_tabs.tabText(i)
            for i in range(window.orm_tabs.count())] == \
        ["Filter surfaces", "Cross-identity rows", "Seeded canaries", "Coverage"]
    # Inserting a screen must not move what the graph auto-refresh watches.
    assert window.SCREEN_GRAPH_INDEX == keys.index("graph")
    window.close()
    app.processEvents()


def test_tenth_screen_gets_ctrl_0_not_a_duplicate_shortcut():
    assert MainWindow._screen_shortcut(0) == "Ctrl+1"
    assert MainWindow._screen_shortcut(8) == "Ctrl+9"
    assert MainWindow._screen_shortcut(9) == "Ctrl+0"
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    assert len(window.SCREEN_DEFS) == 10
    assert "Ctrl+0" in window.nav_buttons[9].toolTip()
    window.close()
    app.processEvents()


def test_orm_screen_counts_what_was_driven_not_what_was_planned(tmp_path):
    app, window = _loaded(tmp_path)

    assert window.orm_planned_value.text() == "4"
    # Only two surfaces ever received a filter value.
    assert window.orm_probed_value.text() == "2"
    assert window.orm_candidates_value.text() == "1"
    assert window.orm_proofs_value.text() == "1"
    # Unverified cleanup plus the canary that stopped before cleanup.
    assert window.orm_cleanup_value.text() == "2"
    assert window.orm_gap_value.text() == "2"
    tiers = [window.orm_surfaces_table.item(row, 0).text()
             for row in range(window.orm_surfaces_table.rowCount())]
    assert tiers == ["CANDIDATE", "HEALTHY", "-", "-"]
    assert "1 seeded-record proof" in window.orm_run_label.text()
    window.close()
    app.processEvents()


def test_candidate_rows_stay_candidates_and_ask_for_a_seed(tmp_path):
    app, window = _loaded(tmp_path)

    window.orm_surfaces_table.setCurrentCell(0, 0)
    detail = window.orm_detail_body.toPlainText()
    assert detail.startswith("CANDIDATE")
    assert "values never stored" in detail
    assert "Still needed" in detail
    assert "seeded canary on the same parameter" in detail
    assert window.orm_open_finding_button.isEnabled()
    # The cross-identity tab is the same probe, seen from the finding side.
    assert window.orm_candidates_table.rowCount() == 1
    assert window.orm_candidates_table.item(0, 4).text() == "2"
    window.orm_candidates_table.setCurrentCell(0, 0)
    assert "seeded canary on the same parameter" in \
        window.orm_detail_body.toPlainText()
    window.close()
    app.processEvents()


def test_proven_canary_shows_every_lane_and_asks_for_nothing_more(tmp_path):
    app, window = _loaded(tmp_path)

    row = _select_canary(window, "seeded_owner_filter")
    detail = window.orm_detail_body.toPlainText()
    assert row["tier"] == "PROOF"
    assert "denied, which is what a filter leak needs" in detail
    assert "baseline clean, absent clean" in detail
    assert "Owner positive yes" in detail
    assert "Cleanup verified" in detail
    assert "MUT-0001" in detail
    assert "Still needed" not in detail
    # The run token is not a seed value: the engine never stores the seed.
    assert detail.count(SEED) == 1
    assert "Seed value" not in detail
    # The evidence button opens the canary artifact, not the whole report.
    assert row["evidence_path"].endswith(".json")
    assert row["evidence_path"] != getattr(
        window, "_orm_surface_rows_cache")[0]["evidence_path"]
    assert window.orm_open_finding_button.isEnabled()
    window.close()
    app.processEvents()


def test_clean_negative_canary_is_healthy_not_a_proof(tmp_path):
    app, window = _loaded(tmp_path)

    row = _select_canary(window, "seeded_scope_probe")
    assert row["tier"] == "HEALTHY"
    assert "Seed read back through filter no" in \
        window.orm_detail_body.toPlainText()
    assert window.orm_proofs_value.text() == "1"
    window.close()
    app.processEvents()


def test_unverified_cleanup_is_an_observation_with_a_ledger_todo(tmp_path):
    app, window = _loaded(tmp_path)

    row = _select_canary(window, "seeded_unverified")
    detail = window.orm_detail_body.toPlainText()
    assert row["tier"] == "OBSERVATION"
    assert "Cleanup failed" in detail
    assert "verify cleanup on the mutation ledger" in detail
    window.close()
    app.processEvents()


def test_allowed_direct_read_is_called_the_direct_read_lane(tmp_path):
    app, window = _loaded(tmp_path)

    row = _select_canary(window, "seeded_direct_open")
    detail = window.orm_detail_body.toPlainText()
    assert row["tier"] == "OBSERVATION"
    assert "200 — allowed, so this is the direct-read lane" in detail
    assert "prerequisite failed (direct read 200)" in detail
    # The table cell must agree: a 200 is not a denial, and printing it as
    # one would hide the exact prerequisite that failed.
    rows = getattr(window, "_orm_canary_rows_cache")
    index = rows.index(row)
    assert window.orm_canaries_table.item(index, 4).text() == "ALLOWED 200"
    window.close()
    app.processEvents()


def test_non_denial_direct_reads_are_never_labelled_as_access():
    short = MainWindow._orm_direct_short
    assert short(0) == "no response"
    assert short(500) == "not denied 500"
    assert short(403) == "denied 403"
    assert short(None) == "not run"
    assert "never ran" in MainWindow._orm_direct_text({"direct_status": 0})
    assert MainWindow._orm_control_text(
        {"baseline": None, "absent": False}) == "baseline not run, absent clean"


def test_surface_cells_show_the_path_and_keep_the_full_url_on_hover(tmp_path):
    app, window = _loaded(tmp_path)

    table = window.orm_surfaces_table
    assert table.item(0, 1).text() == "/api/items"
    assert table.item(0, 1).toolTip() == ITEMS
    # Every row shares one origin, so full URLs would elide identically.
    assert window.orm_candidates_table.item(0, 0).text() == "/api/items"
    assert window.orm_candidates_table.item(0, 0).toolTip() == ITEMS
    window.close()
    app.processEvents()


def test_undriven_surface_is_not_a_negative_result(tmp_path):
    app, window = _loaded(tmp_path)

    rows = getattr(window, "_orm_surface_rows_cache")
    index = next(i for i, row in enumerate(rows) if row["url"] == INVOICES)
    window.orm_surfaces_table.setCurrentCell(index, 0)
    detail = window.orm_detail_body.toPlainText()
    assert rows[index]["tier"] == ""
    assert window.orm_detail_title.text().startswith("NOT DRIVEN")
    assert "planned but no filter value reached it" in detail
    assert "Still needed" in detail
    # The engine named the other one; both belong on the coverage tab.
    other = next(i for i, row in enumerate(rows) if row["url"] == ORDERS)
    assert "max_payloads reached" in rows[other]["outcome"]
    window.close()
    app.processEvents()


def test_coverage_tab_names_the_lane_and_the_surface_it_never_reached(tmp_path):
    app, window = _loaded(tmp_path)

    table = window.orm_gap_table
    assert table.rowCount() == 2
    surfaces = {table.item(row, 0).text() for row in range(table.rowCount())}
    assert surfaces == {"/api/orders", "/api/invoices"}
    # The cell is the path; the full URL is still one hover away.
    assert table.item(0, 0).toolTip() in (ORDERS, INVOICES)
    assert "2 surface(s) or lane(s) the last run never drove" in \
        window.orm_gap_note.text()
    assert window.orm_gap_note.property("tone") == "warn"
    window.orm_gap_table.setCurrentCell(0, 0)
    assert "NOT TESTED" in window.orm_detail_body.toPlainText()
    window.close()
    app.processEvents()


def test_orm_filter_narrows_rows(tmp_path):
    app, window = _loaded(tmp_path)

    window.orm_tier_combo.setCurrentText("HEALTHY")
    assert window.orm_surfaces_table.rowCount() == 1
    assert window.orm_surfaces_table.item(0, 2).text() == "include"
    window._reset_orm_filter()
    window.orm_search.setText("invoices")
    assert window.orm_surfaces_table.rowCount() == 1
    assert window.orm_count_label.text() == "1 of 4"
    window._reset_orm_filter()
    assert window.orm_surfaces_table.rowCount() == 4
    window.close()
    app.processEvents()


def test_detail_panes_put_one_field_per_line(tmp_path):
    app, window = _loaded(tmp_path)

    _select_canary(window, "seeded_owner_filter")
    lines = [line.strip()
             for line in window.orm_detail_body.toPlainText().splitlines()
             if line.strip()]
    assert lines[0].startswith("PROOF —")
    assert "Module orm_filter_audit" in lines
    assert any(line.startswith("Filter parameter filter[owner_id]")
               for line in lines)
    assert any(line.startswith("Finding FINDING-") for line in lines)
    window.close()
    app.processEvents()


def test_open_in_triage_routes_to_the_orm_finding(tmp_path):
    app, window = _loaded(tmp_path)

    _select_canary(window, "seeded_owner_filter")
    window._open_orm_finding()
    assert window.screen_stack.currentIndex() == MainWindow._screen_index("triage")
    assert window.finding_search.text()
    window.close()
    app.processEvents()


def _plan_config():
    return {
        "modules": {
            "orm_filter_audit": {
                "enabled": False, "max_surfaces": 8, "max_payloads": 12,
                "max_seconds": 300, "vector_values": ["user_b", "42"],
                "filter_names": ["q", "owner_id"],
                "surfaces": [{"url": ITEMS,
                              "filter_params": ["filter[owner_id]"]}],
                "source_rules": {"enabled": False,
                                 "root": "/tmp/framework-src"},
                "canary": {
                    "enabled": True, "max": 2,
                    "owner_identity": "user_a",
                    "forbidden_identity": "user_b",
                    "probes": [{"name": "seeded_owner_filter",
                                "param": "filter[owner_id]",
                                "url_template": ITEMS}],
                    "record": {"url_template": ITEMS, "method": "POST",
                               "body_template": '{"owner":"{run}"}',
                               "extract_id": {"type": "jsonpath",
                                              "path": "id"}},
                    "read": {"direct_url_template": ITEMS + "/{id}",
                             "extract": {"type": "jsonpath",
                                         "path": "owner"}},
                    "cleanup": {"enabled": True, "method": "DELETE"},
                },
            },
        },
        "auth": {"identities": [{"name": "user_a"}, {"name": "user_b"}]},
    }


def test_orm_plan_saves_and_keeps_nested_yaml(tmp_path):
    _write_config(tmp_path, _plan_config())
    app, window = _window(tmp_path)
    window._load_settings_form()

    assert window.orm_enabled_check.isChecked() is False
    assert window.orm_canary_check.isChecked() is True
    assert window.orm_owner_combo.currentText() == "user_a"
    assert window.orm_forbidden_combo.currentText() == "user_b"
    assert window._orm_proof_ready() is True
    assert "user_b, 42" in window.orm_values_label.text()
    assert window.orm_spec_label.property("tone") == "ok"
    assert "Owner user_a → reader user_b" in window.orm_identity_label.text()

    window.orm_enabled_check.setChecked(True)
    assert window.orm_state_label.text() == "module enabled"
    window.orm_max_surfaces_spin.setValue(5)
    window.orm_canary_max_spin.setValue(1)
    window.orm_source_check.setChecked(True)
    assert window._save_orm_plan() is True

    saved = yaml.safe_load((tmp_path / "config.yaml").read_text())
    section = saved["modules"]["orm_filter_audit"]
    assert section["enabled"] is True
    assert section["max_surfaces"] == 5
    assert section["source_rules"]["enabled"] is True
    # The panel reports on these; it must never rewrite them.
    assert section["source_rules"]["root"] == "/tmp/framework-src"
    assert section["vector_values"] == ["user_b", "42"]
    assert section["surfaces"][0]["filter_params"] == ["filter[owner_id]"]
    canary = section["canary"]
    assert canary["max"] == 1
    assert canary["record"]["body_template"] == '{"owner":"{run}"}'
    assert canary["read"]["direct_url_template"] == ITEMS + "/{id}"
    assert canary["cleanup"] == {"enabled": True, "method": "DELETE"}
    assert canary["probes"][0]["name"] == "seeded_owner_filter"
    message = window.statusBar().currentMessage()
    assert "ORM plan saved" in message
    assert "no proof path" not in message
    window.close()
    app.processEvents()


def test_saving_without_a_proof_path_names_the_missing_pieces(tmp_path):
    _write_config(tmp_path, {"modules": {"orm_filter_audit": {}}})
    app, window = _window(tmp_path)
    window._load_settings_form()

    assert window._orm_proof_ready() is False
    # The engine runs canaries only when the key is present and true.
    assert window.orm_canary_check.isChecked() is False
    assert "vector_values is" in window.orm_values_label.text()
    window.orm_enabled_check.setChecked(True)
    assert window.orm_state_label.text() == "module enabled · candidates only"
    assert window._save_orm_plan() is True
    message = window.statusBar().currentMessage()
    assert "ORM plan saved" in message
    assert "no proof path yet" in message
    assert "canary.record.url_template" in message
    assert "two different identities" in message
    window.close()
    app.processEvents()


def test_turning_the_canary_off_also_turns_off_the_proof_claim(tmp_path):
    _write_config(tmp_path, _plan_config())
    app, window = _window(tmp_path)
    window._load_settings_form()
    assert window._orm_proof_ready() is True
    window.orm_canary_check.setChecked(False)
    assert window._orm_proof_ready() is False
    assert "canary.enabled is off" in window._orm_missing_proof_steps()
    window.close()
    app.processEvents()


def test_same_identity_both_ways_is_refused(tmp_path, monkeypatch):
    payload = _plan_config()
    payload["modules"]["orm_filter_audit"]["canary"]["forbidden_identity"] = \
        "user_a"
    _write_config(tmp_path, payload)
    app, window = _window(tmp_path)
    window._load_settings_form()

    warnings = []
    monkeypatch.setattr(QMessageBox, "warning", staticmethod(
        lambda *a, **k: warnings.append(a[2])))
    assert window.orm_owner_combo.currentText() == \
        window.orm_forbidden_combo.currentText() == "user_a"
    assert window._save_orm_plan() is False
    assert warnings and "proves nothing" in str(warnings[0])
    saved = yaml.safe_load((tmp_path / "config.yaml").read_text())
    # A refused save must not leave a half plan behind.
    assert saved == payload
    window.close()
    app.processEvents()


def test_run_requires_the_gate_then_values_then_confirmation(
        tmp_path, monkeypatch):
    _write_config(tmp_path, {"modules": {"orm_filter_audit": {}}})
    app, window = _window(tmp_path)
    window._load_settings_form()

    warnings = []
    monkeypatch.setattr(QMessageBox, "warning", staticmethod(
        lambda *a, **k: warnings.append(a[2])))
    window._run_orm_pass()
    assert warnings and "enabled is off" in str(warnings[0])

    window.orm_enabled_check.setChecked(True)
    warnings.clear()
    window._run_orm_pass()
    assert warnings and "vector_values is empty" in str(warnings[0])

    payload = _plan_config()
    payload["modules"]["orm_filter_audit"]["enabled"] = True
    _write_config(tmp_path, payload)
    asked = []

    def fake_question(*args, **_kwargs):
        asked.append(args[2])
        return QMessageBox.StandardButton.Yes

    started = []
    monkeypatch.setattr(QMessageBox, "question", staticmethod(fake_question))
    monkeypatch.setattr(window, "start_scan", lambda: started.append(1))
    window._run_orm_pass()
    assert len(asked) == 1
    # The dialog has to say this pass writes, unlike the read-only screens.
    assert "CREATES a record on the target" in asked[0]
    assert started == [1]
    assert window.module_combo.currentData() == "orm_filter_audit"
    assert window.screen_stack.currentIndex() == MainWindow._screen_index("run")
    saved = yaml.safe_load((tmp_path / "config.yaml").read_text())
    assert saved["modules"]["orm_filter_audit"]["enabled"] is True
    window.close()
    app.processEvents()


def test_a_configured_canary_is_a_real_run_even_without_filter_values(
        tmp_path, monkeypatch):
    payload = _plan_config()
    payload["modules"]["orm_filter_audit"]["enabled"] = True
    payload["modules"]["orm_filter_audit"]["vector_values"] = []
    _write_config(tmp_path, payload)
    app, window = _window(tmp_path)
    window._load_settings_form()

    asked = []

    def fake_question(*args, **_kwargs):
        asked.append(args[2])
        return QMessageBox.StandardButton.Yes

    started = []
    monkeypatch.setattr(QMessageBox, "question", staticmethod(fake_question))
    monkeypatch.setattr(window, "start_scan", lambda: started.append(1))
    window._run_orm_pass()
    # The candidate lane has nothing to send, but the proof lane is complete.
    assert len(asked) == 1
    assert "only the canary runs" in asked[0]
    assert started == [1]
    window.close()
    app.processEvents()


def test_unreadable_orm_payload_is_reported_not_silent(tmp_path):
    _orm_state(tmp_path)
    app, window = _window(tmp_path)
    window.load_results()
    victim = next(item for item in window.current_evidence["items"]
                  if item.get("type") == "orm_filter_report")
    (window._assessment_dir() / victim["path"]).write_text(
        "{not json", encoding="utf-8")

    window.load_results()
    assert window.orm_planned_value.text() == "0"
    assert window.orm_proofs_value.text() == "0"
    assert "unreadable" in window.statusBar().currentMessage()
    window.close()
    app.processEvents()


def test_orm_screen_with_no_run_data_stays_quiet(tmp_path):
    state = StateManager(str(tmp_path / "reports" / "example.com"))
    state.complete_module("seed")
    state.save()
    app, window = _window(tmp_path)
    window.load_results()

    assert window.orm_planned_value.text() == "0"
    assert window.orm_probed_value.text() == "0"
    assert window.orm_run_label.text() == "no orm run loaded"
    assert window.orm_detail_body.toPlainText() == ""
    assert not window.orm_open_evidence_button.isEnabled()
    assert not window.orm_open_finding_button.isEnabled()
    assert window.orm_gap_note.text() == \
        "no ORM run loaded — nothing has been tested yet"
    window.close()
    app.processEvents()


def test_theme_covers_the_orm_screen():
    qss = (Path(__file__).resolve().parent.parent / "gui"
           / "theme.qss").read_text(encoding="utf-8")
    for selector in ("#screenOrm", "#ormStrip", "#ormCaption",
                     "#ormState[state=\"ok\"]", "#ormTool", "#ormLegend",
                     "#ormWarning", "#ormResults", "#ormViews",
                     "#ormProofState", "#ormIdentity", "#ormDetail",
                     "#ormDetailTitle", "#ormDetailBody", "#ormSplitter"):
        assert selector in qss, f"missing QSS selector {selector}"
