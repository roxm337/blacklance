"""Tests for the I2 stateful API schema screen in the desktop GUI."""

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


SPEC_URL = "https://api.example.test/openapi.json"


def _schema_state(tmp_path):
    """A finished I2 pass: one replay-confirmed candidate, one observation."""
    state = StateManager(str(tmp_path / "reports" / "example.com"))
    state.add_asset(
        "api_endpoint", f"api_endpoint:{SPEC_URL}", SPEC_URL,
        attrs={"type": "openapi", "endpoint_count": 12})
    state.add_asset(
        "api_workflow_scan", "api_workflow_scan:example.com", "example.com",
        attrs={"tool": "schemathesis", "version": "4.32.5",
               "backend": "local", "schemas_tested": 1,
               "schemas_discovered": 1, "proven": 1})
    candidate_evidence = state.add_evidence(
        "api_workflows", "schemathesis", SPEC_URL,
        {"fingerprint": "c" * 16, "check": "not_a_server_error",
         "method": "POST", "path": "/api/orders", "count": 7,
         "min_interactions": 3, "seed": 4211,
         "curl_repro": "curl -X POST https://api.example.test/api/orders",
         "tier": "candidate", "proven_impact": False})
    observation_evidence = state.add_evidence(
        "api_workflows", "schemathesis", SPEC_URL,
        {"fingerprint": "o" * 16, "check": "response_schema_conformance",
         "method": "GET", "path": "/api/products", "count": 2,
         "min_interactions": 1, "seed": 91,
         "curl_repro": "curl -X GET https://api.example.test/api/products",
         "tier": "observation", "proven_impact": False})
    impact_evidence = state.add_evidence(
        "api_workflows", "schemathesis_impact", SPEC_URL,
        {"fingerprint": "c" * 16, "probe_url": "https://api.example.test/api/orders/7",
         "observed": -3, "expectation": {"op": "lt", "value": 0}})
    state.add_finding(
        title="API state violation: POST /api/orders [cccccccc]",
        severity="HIGH", confidence="CONFIRMED",
        category="API State Machine Violation",
        description="Proven by replay plus impact re-read.",
        evidence=[f"fingerprint:{'c' * 16}", f"evidence:{impact_evidence}"],
        verified=True)
    state.add_finding(
        title="API schema violations: " + SPEC_URL,
        severity="LOW", confidence="TENTATIVE",
        category="API Schema Conformance",
        description="Conformance drift.",
        evidence=[observation_evidence],
        verified=False)
    state.complete_module("api_workflows")
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


def test_schema_screen_is_registered_on_the_rail():
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    keys = [entry[0] for entry in window.SCREEN_DEFS]
    # The full rail list is asserted once, in test_gui_app.py; here
    # only the invariants matter, so adding a screen is not a second edit.
    assert "schema" in keys
    index = MainWindow._screen_index("schema")
    assert index == keys.index("schema")
    assert window.screen_stack.count() == len(keys)
    assert window.screen_stack.widget(index).objectName() == "screenSchema"
    # Inserting a screen must not move what the graph auto-refresh watches.
    assert window.SCREEN_GRAPH_INDEX == keys.index("graph")
    window.show_screen(index)
    assert window.screen_stack.currentIndex() == index
    assert window.nav_buttons[index].isChecked()
    window.close()
    app.processEvents()


def test_schema_screen_grades_groups_by_tier(tmp_path):
    _schema_state(tmp_path)
    app, window = _window(tmp_path)
    window.load_results()

    assert window.schema_discovered_value.text() == "1"
    assert window.schema_tested_value.text() == "1"
    assert window.schema_groups_value.text() == "2"
    assert window.schema_observations_value.text() == "1"
    # The impact re-read promotes the candidate off the CANDIDATE rung: a
    # group leaves that bucket only once this framework proved it.
    assert window.schema_candidates_value.text() == "0"
    assert window.schema_proofs_value.text() == "1"
    assert window.schema_tool_label.text().startswith("schemathesis 4.32.5")

    tiers = [window.schema_groups_table.item(row, 0).text()
             for row in range(window.schema_groups_table.rowCount())]
    assert tiers == ["PROOF", "OBSERVATION"]
    assert window.schema_groups_table.item(0, 2).text() == "/api/orders"
    assert window.schema_groups_table.item(0, 4).text() == "7"
    assert window.schema_count_label.text() == "2 of 2"

    detail = window.schema_detail_body.toPlainText()
    assert "not_a_server_error" in detail
    assert "/api/orders/7" in detail
    assert "-3" in detail
    assert "cccccccccccccccc" in detail
    assert window.schema_copy_curl_button.isEnabled()
    assert window.schema_open_finding_button.isEnabled()
    assert "PROOF" in window.schema_detail_title.text()
    window.close()
    app.processEvents()


def test_schema_detail_states_no_proof_without_a_replay(tmp_path):
    state = StateManager(str(tmp_path / "reports" / "example.com"))
    state.add_evidence(
        "api_workflows", "schemathesis", SPEC_URL,
        {"fingerprint": "a" * 16, "check": "not_a_server_error",
         "method": "GET", "path": "/api/things", "count": 3,
         "min_interactions": None, "seed": None, "curl_repro": "",
         "tier": "candidate", "proven_impact": False})
    state.save()
    app, window = _window(tmp_path)
    window.load_results()

    assert window.schema_candidates_value.text() == "1"
    assert window.schema_proofs_value.text() == "0"
    assert window.schema_groups_table.item(0, 0).text() == "CANDIDATE"
    detail = window.schema_detail_body.toPlainText()
    # The fuzzer's own word is never a proof, and the screen says so.
    assert "Impact re-read none" in detail
    assert not window.schema_copy_curl_button.isEnabled()
    window.close()
    app.processEvents()


def test_proof_detail_reads_the_expectation_in_words(tmp_path):
    _schema_state(tmp_path)
    app, window = _window(tmp_path)
    window.load_results()

    window.schema_groups_table.setCurrentCell(0, 0)
    detail = window.schema_detail_body.toPlainText()
    assert window.schema_groups_table.item(0, 0).text() == "PROOF"
    # The operator sees the claim the probe tested, not a serialized dict.
    assert "expected < 0" in detail
    assert "'op'" not in detail
    window.close()
    app.processEvents()


def test_legacy_group_without_route_falls_back_to_curl(tmp_path):
    state = StateManager(str(tmp_path / "reports" / "example.com"))
    state.add_evidence(
        "api_workflows", "schemathesis", SPEC_URL,
        {"fingerprint": "b" * 16, "check": "status_code_conformance",
         "count": 1, "min_interactions": 2, "seed": 7,
         "curl_repro": "curl -X DELETE https://api.example.test/api/cart",
         "tier": "candidate", "proven_impact": False})
    state.save()
    app, window = _window(tmp_path)
    window.load_results()

    assert window.schema_groups_table.item(0, 1).text() == "DELETE"
    assert window.schema_groups_table.item(0, 2).text() == \
        "https://api.example.test/api/cart"
    window.close()
    app.processEvents()


def test_corrupt_evidence_payload_is_reported_not_silent(tmp_path):
    state = _schema_state(tmp_path)
    victim = next(
        path for path in sorted(state.evidence_dir.glob("*.json"))
        if "response_schema_conformance" in path.read_text(encoding="utf-8"))
    victim.write_text("{not json at all", encoding="utf-8")
    app, window = _window(tmp_path)
    window.load_results()

    assert window.schema_groups_value.text() == "1"
    assert window.schema_proofs_value.text() == "1"
    message = window.statusBar().currentMessage()
    assert "unreadable" in message
    assert "partial" in message.lower()
    window.close()
    app.processEvents()


def test_schema_filter_narrows_rows(tmp_path):
    _schema_state(tmp_path)
    app, window = _window(tmp_path)
    window.load_results()

    window.schema_tier_combo.setCurrentText("OBSERVATION")
    assert window.schema_groups_table.rowCount() == 1
    assert window.schema_count_label.text() == "1 of 2"
    window.schema_search.setText("orders")
    assert window.schema_groups_table.rowCount() == 0
    window._reset_schema_filter()
    assert window.schema_groups_table.rowCount() == 2
    window.close()
    app.processEvents()


def test_schema_plan_saves_and_reloads_config(tmp_path, monkeypatch):
    app, window = _window(tmp_path)
    (tmp_path / "config.yaml").write_text(
        yaml.safe_dump({"modules": {"api_workflows": {"enabled": False}}}),
        encoding="utf-8")
    window._load_settings_form()
    assert window.schema_enabled_check.isChecked() is False

    window.schema_enabled_check.setChecked(True)
    window.schema_stateful_combo.setCurrentText("none")
    window.schema_max_cases_spin.setValue(25)
    window.schema_max_seconds_spin.setValue(60)
    window.schema_identities_input.setText("owner, viewer")
    window._schema_method_checks["POST"].setChecked(True)
    window._schema_method_checks["DELETE"].setChecked(True)
    window._save_schema_plan()

    saved = yaml.safe_load(
        (tmp_path / "config.yaml").read_text(encoding="utf-8"))
    plan = saved["modules"]["api_workflows"]
    assert plan["enabled"] is True
    assert plan["stateful"] == "none"
    assert plan["max_cases"] == 25
    assert plan["max_seconds"] == 60
    assert plan["identities"] == ["owner", "viewer"]
    assert plan["methods"] == ["POST", "DELETE"]

    # Nested operator specs the panel only reports on must survive a save.
    plan["impact_probe"] = {"url_template": "/api/orders/{order_id}",
                            "extract": {"type": "jsonpath", "path": "total"},
                            "expect": {"op": "lt", "value": 0}}
    plan["cleanup"] = {"method": "DELETE",
                      "url_template": "/api/orders/{order_id}"}
    (tmp_path / "config.yaml").write_text(yaml.safe_dump(saved),
                                          encoding="utf-8")
    window._load_settings_form()
    assert window.schema_max_cases_spin.value() == 25
    assert window.schema_identities_input.text() == "owner, viewer"
    assert window._schema_method_checks["POST"].isChecked()
    assert "Impact probe: ON" in window.schema_impact_probe_label.text()
    assert "Cleanup: DELETE" in window.schema_cleanup_label.text()
    window._save_schema_plan()
    reloaded = yaml.safe_load(
        (tmp_path / "config.yaml").read_text(encoding="utf-8"))
    assert reloaded["modules"]["api_workflows"]["impact_probe"] == \
        plan["impact_probe"]
    assert reloaded["modules"]["api_workflows"]["cleanup"] == plan["cleanup"]
    window.close()
    app.processEvents()


def test_enabling_without_impact_probe_is_warned(tmp_path):
    app, window = _window(tmp_path)
    (tmp_path / "config.yaml").write_text(
        yaml.safe_dump({"modules": {"api_workflows": {"enabled": False}}}),
        encoding="utf-8")
    window._load_settings_form()
    window.schema_enabled_check.setChecked(True)
    window._save_schema_plan()

    assert "no candidate can be promoted" in \
        window.schema_impact_probe_label.text()
    assert "impact probe" in window.statusBar().currentMessage().lower()
    assert window.schema_state_label.text() == "module enabled"
    window.close()
    app.processEvents()


def test_probe_tool_labels_unavailable_and_supported(tmp_path, monkeypatch):
    import gui.screens.schema as schema_screen
    app, window = _window(tmp_path)
    monkeypatch.setattr(
        schema_screen, "schemathesis_available",
        lambda: {"available": False,
                 "reason": "schemathesis 3.19.0 < 3.21.0 (auth config unsupported)"})
    window._probe_schema_tool()
    assert "unavailable" in window.schema_tool_label.text()
    assert "3.21.0" in window.schema_tool_label.text()

    monkeypatch.setattr(
        schema_screen, "schemathesis_available",
        lambda: {"available": True, "version": "4.32.5", "backend": "local"})
    window._probe_schema_tool()
    assert window.schema_tool_label.text() == \
        "schemathesis 4.32.5 · local backend"
    window.close()
    app.processEvents()


def test_run_schema_pass_is_confirmed_then_single_modules(tmp_path, monkeypatch):
    app, window = _window(tmp_path)
    (tmp_path / "config.yaml").write_text("{}", encoding="utf-8")
    # The window was built before this isolated config existed, so it may hold
    # the developer's local api_workflows.enabled switch. Load the empty file.
    window._load_settings_form()
    # Modal boxes block the offscreen test run: answers come from the tap.
    monkeypatch.setattr(QMessageBox, "information",
                        staticmethod(lambda *a, **k: QMessageBox.Ok))
    monkeypatch.setattr(QMessageBox, "warning",
                        staticmethod(lambda *a, **k: QMessageBox.Ok))
    calls = {}
    monkeypatch.setattr(QMessageBox, "question",
                        staticmethod(lambda *a, **k: QMessageBox.No))
    monkeypatch.setattr(window, "start_scan",
                        lambda: calls.setdefault("started", True))
    window._run_schema_pass()
    assert "started" not in calls

    monkeypatch.setattr(QMessageBox, "question",
                        staticmethod(lambda *a, **k: QMessageBox.Yes))
    started = []
    monkeypatch.setattr(window, "start_scan", lambda: started.append(True))
    window._save_schema_plan = lambda: calls.setdefault("saved", True)
    window._run_schema_pass()
    assert calls.get("saved") is True
    assert started == []  # plan was saved disabled: the module would skip
    assert window.mode_combo.currentText() != "Single module"

    window.schema_enabled_check.setChecked(True)
    window._run_schema_pass()
    assert window.mode_combo.currentText() == "Single module"
    assert window.module_combo.currentData() == "api_workflows"
    assert started == [True]
    assert window.screen_stack.currentIndex() == \
        MainWindow._screen_index("run")
    window.close()
    app.processEvents()


def test_copy_curl_puts_repro_on_the_clipboard(tmp_path):
    _schema_state(tmp_path)
    app, window = _window(tmp_path)
    window.load_results()
    window.schema_groups_table.selectRow(0)
    window._copy_schema_curl()
    assert QApplication.clipboard().text() == \
        "curl -X POST https://api.example.test/api/orders"
    window.close()
    app.processEvents()


def test_open_in_triage_routes_to_the_finding(tmp_path):
    _schema_state(tmp_path)
    app, window = _window(tmp_path)
    window.load_results()
    window.schema_groups_table.selectRow(0)
    window._open_schema_finding()
    assert window.screen_stack.currentIndex() == \
        MainWindow._screen_index("triage")
    assert window.finding_search.text()
    window.close()
    app.processEvents()


def test_schema_screen_with_no_i2_data_stays_quiet(tmp_path):
    state = StateManager(str(tmp_path / "reports" / "example.com"))
    state.add_asset("domain", "domain:example.com", "example.com")
    state.save()
    app, window = _window(tmp_path)
    window.load_results()

    assert window.schema_groups_table.rowCount() == 0
    assert window.schema_groups_value.text() == "0"
    assert window.schema_discovered_value.text() == "0"
    assert window.schema_tested_value.text() == "-"
    assert window.schema_count_label.text() == "0 of 0"
    assert window.schema_detail_title.text() == "No failure group selected"
    window.close()
    app.processEvents()


def test_theme_covers_the_schema_screen():
    text = (Path(__file__).resolve().parent.parent / "gui" /
            "theme.qss").read_text(encoding="utf-8")
    for needle in (
        "#screenSchema",
        "#schemaStrip",
        "#schemaState[state=\"ok\"]",
        "#schemaTool[tone=\"warn\"]",
        "#schemaProofState[tone=\"warn\"]",
        "#schemaDetailBody",
        "#schemaSplitter::handle",
        "#schemaLegend",
    ):
        assert needle in text, f"missing schema theme selector: {needle}"
