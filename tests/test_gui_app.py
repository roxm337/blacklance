"""Tests for GUI state loading helpers."""

import json
import os
import sys
import time
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("QTWEBENGINE_DISABLE_SANDBOX", "1")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml
import pytest
from PySide6.QtCore import QItemSelectionModel, QProcess, Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QMessageBox, QTableWidgetItem

from gui.app import MainWindow, build_scan_args
from modules import get_all_module_ids
from state.manager import StateManager
from core.assessments import AssessmentStore


def test_gui_loads_advanced_state_tabs(tmp_path):
    app = QApplication.instance() or QApplication([])
    state = StateManager(str(tmp_path / "reports" / "example.com"))
    state.add_asset("domain", "domain:example.com", "example.com")
    state.add_asset("screenshot_target", "screenshot:https://example.com", "https://example.com")
    evidence_id = state.add_evidence("test_module", "json", "subject", {"ok": True})
    state.add_finding(
        title="Example Finding",
        severity="HIGH",
        confidence="FIRM",
        category="Test",
        description="Test finding.",
        evidence_refs=[evidence_id],
        risk_score=80,
    )
    run_id = state.begin_module_run("test_module", "low", 4)
    state.finish_module_run(run_id, "completed")
    state.save()
    submission_dir = state.output_dir / "submissions"
    submission_dir.mkdir()
    (submission_dir / "INDEX.md").write_text("# Index")
    (submission_dir / "FINDING-0001_open-redirect.md").write_text("# Report")
    (state.output_dir / "example.com_summary.json").write_text(
        '{"risk":{"max_score":80,"critical_high":1}}'
    )

    window = MainWindow()
    window.output_dir = tmp_path / "reports"
    window.output_input.setText(str(window.output_dir))
    window.target_input.setText("example.com")
    window.refresh_graph = lambda: None
    window.load_results()

    assert window.assets_value.text() == "2"
    assert window.findings_value.text() == "1"
    assert window.evidence_value.text() == "1"
    assert window.max_risk_value.text() == "80"
    assert window.evidence_table.rowCount() == 1
    assert window.submissions_table.rowCount() == 1
    assert window.modules_table.rowCount() > 0

    window.close()
    app.processEvents()


def test_gui_saves_llm_settings(tmp_path):
    app = QApplication.instance() or QApplication([])
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "llm:\n"
        "  model: \"\"\n"
        "  api_key: \"\"\n"
        "  temperature: 0.1\n"
        "  max_tokens: 2000\n"
        "api_keys: {}\n"
    )

    window = MainWindow()
    window.config_path = config_path
    window._load_settings_form()
    window.llm_model_combo.setCurrentText("ollama/llama3.1")
    window.llm_api_key_input.setText("")
    window.llm_temperature_spin.setValue(0.2)
    window.llm_max_tokens_spin.setValue(4096)
    window._save_settings_form()

    saved = config_path.read_text()
    assert "ollama/llama3.1" in saved
    assert "temperature: 0.2" in saved
    assert "max_tokens: 4096" in saved

    window.close()
    app.processEvents()


def test_gui_saves_scanner_settings(tmp_path):
    app = QApplication.instance() or QApplication([])
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "target: {}\n"
        "llm: {}\n"
        "api_keys: {}\n"
        "auth: {}\n"
        "xss: {}\n"
        "nuclei: {}\n"
        "oob: {}\n"
    )

    window = MainWindow()
    window.config_path = config_path
    window._load_settings_form()
    window.auth_bearer_input.setText("token-123")
    window.auth_cookie_input.setText("sid=abc")
    window.auth_headers_input.setPlainText("X-Test: yes\nBad header")
    window.auth_probe_backoff_spin.setValue(12)
    window.xss_browser_confirm_check.setChecked(True)
    window.xss_max_points_spin.setValue(123)
    window.xss_dalfox_timeout_spin.setValue(456)
    window.xss_dalfox_blind_oob_check.setChecked(True)
    window.xss_dalfox_rate_spin.setValue(10)
    window.kr_enabled_check.setChecked(False)
    window.kr_wordlist_input.setText("apiroutes-260227")
    window.kr_max_routes_spin.setValue(500)
    window.semgrep_enabled_check.setChecked(True)
    window.semgrep_rules_input.setText("rules/semgrep")
    window.ssrf_enabled_check.setChecked(True)
    window.ssrf_max_points_spin.setValue(9)
    window.logic_enabled_check.setChecked(True)
    window.logic_max_probes_spin.setValue(15)
    window.crawl_enabled_check.setChecked(True)
    window.crawl_max_pages_spin.setValue(12)
    window.crawl_depth_spin.setValue(2)
    window.crawl_max_identities_spin.setValue(3)
    window.kr_delay_spin.setValue(1000)
    window.kr_connections_spin.setValue(1)
    window.idor_endpoints_text.setPlainText("https://api.example.com/orders/{id}")
    window.idor_max_probes_spin.setValue(7)
    window.idor_object_probe_check.setChecked(False)
    window.idor_test_anonymous_check.setChecked(True)
    window.idor_write_methods_text.setText("PATCH")
    window.idor_allow_destructive_check.setChecked(False)
    window.idor_id_probing_check.setChecked(True)
    window.mass_enabled_check.setChecked(True)
    window.mass_endpoints_text.setPlainText("https://api.example.com/users/me")
    window.mass_write_endpoint_input.setText("/api/users/me")
    window.mass_method_combo.setCurrentText("PUT")
    window.mass_fields_text.setText("role, is_admin")
    window.mass_probe_type_combo.setCurrentText("string")
    window.proto_enabled_check.setChecked(False)
    window.proto_endpoints_text.setPlainText("https://api.example.com/api/profile")
    window.smuggling_enabled_check.setChecked(False)
    window.smuggling_max_targets_spin.setValue(3)
    window.redirect_params_text.setText("next, target")
    window.redirect_endpoints_text.setPlainText("https://example.com/login")
    window.redirect_max_targets_spin.setValue(11)
    window.cms_max_targets_spin.setValue(2)
    window.content_enabled_check.setChecked(False)
    window.cors_endpoints_text.setPlainText("https://api.example.com/data")
    window.cors_max_endpoints_spin.setValue(9)
    window.auth_test_password_check.setChecked(True)
    window.auth_test_register_check.setChecked(True)
    window.nuclei_full_cve_check.setChecked(False)
    window.nuclei_update_check.setChecked(True)
    window.nuclei_max_age_spin.setValue(14)
    window.nuclei_batch_seconds_spin.setValue(200)
    window.nuclei_max_seconds_spin.setValue(900)
    window.crawl_wait_ms_spin.setValue(2500)
    window.logic_endpoints_text.setPlainText("https://api.example.com/cart")
    window.idor_probe_radius_spin.setValue(5)
    window.idor_probe_max_spin.setValue(30)
    window.idor_refs_spin.setValue(9)
    window.idor_fetches_spin.setValue(18)
    window.idor_total_fetches_spin.setValue(120)
    window.idor_misses_spin.setValue(4)
    window.idor_collection_paths_text.setPlainText("/api/v1/orders")
    window.idor_api_prefixes_text.setText("/api, /v2")
    window.idor_account_endpoint_text.setText("https://api.example.com/me")
    window.idor_resources_text.setPlainText("invoices")
    window.proto_reflect_input.setText("https://api.example.com/reflect")
    window.proto_methods_text.setText("POST")
    window.proto_payloads_text.setPlainText("__proto__")
    window.misconfig_timeout_spin.setValue(7)
    window.misconfig_concurrency_spin.setValue(9)
    window.misconfig_max_paths_spin.setValue(100)
    window.misconfig_max_empty_spin.setValue(40)
    window.misconfig_progress_spin.setValue(20)
    window.ssti_max_points_spin.setValue(25)
    window.nosql_max_points_spin.setValue(22)
    window.dom_max_pages_spin.setValue(15)
    window.param_seed_check.setChecked(False)
    window.param_seed_targets_spin.setValue(7)
    window.param_seed_params_text.setText("debug, trace")
    window.fast_scan_paths_input.setPlainText("/.env\n/.git/config")
    window.fast_scan_timeout_spin.setValue(3)
    window.fast_scan_concurrency_spin.setValue(6)
    window.fast_scan_max_paths_spin.setValue(12)
    window.oob_callback_domain_input.setText("oob.example.test")
    window.oob_poll_timeout_spin.setValue(44)
    window._save_settings_form()

    saved = config_path.read_text()
    assert "bearer_token: token-123" in saved
    assert "cookie: sid=abc" in saved
    assert "X-Test: 'yes'" in saved or "X-Test: yes" in saved
    assert "max_points: 123" in saved
    assert "dalfox_timeout: 456" in saved
    assert "dalfox_blind_oob: true" in saved
    assert "dalfox_rate_limit: 10" in saved
    assert "kiterunner:" in saved
    assert "max_routes: 500" in saved
    assert "delay_ms: 1000" in saved
    assert "connections: 1" in saved
    assert "semgrep:" in saved
    assert "ssrf_scan:" in saved
    assert "max_points: 9" in saved
    assert "business_logic:" in saved
    assert "max_probes: 15" in saved
    assert "browser:" in saved
    assert "max_targets: 12" in saved
    assert "depth: 2" in saved
    assert "max_identities: 3" in saved
    assert "max_probes_per_template: 7" in saved
    assert "test_anonymous: true" in saved
    assert "allow_destructive: false" in saved
    assert "mass_assignment:" in saved
    assert "write_endpoint: /api/users/me" in saved
    assert "probe_type: string" in saved
    assert "prototype_pollution:" in saved
    assert "http_smuggling:" in saved
    assert "open_redirect:" in saved
    assert "cms_deep_scan:" in saved
    assert "content_discovery:" in saved
    assert "cors_audit:" in saved
    assert "max_endpoints: 9" in saved
    assert "auth_audit:" in saved
    assert "test_password_change: true" in saved
    assert "test_registration_oracle: true" in saved
    assert "full_cve_on_confirmed_apex: false" in saved
    assert "update_templates: true" in saved
    assert "max_age_days: 14" in saved
    assert "batch_seconds: 200" in saved
    assert "max_seconds: 900" in saved
    assert "wait_ms: 2500" in saved
    assert "https://api.example.com/cart" in saved
    assert "radius: 5" in saved
    assert "max_refs: 9" in saved
    assert "max_fetches: 18" in saved
    assert "max_total_fetches: 120" in saved
    assert "stop_after_misses: 4" in saved
    assert "/api/v1/orders" in saved
    assert "https://api.example.com/me" in saved
    assert "invoices" in saved
    assert "https://api.example.com/reflect" in saved
    assert "misconfig_probes:" in saved
    assert "max_consecutive_empty: 40" in saved
    assert "progress_every: 20" in saved
    assert "ssti_scan:" in saved
    assert "nosql_scan:" in saved
    assert "dom_xss_scan:" in saved
    assert "max_pages: 15" in saved
    assert "seed_when_empty: false" in saved
    assert "seed_targets: 7" in saved
    assert "/.env" in saved
    assert "/.git/config" in saved
    assert "timeout: 3" in saved
    assert "concurrency: 6" in saved
    assert "max_paths: 12" in saved
    assert "callback_domain: oob.example.test" in saved
    assert "poll_timeout: 44" in saved

    # And back: reload must restore the safety-critical switches as set,
    # not as their defaults.
    window._load_settings_form()
    assert window.mass_enabled_check.isChecked()
    assert window.mass_method_combo.currentText() == "PUT"
    assert window.idor_max_probes_spin.value() == 7
    assert window.idor_test_anonymous_check.isChecked()
    assert not window.idor_object_probe_check.isChecked()
    assert window.idor_id_probing_check.isChecked()
    assert not window.proto_enabled_check.isChecked()
    assert not window.smuggling_enabled_check.isChecked()
    assert window.redirect_max_targets_spin.value() == 11
    assert window.cms_max_targets_spin.value() == 2
    assert not window.content_enabled_check.isChecked()
    assert window.cors_max_endpoints_spin.value() == 9
    assert window.auth_test_password_check.isChecked()
    assert window.auth_test_register_check.isChecked()
    assert window.kr_delay_spin.value() == 1000
    assert window.ssrf_max_points_spin.value() == 9
    assert window.nuclei_batch_seconds_spin.value() == 200
    assert window.nuclei_max_seconds_spin.value() == 900
    assert window.crawl_wait_ms_spin.value() == 2500
    assert window.idor_probe_radius_spin.value() == 5
    assert window.idor_probe_max_spin.value() == 30
    assert window.idor_refs_spin.value() == 9
    assert window.idor_misses_spin.value() == 4
    assert window.proto_reflect_input.text() == "https://api.example.com/reflect"
    assert window.misconfig_max_paths_spin.value() == 100
    assert window.ssti_max_points_spin.value() == 25
    assert window.nosql_max_points_spin.value() == 22
    assert window.dom_max_pages_spin.value() == 15
    assert not window.param_seed_check.isChecked()
    assert window.param_seed_targets_spin.value() == 7

    window.close()
    app.processEvents()


def test_gui_saves_toolchain_and_oob_settings(tmp_path):
    app = QApplication.instance() or QApplication([])
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "tools: {}\n"
        "oob: {}\n"
        "modules:\n"
        "  sqli_scan: {}\n"
    )

    window = MainWindow()
    window.config_path = config_path
    window._load_settings_form()
    assert window.tools_backend_combo.currentText() == "local"
    assert window.oob_mode_combo.currentData() == ""
    assert window.oob_enabled_check.isChecked()
    assert window.sqli_oast_check.isChecked()

    window.tools_backend_combo.setCurrentText("docker")
    window.tools_image_input.setText("osint-tools:test")
    window.oob_mode_combo.setCurrentIndex(window.oob_mode_combo.findData("public"))
    window.oob_enabled_check.setChecked(False)
    window.sqli_oast_check.setChecked(False)
    window._save_settings_form()

    saved = yaml.safe_load(config_path.read_text())
    assert saved["tools"] == {"backend": "docker", "image": "osint-tools:test"}
    assert saved["oob"]["mode"] == "public"
    assert saved["oob"]["enabled"] is False
    assert saved["modules"]["sqli_scan"]["oast"] is False

    # Reload reads everything back, including the image default fallback.
    window._load_settings_form()
    assert window.tools_backend_combo.currentText() == "docker"
    assert window.tools_image_input.text() == "osint-tools:test"
    assert window.oob_mode_combo.currentData() == "public"
    assert not window.oob_enabled_check.isChecked()
    assert not window.sqli_oast_check.isChecked()

    window.close()
    app.processEvents()


def test_tools_tab_shows_container_toolchain():
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    window._refresh_tools_status()

    tools = {
        window.tools_table.item(row, 0).text(): (
            window.tools_table.item(row, 1).text(),
            window.tools_table.item(row, 2).text(),
        )
        for row in range(window.tools_table.rowCount())
    }
    assert {"nuclei", "httpx"} <= set(tools)
    # Tier-1 / container-only tools are visible with a docker route.
    for name in ("jsluice", "gxss", "uro", "graphql-cop", "interactsh-client"):
        assert name in tools, f"missing container tool row: {name}"
        assert tools[name][1] == "docker"
    assert window.tools_backend_label.text().startswith("Backend: ")

    window.close()
    app.processEvents()


def test_gui_full_url_uses_hostname_output_folder(tmp_path):
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    window.output_dir = tmp_path / "reports"
    window.target_input.setText("https://pentest-ground.com:4280/vulnerabilities/xss_r/?name=test")

    assert window._target_output_name() == "pentest-ground.com"
    assert window._report_path() == tmp_path / "reports" / "pentest-ground.com" / "pentest-ground.com_report.md"

    window.close()
    app.processEvents()


def test_build_scan_args_reaches_cli():
    args = build_scan_args("example.com", "/tmp/out", "/repo/config.yaml")
    assert args[:7] == [
        args[0], "-t", "example.com", "-o", "/tmp/out", "-c", "/repo/config.yaml",
    ]
    assert args[0].endswith("orchestrator.py")
    assert "--active" not in args and "--pentest" not in args

    args = build_scan_args(
        "example.com", "/tmp/out", "/repo/config.yaml",
        mode="LLM", active=True, module="xss_scanner",
    )
    assert "--active" in args
    assert args[args.index("--mode") + 1] == "llm"
    assert args[args.index("--module") + 1] == "xss_scanner"


def _assessment_window(tmp_path, target="localhost:3000"):
    from PySide6.QtCore import QSettings
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    window._settings = QSettings(str(tmp_path / "assessment-gui.ini"), QSettings.IniFormat)
    window.output_dir = tmp_path / "reports"
    window.target_input.setText(target)
    window._target_reload_timer.stop()
    return window, app


@pytest.mark.parametrize("corruption", ["broken", "swapped"])
def test_gui_selection_routes_all_artifacts_and_clears_other_run_data(tmp_path, corruption):
    window, app = _assessment_window(tmp_path)
    store = AssessmentStore(window.output_dir, "localhost:3000")
    first, second = store.create(), store.create()
    state = StateManager(str(first.directory))
    state.complete_module("m")
    state.add_finding("first", "HIGH", "FIRM", "Test", "fixture")
    state.save()
    window._refresh_assessments(preferred=first.id)
    window.load_results()
    assert window.current_findings[0]["title"] == "first"
    assert window._report_path().parent == first.directory
    assert window._triage_path().parent == first.directory
    assert window._attack_graph_path().parent == first.directory
    # A broken newly selected snapshot must not borrow last-good data from first.
    snapshot = second.directory / "state" / "snapshot.json"
    if corruption == "broken":
        snapshot.write_text("{broken")
    else:
        snapshot.write_bytes((first.directory / "state" / "snapshot.json").read_bytes())
    window._refresh_assessments(preferred=second.id)
    window.load_results()
    assert not window.current_findings
    assert not window.current_module
    assert "Corrupt" in window.status_label.text()
    window.target_input.setText("localhost:3001")
    window.load_results()
    assert not window.current_findings
    assert window.assessment_combo.currentData() is None
    window.close()
    app.processEvents()


def test_gui_fresh_resume_and_retest_forward_their_selections(tmp_path, monkeypatch):
    window, app = _assessment_window(tmp_path)
    store = AssessmentStore(window.output_dir, "localhost:3000")
    selected = store.create()
    captured = []
    monkeypatch.setattr(window, "_start_process", lambda args, **kw: captured.append(args))
    monkeypatch.setattr(window, "_confirm_engagement", lambda: True)
    window._refresh_assessments(preferred=selected.id)
    window.start_scan()
    fresh_id = captured[-1][captured[-1].index("--assessment") + 1]
    assert fresh_id != selected.id
    assert captured[-1][captured[-1].index("--run-mode") + 1] == "fresh"
    window._pending_assessment = None
    window._refresh_assessments(preferred=selected.id)
    window.lifecycle_combo.setCurrentText("Resume")
    window.start_scan()
    assert captured[-1][captured[-1].index("--assessment") + 1] == selected.id
    assert captured[-1][captured[-1].index("--run-mode") + 1] == "resume"
    window.lifecycle_combo.setCurrentText("Retest")
    window.start_scan()
    assert captured[-1][captured[-1].index("--from-assessment") + 1] == selected.id
    assert captured[-1][captured[-1].index("--assessment") + 1] != selected.id
    window.close()
    app.processEvents()


def test_gui_automatic_report_resumes_the_just_completed_assessment(tmp_path, monkeypatch):
    window, app = _assessment_window(tmp_path)
    captured = []
    monkeypatch.setattr(window, "_start_process", lambda args, **kw: captured.append((args, kw)))
    monkeypatch.setattr(window, "_confirm_engagement", lambda: True)
    window.start_scan()
    args = captured[-1][0]
    identifier = args[args.index("--assessment") + 1]
    store = AssessmentStore(window.output_dir, "localhost:3000")
    # Simulate the child's published assessment, not a second assessment.
    store.create(assessment_id=identifier)
    window._process_finished(0, None)
    report_args, options = captured[-1]
    assert report_args[report_args.index("--run-mode") + 1] == "resume"
    assert report_args[report_args.index("--assessment") + 1] == identifier
    assert report_args[report_args.index("--module") + 1] == "reporting"
    assert options["report_run"]
    assert len(store.list()) == 1
    window.close()
    app.processEvents()


def test_gui_resume_requires_selection_not_an_implicit_legacy_run(tmp_path, monkeypatch):
    window, app = _assessment_window(tmp_path)
    warnings, started = [], []
    monkeypatch.setattr(QMessageBox, "warning", lambda *args: warnings.append(args))
    monkeypatch.setattr(window, "_start_process", lambda *args, **kw: started.append(args))
    window.lifecycle_combo.setCurrentText("Resume")
    window.start_scan()
    assert warnings and not started
    assert not window.output_dir.exists()
    window.close()
    app.processEvents()


def test_build_scan_args_pentest_flags():
    # execute without pentest must not reach the CLI (nothing to execute).
    args = build_scan_args("e.com", "/o", "/c", pentest=False, execute=True, max_risk="HIGH")
    assert "--execute" not in args and "--max-risk" not in args and "--pentest" not in args

    args = build_scan_args(
        "e.com", "/o", "/c",
        pentest=True, execute=True, max_risk="HIGH",
        max_actions=7, max_chains=3,
    )
    assert args[args.index("--max-risk") + 1] == "HIGH"
    assert args[args.index("--max-actions") + 1] == "7"
    assert args[args.index("--max-chains") + 1] == "3"
    assert "--execute" in args
    assert args.index("--pentest") < args.index("--execute")


def test_engagement_gate_only_gates_high_risk_execution(monkeypatch):
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    window.target_input.setText("example.com")
    window.pentest_check.setChecked(True)
    window.execute_check.setChecked(True)

    calls = []

    def fake_warning(*_args, **_kwargs):
        calls.append(1)
        return QMessageBox.No

    monkeypatch.setattr(QMessageBox, "warning", fake_warning)

    # Low risk: no gate.
    window.risk_combo.setCurrentText("LOW")
    assert window._confirm_engagement() is True
    assert calls == []

    # High risk + execute: gated, and the default answer is "No".
    window.risk_combo.setCurrentText("HIGH")
    assert window._confirm_engagement() is False
    assert len(calls) == 1

    # Pentest without execute: never gated.
    window.execute_check.setChecked(False)
    assert window._confirm_engagement() is True
    assert len(calls) == 1

    window.close()
    app.processEvents()


def _sample_findings():
    return [
        {
            "id": "F-1", "severity": "HIGH", "confidence": "FIRM",
            "risk_score": 90, "title": "SQLi in login", "category": "sqli",
            "description": "login injects", "module_id": "sqli_scanner",
            "verified": True, "asset_keys": ["api.example.com"],
        },
        {
            "id": "F-2", "severity": "LOW", "confidence": "TENTATIVE",
            "risk_score": 20, "title": "Missing header", "category": "headers",
            "description": "no csp", "module_id": "fast_scan",
            "verified": False, "asset_keys": [],
        },
        {
            "id": "F-3", "severity": "MEDIUM", "confidence": "CONFIRMED",
            "risk_score": 55, "title": "Open redirect", "category": "redirect",
            "description": "redirect x", "module_id": "openredirex",
            "verified": True, "asset_keys": ["www.example.com"],
            "priority": "P1",
        },
    ]


def test_findings_filter_sort_and_detail_pane(tmp_path):
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    window.output_dir = tmp_path / "reports"
    window.target_input.setText("example.com")
    window._load_findings(_sample_findings())

    assert window.findings_table.rowCount() == 3
    assert window.finding_count_label.text() == "showing 3 of 3"
    # Default sort: score descending (F-1 = 90 first).
    assert window.findings_table.item(0, 0).text() == "F-1"

    # Re-click the score column to flip to ascending.
    window._sort_findings(3)
    assert window.findings_table.item(0, 0).text() == "F-2"
    assert window._findings_sort == [3, Qt.AscendingOrder]

    # Severity filter reduces rows but not the total.
    window.finding_severity_combo.setCurrentText("HIGH")
    assert window.findings_table.rowCount() == 1
    assert window.finding_count_label.text() == "showing 1 of 3"
    window.finding_severity_combo.setCurrentText("All severities")

    # Search filter.
    window.finding_search.setText("redirect")
    assert window.findings_table.rowCount() == 1
    assert window.findings_table.item(0, 0).text() == "F-3"
    window.finding_search.setText("")

    # Detail pane mirrors the selected row (sort back to score descending
    # first so row 0 is F-1 again).
    window._sort_findings(3)
    window.findings_table.selectRow(0)
    detail = window.finding_detail.toPlainText()
    assert "F-1" in detail
    assert "login injects" in detail

    window.close()
    app.processEvents()


def test_triage_verdict_persists_outside_state(tmp_path):
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    window.output_dir = tmp_path / "reports"
    window.target_input.setText("example.com")
    findings = _sample_findings()
    window._load_findings(findings)

    window._set_finding_verdict(findings[0], "false_positive")

    triage_path = tmp_path / "reports" / "example.com" / "example.com_triage.json"
    assert triage_path.exists()
    data = json.loads(triage_path.read_text())
    assert data["F-1"]["verdict"] == "false_positive"

    # The filter reads verdicts back from disk-backed triage.
    window.finding_triage_combo.setCurrentIndex(3)  # False positive only
    assert window.findings_table.rowCount() == 1
    assert window.findings_table.item(0, 0).text() == "F-1"

    window._set_finding_verdict(findings[0], "")
    window.finding_triage_combo.setCurrentIndex(3)  # False positive only
    assert window.findings_table.rowCount() == 0
    window.finding_triage_combo.setCurrentIndex(0)  # All triage
    assert window.findings_table.rowCount() == 3

    window.close()
    app.processEvents()


def test_incomplete_count_flags_unresolved_timeouts():
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    module = {
        "completed": ["done_mod"],
        "skipped": [{"module_id": "skip_mod"}],
        "blocked": [{"module_id": "blocked_mod"}],
        "runs": [
            {"module_id": "done_mod", "status": "completed"},
            {"module_id": "skip_mod", "status": "skipped"},
            {"module_id": "blocked_mod", "status": "blocked"},
            {"module_id": "timeout_mod", "status": "timeout"},
            # Latest run wins: this module failed once then finished.
            {"module_id": "flaky_mod", "status": "error"},
            {"module_id": "flaky_mod", "status": "completed"},
        ],
    }
    assert window._incomplete_count(module) == 1

    empty = {"completed": [], "runs": []}
    assert window._incomplete_count(empty) == 0

    window.close()
    app.processEvents()


def test_attack_graph_tab_counts_and_probe_plan(tmp_path):
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    window.output_dir = tmp_path / "reports"
    window.target_input.setText("example.com")

    # Empty state first: no artifact on disk yet.
    window._load_attack_graph()
    assert window.attack_graph_summary.text() == "No attack graph loaded"

    target_dir = tmp_path / "reports" / "example.com"
    target_dir.mkdir(parents=True, exist_ok=True)
    graph = {
        "nodes": [
            {"id": "a", "type": "goal"},
            {"id": "b", "type": "url"},
            {"id": "c", "type": "vuln"},
        ],
        "edges": [
            {"source": "a", "target": "b", "type": "extract",
             "attrs": {"proposed": True, "action_id": "http_probe"}},
            {"source": "b", "target": "c", "type": "affected_by", "attrs": {}},
        ],
        "probe_plan": {
            "risk_ceiling": "MEDIUM",
            "surfaces_considered": 145,
            "probes_proposed": 25,
            "capped_at": 25,
            "not_proposed": {
                "no parameter on the surface": 202,
                "already safe": 3,
            },
        },
    }
    (target_dir / "attack_graph.json").write_text(json.dumps(graph))

    window._load_attack_graph()
    assert window.attack_graph_summary.text() == (
        "Attack model: 3 entities · 2 transitions  |  1 established · "
        "0 inferred · 1 proposed · 1 vulnerabilities · 1 objectives"
    )
    assert "MEDIUM" in window.probe_plan_label.text()
    assert "145 surfaces considered" in window.probe_plan_label.text()
    assert "25 probes proposed" in window.probe_plan_label.text()
    assert window.probe_plan_table.rowCount() == 2
    # Reasons sorted by count descending.
    assert window.probe_plan_table.item(0, 0).text() == "no parameter on the surface"
    assert window.probe_plan_table.item(0, 1).data(Qt.UserRole) == 202

    window.close()
    app.processEvents()


def test_identities_settings_round_trip(tmp_path):
    app = QApplication.instance() or QApplication([])
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "target: {}\n"
        "llm: {}\n"
        "api_keys: {}\n"
        "auth:\n"
        "  identities:\n"
        "    - name: alice\n"
        "      bearer_token: tok-alice\n"
        "      cookies:\n"
        "        sid: abc\n"
        "      verify_url: https://example.com/me\n"
        "      role: user\n"
        "      owner_id: '42'\n"
        "xss: {}\n"
        "nuclei: {}\n"
        "oob: {}\n"
    )

    window = MainWindow()
    window.config_path = config_path
    window._load_settings_form()

    assert window.identities_table.rowCount() == 1
    assert window.identities_table.item(0, 0).text() == "alice"
    assert window.identities_table.item(0, 1).text() == "tok-alice"
    assert window.identities_table.item(0, 2).text() == "sid=abc"
    assert window.identities_table.item(0, 3).text() == "https://example.com/me"

    # Rename in place, then add a second identity.
    window.identities_table.setItem(0, 0, QTableWidgetItem("alice2"))
    window._add_identity_row()
    assert window.identities_table.rowCount() == 2
    window.identities_table.setItem(1, 1, QTableWidgetItem("tok-bob"))
    window._save_settings_form()

    saved = yaml.safe_load(config_path.read_text())
    identities = saved["auth"]["identities"]
    assert len(identities) == 2
    assert identities[0]["name"] == "alice2"
    assert identities[0]["bearer_token"] == "tok-alice"
    assert identities[0]["owner_id"] == "42"  # unknown field survives table edits
    assert identities[0]["cookies"] == {"sid": "abc"}
    assert identities[1]["name"] == "identity_2"
    assert identities[1]["bearer_token"] == "tok-bob"

    # Removing a row drops the identity on save.
    window.identities_table.selectRow(0)
    window._remove_identity_rows()
    window._save_settings_form()
    saved = yaml.safe_load(config_path.read_text())
    assert [item["name"] for item in saved["auth"]["identities"]] == ["identity_2"]

    window.close()
    app.processEvents()


def test_runtime_limits_round_trip(tmp_path):
    app = QApplication.instance() or QApplication([])
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "target: {}\n"
        "llm: {}\n"
        "api_keys: {}\n"
        "auth: {}\n"
        "xss: {}\n"
        "nuclei: {}\n"
        "oob: {}\n"
        "module_timeout: 300\n"
        "budget_limits:\n"
        "  max_concurrent_actions: 4\n"
        "  max_llm_calls: 0\n"
    )

    window = MainWindow()
    window.config_path = config_path
    window._load_settings_form()
    assert window.module_timeout_spin.value() == 300
    assert window.budget_requests_spin.value() == 0

    window.module_timeout_spin.setValue(450)
    window.budget_requests_spin.setValue(5000)
    window.budget_wall_clock_spin.setValue(120)
    window.budget_external_commands_spin.setValue(40)
    window._save_settings_form()

    saved = yaml.safe_load(config_path.read_text())
    assert saved["module_timeout"] == 450
    assert saved["budget_limits"]["max_requests"] == 5000
    assert saved["budget_limits"]["max_wall_clock_seconds"] == 120
    assert saved["budget_limits"]["max_external_commands"] == 40
    # Fields the GUI does not expose must survive the round trip.
    assert saved["budget_limits"]["max_concurrent_actions"] == 4

    window.close()
    app.processEvents()


def test_theme_qss_applied_and_dark():
    app = QApplication.instance() or QApplication([])
    qss_path = Path(__file__).resolve().parent.parent / "gui" / "theme.qss"
    assert qss_path.exists()
    qss = qss_path.read_text()
    assert "#0a0f14" in qss  # dark background
    assert "QMenu" in qss  # context menus are styled too

    window = MainWindow()
    applied = window.styleSheet()
    assert "#0a0f14" in applied
    assert "QMenu" in applied
    window.close()
    app.processEvents()


def test_actions_and_tools_tabs_populated():
    app = QApplication.instance() or QApplication([])
    window = MainWindow()

    assert window.actions_table.rowCount() >= 10
    risk_values = {
        window.actions_table.item(row, 1).text()
        for row in range(window.actions_table.rowCount())
    }
    assert {"SAFE", "MEDIUM"} <= risk_values
    # Sorted by risk rank, not alphabetically: SAFE must come before MEDIUM.
    first_risks = [
        window.actions_table.item(row, 1).text()
        for row in range(min(3, window.actions_table.rowCount()))
    ]
    assert first_risks[0] == "SAFE"

    tools = {
        window.tools_table.item(row, 0).text()
        for row in range(window.tools_table.rowCount())
    }
    assert {"nuclei", "httpx"} <= tools

    window.close()
    app.processEvents()


def test_process_error_restores_buttons_and_pill(monkeypatch):
    """A FailedToStart must re-enable Run and show a red pill, not hang."""
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    window.target_input.setText("")
    warnings = []
    monkeypatch.setattr(
        QMessageBox, "warning", lambda *args, **kwargs: warnings.append(args)
    )

    # Simulate a run in progress: disabled buttons, ticking timers, busy pill.
    window.run_button.setEnabled(False)
    window.stop_button.setEnabled(True)
    window._elapsed_timer.start()
    window._poll_timer.start()
    window._set_status("busy", "Running")

    window._process_error(QProcess.FailedToStart)

    assert window.run_button.isEnabled()
    assert not window.stop_button.isEnabled()
    assert not window._elapsed_timer.isActive()
    assert not window._poll_timer.isActive()
    assert window.status_label.property("state") == "error"
    assert window.status_label.text() == "Failed to start"
    assert warnings, "a failed start must warn the operator"

    window.close()
    app.processEvents()


def test_process_finished_exit_codes_drive_pill():
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    window.target_input.setText("")
    window.report_after_process = False

    # Exit 1: error pill + buttons restored.
    window.run_button.setEnabled(False)
    window.running_report = False
    window._process_finished(1, None)
    assert window.status_label.property("state") == "error"
    assert window.status_label.text() == "Failed (exit 1)"
    assert window.run_button.isEnabled()

    # Exit 0 (report already produced / not requested): ok pill.
    window.running_report = True  # skip the auto-report spawn
    window.run_button.setEnabled(False)
    window._process_finished(0, None)
    assert window.status_label.property("state") == "ok"
    assert window.status_label.text() == "Completed"
    assert window.run_button.isEnabled()
    assert not window.stop_button.isEnabled()

    window.close()
    app.processEvents()


def test_poll_run_state_updates_progress_and_pill(tmp_path):
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    window.output_dir = tmp_path / "reports"
    window.target_input.setText("example.com")
    state_dir = tmp_path / "reports" / "example.com" / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "module.json").write_text(
        json.dumps(
            {
                "completed": ["seed_discovery", "fast_scan", "openredirex"],
                "runs": [
                    {"module_id": "seed_discovery", "status": "completed"},
                    {"module_id": "fast_scan", "status": "completed"},
                    {"module_id": "openredirex", "status": "completed"},
                ],
                "stats": {"total_requests": 7},
            }
        )
    )
    window._run_started_at = time.monotonic()

    window._poll_run_state()

    total = len(get_all_module_ids())
    assert window.progress_bar.value() == min(100, int(3 / total * 100))
    assert window.progress_bar.format() == f"3/{total} modules complete"
    assert window.completed_value.text() == "3"
    assert window.incomplete_value.text() == "0"
    assert window.requests_value.text() == "7"
    assert window.status_label.text().startswith(f"Running · 3/{total} · ")

    window.close()
    app.processEvents()


def test_verdict_preserves_selection(tmp_path):
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    window.output_dir = tmp_path / "reports"
    window.target_input.setText("example.com")
    window._load_findings(_sample_findings())

    window.findings_table.selectRow(0)
    assert [f["id"] for f in window._selected_findings()] == ["F-1"]

    window._apply_verdict_action("true_positive")

    selected_rows = {index.row() for index in window.findings_table.selectedIndexes()}
    assert len(selected_rows) == 1
    row = selected_rows.pop()
    assert window.findings_table.item(row, 0).text() == "F-1"
    assert window.verdict_chip.property("verdict") == "true_positive"

    window.close()
    app.processEvents()


def test_multi_select_verdict_round_trip(tmp_path):
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    window.output_dir = tmp_path / "reports"
    window.target_input.setText("example.com")
    findings = _sample_findings()
    window._load_findings(findings)

    model = window.findings_table.model()
    selection = window.findings_table.selectionModel()
    selection.clearSelection()
    # Score-descending order: row 0 = F-1 (90), row 1 = F-3 (55).
    for row in (0, 1):
        selection.select(
            model.index(row, 0),
            QItemSelectionModel.Select | QItemSelectionModel.Rows,
        )
    assert len(window._selected_findings()) == 2

    window._apply_verdict_action("true_positive")

    triage_path = tmp_path / "reports" / "example.com" / "example.com_triage.json"
    data = json.loads(triage_path.read_text())
    assert data["F-1"]["verdict"] == "true_positive"
    assert data["F-3"]["verdict"] == "true_positive"
    assert "F-2" not in data
    # Refiltered but the two selected rows stay selected.
    assert len(window.findings_table.selectedIndexes()) > 0
    assert len(window._selected_findings()) == 2

    window.close()
    app.processEvents()


def test_detail_action_buttons_set_verdict(tmp_path):
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    window.output_dir = tmp_path / "reports"
    window.target_input.setText("example.com")
    window._load_findings(_sample_findings())

    window.findings_table.selectRow(0)
    window.tp_button.click()
    # Score-descending order: row 1 is F-3, not F-2.
    window.findings_table.selectRow(1)
    window.fp_button.click()

    triage_path = tmp_path / "reports" / "example.com" / "example.com_triage.json"
    data = json.loads(triage_path.read_text())
    assert data["F-1"]["verdict"] == "true_positive"
    assert data["F-3"]["verdict"] == "false_positive"

    window.close()
    app.processEvents()


def test_data_tab_filters(tmp_path):
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    window.output_dir = tmp_path / "reports"
    window.target_input.setText("example.com")

    # Assets: free-text search across every column with live counts.
    window._load_assets(
        [
            {"type": "domain", "value": "a.example.com", "confidence": "high", "sources": ["seed"]},
            {"type": "domain", "value": "b.example.org", "confidence": "low", "sources": ["seed"]},
            {"type": "ip", "value": "203.0.113.9", "confidence": "high", "sources": ["probe"]},
        ]
    )
    search, count_label, status_combo = window._table_filters[window.assets_table]
    assert status_combo is None
    assert count_label.text() == "3 of 3"
    search.setText("example.org")
    visible = [r for r in range(window.assets_table.rowCount())
               if not window.assets_table.isRowHidden(r)]
    assert len(visible) == 1
    assert window.assets_table.item(visible[0], 1).text() == "b.example.org"
    assert count_label.text() == "1 of 3"
    search.setText("")
    assert count_label.text() == "3 of 3"

    # Modules: status combo narrows to one module, search narrows by id.
    first_id = get_all_module_ids()[0]
    window._load_modules(
        {"runs": [{"module_id": first_id, "status": "timeout"}], "completed": []}
    )
    msearch, mcount, mcombo = window._table_filters[window.modules_table]
    total = window.modules_table.rowCount()
    assert total == len(get_all_module_ids())
    mcombo.setCurrentText("timeout")
    visible = [r for r in range(total)
               if not window.modules_table.isRowHidden(r)]
    assert len(visible) == 1
    assert window.modules_table.item(visible[0], 1).text() == first_id
    assert mcount.text() == f"1 of {total}"
    mcombo.setCurrentText("All statuses")
    msearch.setText(first_id)
    visible = [r for r in range(total)
               if not window.modules_table.isRowHidden(r)]
    assert len(visible) == 1
    assert window.modules_table.item(visible[0], 1).text() == first_id

    window.close()
    app.processEvents()


def test_init_invokes_load_results(monkeypatch):
    app = QApplication.instance() or QApplication([])
    calls = []
    monkeypatch.setattr(MainWindow, "load_results", lambda self: calls.append(1))

    window = MainWindow()

    assert len(calls) == 1, "startup must read results once"
    window.close()
    app.processEvents()


def test_target_debounce_reloads_once_per_burst(monkeypatch):
    app = QApplication.instance() or QApplication([])
    calls = []
    monkeypatch.setattr(MainWindow, "load_results", lambda self: calls.append(1))

    window = MainWindow()
    baseline = len(calls)

    for text in ("e", "ex", "exa", "exam"):
        window.target_input.setText(text)
    QTest.qWait(900)
    assert len(calls) == baseline + 1, "a burst of keystrokes reloads once"

    window.target_input.setText("example.com")
    window.target_input.setText("example.org")
    QTest.qWait(900)
    assert len(calls) == baseline + 2, "each later burst reloads once"

    window.close()
    app.processEvents()


def test_nav_rail_switches_stacked_screens():
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    count = len(window.SCREEN_DEFS)
    assert window.screen_stack.count() == count

    for index in range(count):
        window.nav_buttons[index].click()
        app.processEvents()
        assert window.screen_stack.currentIndex() == index
        assert window.nav_buttons[index].isChecked()

    # Out-of-range switches are ignored, not crashes.
    window.show_screen(count + 93)
    assert window.screen_stack.currentIndex() == count - 1
    window.show_screen(-1)
    assert window.screen_stack.currentIndex() == count - 1

    window.close()
    app.processEvents()


def test_theme_qss_contains_new_selectors():
    qss_path = Path(__file__).resolve().parent.parent / "gui" / "theme.qss"
    text = qss_path.read_text()
    for needle in (
        "QScrollBar:horizontal",
        "QSpinBox",
        ":focus",
        "#btnPrimary",
        "#btnDanger",
        "#verdictChip",
        "#navRail",
        "QTableView::corner",
        "QHeaderView::section",
        "QTabBar::tab:selected",
    ):
        assert needle in text, f"missing theme selector: {needle}"


def test_run_screen_keeps_engagement_widgets_reachable():
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    window.show_screen(0)
    run_screen = window.screen_stack.widget(0)

    def on_run_screen(widget):
        node = widget
        while node is not None:
            if node is run_screen:
                return True
            node = node.parentWidget()
        return False

    for widget in (
        window.target_input,
        window.run_button,
        window.stop_button,
        window.mode_combo,
        window.stage_filter_combo,
        window.module_combo,
        window.pentest_check,
        window.execute_check,
        window.risk_combo,
        window.max_actions_spin,
        window.ai_run_button,
        window.generate_report_button,
    ):
        assert on_run_screen(widget), (
            f"{widget.objectName() or widget} escaped the run screen"
        )

    window.close()
    app.processEvents()


def test_spin_clamp_is_reported_not_silent(tmp_path):
    from PySide6.QtWidgets import QApplication, QSpinBox
    app = QApplication.instance() or QApplication([])
    spin = QSpinBox()
    spin.setRange(1, 100)
    window = MainWindow()
    assert window._set_spin(spin, 1000, 15) is True
    assert spin.value() == 100
    assert spin.property("clamped_from") == 1000
    assert window._set_spin(spin, 7, 15) is False
    assert spin.value() == 7
    window.close()
    app.processEvents()


def test_text_to_list_keeps_commas_inside_values():
    window = MainWindow.__new__(MainWindow)
    assert window._text_to_list("https://h.test/?a=1,b=2\n/x") == \
        ["https://h.test/?a=1,b=2", "/x"]
