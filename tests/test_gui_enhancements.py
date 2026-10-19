"""Tests for GUI enhancement work: filters, scope, chips, menus, guards."""

import csv
import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("QTWEBENGINE_DISABLE_SANDBOX", "1")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QApplication, QMessageBox

from gui.app import MainWindow
from modules import get_all_module_ids


def _window(tmp_path=None):
    """Fresh window; with tmp_path, fully isolated from the operator's
    real reports/ dir, restored target and QSettings."""
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    if tmp_path is not None:
        window.output_dir = tmp_path / "reports"
        window.output_input.setText(str(window.output_dir))
        window.target_input.setText("unit.test")
        window._settings = QSettings(
            str(tmp_path / "gui-test.ini"), QSettings.IniFormat
        )
        window._recent_targets = []
        window._triage = {}
    return window, app


def _finding(module_id, severity="HIGH", title="Finding", verdict=None):
    finding = {
        "id": f"F-{module_id}",
        "title": title,
        "severity": severity,
        "confidence": "FIRM",
        "category": "Test",
        "module_id": module_id,
        "description": "desc",
        "verified": False,
    }
    if verdict:
        finding["triage"] = {"verdict": verdict}
    return finding


def test_module_filter_search_covers_module_id(tmp_path):
    window, app = _window(tmp_path)
    window._load_findings([
        _finding("nmap_discovery", title="open port"),
        _finding("cors_misconfig", title="open header"),
    ])
    window.finding_search.setText("nmap_discovery")
    assert [f["id"] for f in window._filtered_findings] == ["F-nmap_discovery"]
    window.close()
    app.processEvents()


def test_severity_chips_counts_and_click_toggle(tmp_path):
    window, app = _window(tmp_path)
    window._load_findings([
        _finding("a", severity="HIGH"),
        _finding("b", severity="HIGH"),
        _finding("c", severity="CRITICAL"),
        _finding("d", severity="INFO"),
    ])
    assert window._severity_chips["HIGH"].text() == "HIGH 2"
    assert window._severity_chips["CRITICAL"].text() == "CRITICAL 1"
    assert window._severity_chips["LOW"].text() == "LOW 0"
    assert window._severity_chips["LOW"].property("dim") is True

    window._severity_chips["HIGH"].mousePressEvent(None)
    assert window.finding_severity_combo.currentText() == "HIGH"
    assert len(window._filtered_findings) == 2
    # Clicking the active severity clears back to all.
    window._severity_chips["HIGH"].mousePressEvent(None)
    assert window.finding_severity_combo.currentText() == "All severities"
    assert len(window._filtered_findings) == 4
    window.close()
    app.processEvents()


def test_single_module_run_scope_and_report_flag(tmp_path, monkeypatch):
    window, app = _window(tmp_path)
    captured = {}

    def fake_start(args, report_run=False):
        captured["args"] = args
        captured["report_run"] = report_run

    monkeypatch.setattr(window, "_start_process", fake_start)
    monkeypatch.setattr(window, "_confirm_engagement", lambda: True)
    monkeypatch.setattr(QMessageBox, "warning", staticmethod(lambda *a, **k: None))

    # Single module: scope is 1.
    window.target_input.setText("example.com")
    window.mode_combo.setCurrentText("Single module")
    module_id = get_all_module_ids()[0]
    window.module_combo.setCurrentText(
        window.module_combo.itemText(window.module_combo.findData(module_id))
    )
    window.start_scan()
    assert window._run_scope_total == 1

    # Auto: scope is the whole registry.
    window.mode_combo.setCurrentText("Auto")
    window.auto_report_check.setChecked(True)
    window.start_scan()
    assert window._run_scope_total == len(get_all_module_ids())
    # Generate-report-after-run now applies to Auto runs too.
    assert window.report_after_process is True
    assert "--module" not in captured["args"]

    window.close()
    app.processEvents()


def test_single_module_mode_empty_combo_aborts(tmp_path, monkeypatch):
    window, app = _window(tmp_path)
    started = []
    monkeypatch.setattr(window, "_start_process", lambda *a, **k: started.append(a))
    monkeypatch.setattr(window, "_confirm_engagement", lambda: True)
    monkeypatch.setattr(QMessageBox, "warning", staticmethod(lambda *a, **k: None))
    window.target_input.setText("example.com")
    window.mode_combo.setCurrentText("Single module")
    window.module_combo.clear()
    window.start_scan()
    assert started == []
    assert window.process is None
    window.close()
    app.processEvents()


def test_recent_targets_dedup_and_cap(tmp_path, monkeypatch):
    window, app = _window(tmp_path)
    monkeypatch.setattr(window, "_start_process", lambda *a, **k: None)
    monkeypatch.setattr(window, "_confirm_engagement", lambda: True)
    monkeypatch.setattr(QMessageBox, "warning", staticmethod(lambda *a, **k: None))
    window.mode_combo.setCurrentText("Auto")
    for i in range(10):
        window.target_input.setText(f"target{i}.com")
        window.start_scan()
    # Dedup: re-running the first target moves it to front, no duplicates.
    window.target_input.setText("target9.com")
    window.start_scan()
    window._record_recent_target("target9.com")
    assert window._recent_targets.count("target9.com") == 1
    assert len(window._recent_targets) == 8
    assert window._recent_targets[0] == "target9.com"
    assert "target9.com" in window._settings.value("recent_targets", "", type=str)
    window.close()
    app.processEvents()


def test_export_findings_csv(tmp_path, monkeypatch):
    window, app = _window(tmp_path)
    window._load_findings([
        _finding("a", severity="HIGH", title="first"),
        _finding("b", severity="LOW", title="second"),
    ])
    out = tmp_path / "findings.csv"
    monkeypatch.setattr(
        "gui.app.QFileDialog.getSaveFileName",
        staticmethod(lambda *a, **k: (str(out), "CSV Files (*.csv)")),
    )
    monkeypatch.setattr(QMessageBox, "information", staticmethod(lambda *a, **k: None))
    window._export_findings_csv()
    with open(out, newline="", encoding="utf-8") as handle:
        rows = list(csv.reader(handle))
    assert rows[0][:4] == ["id", "title", "severity", "risk_score"]
    assert len(rows) == 3
    assert rows[1][1] == "first"
    window.close()
    app.processEvents()


def test_settings_filter_hides_non_matching_groups(tmp_path):
    window, app = _window(tmp_path)
    tabs = window.settings_tabs
    # A query matching nothing collapses every tab except... none match.
    window._apply_settings_filter(tabs, "nonexistent-section-xyz")
    assert any(not tabs.isTabVisible(i) for i in range(tabs.count()))
    # A query matching a known section keeps its tab visible.
    window._apply_settings_filter(tabs, "provider")
    assert tabs.isTabVisible(0), "LLM Provider group lives on tab 0"
    # Empty query restores everything.
    window._apply_settings_filter(tabs, "")
    assert all(tabs.isTabVisible(i) for i in range(tabs.count()))
    window.close()
    app.processEvents()


def test_window_title_reflects_target_and_state(tmp_path):
    window, app = _window(tmp_path)
    window.target_input.setText("example.com")
    window._set_status("busy", "Running · 3/40 · 00:12")
    title = window.windowTitle()
    assert "example.com" in title
    assert "Running" in title
    window._set_status("error", "orchestrator exited 1")
    assert "Error" in window.windowTitle()
    window.close()
    app.processEvents()


def test_nav_badge_tracks_untriaged_findings(tmp_path):
    window, app = _window(tmp_path)
    window._load_findings([
        _finding("a"),
        _finding("b"),
        _finding("c", verdict="true_positive"),
    ])
    badge = window.nav_badges[1]
    assert badge.text() == "2"
    assert not badge.isHidden()
    # Triaging the remaining two hides the badge.
    for f in window.current_findings:
        window._set_finding_verdict(f, "true_positive", refilter=True)
    assert badge.text() == ""
    window.close()
    app.processEvents()


def test_close_event_refuses_while_running_without_confirmation(tmp_path, monkeypatch):
    window, app = _window(tmp_path)

    class FakeEvent:
        def __init__(self):
            self.ignore_called = False

        def ignore(self):
            self.ignore_called = True

        def accept(self):
            pass

    class FakeProcess:
        @staticmethod
        def state():
            return 2  # QProcess.Running

    window.process = FakeProcess()
    stopped = []
    monkeypatch.setattr(window, "stop_scan", lambda: stopped.append(True))
    monkeypatch.setattr(
        QMessageBox, "question",
        staticmethod(lambda *a, **k: QMessageBox.No),
    )
    event = FakeEvent()
    window.closeEvent(event)
    assert event.ignore_called, "close must be refused when the operator says No"
    assert stopped == []
    window.process = None
    window.close()
    app.processEvents()


def test_docker_backend_install_guard(tmp_path, monkeypatch):
    window, app = _window(tmp_path)
    window._tools_backend_mode = "docker"
    messages = []
    monkeypatch.setattr(
        QMessageBox, "information",
        staticmethod(lambda *a, **k: messages.append(a[1] if len(a) > 1 else "")),
    )
    started = []
    monkeypatch.setattr(window, "_start_process", lambda *a, **k: started.append(a))
    window.install_missing_tools()
    assert started == []
    assert messages and "Docker" in str(messages[0])
    window.close()
    app.processEvents()


def test_report_path_copy(tmp_path):
    window, app = _window(tmp_path)
    window.target_input.setText("example.com")
    window._copy_report_path()
    from PySide6.QtWidgets import QApplication
    assert "example.com" in QApplication.clipboard().text()
    window.close()
    app.processEvents()


def test_drag_drop_config_accepts_yaml_only(tmp_path):
    window, app = _window(tmp_path)

    class FakeUrl:
        def __init__(self, path):
            self._path = path

        def toLocalFile(self):
            return self._path

    class FakeMime:
        def __init__(self, paths):
            self._paths = paths

        def hasUrls(self):
            return True

        def urls(self):
            return [FakeUrl(p) for p in self._paths]

    class FakeDragEvent:
        def __init__(self, paths):
            self._mime = FakeMime(paths)
            self.accepted = False

        def mimeData(self):
            return self._mime

        def acceptProposedAction(self):
            self.accepted = True

    ok = FakeDragEvent(["/tmp/config.yaml"])
    window.dragEnterEvent(ok)
    assert ok.accepted

    bad = FakeDragEvent(["/tmp/notes.txt"])
    window.dragEnterEvent(bad)
    assert not bad.accepted
    window.close()
    app.processEvents()
