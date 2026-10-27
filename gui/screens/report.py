"""Report, attack plan and submission actions.

Mixin for gui.app.MainWindow; see that class for composition.
"""
from __future__ import annotations

from gui._shared import *  # noqa: F401,F403


class ReportScreenMixin:

    def _build_report_screen(self) -> QWidget:
        """Screen 4: report preview, markdown, attack plan, summary JSON."""
        page = QWidget()
        page.setObjectName("screenReport")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        path_row = QHBoxLayout()
        path_row.setSpacing(16)
        self.report_path_label = QLabel("No report loaded")
        self.report_path_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.report_path_label.setWordWrap(True)
        self.report_path_label.setMinimumWidth(0)
        self.attack_plan_path_label = QLabel("No attack plan loaded")
        self.attack_plan_path_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.attack_plan_path_label.setWordWrap(True)
        self.attack_plan_path_label.setMinimumWidth(0)
        path_row.addWidget(self.report_path_label, 1)
        path_row.addWidget(self.attack_plan_path_label, 1)
        report_buttons = QVBoxLayout()
        report_buttons.setSpacing(4)
        open_report_btn = QPushButton("Open Report")
        open_report_btn.clicked.connect(self.open_report)
        copy_path_btn = QPushButton("Copy Report Path")
        copy_path_btn.clicked.connect(self._copy_report_path)
        report_buttons.addWidget(open_report_btn)
        report_buttons.addWidget(copy_path_btn)
        path_row.addLayout(report_buttons)
        layout.addLayout(path_row)

        tabs = QTabWidget()
        tabs.setObjectName("screenTabs")
        tabs.setDocumentMode(True)
        tabs.tabBar().setUsesScrollButtons(True)
        tabs.tabBar().setElideMode(Qt.ElideRight)
        tabs.tabBar().setDrawBase(False)
        self.report_preview = QTextEdit()
        self.report_preview.setReadOnly(True)
        self.report_raw = QPlainTextEdit()
        self.report_raw.setReadOnly(True)
        self.report_raw.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.report_raw.setFont(code_font(12))
        self.attack_plan_preview = QTextEdit()
        self.attack_plan_preview.setReadOnly(True)
        self.summary_json = QPlainTextEdit()
        self.summary_json.setReadOnly(True)
        self.summary_json.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.summary_json.setFont(code_font(12))
        tabs.addTab(self.report_preview, "Rendered")
        tabs.addTab(self.report_raw, "Markdown")
        tabs.addTab(self.attack_plan_preview, "Attack Plan")
        tabs.addTab(self.summary_json, "Summary JSON")
        layout.addWidget(tabs, 1)
        return page

    def generate_report(self):
        self.run_module_action("reporting", report_run=True)

    def generate_submissions(self):
        self.run_module_action("bounty_submission")

    def open_report(self):
        path = self._report_path()
        if not path.exists():
            QMessageBox.information(self, "Report Missing", "No report exists for this target yet.")
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def _copy_report_path(self):
        """Copy the report path so the analyst can attach/paste it elsewhere."""
        path = self._report_path()
        QApplication.clipboard().setText(str(path))
        self.statusBar().showMessage(f"Report path copied: {path}", 4000)

    def _report_path(self) -> Path:
        target = self._target_output_name()
        return self._assessment_dir() / f"{target}_report.md"

    def _load_submissions(self):
        target = self._target_output_name()
        submission_dir = self._assessment_dir() / "submissions"
        files = sorted(submission_dir.glob("*.md")) if submission_dir.exists() else []
        # INDEX.md is an operator bookkeeping file, not a submission.
        files = [p for p in files if p.name != "INDEX.md"]
        self.submissions_table.setSortingEnabled(False)
        self.submissions_table.setRowCount(len(files))
        for row, path in enumerate(files):
            # Submission files are named <finding_id>_<slug>.md (bounty_submission).
            finding_id = path.name.split("_", 1)[0] if path.name.startswith("FINDING-") else ""
            values = [path.name, finding_id, str(path.stat().st_size), str(path)]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                if col == 2:
                    item.setData(Qt.UserRole, path.stat().st_size)
                self.submissions_table.setItem(row, col, item)
        self.submissions_table.setSortingEnabled(True)
        self._apply_table_filter(self.submissions_table)

    def _report_spin_clamps(self) -> None:
        notes = getattr(self, "_spin_clamp_notes", []) or []
        self._spin_clamp_notes = []
        if notes:
            self.statusBar().showMessage(
                f"Config values clamped to widget range: {', '.join(notes)} "
                f"(file values kept only if you edit them back)", 8000)

    def _open_submission_cell(self, row: int, _col: int):
        item = self.submissions_table.item(row, 3)
        if item and Path(item.text()).exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(item.text()))
