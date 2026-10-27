"""Desktop GUI for OSINT Agent — window shell and composition.

The per-screen behaviour lives in mixin modules under gui/screens/ and
gui/common.py; MainWindow composes them. Pure helpers and constants are
in gui/_shared.py.
"""
from __future__ import annotations

from gui._shared import *  # noqa: F401,F403
from gui.screens.run import RunScreenMixin
from gui.screens.triage import TriageScreenMixin
from gui.screens.graph import GraphScreenMixin
from gui.screens.data import DataScreenMixin
from gui.screens.schema import SchemaScreenMixin
from gui.screens.authz import AuthzScreenMixin
from gui.screens.cspt import CsptScreenMixin
from gui.screens.orm import OrmScreenMixin
from gui.screens.report import ReportScreenMixin
from gui.screens.settings import SettingsScreenMixin
from gui.common import CommonMixin


class MainWindow(RunScreenMixin, TriageScreenMixin, GraphScreenMixin, DataScreenMixin, SchemaScreenMixin, AuthzScreenMixin, CsptScreenMixin, OrmScreenMixin, ReportScreenMixin, SettingsScreenMixin, CommonMixin, QMainWindow):
    SCREEN_DEFS = [
        ("run", "Run", QStyle.SP_MediaPlay,
         "Control room: mission setup, run controls, live log"),
        ("triage", "Triage", QStyle.SP_DialogApplyButton,
         "Findings triage: filters, verdicts, detail pane"),
        ("graph", "Graph", QStyle.SP_ComputerIcon,
         "Asset graph and attack graph with probe plan"),
        ("data", "Data", QStyle.SP_DirIcon,
         "Assets, modules, evidence and submissions"),
        ("schema", "Schema", QStyle.SP_DriveNetIcon,
         "I2 stateful API schema testing: fuzz plan, graded failure tiers, "
         "replay and repro"),
        ("authz", "Authz", QStyle.SP_DirClosedIcon,
         "I3 authorization matrix: identity × object cells, canary proofs, "
         "session and sharing checks"),
        ("cspt", "CSPT", QStyle.SP_FileDialogContentsView,
         "I4 client-side path traversal: inject points, resolved escapes, "
         "impact replays"),
        ("orm", "ORM Leak", QStyle.SP_DriveHDIcon,
         "I5 ORM / filter leaks: probe surfaces, cross-identity rows, "
         "seeded-record canaries"),
        ("report", "Report", QStyle.SP_FileIcon,
         "Report, attack plan and summary JSON"),
        ("settings", "Settings", QStyle.SP_FileDialogDetailedView,
         "LLM, runtime, scanner, tools and config editor"),
    ]
    # Derived, not hard-coded: inserting a screen above Graph used to silently
    # point the graph auto-refresh at whatever screen moved into that slot.
    SCREEN_GRAPH_INDEX = [index for index, entry in enumerate(SCREEN_DEFS)
                          if entry[0] == "graph"][0]

    def __init__(self):
        super().__init__()
        self.setWindowTitle("OSINT Agent")
        self._settings = QSettings("osintAgent", "gui")
        self.process: QProcess | None = None
        self.running_report = False
        self.report_after_process = False
        self.current_assets = {"nodes": [], "edges": []}
        self.current_module = {}
        self.current_evidence = {"items": []}
        self._read_errors: list[str] = []
        self.current_findings: list[dict] = []
        self.current_attack_graph: dict = {}
        self._identity_records: list[dict] = []
        self._triage: dict = {}
        self._findings_sort: list = [3, Qt.DescendingOrder]
        self._filtered_findings: list[dict] = []
        self.output_dir = ROOT_DIR / "reports"
        self._assessment_context = None
        self._pending_assessment = None
        self._loaded_assessment_path = None
        self.config_path = ROOT_DIR / "config.yaml"
        self._run_started_at: float | None = None
        # Modules this run will touch: 1 for Single module / module actions,
        # the full registry otherwise. The progress denominator must match
        # the run's scope or a single-module run crawls at 2% forever.
        self._run_scope_total = len(get_all_module_ids())
        self._recent_targets: list[str] = list(
            self._settings.value("recent_targets", "", type=str).split(";;")
        ) if self._settings.value("recent_targets", "", type=str) else []
        self.nav_badges: list[QLabel] = []
        self.run_splitter: QSplitter | None = None
        self.finding_splitter: QSplitter | None = None
        # Timers exist before _build_ui so signal wiring in it is safe.
        self._elapsed_timer = QTimer(self)
        self._elapsed_timer.setInterval(1000)
        self._elapsed_timer.timeout.connect(self._tick_run_progress)
        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(750)
        self._poll_timer.timeout.connect(self._poll_run_state)
        # Debounced reload: typing a target must not re-read disk per keystroke.
        self._target_reload_timer = QTimer(self)
        self._target_reload_timer.setSingleShot(True)
        self._target_reload_timer.setInterval(600)
        self._target_reload_timer.timeout.connect(self.load_results)
        self._build_ui()
        # Drag a .yaml/.yml onto the window to load it as the config.
        self.setAcceptDrops(True)
        self.target_input.textChanged.connect(
            lambda *_: self._target_reload_timer.start()
        )
        self._restore_window_state()
        self._apply_style()
        self._load_settings_form()
        self._refresh_module_list()
        self._refresh_key_status()
        self._refresh_tools_status()
        self._prefer_llm_if_ready()
        self._update_operation_context()
        # First window of a session opens on data, not on empty widgets.
        last_target = self._settings.value("target", "", type=str)
        if last_target:
            self.target_input.setText(last_target)
        try:
            self.load_results()
        except Exception:
            pass  # a corrupt state file must never block startup
        self._target_reload_timer.stop()

    def _build_ui(self):
        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        top_bar = QFrame()
        top_bar.setObjectName("topBar")
        header = QHBoxLayout(top_bar)
        header.setContentsMargins(16, 11, 14, 11)
        header.setSpacing(10)
        title_stack = QVBoxLayout()
        title = QLabel("RED TEAM OPS CONSOLE")
        title.setObjectName("title")
        subtitle = QLabel("OSINT collection, exposure mapping, evidence handling")
        subtitle.setObjectName("subtitle")
        title_stack.addWidget(title)
        title_stack.addWidget(subtitle)
        header.addLayout(title_stack)

        self.config_chip = QLabel(self.config_path.name)
        self.config_chip.setObjectName("contextChip")
        self.config_chip.setToolTip(str(self.config_path))
        self.output_chip = QLabel(self._display_path(self.output_dir, 3))
        self.output_chip.setObjectName("contextChip")
        self.output_chip.setToolTip(str(self.output_dir))
        header.addSpacing(8)
        header.addWidget(self.config_chip)
        header.addWidget(self.output_chip)
        header.addStretch(1)

        self.status_label = QLabel("Idle")
        self.status_label.setObjectName("status")
        self.status_label.setProperty("state", "idle")
        header.addWidget(self.status_label)
        layout.addWidget(top_bar)

        body = QHBoxLayout()
        body.setSpacing(12)
        body.addWidget(self._build_nav_rail())

        self.screen_stack = QStackedWidget()
        self.screen_stack.setObjectName("screenStack")
        # Build order must match SCREEN_DEFS (rail index == stack index).
        self.screen_stack.addWidget(self._build_run_screen())
        self.screen_stack.addWidget(self._build_triage_screen())
        self.screen_stack.addWidget(self._build_graph_screen())
        self.screen_stack.addWidget(self._build_data_screen())
        self.screen_stack.addWidget(self._build_schema_screen())
        self.screen_stack.addWidget(self._build_authz_screen())
        self.screen_stack.addWidget(self._build_cspt_screen())
        self.screen_stack.addWidget(self._build_orm_screen())
        self.screen_stack.addWidget(self._build_report_screen())
        self.screen_stack.addWidget(self._build_settings_panel())
        body.addWidget(self.screen_stack, 1)
        layout.addLayout(body, 1)

        self.status_bar_label = QLabel("")
        self.status_bar_label.setObjectName("statusBarLabel")
        self.statusBar().addWidget(self.status_bar_label, 1)

        self.setCentralWidget(root)
        self._build_menu()

    def _build_nav_rail(self) -> QWidget:
        rail = QWidget()
        rail.setObjectName("navRail")
        rail.setFixedWidth(84)
        rail_layout = QVBoxLayout(rail)
        rail_layout.setContentsMargins(7, 9, 7, 9)
        rail_layout.setSpacing(5)
        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)
        self.nav_buttons: list[QToolButton] = []
        for index, (_key, label, icon, tip) in enumerate(self.SCREEN_DEFS):
            button = QToolButton()
            button.setObjectName("navButton")
            button.setToolButtonStyle(Qt.ToolButtonTextUnderIcon)
            button.setCheckable(True)
            button.setAutoRaise(True)
            button.setIcon(self.style().standardIcon(icon))
            button.setIconSize(QSize(21, 21))
            button.setText(label)
            button.setToolTip(f"{tip}  ({self._screen_shortcut(index)})")
            button.setFixedSize(70, 62)
            button.clicked.connect(lambda _checked=False, i=index: self.show_screen(i))
            self.nav_group.addButton(button, index)
            self.nav_buttons.append(button)
            rail_layout.addWidget(button)
            # Count badge, top-right; hidden when zero. Kept as a sibling so
            # the button's fixed size / text-under-icon layout is untouched.
            badge = QLabel("", button)
            badge.setObjectName("navBadge")
            badge.setAlignment(Qt.AlignCenter)
            badge.hide()
            self.nav_badges.append(badge)
        rail_layout.addStretch(1)
        if self.nav_buttons:
            self.nav_buttons[0].setChecked(True)
        return rail

    def show_screen(self, index: int) -> None:
        """Switch the stacked screen and keep rail, stack and settings in sync."""
        if not 0 <= index < self.screen_stack.count():
            return
        previous_index = self.screen_stack.currentIndex()
        self.screen_stack.setCurrentIndex(index)
        if index < len(self.nav_buttons):
            self.nav_buttons[index].setChecked(True)
        self._settings.setValue("screen", index)
        if previous_index != index and self.isVisible():
            self._fade_in_screen(self.screen_stack.widget(index))

    def _fade_in_screen(self, page: QWidget) -> None:
        """Give navigation a short, non-blocking visual handoff."""
        previous = getattr(self, "_page_animation", None)
        if previous is not None:
            previous.stop()
        effect = QGraphicsOpacityEffect(page)
        page.setGraphicsEffect(effect)
        animation = QPropertyAnimation(effect, b"opacity", page)
        animation.setDuration(150)
        animation.setStartValue(0.72)
        animation.setEndValue(1.0)
        animation.setEasingCurve(QEasingCurve.OutCubic)
        animation.finished.connect(lambda: page.setGraphicsEffect(None))
        self._page_animation = animation
        animation.start()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._position_nav_badges()

    def _position_nav_badges(self):
        # Badges are child labels of the nav buttons; park each one in the
        # button's top-right corner (offset past the icon). Guarded: a
        # resize can land while _build_ui is still constructing the rail.
        buttons = getattr(self, "nav_buttons", [])
        for button, badge in zip(buttons, getattr(self, "nav_badges", [])):
            size = button.size()
            badge.setGeometry(size.width() - 22, 2, 20, 14)

    @classmethod
    def _screen_index(cls, key: str) -> int:
        """Stack index of a named screen, so callers never hard-code a slot."""
        for index, entry in enumerate(cls.SCREEN_DEFS):
            if entry[0] == key:
                return index
        return -1

    @staticmethod
    def _screen_shortcut(index: int) -> str:
        """Ctrl+1..9 for the first nine screens, Ctrl+0 for the tenth.

        A tenth screen would otherwise ask for "Ctrl+10", which is not one
        keystroke; wrapping to 0 keeps the rail position and the key in step
        the way a browser tab strip does.
        """
        return f"Ctrl+{(index + 1) % 10}"

    def _refresh_nav_badges(self):
        """Populate nav-rail count badges so triage volume is visible at a glance."""
        if not self.nav_badges:
            return
        # Triage (index 1) carries the open-findings count. Verdicts live in
        # the _triage dict; some loaded findings also embed one inline.
        findings = self.current_findings if isinstance(self.current_findings, list) else []
        triage_count = 0
        for finding in findings:
            verdict = self._verdict_of(finding) or str(
                (finding.get("triage") or {}).get("verdict") or ""
            )
            if not verdict or verdict == "untriaged":
                triage_count += 1
        self._set_nav_badge(1, triage_count, "untriaged finding(s)")
        self._position_nav_badges()

    def _set_nav_badge(self, index: int, count: int, noun: str):
        if not 0 <= index < len(self.nav_badges):
            return
        badge = self.nav_badges[index]
        if count > 0:
            badge.setText(str(count) if count < 100 else "99+")
            badge.setToolTip(f"{count} {noun}")
            badge.show()
        else:
            badge.clear()
            badge.hide()

    def _build_menu(self):
        file_menu = self.menuBar().addMenu("File")
        open_output = QAction("Choose Output Directory", self)
        open_output.triggered.connect(self.choose_output_dir)
        file_menu.addAction(open_output)

        use_config = QAction("Use Config File...", self)
        use_config.setShortcut(QKeySequence("Ctrl+O"))
        use_config.triggered.connect(self.choose_config_file)
        file_menu.addAction(use_config)

        open_target = QAction("Open Target Folder", self)
        open_target.triggered.connect(self.open_target_folder)
        file_menu.addAction(open_target)

        reload_report = QAction("Reload Current Results", self)
        reload_report.setShortcuts([QKeySequence("F5"), QKeySequence("Ctrl+R")])
        reload_report.triggered.connect(self.load_results)
        file_menu.addAction(reload_report)

        # Populated on demand so the menu never shows a stale list.
        self.recent_targets_menu = file_menu.addMenu("Recent Targets")
        self.recent_targets_menu.aboutToShow.connect(self._populate_recent_targets)

        file_menu.addSeparator()
        export_csv = QAction("Export Findings as CSV...", self)
        export_csv.triggered.connect(self._export_findings_csv)
        file_menu.addAction(export_csv)

        file_menu.addSeparator()
        quit_action = QAction("Quit", self)
        quit_action.setShortcut(QKeySequence("Ctrl+Q"))
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)

        operation_menu = self.menuBar().addMenu("Operation")
        run_action = QAction("Run", self)
        run_action.setShortcut(QKeySequence("Ctrl+Return"))
        run_action.triggered.connect(self.start_scan)
        operation_menu.addAction(run_action)

        stop_action = QAction("Stop", self)
        stop_action.setShortcut(QKeySequence("Ctrl+."))
        stop_action.triggered.connect(self.stop_scan)
        operation_menu.addAction(stop_action)

        report_action = QAction("Generate Report", self)
        report_action.triggered.connect(self.generate_report)
        operation_menu.addAction(report_action)

        settings_menu = self.menuBar().addMenu("Settings")
        reload_settings = QAction("Reload Config", self)
        reload_settings.triggered.connect(self._load_settings_form)
        settings_menu.addAction(reload_settings)

        save_settings = QAction("Save Config", self)
        save_settings.triggered.connect(self._save_settings_form)
        settings_menu.addAction(save_settings)

        help_menu = self.menuBar().addMenu("Help")
        shortcuts_action = QAction("Keyboard Shortcuts", self)
        shortcuts_action.triggered.connect(self._show_shortcuts)
        help_menu.addAction(shortcuts_action)
        about_action = QAction("About", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

        # Ctrl+<n> jumps to the screen at that rail position.
        for index in range(len(self.SCREEN_DEFS)):
            shortcut = QShortcut(
                QKeySequence(self._screen_shortcut(index)), self)
            shortcut.setContext(Qt.ApplicationShortcut)
            shortcut.activated.connect(lambda i=index: self.show_screen(i))

    # Controls r10xM takes ownership of while it is on: it pins them to the
    # maximum-autonomous preset and disables them so the run is unambiguous.
    _R10XM_OWNED = ("mode_combo", "stage_filter_combo", "module_combo",
                    "active_check", "pentest_check", "execute_check",
                    "risk_combo")

    def _set_status(self, state: str, text: str, ops_text: str | None = None):
        """Drive the header pill and ops-strip badge from one state value.

        `state` is one of idle / busy / ok / error; theme.qss styles each via
        `[state="..."]` so a failure can never look like a success.
        """
        self.status_label.setText(text)
        self.status_label.setProperty("state", state)
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)
        if hasattr(self, "operation_state_label"):
            self.operation_state_label.setText(ops_text or text)
            self.operation_state_label.setProperty("state", state)
            self.operation_state_label.style().unpolish(self.operation_state_label)
            self.operation_state_label.style().polish(self.operation_state_label)
        self._refresh_window_title(state, text)

    def _refresh_window_title(self, state: str = "idle", text: str = ""):
        """Keep the OS title bar informative: target + current state.

        Operators running several windows side-by-side need to tell them
        apart without focusing each one, and a scan's state should be
        readable from the taskbar/dock.
        """
        target = self.target_input.text().strip() if hasattr(self, "target_input") else ""
        title = "OSINT Agent"
        if target:
            title += f" — {target}"
        state_word = {"idle": "Ready", "busy": "Running", "ok": "OK", "error": "Error"}.get(state)
        if state_word and state != "idle":
            detail = f": {text}" if text and text != state_word else ""
            title += f" — {state_word}{detail}"
        self.setWindowTitle(title)


def main():
    app = QApplication(sys.argv)
    # Fusion gives consistent cross-platform rendering under our stylesheet
    # (macOS native style ignores large parts of a QSS theme).
    app.setStyle("Fusion")
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
