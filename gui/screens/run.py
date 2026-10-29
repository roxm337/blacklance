"""Run control room: mission setup, scan launch, r10xM-mode, process.

Mixin for gui.app.MainWindow; see that class for composition.
"""
from __future__ import annotations

from gui._shared import *  # noqa: F401,F403


class RunScreenMixin:

    # ---- Recent targets -------------------------------------------------

    def _record_recent_target(self, target: str):
        """Prepend target to the recent list (dedup, cap 8) and persist."""
        target = (target or "").strip()
        if not target:
            return
        self._recent_targets = [t for t in self._recent_targets if t != target]
        self._recent_targets.insert(0, target)
        del self._recent_targets[8:]
        self._settings.setValue("recent_targets", ";;".join(self._recent_targets))

    def _populate_recent_targets(self):
        self.recent_targets_menu.clear()
        if not self._recent_targets:
            empty = QAction("(none yet)", self)
            empty.setEnabled(False)
            self.recent_targets_menu.addAction(empty)
            return
        for target in self._recent_targets:
            action = QAction(target, self)
            action.triggered.connect(lambda _checked=False, t=target: self._use_recent_target(t))
            self.recent_targets_menu.addAction(action)

    def _use_recent_target(self, target: str):
        self.target_input.setText(target)
        self.show_screen(0)
        self.statusBar().showMessage(f"Target set to {target}", 3000)

    def _build_controls(self) -> QWidget:
        panel = QFrame()
        panel.setObjectName("sidePanel")
        panel.setMinimumWidth(0)
        layout = QVBoxLayout(panel)
        layout.setSpacing(12)

        # ── r10xM-mode: one-switch maximum autonomous engagement ──
        # Docker toolchain, deep coverage, unlimited budgets/tokens, and a full
        # autonomous recon -> exploit -> verify -> report run — no hand config.
        # The authorisation gate still fires before anything executes.
        r10xm_box = QGroupBox("r10xM-mode")
        r10xm_box.setObjectName("r10xmBox")
        r10xm_layout = QVBoxLayout(r10xm_box)
        r10xm_layout.setSpacing(6)
        self.r10xm_check = QCheckBox("Maximum autonomous engagement")
        self.r10xm_check.setObjectName("r10xmToggle")
        self.r10xm_check.setToolTip(
            "One switch, zero config: Docker toolchain, deep coverage, "
            "unlimited requests / wall-clock / LLM tokens, and a full "
            "autonomous recon → exploit → verify → report run. "
            "You still confirm authorisation once before it executes."
        )
        self.r10xm_check.toggled.connect(self._toggle_r10xm)
        self.r10xm_hint = QLabel(
            "Off — manual controls below. Turn on for full-auto, max-access, "
            "Docker-default, unlimited-token exploitation."
        )
        self.r10xm_hint.setObjectName("r10xmHint")
        self.r10xm_hint.setWordWrap(True)
        r10xm_layout.addWidget(self.r10xm_check)
        r10xm_layout.addWidget(self.r10xm_hint)
        layout.addWidget(r10xm_box)

        target_box = QGroupBox("Mission Setup")
        form = QFormLayout(target_box)
        form.setRowWrapPolicy(QFormLayout.WrapLongRows)
        form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.target_input = QLineEdit("example.com")
        self.target_input.setPlaceholderText("example.com")
        # Enter in the target field is the classic "just run it" gesture.
        self.target_input.returnPressed.connect(self.start_scan)
        self.target_input.setMinimumWidth(0)
        self.target_input.textChanged.connect(self._update_operation_context)
        self.output_input = QLineEdit(str(self.output_dir))
        self.output_input.setReadOnly(True)
        self.output_input.setMinimumWidth(0)
        self.output_input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        choose_output = QPushButton("Browse")
        self.choose_output_button = choose_output
        choose_output.clicked.connect(self.choose_output_dir)
        output_row = QHBoxLayout()
        output_row.setContentsMargins(0, 0, 0, 0)
        output_row.addWidget(self.output_input, 1)
        output_row.addWidget(choose_output)
        form.addRow("Target", self.target_input)
        form.addRow("Output", output_row)

        self.lifecycle_combo = QComboBox()
        self.lifecycle_combo.addItems(["Fresh", "Resume", "Retest"])
        self.lifecycle_combo.setToolTip(
            "Fresh: empty assessment. Resume: selected assessment and budget. "
            "Retest: new assessment using only the selected history baseline.")
        self.assessment_combo = QComboBox()
        self.assessment_combo.setMinimumWidth(0)
        self.assessment_combo.addItem("No assessment selected", None)
        self.assessment_combo.currentIndexChanged.connect(self._assessment_changed)
        refresh_assessments = QPushButton("Refresh assessments")
        refresh_assessments.clicked.connect(lambda: self._refresh_assessments())
        self.import_legacy_button = QPushButton("Import legacy results…")
        self.import_legacy_button.clicked.connect(self.import_legacy_results)
        form.addRow("Lifecycle", self.lifecycle_combo)
        form.addRow("Assessment", self.assessment_combo)
        form.addRow("", refresh_assessments)
        form.addRow("", self.import_legacy_button)

        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Auto", "LLM", "Single module"])
        self.mode_combo.setMinimumWidth(0)
        self.mode_combo.setToolTip(
            "Auto: run active modules. LLM: AI-guided run. "
            "Single module: only the module selected below."
        )
        self.mode_combo.currentIndexChanged.connect(self._sync_mode)
        self.mode_combo.currentIndexChanged.connect(self._update_operation_context)
        self.stage_filter_combo = QComboBox()
        self.stage_filter_combo.setMinimumWidth(0)
        self.stage_filter_combo.addItem("All stages", 0)
        for stage in range(1, 7):
            self.stage_filter_combo.addItem(f"Stage {stage}", stage)
        self.stage_filter_combo.setToolTip(
            "Restrict the module picker to one pipeline stage "
            "(Single module mode; Auto runs the full active chain)."
        )
        self.stage_filter_combo.currentIndexChanged.connect(self._refresh_module_list)
        self.module_combo = QComboBox()
        self.module_combo.setMinimumWidth(0)
        self.module_combo.setToolTip(
            "Used by Single module mode and by the plan/probe actions."
        )
        self.module_combo.currentIndexChanged.connect(self._update_module_hint)
        self.module_combo.currentIndexChanged.connect(self._update_operation_context)
        self.module_hint = QLabel("-")
        self.module_hint.setWordWrap(True)
        self.active_check = QCheckBox("Active mode")
        self.auto_report_check = QCheckBox("Generate report after run")
        self.auto_report_check.setChecked(True)
        form.addRow("Mode", self.mode_combo)
        form.addRow("Stage", self.stage_filter_combo)
        form.addRow("Module", self.module_combo)
        form.addRow("Info", self.module_hint)
        form.addRow("", self.active_check)
        form.addRow("", self.auto_report_check)
        layout.addWidget(target_box)

        engage_box = QGroupBox("Engagement")
        engage_form = QFormLayout(engage_box)
        engage_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.pentest_check = QCheckBox("Attack graph + probe plan (--pentest)")
        self.execute_check = QCheckBox("Execute proposed chains (--execute)")
        self.execute_check.setEnabled(False)
        self.pentest_check.toggled.connect(self.execute_check.setEnabled)
        self.pentest_check.toggled.connect(self._update_operation_context)
        self.risk_combo = QComboBox()
        self.risk_combo.addItems(["SAFE", "LOW", "MEDIUM", "HIGH", "DESTRUCTIVE"])
        self.risk_combo.setCurrentText("DESTRUCTIVE")
        self.risk_combo.setMinimumWidth(0)
        self.risk_combo.setToolTip(
            "Highest action risk the AI attack plan may propose (pentest mode)."
        )
        self.max_actions_spin = QSpinBox()
        self.max_actions_spin.setRange(0, 1000)
        self.max_actions_spin.setValue(0)
        self.max_actions_spin.setToolTip(
            "Cap on executed actions. 0 = use the configured budget cap."
        )
        self.max_chains_spin = QSpinBox()
        self.max_chains_spin.setRange(0, 1000)
        self.max_chains_spin.setValue(0)
        engage_form.addRow("", self.pentest_check)
        engage_form.addRow("", self.execute_check)
        engage_form.addRow("Risk ceiling", self.risk_combo)
        engage_form.addRow("Max actions", self.max_actions_spin)
        engage_form.addRow("Max chains", self.max_chains_spin)
        layout.addWidget(engage_box)

        ai_box = QGroupBox("AI Assist")
        ai_layout = QVBoxLayout(ai_box)
        self.llm_status_label = QLabel("LLM status: checking")
        self.llm_status_label.setWordWrap(True)
        self.llm_status_label.setObjectName("assistantStatus")
        self.llm_status_label.setMinimumWidth(0)
        self.ai_run_button = QPushButton("AI Guided Run")
        self.ai_run_button.setObjectName("btnPrimary")
        self.ai_run_button.clicked.connect(self.start_llm_scan)
        self.ai_plan_button = QPushButton("AI Attack Plan")
        self.ai_plan_button.setObjectName("btnPrimary")
        self.ai_plan_button.clicked.connect(self.generate_attack_plan)
        ai_layout.addWidget(self.llm_status_label)
        ai_layout.addWidget(self.ai_run_button)
        ai_layout.addWidget(self.ai_plan_button)
        layout.addWidget(ai_box)

        action_box = QGroupBox("Execution Controls")
        action_layout = QGridLayout(action_box)
        self.run_button = QPushButton("Run")
        self.run_button.setObjectName("btnPrimary")
        self.run_button.setDefault(True)
        self.run_button.setAutoDefault(True)
        self.run_button.clicked.connect(self.start_scan)
        self.stop_button = QPushButton("Stop")
        self.stop_button.setObjectName("btnDanger")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        self.reload_button = QPushButton("Reload")
        self.reload_button.clicked.connect(self.load_results)
        self.clear_button = QPushButton("Clear Log")
        self.clear_button.clicked.connect(self.log_output.clear)
        self.generate_report_button = QPushButton("Report")
        self.generate_report_button.setObjectName("btnPrimary")
        self.generate_report_button.clicked.connect(self.generate_report)
        self.prioritize_button = QPushButton("Prioritize")
        self.prioritize_button.clicked.connect(self.prioritize_findings)
        self.submission_button = QPushButton("Submissions")
        self.submission_button.clicked.connect(self.generate_submissions)
        self.open_report_button = QPushButton("Open")
        self.open_report_button.clicked.connect(self.open_report)
        self.open_folder_button = QPushButton("Folder")
        self.open_folder_button.clicked.connect(self.open_target_folder)
        action_layout.addWidget(self.run_button, 0, 0)
        action_layout.addWidget(self.stop_button, 0, 1)
        action_layout.addWidget(self.reload_button, 1, 0)
        action_layout.addWidget(self.clear_button, 1, 1)
        action_layout.addWidget(self.generate_report_button, 2, 0)
        action_layout.addWidget(self.prioritize_button, 2, 1)
        action_layout.addWidget(self.submission_button, 3, 0)
        action_layout.addWidget(self.open_report_button, 3, 1)
        action_layout.addWidget(self.open_folder_button, 4, 0, 1, 2)
        layout.addWidget(action_box)

        summary_box = QGroupBox("Operational Telemetry")
        summary_layout = QVBoxLayout(summary_box)
        self.assets_value = QLabel("-")
        self.relations_value = QLabel("-")
        self.findings_value = QLabel("-")
        self.evidence_value = QLabel("-")
        self.max_risk_value = QLabel("-")
        self.critical_high_value = QLabel("-")
        self.requests_value = QLabel("-")
        self.completed_value = QLabel("-")
        self.skipped_value = QLabel("-")
        self.incomplete_value = QLabel("-")
        self.blocked_value = QLabel("-")
        self.active_value = QLabel("-")
        self.report_value = QLabel("-")
        self.report_value.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.report_value.setWordWrap(True)
        self.report_value.setMinimumWidth(0)
        metrics_grid = QGridLayout()
        metric_cards = [
            ("Assets", self.assets_value, "info"),
            ("Relations", self.relations_value, "info"),
            ("Findings", self.findings_value, "warning"),
            ("Evidence", self.evidence_value, "success"),
            ("Max Risk", self.max_risk_value, "danger"),
            ("Crit/High", self.critical_high_value, "danger"),
            ("Requests", self.requests_value, "info"),
            ("Complete", self.completed_value, "success"),
            ("Incomplete", self.incomplete_value, "danger"),
        ]
        for index, (label, value_label, tone) in enumerate(metric_cards):
            metrics_grid.addWidget(self._metric_card(label, value_label, tone), index // 2, index % 2)
        summary_layout.addLayout(metrics_grid)
        secondary_layout = QFormLayout()
        secondary_layout.addRow("Skipped", self.skipped_value)
        secondary_layout.addRow("Blocked", self.blocked_value)
        secondary_layout.addRow("Active modules", self.active_value)
        secondary_layout.addRow("Report", self.report_value)
        summary_layout.addLayout(secondary_layout)
        layout.addWidget(summary_box)

        layout.addStretch(1)
        scroll = QScrollArea()
        scroll.setObjectName("sideScroll")
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setWidget(panel)
        scroll.setMinimumWidth(300)
        scroll.setMaximumWidth(460)
        scroll.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        return scroll

    def _toggle_r10xm(self, enabled: bool) -> None:
        """Pin (or release) the manual controls for r10xM-mode.

        On: force the full-auto / max-access preset — pentest + execute, the
        DESTRUCTIVE risk ceiling, active mode — and lock those selectors so
        the operator cannot half-set the mode. Off: restore manual control,
        including execute's usual dependence on the pentest toggle.
        """
        if enabled:
            self.pentest_check.setChecked(True)
            self.execute_check.setChecked(True)
            self.active_check.setChecked(True)
            self.risk_combo.setCurrentText("DESTRUCTIVE")
            self.mode_combo.setCurrentText("Auto")
            self.r10xm_hint.setText(
                "ON — Docker toolchain, deep coverage, unlimited "
                "requests/wall-clock/LLM tokens, autonomous recon → exploit → "
                "verify → report. A derived config is written; your "
                "config.yaml is untouched. You confirm authorisation once."
            )
        else:
            self.r10xm_hint.setText(
                "Off — manual controls below. Turn on for full-auto, "
                "max-access, Docker-default, unlimited-token exploitation."
            )
        for name in self._R10XM_OWNED:
            widget = getattr(self, name, None)
            if widget is not None:
                widget.setEnabled(not enabled)
        # Off restores execute's dependence on the pentest toggle.
        if not enabled:
            self.execute_check.setEnabled(self.pentest_check.isChecked())
        self._update_operation_context()

    def _build_run_screen(self) -> QWidget:
        """Screen 0: mission setup + live log (was: side panel + ops strip + Log tab)."""
        page = QWidget()
        page.setObjectName("screenRun")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        # Right pane first: the control panel wires buttons to log_output.
        right = QWidget()
        right.setMinimumWidth(420)
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(10)
        right_layout.addWidget(self._build_ops_strip())

        log_caption = QLabel("Run log")
        log_caption.setObjectName("sectionCaption")
        right_layout.addWidget(log_caption)
        self.log_output = QPlainTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.log_output.setFont(code_font(12))
        self.log_output.setPlaceholderText(
            "Output from orchestrator.py appears here once a run starts."
        )
        right_layout.addWidget(self.log_output, 1)

        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self._build_controls())
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setCollapsible(0, False)
        splitter.setCollapsible(1, False)
        splitter.setSizes([380, 900])
        self.run_splitter = splitter
        layout.addWidget(splitter, 1)
        return page

    def start_llm_scan(self):
        index = self.mode_combo.findText("LLM")
        if index >= 0:
            self.mode_combo.setCurrentIndex(index)
        self.start_scan()

    def _r10xm_enabled(self) -> bool:
        check = getattr(self, "r10xm_check", None)
        return bool(check is not None and check.isChecked())

    def _confirm_engagement(self) -> bool:
        """Gate executing engagements behind an explicit authorisation yes.

        Fires for chain execution at MEDIUM+ risk and always for r10xM-mode,
        which is autonomous execution at the DESTRUCTIVE ceiling. This is the
        one gate the maximum-autonomous preset never removes.
        """
        r10xm = self._r10xm_enabled()
        executing = self.pentest_check.isChecked() and self.execute_check.isChecked()
        if not (r10xm or executing):
            return True
        risk = "DESTRUCTIVE" if r10xm else self.risk_combo.currentText()
        if not r10xm and risk in ("SAFE", "LOW"):
            return True
        headline = ("r10xM-mode — autonomous recon → exploit → verify → report\n\n"
                    if r10xm else "")
        answer = QMessageBox.warning(
            self,
            "Authorisation Required",
            headline +
            f"Target: {self.target_input.text().strip()}\n"
            f"Risk ceiling: {risk}\n"
            f"Max actions: {self.max_actions_spin.value()} | "
            f"Max chains: {self.max_chains_spin.value()}\n\n"
            "This will execute attack actions against the target.\n"
            "Only continue if you are authorised to test it.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        return answer == QMessageBox.Yes

    def _start_r10xm_scan(self, target: str) -> None:
        """Launch the autonomous, max-access engagement for r10xM-mode."""
        config_path = self._write_r10xm_config()
        if config_path is None:
            return
        try:
            lifecycle = self._lifecycle_selection(for_action=False)
        except (ValueError, OSError) as exc:
            QMessageBox.warning(self, "Assessment Required", str(exc))
            return
        self._run_scope_total = len(get_all_module_ids())
        args = build_scan_args(
            target=target,
            output_dir=self.output_dir,
            config_path=config_path,
            agent=True,
            active=True,
            pentest=True,
            execute=True,
            max_risk="DESTRUCTIVE",
            max_actions=self.max_actions_spin.value(),
            max_chains=self.max_chains_spin.value(),
            **lifecycle,
        )
        self.log_output.appendPlainText(
            f"\n── r10xM-mode: autonomous engagement · Docker toolchain · "
            f"unlimited budgets · config {config_path.name} ──")
        self.report_after_process = self.auto_report_check.isChecked()
        self.running_report = False
        self._start_process(args)

    def start_scan(self):
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Target Required", "Enter a target domain.")
            return
        if self.process and self.process.state() != QProcess.NotRunning:
            self.statusBar().showMessage("Already running — wait for the current process", 3000)
            return
        if not self._confirm_engagement():
            return

        self._record_recent_target(target)

        # r10xM-mode: one autonomous engagement over a derived max-access
        # config. Short-circuits the per-module/mode selectors entirely.
        if self._r10xm_enabled():
            self._start_r10xm_scan(target)
            return

        mode = self.mode_combo.currentText()
        module = self.module_combo.currentData() if mode == "Single module" else None
        # An empty combo in Single module mode used to fall through to a
        # full Auto scan — the opposite of what the operator asked for.
        if mode == "Single module" and not module:
            QMessageBox.warning(
                self,
                "No Module Selected",
                "Single module mode needs a module in the picker.\n"
                "Pick a module, or switch the mode to Auto.",
            )
            return
        self._run_scope_total = 1 if module else len(get_all_module_ids())
        try:
            lifecycle = self._lifecycle_selection(for_action=module in (
                "reporting", "risk_prioritization", "bounty_submission", "attack_planner"))
        except (ValueError, OSError) as exc:
            QMessageBox.warning(self, "Assessment Required", str(exc))
            return
        args = build_scan_args(
            target=target,
            output_dir=self.output_dir,
            config_path=self.config_path,
            mode=mode,
            active=self.active_check.isChecked(),
            module=module,
            pentest=self.pentest_check.isChecked(),
            execute=self.execute_check.isChecked(),
            max_risk=self.risk_combo.currentText(),
            max_actions=self.max_actions_spin.value(),
            max_chains=self.max_chains_spin.value(),
            **lifecycle,
        )

        # Applies to every mode, not just Single module/LLM: an Auto run
        # with a stale report on disk used to skip regeneration because
        # the "no report yet" fallback already satisfied the old check.
        # The reporting exclusion only matters in Single module mode, where
        # the operator explicitly ran the reporting module (it writes the
        # report itself). In Auto the module combo is disabled.
        self.report_after_process = (
            self.auto_report_check.isChecked()
            and not (
                mode == "Single module"
                and self.module_combo.currentData() == "reporting"
            )
        )
        self.running_report = False
        self._start_process(args)

    def run_module_action(self, module_id: str, report_run: bool = False):
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Target Required", "Enter a target domain.")
            return
        if self.process and self.process.state() != QProcess.NotRunning:
            self.statusBar().showMessage("Already running — wait for the current process", 3000)
            return
        try:
            lifecycle = self._lifecycle_selection(for_action=True)
        except (ValueError, OSError) as exc:
            QMessageBox.warning(self, "Assessment Required", str(exc))
            return
        args = build_scan_args(
            target=target,
            output_dir=self.output_dir,
            config_path=self.config_path,
            module=module_id,
            **lifecycle,
        )
        self._run_scope_total = 1
        self._start_process(args, report_run=report_run)

    def _stop_run_timers(self):
        self._elapsed_timer.stop()
        self._poll_timer.stop()
        self._run_started_at = None

    def _tick_run_progress(self):
        if self._run_started_at is None:
            return
        elapsed = self._format_elapsed(time.monotonic() - self._run_started_at)
        total = max(getattr(self, "_run_scope_total", 0), 1)
        completed = len((self.current_module or {}).get("completed", []))
        self.status_label.setText(f"Running · {min(completed, total)}/{total} · {elapsed}")

    def _poll_run_state(self):
        """Tail state/module.json so metrics move while the engine runs.

        The orchestrator persists state at least five times per run, so a
        750ms poll shows module completions almost immediately instead of
        freezing the progress bar at its pre-run value.
        """
        target_dir = self._assessment_dir()
        module = self._read_investigation(target_dir / "state")["module"]
        if isinstance(module, dict) and module:
            self.current_module = module
            stats = module.get("stats", {})
            completed = len(module.get("completed", []))
            total = max(getattr(self, "_run_scope_total", 0), 1)
            self.progress_bar.setValue(min(100, int((completed / total) * 100)))
            suffix = f", {self._incomplete_count(module)} incomplete" \
                if self._incomplete_count(module) else ""
            self.progress_bar.setFormat(f"{completed}/{total} modules complete{suffix}")
            self.completed_value.setText(str(completed))
            self.skipped_value.setText(str(len(module.get("skipped", []))))
            self.blocked_value.setText(str(len(module.get("blocked", []))))
            self.incomplete_value.setText(str(self._incomplete_count(module)))
            self.requests_value.setText(str(stats.get("total_requests", "-")))
        # Every 4th tick (~3s) also refresh the data tables, so findings
        # and assets collected mid-run appear live instead of only after
        # the whole chain finishes.
        self._poll_data_counter = getattr(self, "_poll_data_counter", 0) + 1
        if self._poll_data_counter % 4 == 1:
            self._poll_data_tables()
        self._tick_run_progress()

    def _poll_data_tables(self):
        """Reload findings/assets/evidence tables while a run is active.

        Only module.json used to be polled, so the tables stayed frozen
        for the entire run. A corrupt or missing file here keeps the
        previous table contents (same policy as load_results) and never
        fights the busy status pill.
        """
        state_dir = self._assessment_dir() / "state"
        self._read_errors = []
        stores = self._read_investigation(state_dir)
        findings, assets, evidence = (stores[k] for k in ("findings", "assets", "evidence"))
        self._read_errors = []
        if isinstance(findings, dict) and isinstance(findings.get("findings"), list):
            self._load_findings(findings["findings"])
            self.findings_value.setText(str(len(findings["findings"])))
            self._update_risk_metrics(findings["findings"], {})
        if isinstance(assets, dict) and isinstance(assets.get("nodes"), list):
            self._load_assets(assets["nodes"])
            self.current_assets = assets
            self.assets_value.setText(str(len(assets["nodes"])))
            self.relations_value.setText(str(count_relations(assets)))
        if isinstance(evidence, dict) and isinstance(evidence.get("items"), list):
            self._load_evidence(evidence["items"])
            self.current_evidence = evidence
            self.evidence_value.setText(str(len(evidence["items"])))

    def _restore_run_buttons(self):
        for control in (self.target_input, self.choose_output_button,
                        self.lifecycle_combo, self.assessment_combo, self.import_legacy_button):
            control.setEnabled(True)
        self.run_button.setEnabled(True)
        self.ai_run_button.setEnabled(True)
        self.ai_plan_button.setEnabled(True)
        self.generate_report_button.setEnabled(True)
        self.prioritize_button.setEnabled(True)
        self.submission_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def _start_process(self, args: list[str], report_run: bool = False):
        self.running_report = report_run
        stamp = time.strftime("%H:%M:%S")
        self.log_output.appendPlainText(
            f"\n── run {stamp} {'(report)' if report_run else ''} ──\n"
            f"$ {sys.executable} {' '.join(args)}\n"
        )
        ops_text = "Report generation" if report_run else "Operation active"
        pill_text = "Generating report" if report_run else "Running"
        self._set_status("busy", pill_text, ops_text)
        self.run_button.setEnabled(False)
        self.ai_run_button.setEnabled(False)
        self.ai_plan_button.setEnabled(False)
        self.generate_report_button.setEnabled(False)
        self.prioritize_button.setEnabled(False)
        self.submission_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        for control in (self.target_input, self.choose_output_button,
                        self.lifecycle_combo, self.assessment_combo, self.import_legacy_button):
            control.setEnabled(False)

        self.process = QProcess(self)
        self.process.setProgram(sys.executable)
        self.process.setArguments(args)
        # The orchestrator resolves a relative config path (and every report
        # path) against CWD; without this pin, Settings edits a config.yaml
        # the engine never reads.
        self.process.setWorkingDirectory(str(ROOT_DIR))
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        self.process.setProcessEnvironment(self._qt_environment(env))
        self.process.readyReadStandardOutput.connect(self._read_stdout)
        self.process.readyReadStandardError.connect(self._read_stderr)
        self.process.finished.connect(self._process_finished)
        self.process.errorOccurred.connect(self._process_error)
        self.process.start()
        self._run_started_at = time.monotonic()
        self._elapsed_timer.start()
        self._poll_timer.start()

    def _process_error(self, error):
        """A failed start never fires `finished` — without this the Run
        button would stay disabled forever."""
        if error != QProcess.FailedToStart:
            # Crashes still emit `finished`; just mark the log now.
            self.log_output.appendHtml(
                f'<span style="color:#f87171">process error: '
                f"{html_escape(self.process.errorString() if self.process else str(error))}"
                "</span>"
            )
            return
        self._stop_run_timers()
        detail = self.process.errorString() if self.process else str(error)
        self._restore_run_buttons()
        self._set_status("error", "Failed to start")
        self.log_output.appendHtml(
            f'<span style="color:#f87171">failed to start orchestrator: '
            f"{html_escape(detail)}</span>"
        )
        QMessageBox.warning(
            self, "Run Failed",
            f"Could not start the orchestrator:\n{detail}",
        )

    def stop_scan(self):
        if self.process and self.process.state() != QProcess.NotRunning:
            self.process.terminate()
            if not self.process.waitForFinished(15000):
                self.process.kill()
        self._stop_run_timers()

    def _process_finished(self, exit_code: int, _status):
        self._stop_run_timers()
        was_report = self.running_report
        self.running_report = False
        self.load_results()
        if (
            not was_report
            and exit_code == 0
            and (self.report_after_process or not self._report_path().exists())
        ):
            self.report_after_process = False
            self.generate_report()
            return

        self.report_after_process = False
        if exit_code == 0:
            self._set_status("ok", "Completed", "Results loaded")
            self.log_output.appendPlainText("── run finished successfully ──")
        else:
            self._set_status("error", f"Failed (exit {exit_code})", f"Failed (exit {exit_code})")
            self.log_output.appendHtml(
                f'<span style="color:#f87171">── run failed with exit code '
                f"{exit_code} ──</span>"
            )
        self._restore_run_buttons()
        self._sync_mode()

    def _update_operation_context(self):
        if not hasattr(self, "operation_target_label"):
            return

        target = self.target_input.text().strip() if hasattr(self, "target_input") else ""
        mode = self.mode_combo.currentText() if hasattr(self, "mode_combo") else "-"
        module = self.module_combo.currentData() if hasattr(self, "module_combo") else "-"
        if mode != "Single module":
            module = "orchestrated chain"

        self.operation_target_label.setText(f"Target: {target or '-'}")
        engagement = ""
        if self._r10xm_enabled():
            mode = "r10xM autonomous"
            module = "recon → exploit → verify → report"
            engagement = " | DESTRUCTIVE · unlimited"
        elif hasattr(self, "pentest_check") and self.pentest_check.isChecked():
            risk = self.risk_combo.currentText() if hasattr(self, "risk_combo") else "LOW"
            engagement = f" | Pentest: {risk}"
        backend = getattr(self, "_tools_backend_mode", "local")
        self.operation_mode_label.setText(
            f"Mode: {mode} | Module: {module}{engagement} | "
            f"Backend: {backend} | Config: {self.config_path.name}"
        )
        ready, llm_message = self._llm_status()
        self.llm_status_label.setText(llm_message)
        self.llm_status_label.setProperty("ready", ready)
        self.llm_status_label.style().unpolish(self.llm_status_label)
        self.llm_status_label.style().polish(self.llm_status_label)
        if hasattr(self, "llm_settings_status"):
            self.llm_settings_status.setText(llm_message)
            self.llm_settings_status.setProperty("ready", ready)
            self.llm_settings_status.style().unpolish(self.llm_settings_status)
            self.llm_settings_status.style().polish(self.llm_settings_status)

        self.config_chip.setText(self.config_path.name)
        self.config_chip.setToolTip(str(self.config_path))
        self.output_chip.setText(self._display_path(self.output_dir, 3))
        self.output_chip.setToolTip(str(self.output_dir))
        self.status_bar_label.setText(
            f"config: {self.config_path}   ·   output: {self.output_dir}"
        )

        module_state = self.current_module if isinstance(self.current_module, dict) else {}
        completed = len(module_state.get("completed", []))
        skipped = len(module_state.get("skipped", []))
        incomplete = self._incomplete_count(module_state)
        total = max(getattr(self, "_run_scope_total", 0), 1)
        progress = min(100, int((completed / total) * 100))
        self.progress_bar.setValue(progress)
        suffix = f", {incomplete} incomplete" if incomplete else ""
        self.progress_bar.setFormat(f"{completed}/{total} modules complete{suffix}")

        if self.process and self.process.state() != QProcess.NotRunning:
            return
        if completed or skipped:
            self.operation_state_label.setText("Results loaded")
        else:
            self.operation_state_label.setText("Ready")

        asset_count = len(self.current_assets.get("nodes", [])) if isinstance(self.current_assets, dict) else 0
        edge_count = count_relations(self.current_assets) if isinstance(self.current_assets, dict) else 0
        evidence_count = len(self.current_evidence.get("items", [])) if isinstance(self.current_evidence, dict) else 0
        self.exposure_label.setText(
            f"Exposure map: {asset_count} assets / {edge_count} relations / {evidence_count} evidence items"
        )

    def _refresh_assessments(self, preferred=None):
        try:
            store = AssessmentStore(self.output_dir, self.target_input.text())
            context = (str(store.root), store.origin)
            entries = store.list()
        except (ValueError, OSError):
            context, entries = None, []
        selected = self.assessment_combo.currentData()
        if context != self._assessment_context:
            selected = None
            self._pending_assessment = None
        self._assessment_context = context
        selected = preferred or self._pending_assessment or selected
        blocked = self.assessment_combo.blockSignals(True)
        self.assessment_combo.clear()
        for entry in entries:
            self.assessment_combo.addItem(
                f"{entry.metadata.get('created_at', '')} · {entry.id[:12]} · {entry.metadata.get('kind', '')}", entry.id)
        if selected and self.assessment_combo.findData(selected) < 0:
            self.assessment_combo.addItem(f"Pending / unavailable · {selected[:12]}", selected)
        if not self.assessment_combo.count():
            self.assessment_combo.addItem("No assessment — legacy results are unbound", None)
        index = self.assessment_combo.findData(selected)
        self.assessment_combo.setCurrentIndex(index if index >= 0 else 0)
        self.assessment_combo.blockSignals(blocked)

    def _assessment_changed(self, *_args):
        self._pending_assessment = None
        if hasattr(self, "findings_table"):
            self.load_results()

    def _assessment_dir(self) -> Path:
        try:
            store = AssessmentStore(self.output_dir, self.target_input.text())
            context = (str(store.root), store.origin)
            if context != self._assessment_context:
                self._refresh_assessments()
            selected = self.assessment_combo.currentData()
            if selected:
                return store.directory(selected)
            legacy = self.output_dir / self._target_output_name()
            # Legacy directories have no origin binding. Never show them as
            # results for an explicit non-default service on the same hostname.
            parsed = urlparse(store.origin)
            if legacy.exists() and (parsed.scheme != "https" or parsed.port is not None):
                return store.service_dir / "unselected"
            return legacy
        except (ValueError, OSError):
            return self.output_dir / "invalid-target"

    def _lifecycle_selection(self, *, for_action=False):
        self._refresh_assessments()
        store = AssessmentStore(self.output_dir, self.target_input.text())
        mode = "resume" if for_action else self.lifecycle_combo.currentText().lower()
        selected = self.assessment_combo.currentData()
        if mode in ("resume", "retest"):
            if not selected:
                raise ValueError("Select an assessment first. Import legacy results explicitly before resuming them.")
            store.open(selected)
        identifier = selected if mode == "resume" else new_assessment_id()
        self._pending_assessment = identifier
        self._refresh_assessments(preferred=identifier)
        self.load_results()
        return {"run_mode": mode, "assessment_id": identifier,
                "from_assessment": selected if mode == "retest" else None}
