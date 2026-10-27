"""I4 client-side path traversal screen.

Mixin for gui.app.MainWindow; see that class for composition.
"""
from __future__ import annotations

from gui._shared import *  # noqa: F401,F403


class CsptScreenMixin:

    # ---- I4 client-side path traversal screen ------------------------------

    def _build_cspt_screen(self) -> QWidget:
        page = QWidget()
        page.setObjectName("screenCspt")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        layout.addWidget(self._build_cspt_strip())

        results = QWidget()
        results.setObjectName("csptResults")
        results.setMinimumWidth(0)
        results_layout = QVBoxLayout(results)
        results_layout.setContentsMargins(0, 0, 0, 0)
        results_layout.setSpacing(6)

        self.cspt_tabs = QTabWidget()
        self.cspt_tabs.setObjectName("csptViews")
        self.cspt_tabs.addTab(self._build_cspt_pairs_tab(), "Inject points")
        self.cspt_tabs.addTab(self._build_cspt_impacts_tab(), "Impact replays")
        self.cspt_tabs.addTab(self._build_cspt_coverage_tab(), "Coverage")
        results_layout.addWidget(self.cspt_tabs, 3)
        results_layout.addWidget(self._build_cspt_detail(), 2)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setObjectName("csptSplitter")
        splitter.addWidget(self._build_cspt_plan_panel())
        splitter.addWidget(results)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setCollapsible(0, False)
        splitter.setCollapsible(1, False)
        splitter.setSizes([340, 880])
        layout.addWidget(splitter, 1)
        return page

    def _build_cspt_strip(self) -> QFrame:
        strip = QFrame()
        strip.setObjectName("csptStrip")
        layout = QVBoxLayout(strip)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(9)

        head = QHBoxLayout()
        head.setSpacing(8)
        caption = QLabel("I4 · CLIENT-SIDE PATH TRAVERSAL")
        caption.setObjectName("csptCaption")
        self.cspt_state_label = QLabel("module disabled")
        self.cspt_state_label.setObjectName("csptState")
        self.cspt_state_label.setProperty("state", "idle")
        self.cspt_state_label.setToolTip(
            "modules.cspt_audit.enabled — the module skips while it is off, "
            "because it drives a real browser with traversal payloads")
        self.cspt_run_label = QLabel("no cspt run loaded")
        self.cspt_run_label.setObjectName("csptTool")
        self.cspt_run_label.setWordWrap(True)
        self.cspt_run_label.setMinimumWidth(0)
        head.addWidget(caption)
        head.addWidget(self.cspt_state_label)
        head.addWidget(self.cspt_run_label, 1)
        layout.addLayout(head)

        self.cspt_targets_value = QLabel("-")
        self.cspt_points_value = QLabel("-")
        self.cspt_altered_value = QLabel("-")
        self.cspt_proofs_value = QLabel("-")
        self.cspt_look_value = QLabel("-")
        self.cspt_gap_value = QLabel("-")
        cards = [
            ("Targets driven", self.cspt_targets_value, "info"),
            ("Inject points", self.cspt_points_value, "info"),
            ("Paths altered", self.cspt_altered_value, "warning"),
            ("Impact proofs", self.cspt_proofs_value, "success"),
            ("Needs a look", self.cspt_look_value, "info"),
            ("Not tested", self.cspt_gap_value, "warning"),
        ]
        grid = QGridLayout()
        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(8)
        for index, (label, value_label, tone) in enumerate(cards):
            grid.addWidget(self._metric_card(label, value_label, tone),
                           index // 3, index % 3)
        layout.addLayout(grid)

        self.cspt_legend_label = QLabel(
            "<span style='color:#5b7181'>●</span> HEALTHY — the value reached "
            "a request and stayed under the natural prefix &nbsp;·&nbsp; "
            "<span style='color:#93c5fd'>●</span> OBSERVATION — the value "
            "never reached an XHR/fetch, so this inject point is unproven "
            "&nbsp;·&nbsp; "
            "<span style='color:#fdba74'>●</span> CANDIDATE — a payload "
            "resolved outside the prefix &nbsp;·&nbsp; "
            "<span style='color:#4ade80'>●</span> PROOF — the altered URL was "
            "replayed and returned the configured impact value the natural "
            "request does not return"
        )
        self.cspt_legend_label.setObjectName("csptLegend")
        self.cspt_legend_label.setTextFormat(Qt.RichText)
        self.cspt_legend_label.setWordWrap(True)
        layout.addWidget(self.cspt_legend_label)
        return strip

    def _build_cspt_pairs_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 6, 0, 0)
        layout.setSpacing(6)

        bar = QWidget()
        row = QHBoxLayout(bar)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(6)
        self.cspt_search = QLineEdit()
        self.cspt_search.setPlaceholderText(
            "Filter path, payload, identity, inject point or state")
        self.cspt_search.setClearButtonEnabled(True)
        self.cspt_search.setMinimumWidth(0)
        self.cspt_tier_combo = QComboBox()
        self.cspt_tier_combo.setObjectName("filterCombo")
        self.cspt_tier_combo.addItems(["All tiers"] + list(CSPT_TIERS))
        self.cspt_count_label = QLabel("0 of 0")
        self.cspt_count_label.setObjectName("opsSecondary")
        reset_button = QPushButton("Reset")
        reset_button.setObjectName("btnGhost")
        reset_button.clicked.connect(self._reset_cspt_filter)
        self.cspt_search.textChanged.connect(self._render_cspt_pairs)
        self.cspt_tier_combo.currentIndexChanged.connect(
            self._render_cspt_pairs)
        row.addWidget(self.cspt_search, 1)
        row.addWidget(self.cspt_tier_combo)
        row.addWidget(reset_button)
        row.addWidget(self.cspt_count_label)
        layout.addWidget(bar)

        self.cspt_pairs_table = QTableWidget(0, 7)
        self.cspt_pairs_table.setHorizontalHeaderLabels([
            "Tier", "Identity", "Inject", "Natural path", "Resolved path",
            "Status", "State",
        ])
        header = self.cspt_pairs_table.horizontalHeader()
        # Tier and state carry the grading signal; the two paths absorb the
        # width, and a payload this long would otherwise crush everything.
        for column in (0, 1, 2, 5, 6):
            header.setSectionResizeMode(column, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        header.setSectionResizeMode(4, QHeaderView.Stretch)
        header.setStretchLastSection(False)
        self.cspt_pairs_table.setSelectionBehavior(
            QAbstractItemView.SelectRows)
        self.cspt_pairs_table.setSelectionMode(
            QAbstractItemView.SingleSelection)
        self.cspt_pairs_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.cspt_pairs_table.setSortingEnabled(False)
        self.cspt_pairs_table.verticalHeader().setVisible(False)
        self.cspt_pairs_table.currentCellChanged.connect(
            self._on_cspt_pair_changed)
        layout.addWidget(self.cspt_pairs_table, 1)
        return page

    def _reset_cspt_filter(self):
        self.cspt_search.clear()
        self.cspt_tier_combo.setCurrentIndex(0)

    def _build_cspt_impacts_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 6, 0, 0)
        layout.setSpacing(6)
        note = QLabel(
            "One row per replay the framework made itself: the altered URL, "
            "the natural URL and an absent-reference control. A row here is "
            "the only thing that turns a candidate into a proof.")
        note.setObjectName("csptWarning")
        note.setWordWrap(True)
        layout.addWidget(note)
        self.cspt_impacts_table = QTableWidget(0, 6)
        self.cspt_impacts_table.setHorizontalHeaderLabels([
            "Resolved path", "Expected", "Observed", "Natural status",
            "Absent-ref control", "Module",
        ])
        impact_header = self.cspt_impacts_table.horizontalHeader()
        for column in (1, 2, 3, 4, 5):
            impact_header.setSectionResizeMode(
                column, QHeaderView.ResizeToContents)
        impact_header.setSectionResizeMode(0, QHeaderView.Stretch)
        impact_header.setStretchLastSection(False)
        self.cspt_impacts_table.setSelectionBehavior(
            QAbstractItemView.SelectRows)
        self.cspt_impacts_table.setSelectionMode(
            QAbstractItemView.SingleSelection)
        self.cspt_impacts_table.setEditTriggers(
            QAbstractItemView.NoEditTriggers)
        self.cspt_impacts_table.setSortingEnabled(False)
        self.cspt_impacts_table.verticalHeader().setVisible(False)
        self.cspt_impacts_table.currentCellChanged.connect(
            self._on_cspt_impact_changed)
        layout.addWidget(self.cspt_impacts_table, 1)
        return page

    def _build_cspt_coverage_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 6, 0, 0)
        layout.setSpacing(6)
        note = QLabel(
            "Targets the run never drove. An empty matrix is not a clean "
            "matrix if nothing was reached.")
        note.setObjectName("csptWarning")
        note.setWordWrap(True)
        layout.addWidget(note)
        self.cspt_gap_table = QTableWidget(0, 2)
        self.cspt_gap_table.setHorizontalHeaderLabels(["Target", "Why"])
        gap_header = self.cspt_gap_table.horizontalHeader()
        gap_header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        gap_header.setSectionResizeMode(0, QHeaderView.Stretch)
        gap_header.setStretchLastSection(False)
        self.cspt_gap_table.setSelectionBehavior(
            QAbstractItemView.SelectRows)
        self.cspt_gap_table.setSelectionMode(
            QAbstractItemView.SingleSelection)
        self.cspt_gap_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.cspt_gap_table.setSortingEnabled(False)
        self.cspt_gap_table.verticalHeader().setVisible(False)
        self.cspt_gap_note = QLabel("nothing left untested by the last run")
        self.cspt_gap_note.setObjectName("csptProofState")
        self.cspt_gap_note.setProperty("tone", "ok")
        self.cspt_gap_note.setWordWrap(True)
        layout.addWidget(self.cspt_gap_note)
        layout.addWidget(self.cspt_gap_table, 1)
        return page

    def _build_cspt_plan_panel(self) -> QWidget:
        panel = QFrame()
        panel.setObjectName("sidePanel")
        panel.setMinimumWidth(0)
        outer = QVBoxLayout(panel)
        outer.setSpacing(12)

        scroll = QScrollArea()
        scroll.setObjectName("sideScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        body = QWidget()
        layout = QVBoxLayout(body)
        layout.setSpacing(12)
        scroll.setWidget(body)

        gate_box = QGroupBox("Browser gate")
        gate_layout = QVBoxLayout(gate_box)
        gate_layout.setSpacing(6)
        self.cspt_enabled_check = QCheckBox(
            "Client-side path traversal (cspt_audit)")
        self.cspt_enabled_check.setToolTip("modules.cspt_audit.enabled")
        self.cspt_enabled_check.toggled.connect(self._update_cspt_state_label)
        gate_layout.addWidget(self.cspt_enabled_check)
        gate_warning = QLabel(
            "This opens a real browser on the target and navigates it with "
            "traversal payloads in the URL. It is read-only: it never seeds "
            "state, so an escape is graded by what a replay can read back.")
        gate_warning.setObjectName("csptWarning")
        gate_warning.setWordWrap(True)
        gate_layout.addWidget(gate_warning)
        layout.addWidget(gate_box)

        plan_box = QGroupBox("Run plan")
        plan_form = QFormLayout(plan_box)
        plan_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.cspt_max_targets_spin = QSpinBox()
        self.cspt_max_targets_spin.setRange(1, 50)
        self.cspt_max_targets_spin.setValue(3)
        self.cspt_max_targets_spin.setToolTip(
            "modules.cspt_audit.max_targets — pages driven per run")
        self.cspt_max_payloads_spin = QSpinBox()
        self.cspt_max_payloads_spin.setRange(1, 60)
        self.cspt_max_payloads_spin.setValue(6)
        self.cspt_max_payloads_spin.setToolTip(
            "modules.cspt_audit.max_payloads — payload navigations per "
            "inject point")
        self.cspt_wait_spin = QSpinBox()
        self.cspt_wait_spin.setRange(0, 10000)
        self.cspt_wait_spin.setSingleStep(100)
        self.cspt_wait_spin.setValue(1200)
        self.cspt_wait_spin.setToolTip(
            "modules.cspt_audit.wait_ms — settle time per navigation; too "
            "low and the XHR is missed, which reads as not reached")
        plan_form.addRow("Max targets", self.cspt_max_targets_spin)
        plan_form.addRow("Max payloads", self.cspt_max_payloads_spin)
        plan_form.addRow("Settle (ms)", self.cspt_wait_spin)
        points_box = QGroupBox("Inject into")
        points_layout = QHBoxLayout(points_box)
        points_layout.setSpacing(8)
        self.cspt_point_checks: dict[str, QCheckBox] = {}
        for point in CSPT_INJECT_POINTS:
            check = QCheckBox(point)
            check.setToolTip(f"modules.cspt_audit.inject_points — {point}")
            points_layout.addWidget(check)
            self.cspt_point_checks[point] = check
        plan_form.addRow(points_box)
        self.cspt_probe_check = QCheckBox("Impact probe (replay the altered URL)")
        self.cspt_probe_check.setToolTip(
            "modules.cspt_audit.impact_probe.enabled — without it an altered "
            "path stays a candidate; this is the only path to PROOF")
        self.cspt_probe_check.toggled.connect(self._update_cspt_state_label)
        plan_form.addRow(self.cspt_probe_check)
        layout.addWidget(plan_box)

        depth_box = QGroupBox("Configured depth")
        depth_layout = QVBoxLayout(depth_box)
        depth_layout.setSpacing(6)
        self.cspt_driver_label = QLabel("-")
        self.cspt_names_label = QLabel("-")
        self.cspt_route_label = QLabel("-")
        self.cspt_expect_label = QLabel("-")
        # The expectation echo escapes the operator's own JSON, so this label
        # must parse as rich text or the escaped quotes show up literally.
        self.cspt_expect_label.setTextFormat(Qt.RichText)
        self.cspt_identity_label = QLabel("-")
        for widget in (self.cspt_driver_label, self.cspt_names_label,
                       self.cspt_route_label, self.cspt_expect_label,
                       self.cspt_identity_label):
            widget.setObjectName("csptProofState")
            widget.setWordWrap(True)
            widget.setTextInteractionFlags(Qt.TextSelectableByMouse)
            depth_layout.addWidget(widget)
        depth_hint = QLabel(
            "Payload names, sibling routes and the impact expectation are "
            "structured YAML — edit them on the Raw YAML screen.")
        depth_hint.setObjectName("csptWarning")
        depth_hint.setWordWrap(True)
        depth_layout.addWidget(depth_hint)
        layout.addWidget(depth_box)

        actions_box = QGroupBox("Actions")
        actions_layout = QVBoxLayout(actions_box)
        actions_layout.setSpacing(6)
        self.cspt_save_button = QPushButton("Save CSPT plan")
        self.cspt_save_button.setObjectName("btnPrimary")
        self.cspt_save_button.clicked.connect(self._save_cspt_plan)
        actions_layout.addWidget(self.cspt_save_button)
        self.cspt_run_button = QPushButton("Run CSPT audit")
        self.cspt_run_button.setObjectName("btnGhost")
        self.cspt_run_button.clicked.connect(self._run_cspt_pass)
        actions_layout.addWidget(self.cspt_run_button)
        settings_button = QPushButton("Open traversal spec")
        settings_button.setObjectName("btnGhost")
        settings_button.setToolTip("Jump to Raw YAML for inject names, "
                                   "sibling routes and the impact expectation")
        settings_button.clicked.connect(self._open_raw_settings)
        actions_layout.addWidget(settings_button)
        layout.addWidget(actions_box)
        layout.addStretch(1)

        outer.addWidget(scroll)
        return panel

    def _build_cspt_detail(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("csptDetail")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(8)

        head = QHBoxLayout()
        head.setSpacing(8)
        self.cspt_detail_title = QLabel("No inject point selected")
        self.cspt_detail_title.setObjectName("csptDetailTitle")
        self.cspt_detail_title.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.cspt_open_evidence_button = QPushButton("Open evidence")
        self.cspt_open_evidence_button.setObjectName("btnGhost")
        self.cspt_open_evidence_button.setEnabled(False)
        self.cspt_open_evidence_button.clicked.connect(
            self._open_cspt_evidence)
        self.cspt_open_finding_button = QPushButton("Open in Triage")
        self.cspt_open_finding_button.setObjectName("btnGhost")
        self.cspt_open_finding_button.setEnabled(False)
        self.cspt_open_finding_button.clicked.connect(
            self._open_cspt_finding)
        self.cspt_copy_url_button = QPushButton("Copy altered URL")
        self.cspt_copy_url_button.setObjectName("btnGhost")
        self.cspt_copy_url_button.setEnabled(False)
        self.cspt_copy_url_button.clicked.connect(self._copy_cspt_url)
        head.addWidget(self.cspt_detail_title, 1)
        head.addWidget(self.cspt_copy_url_button)
        head.addWidget(self.cspt_open_evidence_button)
        head.addWidget(self.cspt_open_finding_button)
        layout.addLayout(head)

        self.cspt_detail_body = QTextEdit()
        self.cspt_detail_body.setReadOnly(True)
        self.cspt_detail_body.setObjectName("csptDetailBody")
        self.cspt_detail_body.setFont(code_font(12))
        self.cspt_detail_body.setPlaceholderText(
            "Select an inject point to see what was injected, what the "
            "browser actually requested, and what that does — and does not — "
            "prove.")
        layout.addWidget(self.cspt_detail_body, 1)
        return frame

    # ---- I4 screen data ---------------------------------------------------

    MAX_CSPT_REPORTS = 40

    def _load_cspt_view(self):
        """Fill the I4 screen from the stores load_results just read."""
        evidence_items = (self.current_evidence.get("items", [])
                          if isinstance(self.current_evidence, dict) else [])
        if not isinstance(evidence_items, list):
            evidence_items = []
        reports, unreadable, truncated = self._cspt_reports(evidence_items)
        impacts = self._cspt_impacts(evidence_items)
        pairs = self._cspt_pairs(reports, impacts)
        gaps = self._cspt_gaps(reports)
        self._cspt_pair_rows = pairs
        self._cspt_impact_rows = impacts
        self._cspt_gap_rows = gaps

        proven = {row["probe_url"] for row in pairs if row["tier"] == "PROOF"}
        targets = {str(target) for report in reports
                   for target in report["targets"]}
        if not targets:
            # Reports written before the engine recorded target lists have
            # to fall back to where the pairs actually came from, or the
            # card would read zero over a screen full of results.
            targets = {row["target"] for row in pairs if row["target"]}
        self.cspt_targets_value.setText(str(len(targets)))
        self.cspt_points_value.setText(str(len(pairs)))
        self.cspt_altered_value.setText(str(
            sum(1 for row in pairs if row["state"] == "path_altered")))
        self.cspt_proofs_value.setText(str(len(proven)))
        self.cspt_look_value.setText(str(
            sum(1 for row in pairs if row["tier"] == "OBSERVATION")
            + len(gaps)))
        self.cspt_gap_value.setText(str(len(gaps)))
        modules = sorted({row["module"] for row in pairs} |
                         {row["module"] for row in impacts})
        if modules:
            self.cspt_run_label.setText(
                f"CSPT run loaded from {', '.join(modules)} · "
                f"{len(proven)} replay-confirmed escape(s)")
        else:
            self.cspt_run_label.setText("no cspt run loaded")
        self._render_cspt_pairs()
        self._render_cspt_impacts()
        self._render_cspt_gaps()
        self._refresh_cspt_badge()
        notes = []
        if truncated:
            notes.append(
                f"only the first {self.MAX_CSPT_REPORTS} CSPT report(s) parsed")
        if unreadable:
            notes.append(f"{unreadable} CSPT payload(s) unreadable")
        # Nothing is said when the run is simply absent: every screen loading
        # a message would leave only the last one readable, and "no CSPT run"
        # is already on the strip.
        if notes:
            self.statusBar().showMessage(
                "CSPT view is partial: " + "; ".join(notes), 8000)

    def _cspt_reports(self, evidence_items: list) -> tuple[list[dict], int, bool]:
        relevant = [item for item in evidence_items
                    if isinstance(item, dict)
                    and item.get("type") == CSPT_EVIDENCE_TYPE]
        truncated = len(relevant) > self.MAX_CSPT_REPORTS
        docs, unreadable = self._read_evidence_payloads(
            relevant, CSPT_EVIDENCE_TYPE, self.MAX_CSPT_REPORTS)
        reports: list[dict] = []
        for entry in docs:
            data = entry["doc"].get("data")
            if not isinstance(data, dict):
                unreadable += 1
                continue
            item = entry["item"]
            reports.append({
                "module": str(item.get("module_id") or ""),
                "evidence_id": str(item.get("id") or ""),
                "evidence_path": str(item.get("path") or ""),
                "run_token": str(data.get("run_token") or ""),
                "targets": data.get("targets")
                if isinstance(data.get("targets"), list) else [],
                "pairs": data.get("pairs")
                if isinstance(data.get("pairs"), list) else [],
                "untested": data.get("untested")
                if isinstance(data.get("untested"), list) else [],
            })
        return reports, unreadable, truncated

    def _cspt_impacts(self, evidence_items: list) -> list[dict]:
        relevant = [item for item in evidence_items
                    if isinstance(item, dict)
                    and item.get("type") == CSPT_IMPACT_TYPE]
        docs, _ = self._read_evidence_payloads(
            relevant, CSPT_IMPACT_TYPE, self.MAX_CSPT_REPORTS)
        rows: list[dict] = []
        for entry in docs:
            data = entry["doc"].get("data")
            # add_evidence stores the impact dict itself, not under "data".
            payload = data if isinstance(data, dict) else entry["doc"]
            probe_url = str(payload.get("probe_url") or "")
            if not probe_url:
                continue
            item = entry["item"]
            rows.append({
                "kind": "impact",
                "module": str(item.get("module_id") or ""),
                "evidence_id": str(item.get("id") or ""),
                "evidence_path": str(item.get("path") or ""),
                "natural_url": str(payload.get("natural_url") or ""),
                "probe_url": probe_url,
                "resolved_path": str(payload.get("resolved_path") or ""),
                "observed": payload.get("observed"),
                "expectation": payload.get("expectation"),
                "baseline_status": payload.get("baseline_status", ""),
                "catch_all": bool(payload.get("control_same_shape")),
                "finding_id": "",
                "finding_title": "",
            })
        findings = self.current_findings if isinstance(self.current_findings,
                                                      list) else []
        by_url = self._cspt_finding_index(findings)
        for row in rows:
            finding = by_url.get(row["probe_url"])
            if finding is not None:
                row["finding_id"] = str(finding.get("id") or "")
                row["finding_title"] = str(finding.get("title") or "")
        return rows

    @staticmethod
    def _cspt_finding_index(findings: list) -> dict:
        """Findings cite the altered URL — that is the only key that ties a
        finding back to one inject point row."""
        by_url: dict[str, dict] = {}
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            if str(finding.get("category") or "") != CSPT_FINDING_CATEGORY:
                continue
            for entry in finding.get("evidence") or []:
                text = str(entry)
                if text.startswith("altered:"):
                    by_url.setdefault(text.split(":", 1)[1], finding)
        return by_url

    def _cspt_pairs(self, reports: list[dict], impacts: list[dict]) -> list[dict]:
        by_url = self._cspt_finding_index(
            self.current_findings if isinstance(self.current_findings, list)
            else [])
        proven_urls = {row["probe_url"] for row in impacts}
        impact_by_url: dict[str, dict] = {}
        for row in impacts:
            impact_by_url.setdefault(row["probe_url"], row)
        rows: list[dict] = []
        for report in reports:
            for pair in report["pairs"]:
                if not isinstance(pair, dict):
                    continue
                state = str(pair.get("state") or "")
                tier = CSPT_STATE_TIER.get(state, "OBSERVATION")
                probe_url = str(pair.get("probe_url") or "")
                if tier == "CANDIDATE" and probe_url in proven_urls:
                    tier = "PROOF"
                impact = impact_by_url.get(probe_url)
                finding = by_url.get(probe_url)
                rows.append({
                    "kind": "pair",
                    "tier": tier,
                    "module": report["module"],
                    "identity": str(pair.get("identity") or "-"),
                    "point": str(pair.get("point") or ""),
                    "name": str(pair.get("name") or ""),
                    "state": state,
                    "natural_path": str(pair.get("natural_path") or ""),
                    "probe_path": str(pair.get("probe_path") or ""),
                    "prefix": pair.get("prefix")
                    if isinstance(pair.get("prefix"), list) else [],
                    "effects": pair.get("effect_segments")
                    if isinstance(pair.get("effect_segments"), list) else [],
                    "payload": str(pair.get("payload") or ""),
                    "status": str(pair.get("status", "") or ""),
                    "natural_url": str(pair.get("natural_url") or ""),
                    "probe_url": probe_url,
                    "target": str(pair.get("target") or ""),
                    "run_token": report["run_token"],
                    "evidence_id": report["evidence_id"],
                    "evidence_path": report["evidence_path"],
                    "finding_id": str(finding.get("id") or "") if finding else "",
                    "finding_title": str(finding.get("title") or "") if finding else "",
                    "impact": impact,
                })
        rows.sort(key=lambda row: (
            CSPT_TIER_RANK.get(row["tier"], 9), row["identity"],
            row["point"], row["natural_path"]))
        return rows

    def _cspt_gaps(self, reports: list[dict]) -> list[dict]:
        rows = []
        for report in reports:
            for entry in report["untested"]:
                if not isinstance(entry, dict):
                    continue
                rows.append({
                    "kind": "gap",
                    "target": str(entry.get("target") or "-"),
                    "reason": str(entry.get("reason") or "-"),
                    "module": report["module"],
                    "evidence_id": report["evidence_id"],
                    "evidence_path": report["evidence_path"],
                })
        return rows

    def _render_cspt_pairs(self, *_args):
        table = self.cspt_pairs_table
        query = self.cspt_search.text().strip().lower()
        tier = (self.cspt_tier_combo.currentText()
                if self.cspt_tier_combo.currentIndex() > 0 else "")
        rows = getattr(self, "_cspt_pair_rows", [])
        visible = [
            row for row in rows
            if (not tier or row["tier"] == tier)
            and (not query or query in " ".join((
                row["identity"], self._inject_label(row), row["natural_path"],
                row["probe_path"], row["payload"], row["state"])).lower())
        ]
        # The filtered slice has to be remembered: detail lookup is by row.
        self._cspt_visible_pairs = visible
        table.setRowCount(len(visible))
        for index, row in enumerate(visible):
            values = (row["tier"], row["identity"], self._inject_label(row),
                      row["natural_path"], row["probe_path"], row["status"],
                      row["state"])
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 0:
                    color = CSPT_TIER_COLORS.get(value)
                    if color:
                        item.setForeground(QColor(color))
                        font = item.font()
                        font.setBold(True)
                        item.setFont(font)
                item.setToolTip(value)
                table.setItem(index, column, item)
        self.cspt_count_label.setText(f"{len(visible)} of {len(rows)}")
        if not visible:
            self._render_cspt_detail(None)

    def _render_cspt_impacts(self, *_args):
        table = self.cspt_impacts_table
        rows = getattr(self, "_cspt_impact_rows", [])
        table.setRowCount(len(rows))
        for index, row in enumerate(rows):
            control = "SAME SHAPE" if row["catch_all"] else "different shape"
            values = (
                row["resolved_path"] or "-",
                json.dumps(row["expectation"])
                if row["expectation"] not in (None, "") else "-",
                json.dumps(row["observed"])
                if row["observed"] not in (None, "") else "-",
                str(row["baseline_status"] or "-"),
                control,
                row["module"] or "-",
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 4:
                    item.setForeground(
                        QColor("#fdba74" if row["catch_all"] else "#4ade80"))
                if column == 2:
                    font = item.font()
                    font.setBold(True)
                    item.setFont(font)
                item.setToolTip(value)
                table.setItem(index, column, item)
        if not rows:
            self._render_cspt_detail(None)

    def _render_cspt_gaps(self, *_args):
        table = self.cspt_gap_table
        rows = getattr(self, "_cspt_gap_rows", [])
        table.setRowCount(len(rows))
        for index, row in enumerate(rows):
            for column, value in enumerate((row["target"], row["reason"])):
                item = QTableWidgetItem(value)
                if column == 1:
                    item.setForeground(QColor("#fdba74"))
                item.setToolTip(value)
                table.setItem(index, column, item)
        tone = "ok" if not rows else "warn"
        self.cspt_gap_note.setProperty("tone", tone)
        self.cspt_gap_note.setText(
            "nothing left untested by the last run" if not rows
            else f"{len(rows)} target(s) the last run never drove")
        self.cspt_gap_note.style().unpolish(self.cspt_gap_note)
        self.cspt_gap_note.style().polish(self.cspt_gap_note)

    def _on_cspt_pair_changed(self, row: int, *_args):
        rows = getattr(self, "_cspt_visible_pairs", [])
        self._render_cspt_detail(rows[row] if 0 <= row < len(rows) else None)

    def _on_cspt_impact_changed(self, row: int, *_args):
        rows = getattr(self, "_cspt_impact_rows", [])
        if not (0 <= row < len(rows)):
            self._render_cspt_detail(None)
            return
        impact = rows[row]
        match = next((pair for pair in getattr(self, "_cspt_pair_rows", [])
                      if pair["probe_url"] == impact["probe_url"]), None)
        if match is not None:
            self._render_cspt_detail(match)
            return
        # A replay the browser pass never paired with a row (the report was
        # truncated, or a later run rewrote it) still has to be readable.
        self._render_cspt_detail({
            "kind": "impact", "tier": "PROOF", "module": impact["module"],
            "identity": "-", "point": "", "name": "",
            "state": "path_altered", "natural_path": impact["natural_url"],
            "probe_path": impact["resolved_path"], "prefix": [],
            "effects": [], "payload": "", "status": "", "target": "",
            "run_token": "", "natural_url": impact["natural_url"],
            "probe_url": impact["probe_url"], "impact": impact,
            "evidence_id": impact["evidence_id"],
            "evidence_path": impact["evidence_path"],
            "finding_id": impact["finding_id"],
            "finding_title": impact["finding_title"],
        })

    def _render_cspt_detail(self, row: dict | None):
        self._cspt_detail_row = row
        if not row:
            self.cspt_detail_title.setText("No inject point selected")
            self.cspt_detail_body.clear()
            self.cspt_open_evidence_button.setEnabled(False)
            self.cspt_open_finding_button.setEnabled(False)
            self.cspt_copy_url_button.setEnabled(False)
            return
        tier = row.get("tier", "OBSERVATION")
        color = CSPT_TIER_COLORS.get(tier, "#d8e2ea")
        kind = row.get("kind", "pair")
        if kind == "impact":
            self.cspt_detail_title.setText(
                f"{tier} · impact replay · {row.get('resolved_path') or '-'}")
        else:
            self.cspt_detail_title.setText(
                f"{tier} · {row.get('identity') or '-'} via "
                f"{self._inject_label(row)} → {row.get('probe_path') or row.get('state') or '-'}")
        parts = [
            f"<b style='color:{color}'>{html_escape(tier)}</b> — "
            f"{html_escape(CSPT_TIER_MEANING.get(tier, ''))}",
            "",
            f"<b>Module</b> {html_escape(row.get('module') or '-')}",
            f"<b>Target</b> {html_escape(row.get('target') or '-')}",
            f"<b>Identity</b> {html_escape(row.get('identity') or '-')}",
            f"<b>Inject</b> {html_escape(self._inject_label(row))}",
            f"<b>State</b> {html_escape(row.get('state') or '-')}",
            f"<b>Natural path</b> {html_escape(row.get('natural_path') or '-')}",
            f"<b>Resolved path</b> {html_escape(row.get('probe_path') or '-')}",
            f"<b>Natural prefix</b> "
            f"{html_escape('/'.join(str(p) for p in row.get('prefix') or []) or '-')}",
            f"<b>Effect segments</b> "
            f"{html_escape(', '.join(str(e) for e in row.get('effects') or []) or 'none')}",
            f"<b>Status</b> {html_escape(str(row.get('status') or '-'))}",
            f"<b>Run token</b> {html_escape(row.get('run_token') or '-')}",
        ]
        payload = row.get("payload") or ""
        if payload:
            parts.append(f"<b>Payload</b> <span style='font-family:monospace'>"
                         f"{html_escape(payload)}</span>")
        natural_url = row.get("natural_url") or ""
        probe_url = row.get("probe_url") or ""
        if natural_url:
            parts.append(f"<b>Natural URL</b> {html_escape(natural_url)}")
        if probe_url:
            parts.append(f"<b>Altered URL</b> {html_escape(probe_url)}")
        impact = row.get("impact")
        if impact:
            parts += [
                "",
                f"<b>Impact replay</b> expected "
                f"{html_escape(json.dumps(impact['expectation']))}, observed "
                f"{html_escape(json.dumps(impact['observed']))} — natural "
                f"status {html_escape(str(impact['baseline_status'] or '-'))}",
            ]
            if impact["catch_all"]:
                parts.append(
                    "<b style='color:#fdba74'>Catch-all control</b> — the "
                    "absent-reference URL came back the same shape as the "
                    "altered one, so this replay cannot prove access.")
        if tier == "CANDIDATE":
            parts += [
                "",
                "<b>Still needed</b> an impact probe with a configured "
                "expectation — until the altered URL is replayed and returns "
                "something the natural URL does not, this is a candidate, not "
                "a proven traversal.",
            ]
        elif tier == "OBSERVATION":
            parts += [
                "",
                "<b>Unproven</b> — the injected value never appeared in an "
                "XHR/fetch request, so the app may not have used this input "
                "at all. Raising settle time or picking a live parameter "
                "name is what turns this into a real test.",
            ]
        elif tier == "HEALTHY":
            parts += [
                "",
                "<b>No signal</b> — the value reached a request and the "
                "resolved path stayed under the natural prefix.",
            ]
        finding_line = (
            f"{html_escape(row.get('finding_id') or '')} — "
            f"{html_escape(row.get('finding_title') or '')}"
            if row.get("finding_id") else "none filed")
        parts += ["", f"<b>Finding</b> {finding_line}"]
        self.cspt_detail_body.setHtml("<br>".join(parts))
        self.cspt_open_evidence_button.setEnabled(bool(
            row.get("evidence_path")))
        self.cspt_open_finding_button.setEnabled(bool(row.get("finding_id")))
        self.cspt_copy_url_button.setEnabled(bool(probe_url))

    def _copy_cspt_url(self):
        row = self._cspt_selected_detail_row()
        url = str((row or {}).get("probe_url") or "")
        if not url:
            return
        QApplication.clipboard().setText(url)
        self.statusBar().showMessage("Altered URL copied", 3000)

    def _open_cspt_evidence(self):
        row = self._cspt_selected_detail_row()
        if not row or not row.get("evidence_path"):
            return
        path = self._assessment_dir() / row["evidence_path"]
        if path.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))
        else:
            self.statusBar().showMessage("Evidence file is gone", 3000)

    def _open_cspt_finding(self):
        row = self._cspt_selected_detail_row()
        if not row or not row.get("finding_id"):
            return
        self.finding_search.setText(row["finding_id"])
        self.show_screen(self._screen_index("triage"))

    def _cspt_selected_detail_row(self) -> dict | None:
        """Whatever the detail pane is currently showing."""
        return getattr(self, "_cspt_detail_row", None)

    def _refresh_cspt_badge(self):
        index = self._screen_index("cspt")
        count = sum(
            1 for row in getattr(self, "_cspt_pair_rows", [])
            if row["tier"] in ("PROOF", "CANDIDATE"))
        if 0 <= index < len(self.nav_buttons):
            self._set_nav_badge(index, count, "CSPT row(s) worth a look")

    # ---- I4 plan: config round trip and run -------------------------------

    def _apply_cspt_plan(self, config: dict):
        cfg = self._module_section(config or {}, CSPT_MODULE_ID)
        # Cached for the checkbox handlers: this panel edits scalars only, so
        # the nested expect/equals it reports on stay valid until the next
        # config load.
        self._cspt_section = cfg
        self.cspt_enabled_check.setChecked(bool(cfg.get("enabled")))
        self.cspt_probe_check.setChecked(bool(
            (cfg.get("impact_probe") or {}).get("enabled", True)))
        self._note_spin_clamp(
            self._set_spin(self.cspt_max_targets_spin,
                           cfg.get("max_targets"), 3),
            "cspt_audit max_targets")
        self._note_spin_clamp(
            self._set_spin(self.cspt_max_payloads_spin,
                           cfg.get("max_payloads"), 6),
            "cspt_audit max_payloads")
        self._note_spin_clamp(
            self._set_spin(self.cspt_wait_spin, cfg.get("wait_ms"), 1200),
            "cspt_audit wait_ms")
        raw_points = cfg.get("inject_points")
        points = [str(p) for p in raw_points] if isinstance(raw_points, list) \
            else ["query", "fragment"]
        for point, check in self.cspt_point_checks.items():
            check.setChecked(point in points)
        self._render_cspt_depth(cfg)
        self._update_cspt_state_label()

    def _render_cspt_depth(self, cfg: dict) -> None:
        """What the panel deliberately does not edit — and whether the proof
        path exists at all."""
        if _browser_driver_present():
            self.cspt_driver_label.setText("Browser driver: Playwright present")
            self.cspt_driver_label.setProperty("tone", "ok")
        else:
            self.cspt_driver_label.setText(
                "Browser driver: Playwright missing — cspt_audit skips itself "
                "until it is installed")
            self.cspt_driver_label.setProperty("tone", "warn")

        raw_names = cfg.get("inject_names")
        names = [str(n) for n in raw_names] if isinstance(raw_names, list) else []
        self.cspt_names_label.setText(
            f"Inject names: {', '.join(names[:3])}" if names else
            "Inject names: not set — the engine tries r, path, file, url")
        self.cspt_names_label.setProperty("tone", "ok" if names else "warn")

        route = cfg.get("canary_route")
        route = route if isinstance(route, dict) else {}
        raw_siblings = route.get("sibling_paths")
        siblings = [str(s) for s in raw_siblings] \
            if isinstance(raw_siblings, list) else []
        raw_hints = route.get("hint_segments")
        hints = [str(h) for h in raw_hints] \
            if isinstance(raw_hints, list) and raw_hints else \
            ["admin", "internal", "secrets", "users", "export"]
        self.cspt_route_label.setText(
            f"Sibling routes: {', '.join(siblings)}" if siblings else
            "Sibling routes: none — guessing " + " ".join(hints[:5]))
        self.cspt_route_label.setProperty("tone", "ok" if siblings else "warn")

        self._render_cspt_expectation(cfg)

        identities = [str(record.get("name")) for record in self._identity_records
                      if isinstance(record, dict) and record.get("name")]
        try:
            max_identities = int(cfg.get("max_identities", 2) or 2)
        except (TypeError, ValueError):
            max_identities = 2
        anonymous = bool(cfg.get("allow_anonymous"))
        if identities:
            self.cspt_identity_label.setText(
                f"Identities: {', '.join(identities)} — first "
                f"{max(1, min(max_identities, len(identities)))} probed "
                "alongside anonymous")
            self.cspt_identity_label.setProperty("tone", "ok")
        elif anonymous:
            self.cspt_identity_label.setText(
                "Identities: none — anonymous only (allow_anonymous is true)")
            self.cspt_identity_label.setProperty("tone", "ok")
        else:
            self.cspt_identity_label.setText(
                "Identities: none and allow_anonymous is false — the module "
                "will skip before it opens a browser")
            self.cspt_identity_label.setProperty("tone", "warn")
        for label in (self.cspt_driver_label, self.cspt_names_label,
                      self.cspt_route_label, self.cspt_expect_label,
                      self.cspt_identity_label):
            label.style().unpolish(label)
            label.style().polish(label)

    def _render_cspt_expectation(self, cfg: dict) -> None:
        """An altered path only becomes a proof when the replay has something
        configured to look for; say so instead of implying otherwise."""
        probe = cfg.get("impact_probe")
        probe = probe if isinstance(probe, dict) else {}
        expect = probe.get("expect")
        equals = str(probe.get("equals") or "")
        enabled = self.cspt_probe_check.isChecked()
        has_expect = isinstance(expect, dict) and bool(expect)
        if not enabled:
            text = "Impact probe: off — an altered path stays a candidate"
        elif has_expect and equals:
            text = (f"Impact probe: on — expects "
                    f"{html_escape(json.dumps(expect))} to equal "
                    f"{html_escape(json.dumps(equals))}")
        else:
            missing = []
            if not has_expect:
                missing.append("expect")
            if not equals:
                missing.append("equals")
            text = ("Impact probe: on but " + " and ".join(missing) +
                    " not configured — nothing on this screen can reach PROOF")
        self.cspt_expect_label.setText(text)
        self.cspt_expect_label.setProperty(
            "tone", "ok" if self._cspt_proof_ready(cfg) else "warn")
        self.cspt_expect_label.style().unpolish(self.cspt_expect_label)
        self.cspt_expect_label.style().polish(self.cspt_expect_label)

    def _cspt_proof_ready(self, section: dict | None = None) -> bool:
        """Both halves of a proof have to be configured: the replay switch and
        the value that replay is looking for."""
        section = section if section is not None \
            else getattr(self, "_cspt_section", {})
        probe = section.get("impact_probe")
        probe = probe if isinstance(probe, dict) else {}
        if not self.cspt_probe_check.isChecked():
            return False
        expect = probe.get("expect")
        return bool(isinstance(expect, dict) and expect
                    and str(probe.get("equals") or ""))

    def _selected_cspt_points(self) -> list[str]:
        return [point for point in CSPT_INJECT_POINTS
                if self.cspt_point_checks[point].isChecked()]

    def _update_cspt_state_label(self, *_args):
        enabled = self.cspt_enabled_check.isChecked()
        self.cspt_state_label.setText(
            "module enabled" if enabled else "module disabled")
        self.cspt_state_label.setProperty("state", "ok" if enabled else "idle")
        self.cspt_state_label.style().unpolish(self.cspt_state_label)
        self.cspt_state_label.style().polish(self.cspt_state_label)
        # The expectation label reads the probe checkbox, so it refreshes
        # here instead of only on a config load.
        self._render_cspt_expectation(getattr(self, "_cspt_section", {}))

    def _save_cspt_plan(self) -> bool:
        points = self._selected_cspt_points()
        if not points:
            QMessageBox.warning(
                self, "No Inject Point",
                "modules.cspt_audit.inject_points cannot be empty — with no "
                "point ticked the engine silently falls back to query and "
                "fragment, which is not the plan you just saved. Tick at "
                "least one.",
            )
            return False
        config = self._read_config()
        section = self._ensure_module_section(config, CSPT_MODULE_ID)
        section["enabled"] = self.cspt_enabled_check.isChecked()
        section["max_targets"] = self.cspt_max_targets_spin.value()
        section["max_payloads"] = self.cspt_max_payloads_spin.value()
        section["wait_ms"] = self.cspt_wait_spin.value()
        section["inject_points"] = points
        # Read-modify-write: expect and equals are nested and belong to the
        # operator's YAML, so only the switch is rewritten here.
        probe = section.get("impact_probe")
        probe = probe if isinstance(probe, dict) else {}
        probe["enabled"] = self.cspt_probe_check.isChecked()
        section["impact_probe"] = probe
        caveat = ""
        if not self._cspt_proof_ready(section):
            caveat = (" — with no expect/equals configured, an escape stays "
                      "a candidate (modules.cspt_audit.impact_probe in Raw "
                      "YAML)")
        if not self._write_config(config):
            return False
        self._cspt_section = section
        self._update_cspt_state_label()
        self.statusBar().showMessage(
            f"CSPT plan saved to {self.config_path.name}{caveat}", 9000)
        return True

    def _run_cspt_pass(self):
        if self.process and self.process.state() != QProcess.NotRunning:
            self.statusBar().showMessage(
                "Already running — wait for the current process", 3000)
            return
        if not self.cspt_enabled_check.isChecked():
            QMessageBox.warning(
                self, "Gate Off",
                "modules.cspt_audit.enabled is off, so the module skips "
                "itself before it opens a browser. Tick the gate and save the "
                "plan first.",
            )
            return
        if not _browser_driver_present():
            QMessageBox.warning(
                self, "No Browser Driver",
                "cspt_audit drives a real browser and Playwright is not "
                "installed here — the run would skip itself. Install "
                "Playwright and its Chromium, then run again.",
            )
            return
        points = ", ".join(self._selected_cspt_points())
        answer = QMessageBox.question(
            self, "Traversal Payloads Touch the Target",
            "cspt_audit opens the target in a real browser and navigates it "
            "with traversal payloads in the URL, then replays any altered "
            "path over the HTTP transport.\n\n"
            f"Plan: {self.cspt_max_targets_spin.value()} target(s), "
            f"{self.cspt_max_payloads_spin.value()} payload(s) per inject "
            f"point, inject into {points}, settle "
            f"{self.cspt_wait_spin.value()}ms, impact probe "
            f"{'on' if self.cspt_probe_check.isChecked() else 'OFF'}.\n\n"
            "It is read-only — it never creates or mutates target state.\n\n"
            "Run it now?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            self.statusBar().showMessage("CSPT run cancelled", 4000)
            return
        if not self._save_cspt_plan():
            return
        if not self._select_single_module(CSPT_MODULE_ID):
            QMessageBox.warning(
                self, "Module Unavailable",
                "cspt_audit is not in the module picker — check the stage "
                "filter on the run screen.",
            )
            return
        self.show_screen(self._screen_index("run"))
        self.start_scan()
