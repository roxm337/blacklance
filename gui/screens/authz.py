"""I3 authorization matrix screen.

Mixin for gui.app.MainWindow; see that class for composition.
"""
from __future__ import annotations

from gui._shared import *  # noqa: F401,F403


class AuthzScreenMixin:

    # ---- I3 authorization matrix screen ----------------------------------

    def _build_authz_screen(self) -> QWidget:
        page = QWidget()
        page.setObjectName("screenAuthz")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        layout.addWidget(self._build_authz_strip())

        results = QWidget()
        results.setObjectName("authzResults")
        results.setMinimumWidth(0)
        results_layout = QVBoxLayout(results)
        results_layout.setContentsMargins(0, 0, 0, 0)
        results_layout.setSpacing(6)

        self.authz_tabs = QTabWidget()
        self.authz_tabs.setObjectName("authzViews")
        self.authz_tabs.addTab(self._build_authz_cells_tab(), "Cells")
        self.authz_tabs.addTab(self._build_authz_grid_tab(), "Matrix")
        self.authz_tabs.addTab(self._build_authz_canaries_tab(), "Canaries")
        results_layout.addWidget(self.authz_tabs, 3)
        results_layout.addWidget(self._build_authz_detail(), 2)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setObjectName("authzSplitter")
        splitter.addWidget(self._build_authz_plan_panel())
        splitter.addWidget(results)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setCollapsible(0, False)
        splitter.setCollapsible(1, False)
        splitter.setSizes([340, 880])
        layout.addWidget(splitter, 1)
        return page

    def _build_authz_strip(self) -> QFrame:
        strip = QFrame()
        strip.setObjectName("authzStrip")
        layout = QVBoxLayout(strip)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(9)

        head = QHBoxLayout()
        head.setSpacing(8)
        caption = QLabel("I3 · AUTHORIZATION MATRIX")
        caption.setObjectName("authzCaption")
        self.authz_state_label = QLabel("gates off")
        self.authz_state_label.setObjectName("authzState")
        self.authz_state_label.setProperty("state", "idle")
        self.authz_state_label.setToolTip(
            "modules.<module>.matrix.enabled for idor_differ, bfla_audit "
            "and graphql_audit")
        self.authz_run_label = QLabel("no matrix run loaded")
        self.authz_run_label.setObjectName("authzTool")
        self.authz_run_label.setWordWrap(True)
        self.authz_run_label.setMinimumWidth(0)
        head.addWidget(caption)
        head.addWidget(self.authz_state_label)
        head.addWidget(self.authz_run_label, 1)
        layout.addLayout(head)

        self.authz_subjects_value = QLabel("-")
        self.authz_cells_value = QLabel("-")
        self.authz_leaks_value = QLabel("-")
        self.authz_ambiguous_value = QLabel("-")
        self.authz_proofs_value = QLabel("-")
        self.authz_cleanup_value = QLabel("-")
        cards = [
            ("Identities seen", self.authz_subjects_value, "info"),
            ("Cells probed", self.authz_cells_value, "info"),
            ("Leak candidates", self.authz_leaks_value, "warning"),
            ("Needs a look", self.authz_ambiguous_value, "info"),
            ("Canary proofs", self.authz_proofs_value, "success"),
            ("Cleanup outstanding", self.authz_cleanup_value, "warning"),
        ]
        grid = QGridLayout()
        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(8)
        for index, (label, value_label, tone) in enumerate(cards):
            grid.addWidget(self._metric_card(label, value_label, tone),
                           index // 3, index % 3)
        layout.addLayout(grid)

        self.authz_legend_label = QLabel(
            "<span style='color:#5b7181'>●</span> HEALTHY — denied or absent "
            "for this identity &nbsp;·&nbsp; "
            "<span style='color:#93c5fd'>●</span> OBSERVATION — the read "
            "cannot be classified, a human has to look &nbsp;·&nbsp; "
            "<span style='color:#fdba74'>●</span> CANDIDATE — another "
            "identity's data came back &nbsp;·&nbsp; "
            "<span style='color:#4ade80'>●</span> PROOF — a canary the "
            "forbidden identity actually read back, owner re-read intact, "
            "cleanup verified"
        )
        self.authz_legend_label.setObjectName("authzLegend")
        self.authz_legend_label.setTextFormat(Qt.RichText)
        self.authz_legend_label.setWordWrap(True)
        layout.addWidget(self.authz_legend_label)
        return strip

    def _build_authz_cells_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 6, 0, 0)
        layout.setSpacing(6)

        bar = QWidget()
        row = QHBoxLayout(bar)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(6)
        self.authz_search = QLineEdit()
        self.authz_search.setPlaceholderText(
            "Filter subject, object template, ref, field or outcome")
        self.authz_search.setClearButtonEnabled(True)
        self.authz_search.setMinimumWidth(0)
        self.authz_tier_combo = QComboBox()
        self.authz_tier_combo.setObjectName("filterCombo")
        self.authz_tier_combo.addItems(["All tiers"] + list(AUTHZ_TIERS))
        self.authz_count_label = QLabel("0 of 0")
        self.authz_count_label.setObjectName("opsSecondary")
        reset_button = QPushButton("Reset")
        reset_button.setObjectName("btnGhost")
        reset_button.clicked.connect(self._reset_authz_filter)
        self.authz_search.textChanged.connect(self._render_authz_cells)
        self.authz_tier_combo.currentIndexChanged.connect(
            self._render_authz_cells)
        row.addWidget(self.authz_search, 1)
        row.addWidget(self.authz_tier_combo)
        row.addWidget(reset_button)
        row.addWidget(self.authz_count_label)
        layout.addWidget(bar)

        self.authz_cells_table = QTableWidget(0, 7)
        self.authz_cells_table.setHorizontalHeaderLabels([
            "Tier", "Subject", "Operation", "Object", "Ref", "Status",
            "Outcome",
        ])
        header = self.authz_cells_table.horizontalHeader()
        for column in (1, 2, 4, 5, 6):
            header.setSectionResizeMode(column, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        header.setStretchLastSection(False)
        self.authz_cells_table.setSelectionBehavior(
            QAbstractItemView.SelectRows)
        self.authz_cells_table.setSelectionMode(
            QAbstractItemView.SingleSelection)
        self.authz_cells_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.authz_cells_table.setSortingEnabled(False)
        self.authz_cells_table.verticalHeader().setVisible(False)
        # Tier order is the grading order; a leak count of 200 must not bury
        # the one canary proof, and re-sorting by column would do exactly that.
        self.authz_cells_table.currentCellChanged.connect(
            self._on_authz_cell_changed)
        layout.addWidget(self.authz_cells_table, 1)
        return page

    def _reset_authz_filter(self):
        self.authz_search.clear()
        self.authz_tier_combo.setCurrentIndex(0)

    def _build_authz_grid_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 6, 0, 0)
        layout.setSpacing(6)
        hint = QLabel(
            "Rows are the reading identity, columns are the probed operation "
            "and object. Click a cell to open it below.")
        hint.setObjectName("authzWarning")
        hint.setWordWrap(True)
        layout.addWidget(hint)
        self.authz_grid_table = QTableWidget(0, 0)
        self.authz_grid_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.authz_grid_table.setSelectionBehavior(
            QAbstractItemView.SelectItems)
        self.authz_grid_table.setSelectionMode(QAbstractItemView.SingleSelection)
        # The row headers ARE the reading identities — hiding them, as the
        # other tables do, would leave a grid of colours nobody can attribute.
        self.authz_grid_table.verticalHeader().setVisible(True)
        self.authz_grid_table.verticalHeader().setSectionResizeMode(
            QHeaderView.ResizeToContents)
        self.authz_grid_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeToContents)
        self.authz_grid_table.horizontalHeader().setStretchLastSection(False)
        self.authz_grid_table.setWordWrap(False)
        self.authz_grid_table.cellClicked.connect(self._on_authz_grid_clicked)
        layout.addWidget(self.authz_grid_table, 1)
        return page

    def _build_authz_canaries_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 6, 0, 0)
        layout.setSpacing(6)
        self.authz_canaries_table = QTableWidget(0, 7)
        self.authz_canaries_table.setHorizontalHeaderLabels([
            "Tier", "Canary", "Created by", "Read by", "Seed intact",
            "Denied", "Cleanup",
        ])
        canary_header = self.authz_canaries_table.horizontalHeader()
        for column in (0, 2, 3, 4, 5, 6):
            canary_header.setSectionResizeMode(
                column, QHeaderView.ResizeToContents)
        canary_header.setSectionResizeMode(1, QHeaderView.Stretch)
        canary_header.setStretchLastSection(False)
        self.authz_canaries_table.setSelectionBehavior(
            QAbstractItemView.SelectRows)
        self.authz_canaries_table.setSelectionMode(
            QAbstractItemView.SingleSelection)
        self.authz_canaries_table.setEditTriggers(
            QAbstractItemView.NoEditTriggers)
        self.authz_canaries_table.setSortingEnabled(False)
        self.authz_canaries_table.verticalHeader().setVisible(False)
        self.authz_canaries_table.currentCellChanged.connect(
            self._on_authz_canary_changed)
        layout.addWidget(self.authz_canaries_table, 1)
        return page

    def _build_authz_plan_panel(self) -> QWidget:
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

        gates_box = QGroupBox("Matrix gates")
        gates_layout = QVBoxLayout(gates_box)
        gates_layout.setSpacing(6)
        self.authz_gate_checks: dict[str, QCheckBox] = {}
        gate_labels = {
            "idor_differ": "IDOR/BOLA object matrix (idor_differ)",
            "bfla_audit": "Cross-identity collections (bfla_audit)",
            "graphql_audit": "GraphQL field probes (graphql_audit)",
        }
        for module_id in AUTHZ_MODULES:
            check = QCheckBox(gate_labels[module_id])
            check.setToolTip(f"modules.{module_id}.matrix.enabled")
            check.toggled.connect(self._update_authz_state_label)
            self.authz_gate_checks[module_id] = check
            gates_layout.addWidget(check)
        gates_warning = QLabel(
            "The matrix re-reads the same objects as every configured "
            "identity — that is how a leak is attributed. It stays read-only "
            "unless canary specs are configured; a canary CREATES an object, "
            "reads it as the forbidden identity, re-reads it as the owner and "
            "deletes it, all on the mutation ledger (R8).")
        gates_warning.setObjectName("authzWarning")
        gates_warning.setWordWrap(True)
        gates_layout.addWidget(gates_warning)
        layout.addWidget(gates_box)

        plan_box = QGroupBox("Run plan")
        form = QFormLayout(plan_box)
        form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.authz_max_cells_spin = QSpinBox()
        self.authz_max_cells_spin.setRange(1, 2000)
        self.authz_max_cells_spin.setValue(200)
        self.authz_max_cells_spin.setToolTip(
            "modules.idor_differ.matrix.max_cells — identity × object ceiling")
        self.authz_canaries_spin = QSpinBox()
        self.authz_canaries_spin.setRange(0, 20)
        self.authz_canaries_spin.setValue(3)
        self.authz_canaries_spin.setToolTip(
            "modules.idor_differ.matrix.canaries.max — the only path to a "
            "PROOF; 0 disables canaries, so nothing can be proven")
        self.authz_gql_queries_spin = QSpinBox()
        self.authz_gql_queries_spin.setRange(1, 200)
        self.authz_gql_queries_spin.setValue(10)
        self.authz_gql_queries_spin.setToolTip(
            "modules.graphql_audit.matrix.max_queries")
        self.authz_gql_canaries_spin = QSpinBox()
        self.authz_gql_canaries_spin.setRange(0, 20)
        self.authz_gql_canaries_spin.setValue(2)
        self.authz_gql_canaries_spin.setToolTip(
            "modules.graphql_audit.matrix.canaries.max")
        self.authz_freshness_check = QCheckBox("Session freshness check")
        self.authz_freshness_check.setToolTip(
            "modules.idor_differ.matrix.freshness.enabled — re-establish a "
            "session and prove the read did not drift")
        self.authz_revocation_check = QCheckBox("Logout revocation check")
        self.authz_revocation_check.setToolTip(
            "modules.idor_differ.matrix.revocation.enabled — sacrificial "
            "session: logout, prove denied, re-establish, prove allowed. "
            "Needs auth.identities.<name>.logout_url")
        form.addRow("Max cells", self.authz_max_cells_spin)
        form.addRow("Canaries (IDOR)", self.authz_canaries_spin)
        form.addRow("Max queries (GraphQL)", self.authz_gql_queries_spin)
        form.addRow("Canaries (GraphQL)", self.authz_gql_canaries_spin)
        form.addRow("", self.authz_freshness_check)
        form.addRow("", self.authz_revocation_check)
        layout.addWidget(plan_box)

        depth_box = QGroupBox("Configured depth")
        depth_layout = QVBoxLayout(depth_box)
        depth_layout.setSpacing(6)
        self.authz_identities_label = QLabel("-")
        self.authz_sharing_label = QLabel("-")
        self.authz_specs_label = QLabel("-")
        self.authz_probes_label = QLabel("-")
        for widget in (self.authz_identities_label, self.authz_sharing_label,
                       self.authz_specs_label, self.authz_probes_label):
            widget.setObjectName("authzProofState")
            widget.setWordWrap(True)
            widget.setTextInteractionFlags(Qt.TextSelectableByMouse)
            depth_layout.addWidget(widget)
        depth_hint = QLabel(
            "Identities, sharing specs, canary specs and field probes are "
            "structured YAML — edit them on the Raw YAML screen.")
        depth_hint.setObjectName("authzWarning")
        depth_hint.setWordWrap(True)
        depth_layout.addWidget(depth_hint)
        layout.addWidget(depth_box)

        checks_box = QGroupBox("Session checks (last run)")
        checks_layout = QVBoxLayout(checks_box)
        checks_layout.setSpacing(6)
        self.authz_check_sharing = QLabel("-")
        self.authz_check_freshness = QLabel("-")
        self.authz_check_revocation = QLabel("-")
        for widget in (self.authz_check_sharing, self.authz_check_freshness,
                       self.authz_check_revocation):
            widget.setObjectName("authzProofState")
            widget.setWordWrap(True)
            widget.setTextInteractionFlags(Qt.TextSelectableByMouse)
            checks_layout.addWidget(widget)
        layout.addWidget(checks_box)

        actions_box = QGroupBox("Actions")
        actions_layout = QVBoxLayout(actions_box)
        actions_layout.setSpacing(6)
        self.authz_save_button = QPushButton("Save matrix plan")
        self.authz_save_button.setObjectName("btnPrimary")
        self.authz_save_button.clicked.connect(self._save_authz_plan)
        actions_layout.addWidget(self.authz_save_button)
        self.authz_run_buttons: dict[str, QPushButton] = {}
        for module_id in AUTHZ_MODULES:
            button = QPushButton(f"Run matrix: {module_id}")
            button.setObjectName("btnGhost")
            button.clicked.connect(
                lambda _checked=False, mid=module_id: self._run_authz_module(mid))
            self.authz_run_buttons[module_id] = button
            actions_layout.addWidget(button)
        settings_button = QPushButton("Open matrix spec")
        settings_button.setObjectName("btnGhost")
        settings_button.setToolTip("Jump to Raw YAML for the nested specs")
        settings_button.clicked.connect(self._open_raw_settings)
        actions_layout.addWidget(settings_button)
        layout.addWidget(actions_box)
        layout.addStretch(1)

        outer.addWidget(scroll)
        return panel

    def _build_authz_detail(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("authzDetail")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(8)

        head = QHBoxLayout()
        head.setSpacing(8)
        self.authz_detail_title = QLabel("No matrix cell selected")
        self.authz_detail_title.setObjectName("authzDetailTitle")
        self.authz_detail_title.setTextInteractionFlags(
            Qt.TextSelectableByMouse)
        self.authz_open_evidence_button = QPushButton("Open evidence")
        self.authz_open_evidence_button.setObjectName("btnGhost")
        self.authz_open_evidence_button.setEnabled(False)
        self.authz_open_evidence_button.clicked.connect(
            self._open_authz_evidence)
        self.authz_open_finding_button = QPushButton("Open in Triage")
        self.authz_open_finding_button.setObjectName("btnGhost")
        self.authz_open_finding_button.setEnabled(False)
        self.authz_open_finding_button.clicked.connect(
            self._open_authz_finding)
        head.addWidget(self.authz_detail_title, 1)
        head.addWidget(self.authz_open_evidence_button)
        head.addWidget(self.authz_open_finding_button)
        layout.addLayout(head)

        self.authz_detail_body = QTextEdit()
        self.authz_detail_body.setReadOnly(True)
        self.authz_detail_body.setObjectName("authzDetailBody")
        self.authz_detail_body.setFont(code_font(12))
        self.authz_detail_body.setPlaceholderText(
            "Select a cell, a grid square or a canary to see what was read, "
            "as whom, and what that does — and does not — prove.")
        layout.addWidget(self.authz_detail_body, 1)
        return frame

    # ---- I3 screen data ---------------------------------------------------

    def _load_authz_view(self):
        """Fill the I3 screen from the stores load_results just read."""
        evidence_items = (self.current_evidence.get("items", [])
                          if isinstance(self.current_evidence, dict) else [])
        if not isinstance(evidence_items, list):
            evidence_items = []
        reports, unreadable, truncated = self._authz_reports(evidence_items)
        cells = self._authz_cells(reports)
        canaries = self._authz_canaries(reports)
        self._authz_cell_rows = cells
        self._authz_canary_rows = canaries

        subjects = {row["subject"] for row in cells} | {
            row["created_by"] for row in canaries} | {
            row["read_by"] for row in canaries}
        self.authz_subjects_value.setText(str(len(subjects)))
        self.authz_cells_value.setText(str(len(cells)))
        self.authz_leaks_value.setText(str(sum(
            1 for row in cells if row["tier"] == "CANDIDATE")))
        self.authz_ambiguous_value.setText(str(
            sum(1 for row in cells if row["tier"] == "OBSERVATION")
            + sum(1 for row in canaries if row["tier"] == "OBSERVATION")))
        self.authz_proofs_value.setText(str(sum(
            1 for row in canaries if row["tier"] == "PROOF")))
        self.authz_cleanup_value.setText(str(sum(
            1 for row in canaries
            if str(row.get("cleanup_status") or "") not in
            ("verified", "not_required", ""))))
        modules = sorted({row["module"] for row in cells} |
                         {row["module"] for row in canaries})
        if modules:
            self.authz_run_label.setText(
                f"matrix run loaded from {', '.join(modules)} · "
                f"{self.authz_proofs_value.text()} proven canary(ies)")
        else:
            self.authz_run_label.setText("no matrix run loaded")
        self._render_authz_checks(reports)
        self._render_authz_cells()
        self._render_authz_canaries()
        self._render_authz_grid()
        self._refresh_authz_badge()
        notes = []
        if truncated:
            notes.append(
                f"only the first {self.MAX_AUTHZ_REPORTS} matrix report(s) "
                f"parsed")
        if unreadable:
            notes.append(f"{unreadable} matrix payload(s) unreadable")
        if notes:
            self.statusBar().showMessage(
                "Authorization view is partial: " + "; ".join(notes), 8000)

    MAX_AUTHZ_REPORTS = 40

    def _authz_reports(self, evidence_items: list) -> tuple[list[dict], int, bool]:
        """Read every matrix_report payload: (reports, unreadable, truncated).

        One report per module that ran the matrix (idor_differ, graphql_audit).
        A payload that cannot be read is counted, never silently dropped — an
        empty matrix and an unreadable matrix are different claims.
        """
        base = self._assessment_dir()
        relevant = [
            item for item in evidence_items
            if isinstance(item, dict)
            and item.get("type") == AUTHZ_EVIDENCE_TYPE
        ]
        truncated = len(relevant) > self.MAX_AUTHZ_REPORTS
        reports: list[dict] = []
        unreadable = 0
        for item in relevant[: self.MAX_AUTHZ_REPORTS]:
            path = base / str(item.get("path") or "")
            if not path.exists():
                continue
            try:
                doc = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError, UnicodeDecodeError):
                unreadable += 1
                continue
            data = doc.get("data") if isinstance(doc, dict) else None
            if not isinstance(data, dict):
                unreadable += 1
                continue
            reports.append({
                "module": str(item.get("module_id") or ""),
                "evidence_id": str(item.get("id") or ""),
                "evidence_path": str(item.get("path") or ""),
                "subject": str(item.get("subject") or ""),
                "cells": data.get("cells")
                if isinstance(data.get("cells"), list) else [],
                "checks": data.get("checks")
                if isinstance(data.get("checks"), dict) else {},
                "canaries": data.get("canaries")
                if isinstance(data.get("canaries"), list) else [],
            })
        return reports, unreadable, truncated

    @staticmethod
    def _authz_finding_index(findings: list) -> tuple[dict, dict]:
        """cell_sha256:<sha> and canary:<name> are the join keys the modules
        file findings with; anything else cannot be attributed to a row."""
        by_cell: dict[str, dict] = {}
        by_canary: dict[str, dict] = {}
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            if str(finding.get("category") or "") \
                    not in AUTHZ_FINDING_CATEGORIES:
                continue
            for entry in finding.get("evidence") or []:
                text = str(entry)
                if text.startswith("cell_sha256:"):
                    by_cell.setdefault(text.split(":", 1)[1], finding)
                elif text.startswith("canary:"):
                    by_canary.setdefault(text.split(":", 1)[1], finding)
        return by_cell, by_canary

    def _authz_cells(self, reports: list[dict]) -> list[dict]:
        by_cell, _ = self._authz_finding_index(
            self.current_findings if isinstance(self.current_findings, list)
            else [])
        rows = []
        for report in reports:
            for cell in report["cells"]:
                if not isinstance(cell, dict):
                    continue
                outcome = str(cell.get("outcome") or "error")
                sha = str(cell.get("evidence_sha256") or "")
                obj = cell.get("object") if isinstance(cell.get("object"),
                                                       dict) else {}
                rows.append({
                    "kind": "cell",
                    "tier": AUTHZ_OUTCOME_TIER.get(outcome, "OBSERVATION"),
                    "module": report["module"],
                    "subject": str(cell.get("subject") or "-"),
                    "tenant": str(cell.get("tenant") or ""),
                    "operation": str(cell.get("operation") or ""),
                    "template": str(obj.get("template") or "-"),
                    "ref": str(obj.get("ref") or ""),
                    "owner": str(obj.get("owner") or ""),
                    "field": str(cell.get("field") or ""),
                    "status": str(cell.get("status", "") or ""),
                    "outcome": outcome,
                    "attribution": cell.get("attribution")
                    if isinstance(cell.get("attribution"), dict) else {},
                    "diff_fields": cell.get("diff_fields")
                    if isinstance(cell.get("diff_fields"), list) else [],
                    "sha": sha,
                    "evidence_id": report["evidence_id"],
                    "evidence_path": report["evidence_path"],
                    "finding_id": "",
                    "finding_title": "",
                })
                finding = by_cell.get(sha)
                if finding is not None:
                    rows[-1]["finding_id"] = str(finding.get("id") or "")
                    rows[-1]["finding_title"] = str(finding.get("title") or "")
        rows.sort(key=lambda row: (
            AUTHZ_TIER_RANK.get(row["tier"], 9), row["subject"],
            row["template"], row["operation"]))
        return rows

    def _authz_canaries(self, reports: list[dict]) -> list[dict]:
        _, by_canary = self._authz_finding_index(
            self.current_findings if isinstance(self.current_findings, list)
            else [])
        rows = []
        for report in reports:
            for canary in report["canaries"]:
                if not isinstance(canary, dict):
                    continue
                proven = bool(canary.get("proven"))
                denied = bool(canary.get("denied"))
                cleanup = str(canary.get("cleanup_status") or "")
                # A denied read is the healthy outcome only if the seeded
                # object actually left the target — a failed cleanup is an
                # object still sitting there under our account.
                cleaned = cleanup in ("verified", "not_required")
                tier = ("PROOF" if proven
                        else "HEALTHY" if (denied and cleaned)
                        else "OBSERVATION")
                name = str(canary.get("name") or "")
                finding = by_canary.get(name)
                rows.append({
                    "kind": "canary",
                    "tier": tier,
                    "module": report["module"],
                    "name": name,
                    "created_by": str(canary.get("created_by") or "-"),
                    "read_by": str(canary.get("read_by") or "-"),
                    "observed": canary.get("observed"),
                    "expected": str(canary.get("expected") or ""),
                    "proven": proven,
                    "denied": denied,
                    "seed_intact": bool(canary.get("seed_intact")),
                    "cleanup_status": str(canary.get("cleanup_status") or ""),
                    "error": str(canary.get("error") or ""),
                    "mut_id": str(canary.get("mut_id") or ""),
                    "evidence_id": report["evidence_id"],
                    "evidence_path": report["evidence_path"],
                    "finding_id": str(finding.get("id") or "")
                    if finding else "",
                    "finding_title": str(finding.get("title") or "")
                    if finding else "",
                })
        rows.sort(key=lambda row: (
            AUTHZ_TIER_RANK.get(row["tier"], 9), row["name"]))
        return rows

    def _render_authz_checks(self, reports: list[dict]):
        """Sharing / freshness / revocation as the engine reported them."""
        sharing = [r["checks"].get("sharing") for r in reports
                   if isinstance(r["checks"].get("sharing"), dict)]
        freshness = [r["checks"].get("freshness") for r in reports
                     if isinstance(r["checks"].get("freshness"), dict)]
        revocation = [r["checks"].get("revocation") for r in reports
                      if isinstance(r["checks"].get("revocation"), dict)]
        if sharing:
            specs = sum(int(item.get("specs", 0) or 0) for item in sharing)
            ok = sum(int(item.get("ok", 0) or 0) for item in sharing)
            regressions = sum(len(item.get("regressions") or [])
                              for item in sharing)
            self.authz_check_sharing.setText(
                f"Sharing: {ok}/{specs} object(s) still readable by both "
                f"identities · {regressions} regression(s)")
        else:
            self.authz_check_sharing.setText(
                "Sharing: no specs configured")
        if freshness:
            drift = [d for item in freshness
                     for d in (item.get("drift") or [])]
            self.authz_check_freshness.setText(
                "Freshness: clean" if not drift
                else "Freshness drift: " + "; ".join(str(d) for d in drift))
        else:
            self.authz_check_freshness.setText("Freshness: not run")
        if revocation:
            self.authz_check_revocation.setText("; ".join(
                f"{item.get('identity', '?')}: {item.get('status', '?')}"
                f" (after logout {item.get('after_logout', '-')}, "
                f"re-established {item.get('reestablished', '-')})"
                for item in revocation))
        else:
            self.authz_check_revocation.setText("Revocation: not run")

    def _render_authz_cells(self, *_args):
        table = self.authz_cells_table
        query = self.authz_search.text().strip().lower()
        tier = (self.authz_tier_combo.currentText()
                if self.authz_tier_combo.currentIndex() > 0 else "")
        rows = getattr(self, "_authz_cell_rows", [])
        visible = [
            row for row in rows
            if (not tier or row["tier"] == tier)
            and (not query or query in " ".join((
                row["subject"], row["template"], row["ref"], row["field"],
                row["operation"], row["outcome"])).lower())
        ]
        # The filtered slice has to be remembered: detail lookup is by row.
        self._authz_visible_cells = visible
        table.setRowCount(len(visible))
        for index, row in enumerate(visible):
            values = (row["tier"], row["subject"], row["operation"],
                      row["template"], row["ref"], row["status"],
                      row["outcome"])
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 0:
                    color = AUTHZ_TIER_COLORS.get(value)
                    if color:
                        item.setForeground(QColor(color))
                        font = item.font()
                        font.setBold(True)
                        item.setFont(font)
                item.setToolTip(value)
                table.setItem(index, column, item)
        self.authz_count_label.setText(f"{len(visible)} of {len(rows)}")
        if not visible:
            self._render_authz_detail(None)

    def _render_authz_canaries(self, *_args):
        table = self.authz_canaries_table
        rows = getattr(self, "_authz_canary_rows", [])
        table.setRowCount(len(rows))
        for index, row in enumerate(rows):
            values = (
                row["tier"], row["name"], row["created_by"], row["read_by"],
                "yes" if row["seed_intact"] else "no",
                "yes" if row["denied"] else "no",
                row["cleanup_status"] or "-",
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 0:
                    color = AUTHZ_TIER_COLORS.get(value)
                    if color:
                        item.setForeground(QColor(color))
                        font = item.font()
                        font.setBold(True)
                        item.setFont(font)
                item.setToolTip(value)
                table.setItem(index, column, item)
        if not rows:
            self._render_authz_detail(None)

    def _render_authz_grid(self):
        """Subjects × probed operations — coverage, not just leaks."""
        table = self.authz_grid_table
        rows = getattr(self, "_authz_cell_rows", [])
        columns = sorted({(row["operation"], row["template"], row["ref"])
                          for row in rows})
        subjects = sorted({row["subject"] for row in rows})
        table.clearContents()
        table.setColumnCount(len(columns))
        table.setRowCount(len(subjects))
        table.setHorizontalHeaderLabels(
            [f"{op} {template}{'[' + ref + ']' if ref else ''}"
             for op, template, ref in columns])
        table.setVerticalHeaderLabels(subjects)
        lookup: dict[tuple, dict] = {}
        for row in rows:
            key = (subjects.index(row["subject"]),
                   columns.index((row["operation"], row["template"],
                                  row["ref"])))
            previous = lookup.get(key)
            # A subject can hit the same column twice (different tenants);
            # keep the worst grade so the grid never under-reports.
            if previous is not None and AUTHZ_TIER_RANK.get(
                    previous["tier"], 9) <= AUTHZ_TIER_RANK.get(
                    row["tier"], 9):
                continue
            lookup[key] = row
        for (row_index, column_index), row in lookup.items():
            color = AUTHZ_TIER_COLORS.get(row["tier"], "#5b7181")
            item = QTableWidgetItem(row["outcome"])
            item.setForeground(QColor(color))
            item.setBackground(QColor(color).darker(360))
            item.setTextAlignment(Qt.AlignCenter)
            item.setToolTip(
                f"{row['tier']} · {row['outcome']} · {row['status'] or '-'}")
            table.setItem(row_index, column_index, item)
        self._authz_grid_lookup = lookup
        if not rows:
            self.authz_grid_table.setRowCount(0)
            self.authz_grid_table.setColumnCount(0)

    def _on_authz_grid_clicked(self, row_index: int, column_index: int):
        row = getattr(self, "_authz_grid_lookup", {}).get(
            (row_index, column_index))
        if row is not None:
            self._render_authz_detail(row)

    def _on_authz_cell_changed(self, row: int, *_args):
        rows = getattr(self, "_authz_visible_cells", [])
        self._render_authz_detail(rows[row] if 0 <= row < len(rows) else None)

    def _on_authz_canary_changed(self, row: int, *_args):
        rows = getattr(self, "_authz_canary_rows", [])
        self._render_authz_detail(rows[row] if 0 <= row < len(rows) else None)

    def _render_authz_detail(self, row: dict | None):
        self._authz_detail_row = row
        if not row:
            self.authz_detail_title.setText("No matrix cell selected")
            self.authz_detail_body.clear()
            self.authz_open_evidence_button.setEnabled(False)
            self.authz_open_finding_button.setEnabled(False)
            return
        tier = row["tier"]
        color = AUTHZ_TIER_COLORS.get(tier, "#d8e2ea")
        parts = [
            f"<b style='color:{color}'>{html_escape(tier)}</b> — "
            f"{html_escape(AUTHZ_TIER_MEANING.get(tier, ''))}",
            "",
            f"<b>Module</b> {html_escape(row['module'])}",
        ]
        if row["kind"] == "canary":
            self.authz_detail_title.setText(
                f"{tier} · canary {row['name']} · {row['read_by']} reading "
                f"{row['created_by']}'s object")
            parts += [
                f"<b>Created by</b> {html_escape(row['created_by'])}",
                f"<b>Read by</b> {html_escape(row['read_by'])}",
                f"<b>Expected</b> {html_escape(row['expected'] or 'denied')}",
                f"<b>Observed</b> {html_escape(json.dumps(row['observed']))}",
                f"<b>Seed intact on owner re-read</b> "
                f"{'yes' if row['seed_intact'] else 'no'}",
                f"<b>Read denied</b> {'yes' if row['denied'] else 'no'}",
                f"<b>Cleanup</b> {html_escape(row['cleanup_status'] or '-')}"
                f" &nbsp;·&nbsp; <b>Ledger</b> "
                f"{html_escape(row['mut_id'] or '-')}",
            ]
            if row["error"]:
                parts.append(f"<b>Error</b> {html_escape(row['error'])}")
            if not row["proven"]:
                parts += [
                    "",
                    "<b>Not a proof</b> — the forbidden identity never read "
                    "the seeded value back with the owner re-read intact, so "
                    "this canary proves the control works, not a leak.",
                ]
            if row["cleanup_status"] not in ("verified", "not_required"):
                parts.append(
                    "<b style='color:#fdba74'>Cleanup not verified</b> — the "
                    f"object seeded by {row['created_by']} "
                    f"({row['mut_id'] or 'no ledger id'}) may still be on the "
                    "target; check the mutation ledger before you close out.")
        else:
            self.authz_detail_title.setText(
                f"{tier} · {row['subject']} {row['operation']} "
                f"{row['template']} · {row['outcome']}")
            parts += [
                f"<b>Subject</b> {html_escape(row['subject'])}"
                + (f" &nbsp;·&nbsp; <b>Tenant</b> "
                   f"{html_escape(row['tenant'])}" if row["tenant"] else ""),
                f"<b>Operation</b> {html_escape(row['operation'])}",
                f"<b>Object</b> {html_escape(row['template'])}"
                + (f" &nbsp;·&nbsp; <b>ref</b> {html_escape(row['ref'])}"
                   if row["ref"] else ""),
                f"<b>Owner of that ref</b> {html_escape(row['owner'] or '-')}",
                f"<b>Field</b> {html_escape(row['field'] or '-')}",
                f"<b>Status</b> {html_escape(row['status'] or '-')}",
                f"<b>Outcome</b> {html_escape(row['outcome'])}",
                f"<b>Attribution</b> "
                f"{html_escape(json.dumps(row['attribution']) if row['attribution'] else 'none')}",
                f"<b>Differing fields</b> "
                f"{html_escape(', '.join(str(f) for f in row['diff_fields']) or 'none')}",
                # The finding title carries the same short form, and a full
                # 64-char digest on one line pushes the prose off the pane.
                f"<b>Cell digest</b> "
                f"{html_escape(row['sha'][:12] + '…' if row['sha'] else '-')}",
            ]
            if row["tier"] == "CANDIDATE":
                parts.append(
                    "<b>Still needed</b> a canary that reads a seeded value "
                    "as this identity — until then this is a candidate, not a "
                    "proven leak.")
        finding_line = (
            f"{html_escape(row.get('finding_id') or '')} — "
            f"{html_escape(row.get('finding_title') or '')}"
            if row.get("finding_id") else "none filed")
        parts += ["", f"<b>Finding</b> {finding_line}"]
        self.authz_detail_body.setHtml("<br>".join(parts))
        self.authz_open_evidence_button.setEnabled(bool(
            row.get("evidence_path")))
        self.authz_open_finding_button.setEnabled(bool(
            row.get("finding_id")))

    def _open_authz_evidence(self):
        row = self._authz_selected_detail_row()
        if not row or not row.get("evidence_path"):
            return
        path = self._assessment_dir() / row["evidence_path"]
        if path.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))
        else:
            self.statusBar().showMessage("Evidence file is gone", 3000)

    def _open_authz_finding(self):
        row = self._authz_selected_detail_row()
        if not row or not row.get("finding_id"):
            return
        self.finding_search.setText(row["finding_id"])
        self.show_screen(self._screen_index("triage"))

    def _authz_selected_detail_row(self) -> dict | None:
        """Whatever the detail pane is currently showing."""
        return getattr(self, "_authz_detail_row", None)

    def _refresh_authz_badge(self):
        index = self._screen_index("authz")
        count = sum(
            1 for row in getattr(self, "_authz_cell_rows", [])
            if row["tier"] == "CANDIDATE") + sum(
            1 for row in getattr(self, "_authz_canary_rows", [])
            if row["tier"] in ("PROOF", "CANDIDATE"))
        if 0 <= index < len(self.nav_buttons):
            self._set_nav_badge(index, count,
                                "authorization row(s) worth a look")

    # ---- I3 plan: config round trip and run -------------------------------

    def _apply_authz_plan(self, config: dict):
        """Load the three matrix sections plus the specs the panel reports."""
        if not isinstance(config, dict):
            config = {}
        modules = config.get("modules")
        modules = modules if isinstance(modules, dict) else {}
        matrices: dict[str, dict] = {}
        for module_id in AUTHZ_MODULES:
            section = modules.get(module_id)
            section = section if isinstance(section, dict) else {}
            matrix = section.get("matrix")
            matrices[module_id] = matrix if isinstance(matrix, dict) else {}

        for module_id, check in self.authz_gate_checks.items():
            check.setChecked(bool(matrices[module_id].get("enabled")))
        idor = matrices["idor_differ"]
        graphql = matrices["graphql_audit"]
        for spin, container, key, default, label in (
            (self.authz_max_cells_spin, idor, "max_cells", 200,
             "idor_differ max_cells"),
            (self.authz_gql_queries_spin, graphql, "max_queries", 10,
             "graphql_audit max_queries"),
        ):
            self._note_spin_clamp(
                self._set_spin(spin, container.get(key), default), label)
        for spin, container, default, label in (
            (self.authz_canaries_spin, idor.get("canaries"), 3,
             "idor_differ canaries.max"),
            (self.authz_gql_canaries_spin, graphql.get("canaries"), 2,
             "graphql_audit canaries.max"),
        ):
            container = container if isinstance(container, dict) else {}
            self._note_spin_clamp(
                self._set_spin(spin, container.get("max"), default), label)
        self.authz_freshness_check.setChecked(bool(
            (idor.get("freshness") or {}).get("enabled", True)))
        self.authz_revocation_check.setChecked(bool(
            (idor.get("revocation") or {}).get("enabled", True)))
        self._render_authz_depth(idor, graphql, matrices)
        self._update_authz_state_label()

    def _render_authz_depth(self, idor: dict, graphql: dict,
                            matrices: dict) -> None:
        """Counts of the nested specs — the panel never edits them, so it
        has to at least say whether the proof path exists."""
        names = [str(record.get("name")) for record in self._identity_records
                 if isinstance(record, dict) and record.get("name")]
        with_logout = [str(record.get("name")) for record in self._identity_records
                       if isinstance(record, dict)
                       and record.get("name") and record.get("logout_url")]
        if len(names) < 2:
            self.authz_identities_label.setText(
                "Identities: fewer than two configured — a matrix needs two "
                "accounts before a difference can mean anything")
            self.authz_identities_label.setProperty("tone", "warn")
        else:
            self.authz_identities_label.setText(
                f"Identities: {', '.join(names)}")
            self.authz_identities_label.setProperty("tone", "ok")
        sharing = idor.get("sharing")
        sharing_count = len(sharing) if isinstance(sharing, (list, dict)) else 0
        self.authz_sharing_label.setText(
            f"Sharing specs: {sharing_count} configured"
            if sharing_count else "Sharing specs: none")
        self.authz_sharing_label.setProperty(
            "tone", "ok" if sharing_count else "warn")

        idor_specs = ((idor.get("canaries") or {}).get("specs")
                      if isinstance(idor.get("canaries"), dict) else None)
        gql_specs = ((graphql.get("canaries") or {}).get("specs")
                     if isinstance(graphql.get("canaries"), dict) else None)
        specs_count = (len(idor_specs) if isinstance(idor_specs, list) else 0) \
            + (len(gql_specs) if isinstance(gql_specs, list) else 0)
        self.authz_specs_label.setText(
            f"Canary specs: {specs_count} — the only path to PROOF"
            if specs_count else
            "Canary specs: none — nothing on this screen can reach PROOF")
        self.authz_specs_label.setProperty("tone", "ok" if specs_count else "warn")

        probes = graphql.get("field_probes")
        probe_count = len(probes) if isinstance(probes, list) else 0
        self.authz_probes_label.setText(
            f"GraphQL field probes: {probe_count} configured"
            if probe_count else "GraphQL field probes: none")
        self.authz_probes_label.setProperty(
            "tone", "ok" if probe_count else "warn")
        if not with_logout:
            self.authz_revocation_check.setToolTip(
                "modules.idor_differ.matrix.revocation.enabled — no identity "
                "has logout_url configured, so revocation reports untested")
        for label in (self.authz_identities_label, self.authz_sharing_label,
                      self.authz_specs_label, self.authz_probes_label):
            label.style().unpolish(label)
            label.style().polish(label)

    def _update_authz_state_label(self, *_args):
        on = [module_id for module_id, check
              in self.authz_gate_checks.items() if check.isChecked()]
        self.authz_state_label.setText(
            "gates: " + ", ".join(on) if on else "gates off")
        self.authz_state_label.setProperty("state", "ok" if on else "idle")
        self.authz_state_label.style().unpolish(self.authz_state_label)
        self.authz_state_label.style().polish(self.authz_state_label)

    def _save_authz_plan(self):
        config = self._read_config()
        for module_id in AUTHZ_MODULES:
            section = self._ensure_module_section(config, module_id)
            # Read-modify-write the matrix block: sharing specs, canary specs
            # and field probes are nested and belong to the operator's YAML.
            matrix = section.get("matrix")
            matrix = matrix if isinstance(matrix, dict) else {}
            matrix["enabled"] = self.authz_gate_checks[module_id].isChecked()
            if module_id == "idor_differ":
                matrix["max_cells"] = self.authz_max_cells_spin.value()
                for key, check in (("freshness", self.authz_freshness_check),
                                   ("revocation", self.authz_revocation_check)):
                    block = matrix.get(key)
                    block = block if isinstance(block, dict) else {}
                    block["enabled"] = check.isChecked()
                    matrix[key] = block
                canaries = matrix.get("canaries")
                canaries = canaries if isinstance(canaries, dict) else {}
                canaries["max"] = self.authz_canaries_spin.value()
                matrix["canaries"] = canaries
            elif module_id == "graphql_audit":
                matrix["max_queries"] = self.authz_gql_queries_spin.value()
                canaries = matrix.get("canaries")
                canaries = canaries if isinstance(canaries, dict) else {}
                canaries["max"] = self.authz_gql_canaries_spin.value()
                matrix["canaries"] = canaries
            section["matrix"] = matrix
        caveat = ""
        if any(check.isChecked() for check in self.authz_gate_checks.values()) \
                and self.authz_specs_label.text().startswith(
                    "Canary specs: none"):
            caveat = (" — with no canary specs, a leak stays a candidate "
                      "(configure modules.idor_differ.matrix.canaries.specs "
                      "in Raw YAML)")
        if self._write_config(config):
            self._update_authz_state_label()
            self.statusBar().showMessage(
                f"Matrix plan saved to {self.config_path.name}{caveat}", 9000)

    def _run_authz_module(self, module_id: str):
        """One module at a time: the run screen has no multi-module mode and
        a whole-chain run would re-crawl the target for a matrix answer."""
        if not self.authz_gate_checks[module_id].isChecked():
            QMessageBox.warning(
                self, "Gate Off",
                f"modules.{module_id}.matrix.enabled is off — running "
                f"{module_id} now would execute its legacy pass, not the "
                "authorization matrix. Tick the gate and save the plan first.",
            )
            return
        answer = QMessageBox.question(
            self, "Matrix Pass Touches the Target",
            f"{module_id} will re-read the same objects as every configured "
            "identity over an authenticated channel.\n\n"
            "It is read-only unless canary specs are configured; a canary "
            "creates and then deletes an object on the mutation ledger (R8).\n\n"
            "Run it now?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            self.statusBar().showMessage("Matrix run cancelled", 4000)
            return
        self._save_authz_plan()
        if not self._select_single_module(module_id):
            QMessageBox.warning(
                self, "Module Unavailable",
                f"{module_id} is not in the module picker — check the stage "
                "filter on the run screen.",
            )
            return
        self.show_screen(self._screen_index("run"))
        self.start_scan()
