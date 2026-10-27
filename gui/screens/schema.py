"""I2 stateful API schema testing screen.

Mixin for gui.app.MainWindow; see that class for composition.
"""
from __future__ import annotations

from gui._shared import *  # noqa: F401,F403


class SchemaScreenMixin:

    # ---- Screen 4: I2 stateful API schema testing ------------------------

    # Reading every evidence payload is bounded work, not a walk over a
    # multi-GB evidence tree: a long fuzz run can file thousands of groups.
    MAX_SCHEMA_EVIDENCE_PAYLOADS = 400

    def _build_schema_screen(self) -> QWidget:
        """I2 cockpit: fuzz plan, tier-graded failure groups, replayable repro."""
        page = QWidget()
        page.setObjectName("screenSchema")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        layout.addWidget(self._build_schema_strip())

        results = QWidget()
        results.setObjectName("schemaResults")
        results.setMinimumWidth(0)
        results_layout = QVBoxLayout(results)
        results_layout.setContentsMargins(0, 0, 0, 0)
        results_layout.setSpacing(6)
        results_layout.addWidget(self._build_schema_filter_bar())

        self.schema_groups_table = QTableWidget(0, 7)
        self.schema_groups_table.setHorizontalHeaderLabels([
            "Tier", "Method", "Path", "Check", "Cases", "Min steps", "Schema",
        ])
        header = self.schema_groups_table.horizontalHeader()
        # Tier and method carry the grading signal — never let them elide;
        # path/check absorb the width and the schema URL stays a tooltip.
        for column in (0, 1, 4, 5):
            header.setSectionResizeMode(column, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        header.setSectionResizeMode(6, QHeaderView.Interactive)
        header.setStretchLastSection(False)
        self.schema_groups_table.setColumnWidth(6, 90)
        self.schema_groups_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.schema_groups_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.schema_groups_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.schema_groups_table.setSortingEnabled(False)
        self.schema_groups_table.verticalHeader().setVisible(False)
        # Grade order is fixed (proof first): re-sorting by column would put a
        # high-count observation above a proven group and lie about priority.
        self.schema_groups_table.currentCellChanged.connect(self._on_schema_row_changed)
        self.schema_groups_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.schema_groups_table.customContextMenuRequested.connect(
            self._schema_table_menu)
        results_layout.addWidget(self.schema_groups_table, 3)
        results_layout.addWidget(self._build_schema_detail(), 2)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setObjectName("schemaSplitter")
        splitter.addWidget(self._build_schema_plan_panel())
        splitter.addWidget(results)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setCollapsible(0, False)
        splitter.setCollapsible(1, False)
        splitter.setSizes([340, 880])
        layout.addWidget(splitter, 1)
        return page

    def _build_schema_strip(self) -> QFrame:
        strip = QFrame()
        strip.setObjectName("schemaStrip")
        layout = QVBoxLayout(strip)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(9)

        head = QHBoxLayout()
        head.setSpacing(8)
        caption = QLabel("I2 · STATEFUL API SCHEMA TESTING")
        caption.setObjectName("schemaCaption")
        self.schema_state_label = QLabel("module disabled")
        self.schema_state_label.setObjectName("schemaState")
        self.schema_state_label.setProperty("state", "idle")
        self.schema_state_label.setToolTip("modules.api_workflows.enabled")
        self.schema_tool_label = QLabel("schemathesis: not probed")
        self.schema_tool_label.setObjectName("schemaTool")
        self.schema_tool_label.setWordWrap(True)
        self.schema_tool_label.setMinimumWidth(0)
        self.schema_probe_button = QPushButton("Probe tool")
        self.schema_probe_button.setObjectName("btnGhost")
        self.schema_probe_button.setToolTip(
            "Check the local/docker schemathesis binary and version gate")
        self.schema_probe_button.clicked.connect(self._probe_schema_tool)
        head.addWidget(caption)
        head.addWidget(self.schema_state_label)
        head.addWidget(self.schema_tool_label, 1)
        head.addWidget(self.schema_probe_button)
        layout.addLayout(head)

        self.schema_discovered_value = QLabel("-")
        self.schema_tested_value = QLabel("-")
        self.schema_groups_value = QLabel("-")
        self.schema_observations_value = QLabel("-")
        self.schema_candidates_value = QLabel("-")
        self.schema_proofs_value = QLabel("-")
        cards = [
            ("Schemas found", self.schema_discovered_value, "info"),
            ("Schemas tested", self.schema_tested_value, "info"),
            ("Failure groups", self.schema_groups_value, "info"),
            ("Observations", self.schema_observations_value, "info"),
            ("Candidates", self.schema_candidates_value, "warning"),
            ("Proven impact", self.schema_proofs_value, "success"),
        ]
        grid = QGridLayout()
        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(8)
        for index, (label, value_label, tone) in enumerate(cards):
            grid.addWidget(self._metric_card(label, value_label, tone),
                           index // 3, index % 3)
        layout.addLayout(grid)

        self.schema_legend_label = QLabel(
            "<span style='color:#93c5fd'>●</span> OBSERVATION — spec drift, "
            "not a vulnerability &nbsp;·&nbsp; "
            "<span style='color:#fdba74'>●</span> CANDIDATE — server "
            "misbehaved, impact unproven &nbsp;·&nbsp; "
            "<span style='color:#4ade80'>●</span> PROOF — case replayed and "
            "an impact probe re-read confirmed it"
        )
        self.schema_legend_label.setObjectName("schemaLegend")
        self.schema_legend_label.setTextFormat(Qt.RichText)
        self.schema_legend_label.setWordWrap(True)
        layout.addWidget(self.schema_legend_label)
        return strip

    def _build_schema_filter_bar(self) -> QWidget:
        bar = QWidget()
        row = QHBoxLayout(bar)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(6)
        self.schema_search = QLineEdit()
        self.schema_search.setPlaceholderText(
            "Filter method, path, check, fingerprint or schema URL")
        self.schema_search.setClearButtonEnabled(True)
        self.schema_search.setMinimumWidth(0)
        self.schema_tier_combo = QComboBox()
        self.schema_tier_combo.setObjectName("filterCombo")
        self.schema_tier_combo.addItems(["All tiers"] + list(SCHEMA_TIERS))
        self.schema_count_label = QLabel("0 of 0")
        self.schema_count_label.setObjectName("opsSecondary")
        reset_button = QPushButton("Reset")
        reset_button.setObjectName("btnGhost")
        reset_button.clicked.connect(self._reset_schema_filter)
        self.schema_search.textChanged.connect(self._render_schema_groups)
        self.schema_tier_combo.currentIndexChanged.connect(
            self._render_schema_groups)
        row.addWidget(self.schema_search, 1)
        row.addWidget(self.schema_tier_combo)
        row.addWidget(reset_button)
        row.addWidget(self.schema_count_label)
        return bar

    def _reset_schema_filter(self):
        self.schema_search.clear()
        self.schema_tier_combo.setCurrentIndex(0)

    def _build_schema_plan_panel(self) -> QWidget:
        """Left column: the I2 plan the operator can actually edit."""
        panel = QFrame()
        panel.setObjectName("sidePanel")
        panel.setMinimumWidth(0)
        layout = QVBoxLayout(panel)
        layout.setSpacing(12)

        gate_box = QGroupBox("Fuzz gate")
        gate_layout = QVBoxLayout(gate_box)
        gate_layout.setSpacing(6)
        self.schema_enabled_check = QCheckBox(
            "Enable stateful schema fuzzing")
        self.schema_enabled_check.setToolTip(
            "modules.api_workflows.enabled — off by default because the "
            "fuzzer writes to the target")
        self.schema_enabled_check.toggled.connect(
            self._update_schema_state_label)
        gate_warning = QLabel(
            "Schemathesis drives linked operations that CREATE and MUTATE "
            "target state. Every pass is recorded in the mutation ledger "
            "(R8); recovery stays with the operator unless a cleanup spec "
            "is configured in the YAML.")
        gate_warning.setObjectName("schemaWarning")
        gate_warning.setWordWrap(True)
        gate_layout.addWidget(self.schema_enabled_check)
        gate_layout.addWidget(gate_warning)
        layout.addWidget(gate_box)

        plan_box = QGroupBox("Run plan")
        form = QFormLayout(plan_box)
        form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.schema_stateful_combo = QComboBox()
        self.schema_stateful_combo.addItems(["links", "none"])
        self.schema_stateful_combo.setToolTip(
            "links: follow the schema's x-links state machine (the only "
            "path to workflow bugs). none: single-operation fuzzing.")
        self.schema_max_cases_spin = QSpinBox()
        self.schema_max_cases_spin.setRange(1, 2000)
        self.schema_max_cases_spin.setValue(100)
        self.schema_max_cases_spin.setToolTip(
            "Generated cases per operation — the fuzzer's appetite")
        self.schema_max_schemas_spin = QSpinBox()
        self.schema_max_schemas_spin.setRange(1, 20)
        self.schema_max_schemas_spin.setValue(3)
        self.schema_max_schemas_spin.setToolTip(
            "Most endpoint-rich schemas first")
        self.schema_max_seconds_spin = QSpinBox()
        self.schema_max_seconds_spin.setRange(30, 7200)
        self.schema_max_seconds_spin.setValue(480)
        self.schema_max_seconds_spin.setSuffix(" s")
        self.schema_max_seconds_spin.setToolTip("Wall budget per schema")
        self.schema_request_timeout_spin = QSpinBox()
        self.schema_request_timeout_spin.setRange(1, 120)
        self.schema_request_timeout_spin.setValue(10)
        self.schema_request_timeout_spin.setSuffix(" s")
        self.schema_max_findings_spin = QSpinBox()
        self.schema_max_findings_spin.setRange(1, 50)
        self.schema_max_findings_spin.setValue(5)
        self.schema_max_findings_spin.setToolTip(
            "Candidate findings filed per schema — the rest stay as evidence")
        self.schema_identities_input = QLineEdit()
        self.schema_identities_input.setPlaceholderText(
            "identity names, comma-separated")
        self.schema_identities_input.setToolTip(
            "Names only — live session headers come from the auth harness; "
            "no secret is ever typed or stored here")
        form.addRow("State machine", self.schema_stateful_combo)
        form.addRow("Cases / operation", self.schema_max_cases_spin)
        form.addRow("Max schemas", self.schema_max_schemas_spin)
        form.addRow("Time per schema", self.schema_max_seconds_spin)
        form.addRow("Request timeout", self.schema_request_timeout_spin)
        form.addRow("Findings / schema", self.schema_max_findings_spin)
        form.addRow("Identities", self.schema_identities_input)
        layout.addWidget(plan_box)

        methods_box = QGroupBox("Fuzzed methods")
        methods_layout = QGridLayout(methods_box)
        methods_layout.setHorizontalSpacing(10)
        self._schema_method_checks: dict[str, QCheckBox] = {}
        for index, method in enumerate(SCHEMA_METHODS):
            check = QCheckBox(method)
            self._schema_method_checks[method] = check
            methods_layout.addWidget(check, index // 4, index % 4)
        methods_hint = QLabel("None checked = every method the schema allows.")
        methods_hint.setObjectName("schemaWarning")
        methods_hint.setWordWrap(True)
        methods_layout.addWidget(methods_hint, 2, 0, 1, 4)
        layout.addWidget(methods_box)

        proof_box = QGroupBox("Proof path")
        proof_layout = QVBoxLayout(proof_box)
        proof_layout.setSpacing(6)
        self.schema_impact_probe_label = QLabel("-")
        self.schema_impact_probe_label.setObjectName("schemaProofState")
        self.schema_impact_probe_label.setWordWrap(True)
        self.schema_impact_probe_label.setTextInteractionFlags(
            Qt.TextSelectableByMouse)
        self.schema_cleanup_label = QLabel("-")
        self.schema_cleanup_label.setObjectName("schemaProofState")
        self.schema_cleanup_label.setWordWrap(True)
        proof_layout.addWidget(self.schema_impact_probe_label)
        proof_layout.addWidget(self.schema_cleanup_label)
        proof_note = QLabel(
            "The tool's own claim never reaches PROOF: only this framework's "
            "replay + impact re-read does. Edit both specs under Raw YAML → "
            "modules.api_workflows.")
        proof_note.setObjectName("schemaWarning")
        proof_note.setWordWrap(True)
        proof_layout.addWidget(proof_note)
        layout.addWidget(proof_box)

        actions_box = QGroupBox("Actions")
        actions_layout = QVBoxLayout(actions_box)
        self.schema_save_button = QPushButton("Save plan")
        self.schema_save_button.setObjectName("btnPrimary")
        self.schema_save_button.clicked.connect(self._save_schema_plan)
        self.schema_run_button = QPushButton("Run schema pass now")
        self.schema_run_button.setToolTip(
            "Saves the plan, then runs only the api_workflows module in "
            "single-module mode")
        self.schema_run_button.clicked.connect(self._run_schema_pass)
        self.schema_settings_button = QPushButton("Open impact spec")
        self.schema_settings_button.setObjectName("btnGhost")
        self.schema_settings_button.setToolTip(
            "Settings → Raw YAML, where impact_probe and cleanup live")
        self.schema_settings_button.clicked.connect(self._open_raw_settings)
        actions_layout.addWidget(self.schema_save_button)
        actions_layout.addWidget(self.schema_run_button)
        actions_layout.addWidget(self.schema_settings_button)
        layout.addWidget(actions_box)
        layout.addStretch(1)

        scroll = QScrollArea()
        scroll.setObjectName("sideScroll")
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setWidget(panel)
        scroll.setMinimumWidth(280)
        scroll.setMaximumWidth(430)
        scroll.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        return scroll

    def _build_schema_detail(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("schemaDetail")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(6)

        head = QHBoxLayout()
        head.setSpacing(8)
        self.schema_detail_title = QLabel("No failure group selected")
        self.schema_detail_title.setObjectName("schemaDetailTitle")
        self.schema_detail_title.setMinimumWidth(0)
        self.schema_copy_curl_button = QPushButton("Copy curl")
        self.schema_copy_curl_button.setObjectName("btnGhost")
        self.schema_copy_curl_button.clicked.connect(self._copy_schema_curl)
        self.schema_open_evidence_button = QPushButton("Open evidence")
        self.schema_open_evidence_button.setObjectName("btnGhost")
        self.schema_open_evidence_button.clicked.connect(
            self._open_schema_evidence)
        self.schema_open_finding_button = QPushButton("Open in Triage")
        self.schema_open_finding_button.setObjectName("btnGhost")
        self.schema_open_finding_button.clicked.connect(
            self._open_schema_finding)
        head.addWidget(self.schema_detail_title, 1)
        head.addWidget(self.schema_copy_curl_button)
        head.addWidget(self.schema_open_evidence_button)
        head.addWidget(self.schema_open_finding_button)
        layout.addLayout(head)

        self.schema_detail_body = QTextEdit()
        self.schema_detail_body.setReadOnly(True)
        self.schema_detail_body.setObjectName("schemaDetailBody")
        self.schema_detail_body.setFont(code_font(12))
        self.schema_detail_body.setPlaceholderText(
            "Select a row to see the failing check, the replayable request, "
            "the evidence that backs it and what is — and is not — proven.")
        layout.addWidget(self.schema_detail_body, 1)
        return frame

    # ---- I2 screen data ---------------------------------------------------

    def _load_schema_view(self):
        """Fill the I2 screen from the stores load_results just read."""
        assets = (self.current_assets.get("nodes", [])
                  if isinstance(self.current_assets, dict) else [])
        evidence_items = (self.current_evidence.get("items", [])
                          if isinstance(self.current_evidence, dict) else [])
        if not isinstance(assets, list):
            assets = []
        if not isinstance(evidence_items, list):
            evidence_items = []

        scan_attrs = {}
        for node in reversed(assets):
            if isinstance(node, dict) and node.get("type") == "api_workflow_scan":
                attrs = node.get("attrs")
                scan_attrs = attrs if isinstance(attrs, dict) else {}
                break

        groups, unreadable, truncated = self._schema_groups(evidence_items)
        self._schema_groups_rows = groups
        self.schema_discovered_value.setText(str(len(self._schema_urls(assets))))
        tested = scan_attrs.get("schemas_tested")
        self.schema_tested_value.setText(
            "-" if tested is None else str(tested))
        self.schema_groups_value.setText(str(len(groups)))
        self.schema_observations_value.setText(str(sum(
            1 for group in groups if group["tier"] == "OBSERVATION")))
        self.schema_candidates_value.setText(str(sum(
            1 for group in groups if group["tier"] == "CANDIDATE")))
        self.schema_proofs_value.setText(str(sum(
            1 for group in groups if group["tier"] == "PROOF")))
        version = scan_attrs.get("version")
        backend = scan_attrs.get("backend")
        if version:
            self.schema_tool_label.setText(
                f"schemathesis {version} · {backend or 'local'} backend · "
                f"{scan_attrs.get('proven', 0)} proven")
        self._render_schema_groups()
        self._refresh_schema_badge()
        notes = []
        if truncated:
            notes.append(
                f"only the first {self.MAX_SCHEMA_EVIDENCE_PAYLOADS} "
                f"schemathesis evidence record(s) parsed")
        if unreadable:
            notes.append(
                f"{unreadable} evidence payload(s) unreadable")
        if notes:
            self.statusBar().showMessage(
                "Schema view is partial: " + "; ".join(notes), 8000)

    @staticmethod
    def _schema_urls(assets: list) -> list[str]:
        """Schema endpoints in the order the module itself would take them."""
        candidates = []
        for node in assets:
            if not isinstance(node, dict):
                continue
            attrs = node.get("attrs") or {}
            value = str(node.get("value") or "")
            if not value:
                continue
            if node.get("type") == "api_endpoint" \
                    and attrs.get("type") == "openapi":
                candidates.append((int(attrs.get("endpoint_count", 0) or 0),
                                   value))
            elif node.get("type") == "graphql":
                candidates.append((0, value))
        ordered = sorted(candidates, key=lambda item: -item[0])
        unique: list[str] = []
        seen: set[str] = set()
        for _, url in ordered:
            if url in seen:
                continue
            seen.add(url)
            unique.append(url)
        return unique

    def _schema_groups(self, evidence_items: list) -> tuple[list[dict], int, bool]:
        """Join schemathesis group evidence with impact re-reads and findings.

        The evidence index carries only ids and paths; the tier story lives in
        the payload files. Returns (rows, unreadable_payload_count, truncated)
        so a partial read is reported instead of posing as an empty run.
        Impact re-reads are parsed first: dropping them to a cap would demote
        a proven group back to a candidate on screen.
        """
        base = self._assessment_dir()
        relevant = [
            item for item in evidence_items
            if isinstance(item, dict)
            and item.get("type") in SCHEMA_EVIDENCE_TYPES
        ]
        ordered = ([item for item in relevant
                    if item.get("type") == "schemathesis_impact"]
                   + [item for item in relevant
                      if item.get("type") != "schemathesis_impact"])
        truncated = len(ordered) > self.MAX_SCHEMA_EVIDENCE_PAYLOADS
        impacts: dict[str, dict] = {}
        groups: dict[str, dict] = {}
        unreadable = 0
        for item in ordered[: self.MAX_SCHEMA_EVIDENCE_PAYLOADS]:
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
            fingerprint = str(data.get("fingerprint") or "")
            if not fingerprint:
                continue
            if item.get("type") == "schemathesis_impact":
                impacts[fingerprint] = {
                    "evidence_id": str(item.get("id") or ""),
                    "evidence_path": str(item.get("path") or ""),
                    "probe_url": str(data.get("probe_url") or ""),
                    "observed": data.get("observed"),
                    "expectation": data.get("expectation") or {},
                }
                continue
            groups[fingerprint] = {
                "fingerprint": fingerprint,
                "check": str(data.get("check") or ""),
                "method": str(data.get("method") or "").upper(),
                "path": str(data.get("path") or ""),
                "count": int(data.get("count", 0) or 0),
                "min_interactions": data.get("min_interactions"),
                "seed": data.get("seed"),
                "curl": str(data.get("curl_repro") or ""),
                "tier": str(data.get("tier") or "").upper() or "CANDIDATE",
                "schema": str(item.get("subject") or ""),
                "evidence_id": str(item.get("id") or ""),
                "evidence_path": str(item.get("path") or ""),
                "impact": None,
            }
        for fingerprint, impact in impacts.items():
            group = groups.get(fingerprint)
            if group is not None:
                group["impact"] = impact
                group["tier"] = "PROOF"
        findings = self.current_findings \
            if isinstance(self.current_findings, list) else []
        by_fingerprint, by_evidence = self._schema_finding_index(findings)
        for fingerprint, group in groups.items():
            finding = by_fingerprint.get(fingerprint) \
                or by_evidence.get(group["evidence_id"])
            if not group["method"] or not group["path"]:
                group["method"], group["path"] = self._route_from_curl(
                    group["curl"])
            if finding is not None:
                group["finding_id"] = str(finding.get("id") or "")
                group["finding_title"] = str(finding.get("title") or "")
        rows = list(groups.values())
        rows.sort(key=lambda row: (
            SCHEMA_TIER_RANK.get(row["tier"], 9), -row["count"], row["path"]))
        return rows, unreadable, truncated

    @staticmethod
    def _schema_finding_index(findings: list) -> tuple[dict, dict]:
        by_fingerprint: dict[str, dict] = {}
        by_evidence: dict[str, dict] = {}
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            category = str(finding.get("category") or "")
            if category not in ("API Schema Conformance",
                                "API State Machine Violation"):
                continue
            for entry in finding.get("evidence") or []:
                text = str(entry)
                if text.startswith("fingerprint:"):
                    by_fingerprint.setdefault(text.split(":", 1)[1], finding)
                else:
                    by_evidence.setdefault(text, finding)
        return by_fingerprint, by_evidence

    def _render_schema_groups(self, *_args):
        table = self.schema_groups_table
        query = self.schema_search.text().strip().lower()
        tier = (self.schema_tier_combo.currentText()
                if self.schema_tier_combo.currentIndex() > 0 else "")
        rows = getattr(self, "_schema_groups_rows", [])
        visible = [
            row for row in rows
            if (not tier or row["tier"] == tier)
            and (not query or query in " ".join((
                row["method"], row["path"], row["check"],
                row["fingerprint"], row["schema"])).lower())
        ]
        # Row order is the grading order (proof first) and detail lookup is by
        # table row, so the filtered slice has to be remembered as rendered.
        self._schema_visible = visible
        table.setRowCount(len(visible))
        for index, row in enumerate(visible):
            values = (
                row["tier"], row["method"], row["path"], row["check"],
                str(row["count"]),
                "-" if row["min_interactions"] is None
                else str(row["min_interactions"]),
                row["schema"],
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 0:
                    color = SCHEMA_TIER_COLORS.get(value)
                    if color:
                        item.setForeground(QColor(color))
                    item.setFont(_bold_font())
                table.setItem(index, column, item)
        self.schema_count_label.setText(f"{len(visible)} of {len(rows)}")
        if visible:
            table.selectRow(0)
        else:
            self._render_schema_detail(None)

    def _schema_selected_row(self) -> dict | None:
        row = self.schema_groups_table.currentRow()
        rows = getattr(self, "_schema_visible", [])
        if not 0 <= row < len(rows):
            return None
        return rows[row]

    def _on_schema_row_changed(self, row: int, *_args):
        rows = getattr(self, "_schema_visible", [])
        self._render_schema_detail(rows[row] if 0 <= row < len(rows) else None)

    def _render_schema_detail(self, group: dict | None):
        if not group:
            self.schema_detail_title.setText("No failure group selected")
            self.schema_detail_body.clear()
            for button in (self.schema_copy_curl_button,
                           self.schema_open_evidence_button,
                           self.schema_open_finding_button):
                button.setEnabled(False)
            return
        tier = group["tier"]
        color = SCHEMA_TIER_COLORS.get(tier, "#d8e2ea")
        self.schema_detail_title.setText(
            f"{tier} · {group['method']} {group['path']} · {group['check']}")
        finding_line = (
            f"{html_escape(group.get('finding_id') or '')} — "
            f"{html_escape(group.get('finding_title') or '')}"
            if group.get("finding_id") else "none filed (over the per-schema cap)")
        impact = group.get("impact") or {}
        parts = [
            f"<b style='color:{color}'>{html_escape(tier)}</b> — "
            f"{html_escape(SCHEMA_TIER_MEANING.get(tier, ''))}",
            "",
            f"<b>Schema</b> {html_escape(group['schema']) or '-'}",
            f"<b>Check</b> {html_escape(group['check'])}",
            f"<b>Cases</b> {group['count']} &nbsp;·&nbsp; "
            f"<b>Shortest repro</b> "
            f"{'-' if group['min_interactions'] is None else html_escape(str(group['min_interactions'])) + ' interaction(s)'}"
            f" &nbsp;·&nbsp; <b>Seed</b> "
            f"{html_escape('-' if group['seed'] is None else str(group['seed']))}",
            f"<b>Fingerprint</b> {html_escape(group['fingerprint'])}",
            f"<b>Evidence</b> {html_escape(group['evidence_id'])}",
            f"<b>Finding</b> {finding_line}",
        ]
        if impact:
            parts += [
                "",
                "<b>Impact re-read (this is what makes it a PROOF)</b>",
                f"  probe    {html_escape(impact.get('probe_url') or '-')}",
                f"  observed {html_escape(json.dumps(impact.get('observed')))}",
                f"  expected {html_escape(_describe_expectation(impact.get('expectation')))}",
                f"  evidence {html_escape(impact.get('evidence_id') or '-')}",
            ]
        else:
            parts += [
                "",
                "<b>Impact re-read</b> none — nothing here is proven by the "
                "fuzzer's own word.",
            ]
        curl = group.get("curl") or ""
        parts += [
            "",
            "<b>Reproduction</b>",
            f"<pre style='color:#70daca'>{html_escape(curl) or 'not recorded'}</pre>",
        ]
        self.schema_detail_body.setHtml("<br>".join(parts))
        self.schema_copy_curl_button.setEnabled(bool(curl))
        self.schema_open_evidence_button.setEnabled(bool(
            group.get("evidence_path")))
        self.schema_open_finding_button.setEnabled(bool(
            group.get("finding_id")))

    def _copy_schema_curl(self):
        group = self._schema_selected_row()
        if not group or not group.get("curl"):
            self.statusBar().showMessage("No curl repro for this group", 3000)
            return
        QApplication.clipboard().setText(group["curl"])
        self.statusBar().showMessage(
            "Reproduction command copied — re-run it yourself before you "
            "claim it", 5000)

    def _open_schema_evidence(self):
        group = self._schema_selected_row()
        if not group or not group.get("evidence_path"):
            return
        path = self._assessment_dir() / group["evidence_path"]
        if path.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))
        else:
            self.statusBar().showMessage("Evidence file is gone", 3000)

    def _open_schema_finding(self):
        group = self._schema_selected_row()
        if not group or not group.get("finding_id"):
            return
        self.finding_search.setText(group["finding_id"])
        self.show_screen(self._screen_index("triage"))

    def _schema_table_menu(self, pos):
        group = self._schema_selected_row()
        menu = QMenu(self)
        copy_row = menu.addAction("Copy row")
        copy_curl = menu.addAction("Copy curl repro")
        copy_curl.setEnabled(bool(group and group.get("curl")))
        copy_fp = menu.addAction("Copy fingerprint")
        copy_fp.setEnabled(bool(group))
        chosen = menu.exec(self.schema_groups_table.viewport().mapToGlobal(pos))
        if chosen is None:
            return
        clipboard = QApplication.clipboard()
        if chosen is copy_row:
            row = self.schema_groups_table.currentRow()
            texts = [
                self.schema_groups_table.item(row, column).text()
                if self.schema_groups_table.item(row, column) else ""
                for column in range(self.schema_groups_table.columnCount())
            ]
            clipboard.setText("\t".join(texts))
        elif chosen is copy_curl and group:
            clipboard.setText(group["curl"])
        elif chosen is copy_fp and group:
            clipboard.setText(group["fingerprint"])

    def _refresh_schema_badge(self):
        index = self._screen_index("schema")
        unproven = sum(
            1 for group in getattr(self, "_schema_groups_rows", [])
            if group["tier"] in ("PROOF", "CANDIDATE"))
        if 0 <= index < len(self.nav_buttons):
            self._set_nav_badge(index, unproven,
                                "schema failure group(s) worth a look")

    # ---- I2 plan: config round trip, tool probe, run ----------------------

    def _apply_schema_plan(self, cfg: dict):
        if not isinstance(cfg, dict):
            cfg = {}
        self.schema_enabled_check.setChecked(bool(cfg.get("enabled")))
        self._set_combo_value(
            self.schema_stateful_combo, str(cfg.get("stateful", "links")))
        for spin, key, default in (
            (self.schema_max_cases_spin, "max_cases", 100),
            (self.schema_max_schemas_spin, "max_schemas", 3),
            (self.schema_max_seconds_spin, "max_seconds", 480),
            (self.schema_request_timeout_spin, "request_timeout", 10),
            (self.schema_max_findings_spin, "max_findings_per_schema", 5),
        ):
            self._note_spin_clamp(
                self._set_spin(spin, cfg.get(key), default), f"api_workflows {key}")
        identities = cfg.get("identities")
        self.schema_identities_input.setText(", ".join(
            str(name) for name in identities if str(name).strip())
            if isinstance(identities, (list, tuple)) else "")
        methods = {str(name).upper()
                   for name in (cfg.get("methods") or []) if str(name).strip()}
        for name, check in self._schema_method_checks.items():
            check.setChecked(name in methods)
        self._render_proof_path(cfg)

    def _read_schema_plan(self) -> dict:
        identities = [
            part.strip() for part in
            re.split(r"[,\n]", self.schema_identities_input.text())
            if part.strip()
        ]
        return {
            "enabled": self.schema_enabled_check.isChecked(),
            "stateful": self.schema_stateful_combo.currentText(),
            "max_cases": self.schema_max_cases_spin.value(),
            "max_schemas": self.schema_max_schemas_spin.value(),
            "max_seconds": self.schema_max_seconds_spin.value(),
            "request_timeout": self.schema_request_timeout_spin.value(),
            "max_findings_per_schema": self.schema_max_findings_spin.value(),
            "identities": identities,
            "methods": [name for name in SCHEMA_METHODS
                        if self._schema_method_checks[name].isChecked()],
        }

    def _save_schema_plan(self):
        config = self._read_config()
        section = self._ensure_module_section(config, "api_workflows")
        plan = self._read_schema_plan()
        caveat = ""
        if plan["enabled"] and not isinstance(
                section.get("impact_probe"), dict):
            caveat = (
                " — no impact probe configured, so candidates stay unproven "
                "(set modules.api_workflows.impact_probe in Raw YAML)")
        # impact_probe and cleanup are nested specs the panel only reports on;
        # updating the scalar keys must not wipe an operator's probe.
        section.update(plan)
        if self._write_config(config):
            self._update_schema_state_label()
            # One message, not two: a later "saved" note must not erase the
            # caveat that explains why the run cannot reach PROOF.
            self.statusBar().showMessage(
                f"Schema plan saved to {self.config_path.name}{caveat}", 9000)

    def _update_schema_state_label(self, *_args):
        enabled = self.schema_enabled_check.isChecked()
        self.schema_state_label.setText(
            "module enabled" if enabled else "module disabled")
        self.schema_state_label.setProperty("state", "ok" if enabled else "idle")
        self.schema_state_label.style().unpolish(self.schema_state_label)
        self.schema_state_label.style().polish(self.schema_state_label)

    def _probe_schema_tool(self):
        self.schema_tool_label.setText("schemathesis: probing…")
        probe = schemathesis_available()
        if probe.get("available"):
            self.schema_tool_label.setText(
                f"schemathesis {probe.get('version') or '?'} · "
                f"{probe.get('backend') or 'local'} backend")
            self.schema_tool_label.setProperty("tone", "ok")
        else:
            reason = probe.get("reason") or "unavailable"
            self.schema_tool_label.setText(
                f"schemathesis unavailable — {reason}")
            self.schema_tool_label.setProperty("tone", "warn")
        self.schema_tool_label.style().unpolish(self.schema_tool_label)
        self.schema_tool_label.style().polish(self.schema_tool_label)

    def _run_schema_pass(self):
        if self.process and self.process.state() != QProcess.NotRunning:
            self.statusBar().showMessage(
                "Already running — wait for the current process", 3000)
            return
        plan = self._read_schema_plan()
        answer = QMessageBox.question(
            self,
            "Run stateful fuzzer",
            "This runs schemathesis against the current target. It sends "
            "generated requests that CREATE and MUTATE target state, and "
            "every pass is recorded in the mutation ledger.\n\n"
            f"Plan: {plan['max_cases']} cases/operation, "
            f"{plan['max_schemas']} schema(s), "
            f"{plan['max_seconds']}s per schema, "
            f"stateful={plan['stateful']}, "
            f"{'enabled' if plan['enabled'] else 'DISABLED'}.\n\n"
            "Continue?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return
        self._save_schema_plan()
        if not plan["enabled"]:
            QMessageBox.information(
                self,
                "Module is disabled",
                "The plan was saved with fuzzing disabled, so the module "
                "will skip itself. Tick 'Enable stateful schema fuzzing' "
                "to get failures graded, or open the run screen to run "
                "something else.",
            )
            return
        if not self._select_single_module("api_workflows"):
            QMessageBox.warning(
                self, "Module Unavailable",
                "api_workflows is not in the module picker — check the "
                "stage filter on the run screen.",
            )
            return
        self.show_screen(self._screen_index("run"))
        self.start_scan()
