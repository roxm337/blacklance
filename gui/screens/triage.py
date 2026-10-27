"""Findings triage screen.

Mixin for gui.app.MainWindow; see that class for composition.
"""
from __future__ import annotations

from gui._shared import *  # noqa: F401,F403


class TriageScreenMixin:

    # ---- Export ---------------------------------------------------------

    def _export_findings_csv(self):
        """Write the current (unfiltered) findings to a CSV the analyst picks."""
        if not self.current_findings:
            QMessageBox.information(self, "Export CSV", "No findings to export.")
            return
        default = str(self._assessment_dir() / f"{self._target_output_name()}_findings.csv")
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Findings", default, "CSV Files (*.csv)"
        )
        if not path:
            return
        columns = [
            "id", "title", "severity", "risk_score", "confidence", "verified",
            "category", "module_id", "priority", "cwe", "owasp", "description",
        ]
        try:
            with open(path, "w", newline="", encoding="utf-8") as handle:
                writer = csv.writer(handle)
                writer.writerow(columns)
                for finding in self.current_findings:
                    row = []
                    for column in columns:
                        value = finding.get(column, "")
                        if isinstance(value, (list, dict)):
                            value = json.dumps(value, ensure_ascii=False)
                        row.append(value)
                    writer.writerow(row)
        except OSError as error:
            QMessageBox.warning(self, "Export CSV", f"Could not write file:\n{error}")
            return
        self.statusBar().showMessage(f"Exported {len(self.current_findings)} findings", 4000)
        QMessageBox.information(
            self, "Export CSV",
            f"Exported {len(self.current_findings)} findings to:\n{path}",
        )

    def _build_triage_screen(self) -> QWidget:
        """Screen 1: findings filter bar, table and detail pane (was: Findings tab)."""
        findings_widget = QWidget()
        findings_widget.setObjectName("screenTriage")
        findings_layout = QVBoxLayout(findings_widget)
        findings_layout.setContentsMargins(0, 0, 0, 0)
        findings_layout.setSpacing(6)

        filter_row = QHBoxLayout()
        filter_row.setContentsMargins(0, 0, 0, 0)
        filter_row.setSpacing(6)
        self.finding_search = QLineEdit()
        self.finding_search.setPlaceholderText("Filter title, ID, category or description")
        self.finding_search.setMinimumWidth(0)
        self.finding_severity_combo = QComboBox()
        self.finding_severity_combo.addItems(
            ["All severities", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        )
        self.finding_confidence_combo = QComboBox()
        self.finding_confidence_combo.addItems(
            ["All confidence", "CONFIRMED", "FIRM", "TENTATIVE"]
        )
        self.finding_verified_combo = QComboBox()
        self.finding_verified_combo.addItems(
            ["All verification", "Verified only", "Unverified only"]
        )
        self.finding_triage_combo = QComboBox()
        self.finding_triage_combo.addItems([
            "All triage", "Untriaged only", "True positive", "False positive", "Out of scope",
        ])
        self.finding_count_label = QLabel("showing 0 of 0")
        self.finding_count_label.setObjectName("opsSecondary")
        self.finding_search.setClearButtonEnabled(True)
        self.finding_search.textChanged.connect(self._apply_finding_filter)
        self.finding_severity_combo.currentIndexChanged.connect(self._apply_finding_filter)
        self.finding_confidence_combo.currentIndexChanged.connect(self._apply_finding_filter)
        self.finding_verified_combo.currentIndexChanged.connect(self._apply_finding_filter)
        self.finding_triage_combo.currentIndexChanged.connect(self._apply_finding_filter)
        reset_filters_button = QPushButton("Reset")
        reset_filters_button.setObjectName("btnGhost")
        reset_filters_button.clicked.connect(self._reset_finding_filters)
        filter_row.addWidget(self.finding_search, 1)
        filter_row.addWidget(self.finding_severity_combo)
        filter_row.addWidget(self.finding_confidence_combo)
        filter_row.addWidget(self.finding_verified_combo)
        filter_row.addWidget(self.finding_triage_combo)
        filter_row.addWidget(reset_filters_button)
        filter_row.addWidget(self.finding_count_label)
        findings_layout.addLayout(filter_row)

        # Severity chips: at-a-glance distribution, click to filter.
        self.severity_chip_row = QHBoxLayout()
        self.severity_chip_row.setContentsMargins(0, 0, 0, 0)
        self.severity_chip_row.setSpacing(6)
        self._severity_chips: dict[str, QLabel] = {}
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            chip = QLabel(f"{sev} 0")
            chip.setObjectName("severityChip")
            chip.setProperty("severity", sev.lower())
            chip.setCursor(Qt.PointingHandCursor)
            chip.mousePressEvent = lambda _e, s=sev: self._filter_by_severity(s)
            self.severity_chip_row.addWidget(chip)
            self._severity_chips[sev] = chip
        self.severity_chip_row.addStretch(1)
        findings_layout.addLayout(self.severity_chip_row)

        self.findings_table = QTableWidget(0, 10)
        self.findings_table.setHorizontalHeaderLabels([
            "ID", "Priority", "Severity", "Score", "Confidence",
            "Title", "Category", "Module", "Verdict", "Assets",
        ])
        header = self.findings_table.horizontalHeader()
        header.setSectionResizeMode(5, QHeaderView.Stretch)
        header.setSectionResizeMode(6, QHeaderView.Stretch)
        # QTableWidget's built-in sorting only compares DisplayRole strings
        # ("100" < "10" < "2"), so the table sorts itself through
        # `_sort_findings` with real ranks instead.
        self.findings_table.setSortingEnabled(False)
        header.setSortIndicatorShown(True)
        header.sectionClicked.connect(self._sort_findings)
        self.findings_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.findings_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.findings_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.findings_table.customContextMenuRequested.connect(self._findings_context_menu)
        self.findings_table.itemSelectionChanged.connect(self._update_finding_detail)
        self.findings_table.setEditTriggers(QAbstractItemView.NoEditTriggers)

        self.finding_detail = QTextEdit()
        self.finding_detail.setReadOnly(True)
        self.finding_detail.setLineWrapMode(QTextEdit.NoWrap)
        self.finding_detail.setMinimumHeight(160)
        self.finding_detail.setPlaceholderText(
            "Select a finding to see its description, remediation and evidence."
        )

        # Verdict bar: the analyst's primary controls, not buried in a menu.
        detail_container = QWidget()
        detail_layout = QVBoxLayout(detail_container)
        detail_layout.setContentsMargins(0, 0, 0, 0)
        detail_layout.setSpacing(4)
        verdict_row = QHBoxLayout()
        verdict_row.setSpacing(6)
        self.verdict_chip = QLabel("Untriaged")
        self.verdict_chip.setObjectName("verdictChip")
        self.verdict_chip.setProperty("verdict", "none")
        verdict_row.addWidget(self.verdict_chip)
        self.tp_button = QPushButton("True positive")
        self.tp_button.setObjectName("btnVerdict")
        self.tp_button.setToolTip("Mark selected finding(s) as true positive (t)")
        self.tp_button.clicked.connect(lambda: self._apply_verdict_action("true_positive"))
        self.fp_button = QPushButton("False positive")
        self.fp_button.setObjectName("btnVerdict")
        self.fp_button.setToolTip("Mark selected finding(s) as false positive (f)")
        self.fp_button.clicked.connect(lambda: self._apply_verdict_action("false_positive"))
        self.oos_button = QPushButton("Out of scope")
        self.oos_button.setObjectName("btnVerdict")
        self.oos_button.setToolTip("Mark selected finding(s) as out of scope (o)")
        self.oos_button.clicked.connect(lambda: self._apply_verdict_action("out_of_scope"))
        self.note_button = QPushButton("Note…")
        self.note_button.setObjectName("btnGhost")
        self.note_button.clicked.connect(self._edit_selected_note)
        self.open_evidence_button = QPushButton("Open evidence")
        self.open_evidence_button.setObjectName("btnGhost")
        self.open_evidence_button.clicked.connect(self._open_selected_evidence)
        self.filter_module_button = QPushButton("Filter by module")
        self.filter_module_button.setObjectName("btnGhost")
        self.filter_module_button.clicked.connect(self._filter_by_selected_module)
        self.show_assets_button = QPushButton("Show in Assets")
        self.show_assets_button.setObjectName("btnGhost")
        self.show_assets_button.setToolTip(
            "Jump to the Data → Assets tab filtered to this finding's assets")
        self.show_assets_button.clicked.connect(self._show_selected_in_assets)
        verdict_row.addWidget(self.tp_button)
        verdict_row.addWidget(self.fp_button)
        verdict_row.addWidget(self.oos_button)
        verdict_row.addSpacing(8)
        verdict_row.addWidget(self.note_button)
        verdict_row.addWidget(self.open_evidence_button)
        verdict_row.addWidget(self.filter_module_button)
        verdict_row.addWidget(self.show_assets_button)
        verdict_row.addStretch(1)
        detail_layout.addLayout(verdict_row)
        detail_layout.addWidget(self.finding_detail, 1)

        finding_splitter = QSplitter(Qt.Vertical)
        finding_splitter.addWidget(self.findings_table)
        finding_splitter.addWidget(detail_container)
        finding_splitter.setStretchFactor(0, 3)
        finding_splitter.setStretchFactor(1, 2)
        self.finding_splitter = finding_splitter
        findings_layout.addWidget(finding_splitter, 1)

        # Keyboard: focus filter, triage letters when the table has focus.
        find_shortcut = QShortcut(QKeySequence.Find, findings_widget)
        find_shortcut.activated.connect(self.focus_finding_filter)
        self.findings_table.installEventFilter(self)
        return findings_widget

    def focus_finding_filter(self):
        self.show_screen(1)
        self.finding_search.setFocus()
        self.finding_search.selectAll()

    def _reset_finding_filters(self):
        self.finding_search.clear()
        self.finding_severity_combo.setCurrentIndex(0)
        self.finding_confidence_combo.setCurrentIndex(0)
        self.finding_verified_combo.setCurrentIndex(0)
        self.finding_triage_combo.setCurrentIndex(0)

    def _selected_findings(self) -> list[dict]:
        """Every selected row, not just the current one — a 10-row selection
        must not silently apply a verdict to a single finding."""
        rows = sorted({index.row() for index in self.findings_table.selectedIndexes()})
        by_id = {str(f.get("id", "")): f for f in self.current_findings}
        picked = []
        for row in rows:
            item = self.findings_table.item(row, 0)
            if item:
                finding = by_id.get(item.text())
                if finding is not None:
                    picked.append(finding)
        return picked

    def _apply_verdict_action(self, verdict: str):
        findings = self._selected_findings()
        if not findings:
            self.statusBar().showMessage("Select a finding first", 3000)
            return
        for finding in findings:
            self._set_finding_verdict(finding, verdict, refilter=False)
        self._apply_finding_filter()
        label = VERDICT_LABELS.get(verdict, verdict) or "Untriaged"
        if len(findings) == 1:
            self.statusBar().showMessage(f"{findings[0].get('id')} → {label}", 4000)
        else:
            self.statusBar().showMessage(
                f"{len(findings)} findings → {label}", 4000
            )

    def prioritize_findings(self):
        self.run_module_action("risk_prioritization")

    def _load_findings(self, findings: list[dict]):
        self.current_findings = list(findings)
        self._triage = self._read_triage()
        self._apply_finding_filter()

    def _apply_finding_filter(self, *_args):
        """Reduce the findings table to the rows matching the filter bar."""
        self._refresh_nav_badges()
        search = self.finding_search.text().strip().lower()
        severity = self.finding_severity_combo.currentText()
        confidence = self.finding_confidence_combo.currentText()
        verified_mode = self.finding_verified_combo.currentIndex()
        triage_mode = self.finding_triage_combo.currentIndex()
        selected: list[dict] = []
        for finding in self.current_findings:
            if severity != "All severities" and \
                    str(finding.get("severity", "")).upper() != severity:
                continue
            if confidence != "All confidence" and \
                    str(finding.get("confidence", "")).upper() != confidence:
                continue
            is_verified = bool(finding.get("verified"))
            if verified_mode == 1 and not is_verified:
                continue
            if verified_mode == 2 and is_verified:
                continue
            verdict = self._verdict_of(finding)
            if triage_mode == 1 and verdict:
                continue
            if triage_mode == 2 and verdict != "true_positive":
                continue
            if triage_mode == 3 and verdict != "false_positive":
                continue
            if triage_mode == 4 and verdict != "out_of_scope":
                continue
            if search:
                haystack = " ".join([
                    str(finding.get("id", "")),
                    str(finding.get("title", "")),
                    str(finding.get("category", "")),
                    str(finding.get("module_id", "")),
                    str(finding.get("description", "")),
                ]).lower()
                if search not in haystack:
                    continue
            selected.append(finding)
        self._filtered_findings = selected
        self._update_severity_chips()
        self._populate_findings(selected)
        # Keep the graph's finding annotations in sync with the triage
        # filter, but only re-render while the graph is on screen.
        if self.screen_stack.currentIndex() == self.SCREEN_GRAPH_INDEX:
            self.refresh_graph()

    def _finding_sort_key(self, column: int):
        def key(finding: dict):
            if column == 0:
                return str(finding.get("id", ""))
            if column == 1:
                return _priority_rank(finding.get("priority"))
            if column == 2:
                return SEVERITY_RANK.get(str(finding.get("severity", "")).upper(), -1)
            if column == 3:
                return int(finding.get("risk_score") or 0)
            if column == 4:
                return CONFIDENCE_RANK.get(str(finding.get("confidence", "")).upper(), -1)
            if column == 7:
                return str(finding.get("module_id", "")).lower()
            if column == 8:
                return str(self._verdict_of(finding))
            if column == 9:
                return ", ".join(finding.get("asset_keys", [])).lower()
            if column == 6:
                return str(finding.get("category", "")).lower()
            return str(finding.get("title", "")).lower()

        return key

    def _sort_findings(self, column: int):
        order = Qt.DescendingOrder if column == 3 else Qt.AscendingOrder
        if self._findings_sort[0] == column:
            order = (
                Qt.AscendingOrder
                if self._findings_sort[1] == Qt.DescendingOrder
                else Qt.DescendingOrder
            )
        self._findings_sort = [column, order]
        self.findings_table.horizontalHeader().setSortIndicator(column, order)
        self._populate_findings(getattr(self, "_filtered_findings", self.current_findings))

    def _populate_findings(self, findings: list[dict]):
        # Keep the analyst's place: repopulating after a verdict/note used to
        # clear the selection and reset the detail pane mid-triage.
        previous = self._selected_finding()
        previous_id = str(previous.get("id", "")) if previous else ""
        scroll_value = self.findings_table.verticalScrollBar().value()

        column, order = self._findings_sort
        reverse = order == Qt.DescendingOrder
        ordered = sorted(findings, key=self._finding_sort_key(column), reverse=reverse)
        self.findings_table.setRowCount(len(ordered))
        for row, finding in enumerate(ordered):
            verdict = self._verdict_of(finding)
            values = [
                str(finding.get("id", "")),
                str(finding.get("priority") or ""),
                str(finding.get("severity") or ""),
                str(finding.get("risk_score") or 0),
                str(finding.get("confidence") or ""),
                str(finding.get("title") or ""),
                str(finding.get("category") or ""),
                str(finding.get("module_id") or ""),
                VERDICT_LABELS.get(verdict, verdict),
                ", ".join(finding.get("asset_keys", [])[:3]),
            ]
            # Sort keys: numeric rank where a string would sort wrong.
            sort_keys = [
                values[0],
                _priority_rank(values[1]),
                SEVERITY_RANK.get(values[2].upper(), -1),
                int(values[3] or 0),
                CONFIDENCE_RANK.get(values[4].upper(), -1),
                values[5], values[6], values[7], values[8], values[9],
            ]
            severity_color = SEVERITY_COLORS.get(values[2].upper())
            verdict_color = VERDICT_COLORS.get(verdict)
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.UserRole, sort_keys[col])
                if col == 2 and severity_color:
                    item.setForeground(QColor(severity_color))
                    item.setFont(_bold_font())
                if col == 8 and verdict_color:
                    item.setForeground(QColor(verdict_color))
                self.findings_table.setItem(row, col, item)
        self.finding_count_label.setText(
            f"showing {len(ordered)} of {len(self.current_findings)}"
        )
        if previous_id:
            for row in range(self.findings_table.rowCount()):
                item = self.findings_table.item(row, 0)
                if item and item.text() == previous_id:
                    self.findings_table.selectRow(row)
                    self.findings_table.verticalScrollBar().setValue(scroll_value)
                    break
        self._update_finding_detail()

    def _verdict_of(self, finding: dict) -> str:
        entry = self._triage.get(str(finding.get("id", "")), {})
        if isinstance(entry, dict):
            return str(entry.get("verdict", ""))
        return ""

    def _selected_finding(self) -> dict | None:
        row = self.findings_table.currentRow()
        if row < 0:
            return None
        item = self.findings_table.item(row, 0)
        if not item:
            return None
        finding_id = item.text()
        for finding in self.current_findings:
            if str(finding.get("id", "")) == finding_id:
                return finding
        return None

    def _update_finding_detail(self):
        if not hasattr(self, "finding_detail"):
            return
        finding = self._selected_finding()
        if not finding:
            self.finding_detail.setPlainText(
                "Select a finding to see its description, remediation and evidence."
            )
            if hasattr(self, "verdict_chip"):
                self.verdict_chip.setText("Untriaged")
                self.verdict_chip.setProperty("verdict", "")
                self.verdict_chip.style().unpolish(self.verdict_chip)
                self.verdict_chip.style().polish(self.verdict_chip)
            return
        verdict = self._verdict_of(finding)
        if hasattr(self, "verdict_chip"):
            chip_text = VERDICT_LABELS.get(verdict, verdict) if verdict else "Untriaged"
            self.verdict_chip.setText(chip_text)
            self.verdict_chip.setProperty("verdict", verdict or "none")
            self.verdict_chip.style().unpolish(self.verdict_chip)
            self.verdict_chip.style().polish(self.verdict_chip)
        entry = self._triage.get(str(finding.get("id", "")), {})
        note = str(entry.get("note", "")) if isinstance(entry, dict) else ""
        lines = [
            f"{finding.get('id', '')}  —  "
            f"{finding.get('priority') or '-'} / "
            f"{finding.get('severity') or '-'} / "
            f"{finding.get('confidence') or '-'}  "
            f"(score {finding.get('risk_score', 0)})",
            f"Module: {finding.get('module_id', '-')}   "
            f"Category: {finding.get('category', '-')}   "
            f"Verified: {'yes' if finding.get('verified') else 'no'}",
            f"CWE: {', '.join(finding.get('cwe') or []) or '-'}   "
            f"OWASP: {finding.get('owasp') or '-'}",
            f"Triage: {VERDICT_LABELS.get(verdict, verdict) or 'untriaged'}"
            + (f"   Note: {note}" if note else ""),
            "",
            str(finding.get("description") or "").strip(),
            "",
        ]
        remediation = str(finding.get("remediation") or "").strip()
        if remediation:
            lines += ["Remediation:", remediation, ""]
        inline = finding.get("evidence") or []
        if inline:
            lines.append("Evidence:")
            lines += [f"  - {item}" for item in inline[:12]]
            if len(inline) > 12:
                lines.append(f"  ... {len(inline) - 12} more")
            lines.append("")
        refs = finding.get("evidence_refs") or []
        if refs:
            lines.append("Evidence refs: " + ", ".join(str(r) for r in refs))
            lines.append("(double-click a row in the Evidence tab to open files)")
            lines.append("")
        assets = finding.get("asset_keys") or []
        if assets:
            lines.append("Assets:")
            lines += [f"  - {key}" for key in assets]
        verification = finding.get("verification")
        if verification:
            lines += ["", "Verification detail:", json.dumps(verification, indent=2, default=str)]
        self.finding_detail.setPlainText("\n".join(lines))

    def _findings_context_menu(self, pos):
        findings = self._selected_findings()
        if not findings:
            return
        finding = findings[0]
        count = len(findings)
        menu = QMenu(self)
        copy_action = menu.addAction(
            "Copy finding ID" if count == 1 else f"Copy finding ID ({count} findings)"
        )
        evidence_action = menu.addAction("Open evidence file")
        menu.addSeparator()
        verdict_menu = menu.addMenu(
            "Set verdict" if count == 1 else f"Set verdict on {count} findings"
        )
        verdict_actions = {
            verdict_menu.addAction(label): verdict
            for verdict, label in (
                ("true_positive", "True positive"),
                ("false_positive", "False positive"),
                ("out_of_scope", "Out of scope"),
            )
        }
        clear_action = verdict_menu.addAction("Clear verdict")
        note_action = menu.addAction("Edit triage note...")
        chosen = menu.exec(self.findings_table.viewport().mapToGlobal(pos))
        if chosen is None:
            return
        if chosen is copy_action:
            if count == 1:
                QApplication.clipboard().setText(str(finding.get("id", "")))
            else:
                QApplication.clipboard().setText(
                    "\n".join(str(f.get("id", "")) for f in findings)
                )
            self.statusBar().showMessage(f"Copied {count} finding id(s)", 3000)
        elif chosen is evidence_action:
            self._open_finding_evidence(finding)
        elif chosen is clear_action:
            for selected in findings:
                self._set_finding_verdict(selected, "", refilter=False)
            self._apply_finding_filter()
            if count > 1:
                self.statusBar().showMessage(
                    f"Cleared verdict on {count} findings", 4000
                )
        elif chosen in verdict_actions:
            verdict = verdict_actions[chosen]
            for selected in findings:
                self._set_finding_verdict(selected, verdict, refilter=False)
            self._apply_finding_filter()
            if count > 1:
                self.statusBar().showMessage(
                    f"{count} findings → {VERDICT_LABELS.get(verdict, verdict)}", 4000
                )
        elif chosen is note_action:
            self._edit_triage_note(finding)

    def _set_finding_verdict(self, finding: dict, verdict: str, refilter: bool = True):
        finding_id = str(finding.get("id", ""))
        if not finding_id:
            return
        entry = self._triage.setdefault(finding_id, {})
        if not isinstance(entry, dict):
            entry = self._triage[finding_id] = {}
        if verdict:
            entry["verdict"] = verdict
        else:
            entry.pop("verdict", None)
            if not entry:
                self._triage.pop(finding_id, None)
        self._write_triage()
        if refilter:
            self._apply_finding_filter()

    def _edit_triage_note(self, finding: dict):
        finding_id = str(finding.get("id", ""))
        entry = self._triage.get(finding_id, {})
        current = str(entry.get("note", "")) if isinstance(entry, dict) else ""
        note, accepted = QInputDialog.getText(
            self, "Triage note", f"Note for {finding_id}:", text=current
        )
        if not accepted:
            return
        stored = self._triage.setdefault(finding_id, {})
        if not isinstance(stored, dict):
            stored = self._triage[finding_id] = {}
        if note.strip():
            stored["note"] = note.strip()
        else:
            stored.pop("note", None)
            if not stored:
                self._triage.pop(finding_id, None)
        self._write_triage()
        self._apply_finding_filter()

    def _open_finding_evidence(self, finding: dict):
        refs = {str(ref) for ref in (finding.get("evidence_refs") or [])}
        target_dir = self._assessment_dir()
        resolvable = []
        for item in self.current_evidence.get("items", []):
            if str(item.get("id", "")) not in refs:
                continue
            path = target_dir / str(item.get("path", ""))
            if path.exists():
                resolvable.append((str(item.get("id", "")), path))
        if not resolvable:
            QMessageBox.information(
                self, "No Evidence File",
                "This finding has no evidence file on disk (only inline text or refs "
                "that no longer resolve).",
            )
            return
        if len(resolvable) == 1:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(resolvable[0][1])))
            return
        # Several files back this finding: pick instead of silently
        # opening whichever came first in state order.
        labels = [f"{eid}  ({path.name})" for eid, path in resolvable]
        choice, accepted = QInputDialog.getItem(
            self, "Open Evidence",
            f"{len(resolvable)} evidence files back this finding:",
            labels, 0, False,
        )
        if not accepted:
            return
        index = labels.index(choice)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(resolvable[index][1])))

    def _triage_path(self) -> Path:
        target = self._target_output_name()
        return self._assessment_dir() / f"{target}_triage.json"

    def _read_triage(self) -> dict:
        data = self._read_json(self._triage_path(), {})
        return data if isinstance(data, dict) else {}

    def _write_triage(self):
        path = self._triage_path()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            # Atomic: truncate-then-write left a window where a reload
            # could read a half-written file and treat it as empty,
            # silently dropping every verdict.
            tmp = path.with_name(path.name + ".tmp")
            tmp.write_text(json.dumps(self._triage, indent=2, sort_keys=True))
            os.replace(tmp, path)
        except OSError as exc:
            QMessageBox.warning(self, "Save Failed", str(exc))
