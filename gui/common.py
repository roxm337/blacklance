"""Shared helpers used across screens.

Mixin for gui.app.MainWindow; see that class for composition.
"""
from __future__ import annotations

from gui._shared import *  # noqa: F401,F403


class CommonMixin:

    def _restore_window_state(self):
        geometry = self._settings.value("geometry")
        if geometry is not None:
            try:
                self.restoreGeometry(geometry)
            except TypeError:
                self.resize(1280, 820)
        else:
            self.resize(1280, 820)
        self.setMinimumSize(1100, 720)
        screen = self._settings.value("screen", 0, type=int)
        self.show_screen(screen if isinstance(screen, int) else 0)
        # Restore pane splits so the operator's layout survives restarts.
        for name, splitter in (
            ("run_splitter", getattr(self, "run_splitter", None)),
            ("finding_splitter", getattr(self, "finding_splitter", None)),
        ):
            state = self._settings.value(name)
            if state is not None and splitter is not None:
                try:
                    splitter.restoreState(state)
                except TypeError:
                    pass

    def closeEvent(self, event):
        # A running scan is a child QProcess: closing the window kills it
        # mid-run. Confirm before throwing away operator time.
        if self.process and self.process.state() != QProcess.NotRunning:
            answer = QMessageBox.question(
                self,
                "Scan Running",
                "A scan is still running. Stop it and quit?\n"
                "(Unsaved progress in the current run is kept on disk.)",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if answer != QMessageBox.Yes:
                event.ignore()
                return
            self.stop_scan()
        # A closing window must cancel pending work: the debounced target
        # reload would otherwise fire from a hidden window long after close.
        self._target_reload_timer.stop()
        self._elapsed_timer.stop()
        self._poll_timer.stop()
        # Offscreen (test) runs must not clobber the operator's saved layout.
        if os.environ.get("QT_QPA_PLATFORM") != "offscreen":
            self._settings.setValue("geometry", self.saveGeometry())
            self._settings.setValue(
                "target", self.target_input.text().strip()
            )
            if hasattr(self, "screen_stack"):
                self._settings.setValue("screen", self.screen_stack.currentIndex())
            for name in ("run_splitter", "finding_splitter"):
                splitter = getattr(self, name, None)
                if splitter is not None:
                    self._settings.setValue(name, splitter.saveState())
        super().closeEvent(event)

    # ---- Drag & drop: a config file onto the window ---------------------

    def dragEnterEvent(self, event):
        mime = event.mimeData()
        if mime.hasUrls() and any(
            url.toLocalFile().lower().endswith((".yaml", ".yml"))
            for url in mime.urls()
        ):
            event.acceptProposedAction()

    def dropEvent(self, event):
        for url in event.mimeData().urls():
            path = url.toLocalFile()
            if path.lower().endswith((".yaml", ".yml")):
                self._load_config_path(Path(path))
                event.acceptProposedAction()
                return

    # ---- Help -----------------------------------------------------------

    def _show_shortcuts(self):
        QMessageBox.information(
            self,
            "Keyboard Shortcuts",
            "Ctrl+1..9, Ctrl+0\tSwitch screen (Run, Triage, Graph, Data, "
            "Schema, Authz, CSPT, ORM Leak, Report, Settings)\n"
            "Ctrl+O\tOpen config file\n"
            "Ctrl+R / F5\tReload current results\n"
            "Ctrl+Enter\tStart run\n"
            "Ctrl+Q\tQuit\n"
            "Enter (target field)\tStart run\n"
            "t / f / o\tTrue positive / False positive / Out of scope (table focused)\n"
            "Ctrl+.\tStop run",
        )

    def _show_about(self):
        QMessageBox.about(
            self,
            "About OSINT Agent",
            "OSINT Agent — red team ops console\n\n"
            "Proof-before-severity OSINT and exposure-mapping framework.\n"
            "Local-only: runs entirely from this workstation.",
        )

    def _refresh_actions_table(self):
        if not hasattr(self, "actions_table"):
            return
        rank = {"SAFE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "DESTRUCTIVE": 4}
        colors = {
            "SAFE": "#4ade80", "LOW": "#93c5fd", "MEDIUM": "#fde047",
            "HIGH": "#fdba74", "DESTRUCTIVE": "#fb7185",
        }
        metas = sorted(
            ActionRegistry.list(),
            key=lambda meta: (rank.get(meta.risk.value, 9), meta.id),
        )
        self.actions_table.setRowCount(len(metas))
        for row, meta in enumerate(metas):
            values = [
                meta.id,
                meta.risk.value,
                meta.detectability,
                ", ".join(meta.requires),
                meta.description,
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if col == 1:
                    color = colors.get(meta.risk.value)
                    if color:
                        item.setForeground(QColor(color))
                self.actions_table.setItem(row, col, item)

    def _build_ops_strip(self) -> QFrame:
        """Live run context: target, mode, state pill, progress, exposure."""
        ops_strip = QFrame()
        ops_strip.setObjectName("opsStrip")
        ops_layout = QGridLayout(ops_strip)
        ops_layout.setContentsMargins(14, 10, 14, 10)
        self.operation_target_label = QLabel("Target: -")
        self.operation_target_label.setObjectName("opsPrimary")
        self.operation_target_label.setWordWrap(True)
        self.operation_target_label.setMinimumWidth(0)
        self.operation_mode_label = QLabel("Mode: -")
        self.operation_mode_label.setObjectName("opsSecondary")
        self.operation_mode_label.setWordWrap(True)
        self.operation_mode_label.setMinimumWidth(0)
        self.operation_state_label = QLabel("Ready")
        self.operation_state_label.setObjectName("opsState")
        self.operation_state_label.setProperty("state", "idle")
        self.operation_state_label.setMinimumWidth(0)
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimumWidth(0)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.exposure_label = QLabel("Exposure map: waiting for data")
        self.exposure_label.setObjectName("opsSecondary")
        self.exposure_label.setWordWrap(True)
        self.exposure_label.setMinimumWidth(0)
        ops_layout.addWidget(self.operation_target_label, 0, 0)
        ops_layout.addWidget(self.operation_mode_label, 1, 0)
        ops_layout.addWidget(self.operation_state_label, 0, 1, 2, 1)
        ops_layout.addWidget(self.progress_bar, 0, 2)
        ops_layout.addWidget(self.exposure_label, 1, 2)
        ops_layout.setColumnStretch(0, 2)
        ops_layout.setColumnStretch(2, 3)
        return ops_strip

    def eventFilter(self, obj, event):
        if obj is getattr(self, "findings_table", None) and event.type() == QEvent.KeyPress:
            key = event.key()
            mapping = {
                Qt.Key_T: "true_positive",
                Qt.Key_F: "false_positive",
                Qt.Key_O: "out_of_scope",
            }
            if key in mapping and event.modifiers() in (Qt.NoModifier, Qt.ShiftModifier):
                self._apply_verdict_action(mapping[key])
                return True
        return super().eventFilter(obj, event)

    def _filter_by_severity(self, severity: str):
        """Click a severity chip to toggle that severity in the filter combo."""
        index = self.finding_severity_combo.findText(severity)
        if index < 0:
            return
        # Toggle: clicking the active severity clears back to "All".
        if self.finding_severity_combo.currentText() == severity:
            self.finding_severity_combo.setCurrentIndex(0)
        else:
            self.finding_severity_combo.setCurrentIndex(index)

    def _update_severity_chips(self):
        """Refresh the per-severity counts shown on the triage chips."""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for finding in self.current_findings:
            sev = str(finding.get("severity", "")).upper()
            if sev in counts:
                counts[sev] += 1
        for sev, chip in self._severity_chips.items():
            chip.setText(f"{sev} {counts[sev]}")
            # De-emphasise empty buckets so populated ones stand out.
            chip.setProperty("dim", counts[sev] == 0)
            chip.style().unpolish(chip)
            chip.style().polish(chip)

    def _edit_selected_note(self):
        finding = self._selected_finding()
        if not finding:
            self.statusBar().showMessage("Select a finding first", 3000)
            return
        self._edit_triage_note(finding)

    def _apply_table_filter(self, table: QTableWidget):
        entry = getattr(self, "_table_filters", {}).get(table)
        if not entry:
            return
        search, count_label, status_combo = entry
        query = search.text().strip().lower()
        status = ""
        if status_combo is not None and status_combo.currentIndex() > 0:
            status = status_combo.currentText().strip().lower()
        total = table.rowCount()
        visible = 0
        for row in range(total):
            matches_query = not query
            if query:
                for col in range(table.columnCount()):
                    item = table.item(row, col)
                    if item and query in item.text().lower():
                        matches_query = True
                        break
            matches_status = True
            if status:
                item = table.item(row, 2)
                matches_status = item is not None and item.text().strip().lower() == status
            show = matches_query and matches_status
            table.setRowHidden(row, not show)
            if show:
                visible += 1
        count_label.setText(f"{visible} of {total}")

    def _table_context_menu(self, table: QTableWidget, pos):
        index = table.indexAt(pos)
        menu = QMenu(self)
        copy_cell_action = menu.addAction("Copy cell")
        copy_row_action = menu.addAction("Copy row")
        copy_tsv_action = menu.addAction("Copy selected rows (TSV)")
        chosen = menu.exec(table.viewport().mapToGlobal(pos))
        if chosen is None:
            return
        clipboard = QApplication.clipboard()
        if chosen is copy_cell_action:
            item = table.item(index.row(), index.column()) if index.isValid() else None
            if item:
                clipboard.setText(item.text())
                self.statusBar().showMessage("Cell copied", 2000)
        elif chosen is copy_row_action:
            row = index.row()
            texts = []
            for col in range(table.columnCount()):
                item = table.item(row, col)
                texts.append(item.text() if item else "")
            clipboard.setText("\t".join(texts))
            self.statusBar().showMessage(f"Row {row + 1} copied", 2000)
        elif chosen is copy_tsv_action:
            rows = sorted({i.row() for i in table.selectedIndexes()})
            lines = []
            for row in rows:
                texts = []
                for col in range(table.columnCount()):
                    item = table.item(row, col)
                    texts.append(item.text() if item else "")
                lines.append("\t".join(texts))
            clipboard.setText("\n".join(lines))
            self.statusBar().showMessage(f"{len(lines)} row(s) copied", 2000)

    @staticmethod
    def _route_from_curl(curl: str) -> tuple[str, str]:
        """Fall back to the reproduction line for the route.

        Groups recorded before the module stored method/path have no route in
        the payload; the curl line is the only concrete request persisted, so
        it is honest — and when it is empty the row says so instead of
        inventing an endpoint.
        """
        match = re.match(r"curl -X (\w+) (\S+)", str(curl or ""))
        if match:
            return match.group(1).upper(), match.group(2)
        return "-", "-"

    def _render_proof_path(self, cfg: dict):
        probe = cfg.get("impact_probe")
        probe = probe if isinstance(probe, dict) else {}
        template = str(probe.get("url_template") or "")
        if template:
            expect = probe.get("expect") or {}
            self.schema_impact_probe_label.setText(
                f"Impact probe: ON — re-reads {template} and expects "
                f"{expect.get('op', '?')} {expect.get('value', '?')}")
            self.schema_impact_probe_label.setProperty("tone", "ok")
        else:
            self.schema_impact_probe_label.setText(
                "Impact probe: NOT SET — no candidate can be promoted to "
                "PROOF from this screen until it is")
            self.schema_impact_probe_label.setProperty("tone", "warn")
        cleanup = cfg.get("cleanup")
        cleanup = cleanup if isinstance(cleanup, dict) else {}
        if cleanup:
            self.schema_cleanup_label.setText(
                f"Cleanup: {str(cleanup.get('method') or 'DELETE')} "
                f"{str(cleanup.get('url_template') or '')} — verified by re-read")
            self.schema_cleanup_label.setProperty("tone", "ok")
        else:
            self.schema_cleanup_label.setText(
                "Cleanup: NOT SET — fuzzer-created resources stay on the "
                "target; the ledger records them as not_required")
            self.schema_cleanup_label.setProperty("tone", "warn")
        for label in (self.schema_impact_probe_label,
                      self.schema_cleanup_label):
            label.style().unpolish(label)
            label.style().polish(label)

    def _inject_label(self, row: dict) -> str:
        """Render the inject surface the way the operator configures it."""
        point = row.get("point") or "?"
        name = row.get("name") or ""
        if point == "query":
            return f"query?{name or 'r'}"
        if point == "fragment":
            return f"fragment#{name or 'value'}"
        if point == "path":
            return f"path/{name or 'value'}"
        return point

    def _metric_card(self, label: str, value_label: QLabel, tone: str) -> QFrame:
        card = QFrame()
        card.setObjectName("metricCard")
        card.setProperty("tone", tone)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(10, 8, 10, 8)
        label_widget = QLabel(label.upper())
        label_widget.setObjectName("metricLabel")
        value_label.setObjectName("metricValue")
        layout.addWidget(label_widget)
        layout.addWidget(value_label)
        return card

    def _sync_mode(self):
        self.module_combo.setEnabled(self.mode_combo.currentText() == "Single module")
        self.stage_filter_combo.setEnabled(self.mode_combo.currentText() == "Single module")
        if hasattr(self, "ai_run_button"):
            self.ai_run_button.setEnabled(self.mode_combo.currentText() != "Single module")

    def _prefer_llm_if_ready(self):
        # Surface readiness only. Auto-switching the mode on startup would
        # silently override whatever the operator last chose (Auto is the
        # safe default); they opt into LLM via the mode combo or the
        # AI Guided Run button.
        self._update_operation_context()

    def choose_output_dir(self):
        if self.process and self.process.state() != QProcess.NotRunning:
            return
        selected = QFileDialog.getExistingDirectory(
            self,
            "Output Directory",
            str(self.output_dir),
        )
        if selected:
            self.output_dir = Path(selected)
            self.output_input.setText(str(self.output_dir))
            self._refresh_assessments()
            self.load_results()
            self._update_operation_context()

    def open_target_folder(self):
        path = self._assessment_dir()
        if not path.exists():
            QMessageBox.information(self, "Folder Missing", "No output folder exists for this target yet.")
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def _read_investigation(self, state_dir):
        """Read one committed generation, with legacy JSON compatibility."""
        from core.persistence import valid_snapshot
        defaults = {"module": {}, "assets": {"nodes": [], "edges": []},
                    "findings": {"findings": []}, "evidence": {"items": []}}
        snapshot_path = state_dir / "snapshot.json"
        if snapshot_path.exists():
            snapshot = self._read_json(snapshot_path, None)
            if valid_snapshot(snapshot):
                valid_identity = True
                if state_dir.parent.parent.name == "assessments":
                    try:
                        expected = AssessmentStore(self.output_dir, self.target_input.text()).open(
                            state_dir.parent.name).metadata
                        valid_identity = snapshot["module"].get("assessment") == expected
                    except (ValueError, OSError):
                        valid_identity = False
                if valid_identity:
                    return {key: snapshot[key] for key in defaults}
            # Never mix a broken commit with possibly stale compatibility views.
            errors = getattr(self, "_read_errors", [])
            errors.extend(["snapshot.json", *(f"{key}.json" for key in defaults)])
            self._read_errors = list(dict.fromkeys(errors))
            return {key: None for key in defaults}
        return {key: self._read_json(state_dir / f"{key}.json", default)
                for key, default in defaults.items()}

    def _read_stdout(self):
        if not self.process:
            return
        text = bytes(self.process.readAllStandardOutput()).decode("utf-8", errors="replace")
        self.log_output.appendPlainText(text.rstrip())

    def _read_stderr(self):
        if not self.process:
            return
        text = bytes(self.process.readAllStandardError()).decode("utf-8", errors="replace")
        self.log_output.appendHtml(
            f'<span style="color:#f87171">{html_escape(text.rstrip())}</span>'
        )

    def _update_risk_metrics(self, findings_list: list[dict], summary_bundle: dict):
        """Max Risk / Crit-High from live findings; report summary as fallback.

        These two metrics used to read the report-time summary snapshot
        only, so they showed "-" until the first report and went stale
        after any CLI run that added findings.
        """
        if findings_list:
            self.max_risk_value.setText(
                str(max(int(f.get("risk_score") or 0) for f in findings_list)))
            self.critical_high_value.setText(str(sum(
                1 for f in findings_list
                if str(f.get("severity", "")).upper() in ("CRITICAL", "HIGH")
            )))
        else:
            risk = summary_bundle.get("risk", {})
            self.max_risk_value.setText(str(risk.get("max_score", "-")))
            self.critical_high_value.setText(str(risk.get("critical_high", "-")))

    def load_results(self):
        target = self.target_input.text().strip()
        if not target:
            return
        self._read_errors = []
        self._refresh_assessments()
        base = self._assessment_dir()
        identity = str(base.resolve())
        if self._loaded_assessment_path != identity:
            # Last-good data is local to one selection, never another service/run.
            self.current_module = {}
            self.current_assets = {"nodes": [], "edges": []}
            self.current_evidence = {"items": []}
            self.current_findings = []
            self._triage = {}
            self.current_attack_graph = {}
            self._loaded_assessment_path = identity
        state_dir = base / "state"
        stores = self._read_investigation(state_dir)
        module, assets, findings, evidence = (
            stores[k] for k in ("module", "assets", "findings", "evidence"))
        summary_bundle = self._read_json(self._summary_path(), {})
        # A corrupt file must not zero the UI: keep the previous
        # in-memory store for it and flag the problem. Returning the
        # default used to read as "the run produced nothing".
        failed = set(self._read_errors)
        if "module.json" in failed:
            module = self.current_module if isinstance(self.current_module, dict) else {}
        if "assets.json" in failed:
            assets = (self.current_assets if isinstance(self.current_assets, dict)
                      else {"nodes": [], "edges": []})
        if "findings.json" in failed:
            findings_list = list(self.current_findings)
        else:
            findings_list = (findings.get("findings", [])
                             if isinstance(findings, dict) else [])
        if "evidence.json" in failed:
            evidence = (self.current_evidence if isinstance(self.current_evidence, dict)
                        else {"items": []})
        if not isinstance(module, dict):
            module = {}
        if not isinstance(assets, dict):
            assets = {"nodes": [], "edges": []}
        if not isinstance(evidence, dict):
            evidence = {"items": []}
        nodes = assets.get("nodes", [])
        evidence_items = evidence.get("items", [])

        self.assets_value.setText(str(len(nodes)))
        self.relations_value.setText(str(count_relations(assets)))
        self.findings_value.setText(str(len(findings_list)))
        self.evidence_value.setText(str(len(evidence_items)))
        stats = module.get("stats", {})
        self.requests_value.setText(str(stats.get("total_requests", "-")))
        self.completed_value.setText(str(len(module.get("completed", []))))
        self.skipped_value.setText(str(len(module.get("skipped", []))))
        self.blocked_value.setText(str(len(module.get("blocked", []))))
        self.incomplete_value.setText(str(self._incomplete_count(module)))
        active_count = sum(1 for mid, entry in MODULE_REGISTRY.items() if entry.get("active"))
        self.active_value.setText(str(active_count))
        # Live risk: computed from findings in state instead of the
        # report-time summary snapshot, so Max Risk / Crit-High never lag
        # behind findings that changed since the last report run.
        self._update_risk_metrics(findings_list, summary_bundle)

        report_path = self._report_path()
        report_display = self._display_path(report_path) if report_path.exists() else "-"
        self.report_value.setText(report_display)
        self.report_value.setToolTip(str(report_path) if report_path.exists() else "")
        self.report_path_label.setText(report_display if report_path.exists() else "No report generated yet")
        self.report_path_label.setToolTip(str(report_path) if report_path.exists() else "")
        attack_plan_path = self._attack_plan_path()
        attack_plan_display = self._display_path(attack_plan_path) if attack_plan_path.exists() else ""
        self.attack_plan_path_label.setText(
            attack_plan_display if attack_plan_path.exists() else "No AI attack plan generated yet"
        )
        self.attack_plan_path_label.setToolTip(str(attack_plan_path) if attack_plan_path.exists() else "")
        self._load_findings(findings_list)
        self._load_assets(nodes)
        self._load_modules(module)
        self._load_evidence(evidence_items)
        self._load_submissions()
        self._load_summary_json(summary_bundle)
        self.current_assets = assets
        self.current_module = module
        self.current_evidence = evidence
        # Reads the stores above, so it runs after the last-good swap.
        self._load_schema_view()
        self._load_authz_view()
        self._load_cspt_view()
        self._load_orm_view()
        self._update_operation_context()
        self.refresh_graph()
        self._load_attack_graph()
        if failed:
            self._set_status(
                "error",
                "Corrupt: " + ", ".join(sorted(failed)),
                "Showing last good data",
            )
        if report_path.exists():
            report_text = report_path.read_text(errors="replace")
            self.report_preview.setMarkdown(report_text)
            self.report_raw.setPlainText(report_text)
        else:
            message = "No report generated yet. Use the Report action or enable automatic report generation."
            self.report_preview.setPlainText(message)
            self.report_raw.setPlainText("")
        if attack_plan_path.exists():
            self.attack_plan_preview.setMarkdown(attack_plan_path.read_text(errors="replace"))
        else:
            self.attack_plan_preview.setPlainText(
                "No AI attack plan generated yet. Run AI Attack Plan after OSINT collection."
            )

    def _display_path(self, path: Path, max_parts: int = 4) -> str:
        parts = path.parts
        if len(parts) <= max_parts:
            return str(path)
        return str(Path("...").joinpath(*parts[-max_parts:]))

    def _target_output_name(self) -> str:
        target = self.target_input.text().strip()
        try:
            return urlparse(AssessmentStore(self.output_dir, target).origin).hostname
        except (ValueError, OSError):
            pass
        parsed = urlparse(target if "://" in target else f"//{target}")
        return re.sub(r"[^A-Za-z0-9._-]", "_", parsed.hostname or "invalid-target")

    def import_legacy_results(self):
        if self.process and self.process.state() != QProcess.NotRunning:
            return
        source = QFileDialog.getExistingDirectory(self, "Inactive Legacy Result Directory", str(self.output_dir))
        if not source:
            return
        try:
            store = AssessmentStore(self.output_dir, self.target_input.text())
            answer = QMessageBox.question(
                self, "Import Legacy Results",
                f"Copy this inactive legacy investigation and bind the copy to {store.origin}?\n"
                "The original directory will not be changed.", QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No)
            if answer != QMessageBox.Yes:
                return
            imported = store.import_legacy(source)
            self._pending_assessment = None
            self._refresh_assessments(preferred=imported.id)
            self.load_results()
            self._set_status("ok", f"Imported {imported.id[:12]}")
        except (ValueError, OSError) as exc:
            QMessageBox.warning(self, "Import Failed", str(exc))

    def _summary_path(self) -> Path:
        target = self._target_output_name()
        return self._assessment_dir() / f"{target}_summary.json"

    def _incomplete_count(self, module: dict) -> int:
        """Modules whose latest run timed out or errored without ever finishing.

        A deadline kill lands in neither `completed` nor `skipped`, so before
        this the run read as "not started yet": invisible in every metric and
        the progress bar denominator treated it as pending forever.
        """
        completed = set(module.get("completed", []))
        skipped = {
            item.get("module_id") for item in module.get("skipped", [])
            if isinstance(item, dict)
        }
        blocked = {
            item.get("module_id") for item in module.get("blocked", [])
            if isinstance(item, dict)
        }
        resolved = completed | skipped | blocked
        count = 0
        seen: set[str] = set()
        for run in reversed(module.get("runs", [])):
            module_id = run.get("module_id", "")
            if not module_id or module_id in seen:
                continue
            seen.add(module_id)
            status = str(run.get("status", "")).lower()
            if status in ("timeout", "error", "failed", "incomplete", "interrupted", "cancelled", "stopped") and module_id not in resolved:
                count += 1
        return count

    def _load_summary_json(self, summary: dict):
        if summary:
            self.summary_json.setPlainText(json.dumps(summary, indent=2, default=str))
        else:
            self.summary_json.setPlainText("No summary JSON generated yet.")

    def _set_combo_value(self, combo: QComboBox, value: str):
        index = combo.findText(value)
        if index >= 0:
            combo.setCurrentIndex(index)
        elif combo.isEditable():
            combo.setCurrentText(value)

    @staticmethod
    def _set_spin(spin: QSpinBox, value, default: int) -> bool:
        """Load a value into a spin box. Returns True when the file value
        fell outside the widget range and was clamped: saving afterwards
        would otherwise rewrite the config with the clamped value and no
        warning. Callers stash the note via _note_spin_clamp."""
        if value in (None, ""):
            spin.setValue(default)
            return False
        try:
            number = int(value)
        except (TypeError, ValueError):
            spin.setValue(default)
            return False
        clamped = number < spin.minimum() or number > spin.maximum()
        spin.setValue(number)
        if clamped:
            spin.setProperty("clamped_from", number)
        else:
            spin.setProperty("clamped_from", None)
        return clamped

    def _note_spin_clamp(self, clamped: bool, label: str) -> None:
        if clamped:
            notes = getattr(self, "_spin_clamp_notes", None)
            if notes is None:
                notes = self._spin_clamp_notes = []
            notes.append(label)

    def _headers_to_text(self, headers: dict) -> str:
        if not isinstance(headers, dict):
            return ""
        return "\n".join(f"{key}: {value}" for key, value in headers.items())

    def _text_to_headers(self, text: str) -> dict:
        headers = {}
        dropped = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            if ":" not in line:
                dropped.append(line)
                continue
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()
            if key and value:
                headers[key] = value
            else:
                dropped.append(line)
        if dropped:
            self.statusBar().showMessage(
                f"Ignored {len(dropped)} header line(s) without "
                f"'Name: value' shape: {', '.join(dropped[:3])}", 8000)
        return headers

    def _list_to_text(self, value) -> str:
        if isinstance(value, str):
            items = [item.strip() for item in value.split(",")]
        else:
            items = [str(item).strip() for item in (value or [])]
        return "\n".join(item for item in items if item)

    def _text_to_list(self, text: str) -> list[str]:
        # Newlines only: splitting on commas corrupts values that contain
        # them (URLs with query strings, payload lists).
        return [item.strip() for item in str(text or "").splitlines()
                if item.strip()]

    def _read_json(self, path: Path, default):
        """Read JSON, recording corrupt files so load_results can warn.

        A missing file is normal (first run for this target); a file that
        exists but fails to parse is not. That used to silently return the
        default, which zeroed tables and metrics with no explanation.
        """
        if not path.exists():
            return default
        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            errors = getattr(self, "_read_errors", None)
            if errors is not None:
                errors.append(path.name)
            return default

    def _refresh_tools_status(self):
        if not hasattr(self, "tools_table"):
            return
        # Effective backend: shell env wins over the config file
        # (configure_tool_backend reads both; dotenv is loaded via agents).
        mode = configure_tool_backend(self._read_config())
        self._tools_backend_mode = mode
        rows: list[tuple[str, str, str, str]] = [
            (tool.name, ", ".join(tool.categories), tool.description,
             "docker" if tool.name in DOCKER_TOOLS else "local")
            for tool in TOOL_DEFINITIONS
        ]
        known = {name for name, _cats, _desc, _via in rows}
        for name in sorted(DOCKER_TOOLS - known):
            categories, purpose = EXTRA_CONTAINER_TOOLS.get(name, (["container"], "Toolchain image binary"))
            rows.append((name, ", ".join(categories), purpose, "docker"))
        rows.sort(key=lambda row: row[0])
        if hasattr(self, "tools_backend_label"):
            if mode == "docker":
                ready = tool_available("nuclei")
                state = "image ready" if ready else "image missing — build/pull osint-tools"
            else:
                state = "host binaries"
            self.tools_backend_label.setText(f"Backend: {mode} ({state})")
        self.tools_table.setRowCount(len(rows))
        for row, (name, categories, purpose, via) in enumerate(rows):
            ready = tool_available(name)
            values = [name, "yes" if ready else "no", via, categories, purpose]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                if col == 1:
                    item.setForeground(QColor("#4ade80" if ready else "#f87171"))
                self.tools_table.setItem(row, col, item)

    def _load_tools_requirements_preview(self):
        if not hasattr(self, "tools_requirements_preview"):
            return
        if TOOLS_REQUIREMENTS.exists():
            self.tools_requirements_preview.setPlainText(
                TOOLS_REQUIREMENTS.read_text(errors="replace")
            )
        else:
            self.tools_requirements_preview.setPlainText("tools_requirements.txt not found.")

    def open_tools_requirements(self):
        if not TOOLS_REQUIREMENTS.exists():
            QMessageBox.information(self, "Missing File", "tools_requirements.txt does not exist.")
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(TOOLS_REQUIREMENTS)))

    def install_missing_tools(self):
        if self.process and self.process.state() != QProcess.NotRunning:
            self.statusBar().showMessage("Already running — wait for the current process", 3000)
            return
        # Under the docker backend the tools ship inside the image; running
        # the host installer would waste minutes installing binaries nothing
        # will call. Point at the image build instead.
        backend = getattr(self, "_tools_backend_mode", None) or configure_tool_backend(self._read_config())
        if backend == "docker":
            QMessageBox.information(
                self,
                "Docker Backend Active",
                "Tools run inside the osint-tools image under the docker "
                "backend, so there is nothing to install on this host.\n\n"
                "If tools show as missing, build (or rebuild) the image:\n\n"
                "docker build -f docker/Dockerfile.tools -t osint-tools:latest .",
            )
            return
        # `--install-tools` still demands -t because the parser marks it
        # required; the target is irrelevant to the install itself.
        target = self.target_input.text().strip() or "localhost"
        args = [
            str(ORCHESTRATOR),
            "-t", target,
            "-o", str(self.output_dir),
            "-c", str(self.config_path),
            "--install-tools",
        ]
        self._start_process(args)

    def _qt_environment(self, env: dict):
        from PySide6.QtCore import QProcessEnvironment

        process_env = QProcessEnvironment()
        for key, value in env.items():
            process_env.insert(key, value)
        return process_env

    def _apply_style(self):
        app = QApplication.instance()
        if app is not None:
            app.setPalette(_dark_palette())
        theme_path = Path(__file__).with_name("theme.qss")
        try:
            qss = theme_path.read_text(encoding="utf-8")
        except OSError:
            return
        self.setStyleSheet(qss)
