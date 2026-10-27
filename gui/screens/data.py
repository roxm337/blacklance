"""Assets / modules / evidence data screen.

Mixin for gui.app.MainWindow; see that class for composition.
"""
from __future__ import annotations

from gui._shared import *  # noqa: F401,F403


class DataScreenMixin:

    def _open_selected_evidence(self):
        finding = self._selected_finding()
        if not finding:
            self.statusBar().showMessage("Select a finding first", 3000)
            return
        self._open_finding_evidence(finding)

    def _filter_by_selected_module(self):
        finding = self._selected_finding()
        if not finding:
            self.statusBar().showMessage("Select a finding first", 3000)
            return
        module_id = str(finding.get("module_id", ""))
        if module_id:
            self.finding_search.setText(module_id)

    def _show_selected_in_assets(self):
        """Jump to Data → Assets, filtered to this finding's assets."""
        finding = self._selected_finding()
        if not finding:
            self.statusBar().showMessage("Select a finding first", 3000)
            return
        keys = [str(k) for k in (finding.get("asset_keys") or []) if k]
        if not keys:
            self.statusBar().showMessage("This finding has no linked assets", 3000)
            return
        # Data screen is index 3 (run, triage, graph, data, report, settings);
        # Assets is its first sub-tab.
        self.show_screen(3)
        if hasattr(self, "data_tabs"):
            self.data_tabs.setCurrentIndex(0)
        entry = getattr(self, "_table_filters", {}).get(self.assets_table)
        if entry:
            # asset_keys are "type:value"; the table's Value column holds
            # the value, so strip the prefix to get a matchable query.
            first = keys[0]
            query = first.split(":", 1)[1] if ":" in first else first
            entry[0].setText(query)
        self.statusBar().showMessage(
            f"Assets filtered to {finding.get('id')} ({len(keys)} linked)", 4000)

    def _build_data_screen(self) -> QWidget:
        """Screen 3: assets, modules, evidence, submissions in sub-tabs."""
        page = QWidget()
        page.setObjectName("screenData")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        tabs = QTabWidget()
        tabs.setObjectName("screenTabs")
        tabs.setDocumentMode(True)
        tabs.tabBar().setUsesScrollButtons(True)
        tabs.tabBar().setDrawBase(False)
        self.data_tabs = tabs
        self._table_filters: dict[QTableWidget, tuple[QLineEdit, QLabel, QComboBox | None]] = {}

        self.assets_table = QTableWidget(0, 4)
        self.assets_table.setHorizontalHeaderLabels(["Type", "Value", "Confidence", "Sources"])
        self.assets_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        tabs.addTab(self._wrap_data_tab(self.assets_table, "Filter assets…"), "Assets")

        self.modules_table = QTableWidget(0, 8)
        self.modules_table.setHorizontalHeaderLabels([
            "Stage", "Module", "Status", "Detectability", "Requests", "Assets +", "Findings +", "Error",
        ])
        self.modules_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.modules_table.horizontalHeader().setSectionResizeMode(7, QHeaderView.Stretch)
        self.modules_table.setSortingEnabled(True)
        status_combo = QComboBox()
        status_combo.setObjectName("filterCombo")
        status_combo.addItem("All statuses")
        for status in (
            "completed", "running", "pending", "timeout", "incomplete", "interrupted", "cancelled", "stopped",
            "error", "failed", "blocked", "skipped",
        ):
            status_combo.addItem(status)
        status_combo.setToolTip("Show only modules with this status")
        tabs.addTab(
            self._wrap_data_tab(self.modules_table, "Filter modules…", status_combo),
            "Modules",
        )

        self.evidence_table = QTableWidget(0, 6)
        self.evidence_table.setHorizontalHeaderLabels(
            ["ID", "Module", "Type", "Subject", "Path", "Findings"])
        self.evidence_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.evidence_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.evidence_table.cellDoubleClicked.connect(self._open_evidence_cell)
        tabs.addTab(self._wrap_data_tab(self.evidence_table, "Filter evidence…"), "Evidence")

        self.submissions_table = QTableWidget(0, 4)
        self.submissions_table.setHorizontalHeaderLabels(["File", "Finding", "Size", "Path"])
        self.submissions_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.submissions_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.submissions_table.cellDoubleClicked.connect(self._open_submission_cell)
        tabs.addTab(
            self._wrap_data_tab(self.submissions_table, "Filter submissions…"),
            "Submissions",
        )

        layout.addWidget(tabs, 1)
        return page

    def _wrap_data_tab(
        self, table: QTableWidget, placeholder: str, status_combo: QComboBox | None = None
    ) -> QWidget:
        """Filter bar + table, with search, status combo, and live counts."""
        page = QWidget()
        bar_layout = QHBoxLayout()
        bar_layout.setContentsMargins(0, 0, 0, 0)
        bar_layout.setSpacing(6)
        search = QLineEdit()
        search.setPlaceholderText(placeholder)
        search.setClearButtonEnabled(True)
        count_label = QLabel("0 of 0")
        count_label.setObjectName("opsSecondary")
        bar_layout.addWidget(search, 1)
        if status_combo is not None:
            bar_layout.addWidget(status_combo)
        bar_layout.addWidget(count_label)
        table_layout = QVBoxLayout(page)
        table_layout.setContentsMargins(0, 0, 0, 0)
        table_layout.setSpacing(4)
        table_layout.addLayout(bar_layout)
        table_layout.addWidget(table, 1)

        self._table_filters[table] = (search, count_label, status_combo)
        search.textChanged.connect(lambda _text, t=table: self._apply_table_filter(t))
        if status_combo is not None:
            status_combo.currentIndexChanged.connect(
                lambda _index, t=table: self._apply_table_filter(t)
            )
        # Sorting moves rows under a live filter; re-apply so hidden rows
        # stay hidden in the new order.
        table.horizontalHeader().sortIndicatorChanged.connect(
            lambda _order, _sec, t=table: self._apply_table_filter(t)
        )
        table.setSortingEnabled(True)
        table.horizontalHeader().setSortIndicatorShown(True)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setContextMenuPolicy(Qt.CustomContextMenu)
        table.customContextMenuRequested.connect(
            lambda pos, t=table: self._table_context_menu(t, pos)
        )
        return page

    def _select_single_module(self, module_id: str) -> bool:
        """Switch the run screen into single-module mode on one module."""
        self.stage_filter_combo.setCurrentIndex(0)
        self.mode_combo.setCurrentText("Single module")
        index = self.module_combo.findData(module_id)
        if index < 0:
            return False
        self.module_combo.setCurrentIndex(index)
        return True

    def _read_evidence_payloads(self, evidence_items: list, wanted: str,
                                limit: int) -> tuple[list[dict], int]:
        """Read payloads of one type: (documents, unreadable count).

        A payload that cannot be read is counted, never silently dropped —
        an empty matrix and an unreadable matrix are different claims.
        """
        base = self._assessment_dir()
        docs: list[dict] = []
        unreadable = 0
        for item in evidence_items:
            if not isinstance(item, dict) or item.get("type") != wanted:
                continue
            path = base / str(item.get("path") or "")
            if not path.exists():
                continue
            try:
                doc = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError, UnicodeDecodeError):
                unreadable += 1
                continue
            if not isinstance(doc, dict):
                unreadable += 1
                continue
            docs.append({"item": item, "doc": doc})
        return docs[:limit], unreadable

    def _refresh_module_list(self):
        selected = self.module_combo.currentData() if hasattr(self, "module_combo") else None
        self.module_combo.clear()
        stage_filter = self.stage_filter_combo.currentData() if hasattr(self, "stage_filter_combo") else 0
        for module_id in get_all_module_ids():
            entry = MODULE_REGISTRY[module_id]
            if stage_filter and entry.get("stage") != stage_filter:
                continue
            kind = " [ACTIVE]" if entry.get("active") else ""
            label = f"S{entry['stage']}  {module_id}{kind}"
            self.module_combo.addItem(label, module_id)
            if selected == module_id:
                self.module_combo.setCurrentIndex(self.module_combo.count() - 1)
        self._sync_mode()
        self._update_module_hint()

    def _update_module_hint(self):
        module_id = self.module_combo.currentData()
        entry = MODULE_REGISTRY.get(module_id or "", {})
        if not entry:
            self.module_hint.setText("-")
            return
        kind = "active" if entry.get("active") else "passive"
        deps = ", ".join(entry.get("depends_on", [])) or "none"
        self.module_hint.setText(
            f"Stage {entry.get('stage')} · {entry.get('detectability')} · {kind} · deps: {deps}"
        )


    def _load_assets(self, assets: list[dict]):
        self.assets_table.setSortingEnabled(False)
        self.assets_table.setRowCount(len(assets))
        for row, asset in enumerate(assets):
            values = [
                asset.get("type", ""),
                asset.get("value", ""),
                asset.get("confidence", ""),
                ", ".join(asset.get("sources", [])),
            ]
            for col, value in enumerate(values):
                self.assets_table.setItem(row, col, QTableWidgetItem(value))
        self.assets_table.setSortingEnabled(True)
        self._apply_table_filter(self.assets_table)

    def _load_modules(self, module: dict):
        latest_runs = {}
        for run in module.get("runs", []):
            latest_runs[run.get("module_id", "")] = run
        skipped = {
            item.get("module_id"): item.get("reason", "")
            for item in module.get("skipped", [])
            if isinstance(item, dict)
        }
        blocked = {
            item.get("module_id"): item.get("reason", "")
            for item in module.get("blocked", [])
            if isinstance(item, dict)
        }
        completed = set(module.get("completed", []))
        self.modules_table.setSortingEnabled(False)
        module_ids = get_all_module_ids()
        self.modules_table.setRowCount(len(module_ids))
        for row, module_id in enumerate(module_ids):
            entry = MODULE_REGISTRY[module_id]
            run = latest_runs.get(module_id, {})
            status = run.get("status", "")
            if not status:
                if module_id in completed:
                    status = "completed"
                elif module_id in skipped:
                    status = "skipped"
                elif module_id in blocked:
                    status = "blocked"
                else:
                    status = "pending"
            values = [
                str(entry.get("stage", "")),
                module_id,
                status,
                entry.get("detectability", ""),
                str(run.get("requests", 0)),
                str(run.get("assets_added", 0)),
                str(run.get("findings_added", 0)),
                run.get("error") or skipped.get(module_id) or blocked.get(module_id) or "",
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                if col in (0, 4, 5, 6):
                    item.setData(Qt.UserRole, int(value or 0))
                if col == 2:
                    color = STATUS_COLORS.get(status.lower())
                    if color:
                        item.setForeground(QColor(color))
                    if status.lower() in ("timeout", "error", "failed", "incomplete"):
                        item.setToolTip("coverage incomplete — run did not finish")
                if col == 7 and value:
                    item.setToolTip(str(value))
                self.modules_table.setItem(row, col, item)
        self.modules_table.setSortingEnabled(True)
        self._apply_table_filter(self.modules_table)

    def _load_evidence(self, items: list[dict]):
        self.evidence_table.setSortingEnabled(False)
        self.evidence_table.setRowCount(len(items))
        # Reverse evidence_refs so each evidence row shows which findings
        # cite it — without this the evidence table was a dead end.
        cited_by: dict[str, list[str]] = {}
        for finding in self.current_findings:
            for ref in finding.get("evidence_refs") or []:
                cited_by.setdefault(str(ref), []).append(str(finding.get("id", "")))
        for row, item in enumerate(items):
            values = [
                item.get("id", ""),
                item.get("module_id", ""),
                item.get("type", ""),
                str(item.get("subject", "")),
                item.get("path", ""),
                ", ".join(cited_by.get(str(item.get("id", "")), [])),
            ]
            for col, value in enumerate(values):
                self.evidence_table.setItem(row, col, QTableWidgetItem(value))
        self.evidence_table.setSortingEnabled(True)
        self._apply_table_filter(self.evidence_table)

    @staticmethod
    def _module_section(config: dict, name: str) -> dict:
        """The modules.<name> mapping, or {} when absent or malformed."""
        section = (config.get("modules", {}) or {}).get(name, {})
        return section if isinstance(section, dict) else {}

    @staticmethod
    def _ensure_module_section(config: dict, name: str) -> dict:
        """The modules.<name> mapping, created when missing."""
        config.setdefault("modules", {})
        modules_cfg = config["modules"]
        if not isinstance(modules_cfg, dict):
            modules_cfg = config["modules"] = {}
        section = modules_cfg.get(name)
        if not isinstance(section, dict):
            section = modules_cfg[name] = {}
        return section

    def _open_evidence_cell(self, row: int, _col: int):
        item = self.evidence_table.item(row, 4)
        if not item:
            return
        path = self._assessment_dir() / item.text()
        if path.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))
