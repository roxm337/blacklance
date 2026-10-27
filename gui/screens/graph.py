"""Asset + attack graph screen.

Mixin for gui.app.MainWindow; see that class for composition.
"""
from __future__ import annotations

from gui._shared import *  # noqa: F401,F403


class GraphScreenMixin:

    def _build_graph_screen(self) -> QWidget:
        """Screen 2: intelligence graph, analytical filters and attack paths."""
        page = QWidget()
        page.setObjectName("screenGraph")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        tabs = QTabWidget()
        tabs.setObjectName("screenTabs")
        tabs.setDocumentMode(True)
        tabs.tabBar().setUsesScrollButtons(True)
        tabs.tabBar().setDrawBase(False)

        graph_widget = QWidget()
        graph_layout = QVBoxLayout(graph_widget)
        graph_layout.setContentsMargins(0, 0, 0, 0)
        graph_layout.setSpacing(8)
        graph_toolbar = QFrame()
        graph_toolbar.setObjectName("graphToolbar")
        graph_header = QGridLayout(graph_toolbar)
        graph_header.setContentsMargins(12, 9, 12, 9)
        graph_header.setHorizontalSpacing(8)
        graph_header.setVerticalSpacing(7)
        self.graph_summary = QLabel("No graph loaded")
        self.graph_summary.setObjectName("graphSummary")
        self.graph_summary.setWordWrap(True)
        self.graph_summary.setMinimumWidth(0)
        self.graph_search = QLineEdit()
        self.graph_search.setObjectName("graphSearch")
        self.graph_search.setPlaceholderText("Find entity, source or attribute…")
        self.graph_search.setClearButtonEnabled(True)
        self.graph_type_filter = QComboBox()
        self.graph_type_filter.setObjectName("graphFilter")
        self.graph_type_filter.addItem("All entity types", "")
        self.graph_relation_filter = QComboBox()
        self.graph_relation_filter.setObjectName("graphFilter")
        self.graph_relation_filter.addItem("All relations", "")
        self.graph_provenance_filter = QComboBox()
        self.graph_provenance_filter.setObjectName("graphFilter")
        self.graph_provenance_filter.addItem("All provenance", "all")
        self.graph_provenance_filter.addItem("Observed only", "observed")
        self.graph_provenance_filter.addItem("Inferred only", "inferred")
        self.graph_aggregate_check = QCheckBox("Group dense types")
        self.graph_aggregate_check.setChecked(True)
        self.graph_aggregate_check.stateChanged.connect(self.refresh_graph)
        self.graph_labels_check = QCheckBox("Labels")
        self.graph_labels_check.setChecked(False)
        self.graph_labels_check.stateChanged.connect(self.refresh_graph)
        self.graph_edges_check = QCheckBox("Relations")
        self.graph_edges_check.setChecked(True)
        self.graph_edges_check.stateChanged.connect(self.refresh_graph)
        self.fit_graph_button = QPushButton("Fit")
        self.fit_graph_button.setObjectName("btnGhost")
        self.fit_graph_button.clicked.connect(self.refresh_graph)
        self.graph_legend = QLabel(
            "<span style='color:#35c7b1'>●</span> observed &nbsp; "
            "<span style='color:#94a3b8'>●</span> inferred &nbsp; "
            "<span style='color:#fbbf24'>●</span> proposed/focus &nbsp; "
            "<span style='color:#f87171'>◉</span> high-risk finding"
        )
        self.graph_legend.setObjectName("graphLegend")
        graph_header.addWidget(self.graph_summary, 0, 0, 1, 5)
        graph_header.addWidget(self.graph_search, 1, 0, 1, 2)
        graph_header.addWidget(self.graph_type_filter, 1, 2)
        graph_header.addWidget(self.graph_relation_filter, 1, 3)
        graph_header.addWidget(self.graph_provenance_filter, 1, 4)
        graph_header.addWidget(self.graph_legend, 2, 0, 1, 2)
        options = QHBoxLayout()
        options.setSpacing(12)
        options.addWidget(self.graph_aggregate_check)
        options.addWidget(self.graph_labels_check)
        options.addWidget(self.graph_edges_check)
        options.addWidget(self.fit_graph_button)
        graph_header.addLayout(options, 2, 2, 1, 3)
        graph_header.setColumnStretch(0, 2)
        graph_header.setColumnStretch(1, 2)
        graph_layout.addWidget(graph_toolbar)

        self._graph_filter_timer = QTimer(self)
        self._graph_filter_timer.setSingleShot(True)
        self._graph_filter_timer.setInterval(220)
        self._graph_filter_timer.timeout.connect(self.refresh_graph)
        self.graph_search.textChanged.connect(lambda *_: self._graph_filter_timer.start())
        self.graph_type_filter.currentIndexChanged.connect(self.refresh_graph)
        self.graph_relation_filter.currentIndexChanged.connect(self.refresh_graph)
        self.graph_provenance_filter.currentIndexChanged.connect(self.refresh_graph)

        self.graph_view = QWebEngineView()
        # Default page background is white — a jarring flash before the
        # dark graph html paints (and a white block in headless runs).
        self.graph_view.page().setBackgroundColor(QColor("#0a0f14"))
        self.graph_view.setMinimumSize(0, 0)
        self.graph_brief = QLabel("Run collection to build an intelligence brief.")
        self.graph_brief.setObjectName("graphBriefText")
        self.graph_brief.setWordWrap(True)
        self.graph_brief.setTextFormat(Qt.RichText)
        self.graph_brief.setTextInteractionFlags(Qt.TextSelectableByMouse)
        brief_panel = QFrame()
        brief_panel.setObjectName("graphBrief")
        brief_layout = QVBoxLayout(brief_panel)
        brief_layout.setContentsMargins(14, 13, 14, 13)
        brief_title = QLabel("Analyst brief")
        brief_title.setObjectName("graphBriefTitle")
        brief_layout.addWidget(brief_title)
        brief_layout.addWidget(self.graph_brief)
        brief_layout.addStretch(1)
        brief_scroll = QScrollArea()
        brief_scroll.setObjectName("graphBriefScroll")
        brief_scroll.setWidgetResizable(True)
        brief_scroll.setMinimumWidth(285)
        brief_scroll.setMaximumWidth(360)
        brief_scroll.setWidget(brief_panel)
        graph_splitter = QSplitter(Qt.Horizontal)
        graph_splitter.setObjectName("graphSplitter")
        graph_splitter.addWidget(self.graph_view)
        graph_splitter.addWidget(brief_scroll)
        graph_splitter.setStretchFactor(0, 1)
        graph_splitter.setCollapsible(0, False)
        graph_splitter.setCollapsible(1, False)
        graph_splitter.setSizes([900, 310])
        graph_layout.addWidget(graph_splitter, 1)
        self.graph_splitter = graph_splitter
        tabs.addTab(graph_widget, "Asset Graph")

        attack_widget = QWidget()
        attack_layout = QVBoxLayout(attack_widget)
        attack_layout.setContentsMargins(0, 0, 0, 0)
        attack_layout.setSpacing(6)
        attack_toolbar = QFrame()
        attack_toolbar.setObjectName("graphToolbar")
        attack_toolbar_layout = QVBoxLayout(attack_toolbar)
        attack_toolbar_layout.setContentsMargins(12, 9, 12, 9)
        self.attack_graph_summary = QLabel("No attack graph loaded")
        self.attack_graph_summary.setWordWrap(True)
        self.attack_graph_summary.setObjectName("graphSummary")
        attack_toolbar_layout.addWidget(self.attack_graph_summary)
        attack_legend = QLabel(
            "<span style='color:#35c7b1'>●</span> established path &nbsp; "
            "<span style='color:#fbbf24'>●</span> proposed probe &nbsp; "
            "<span style='color:#f87171'>●</span> vulnerability"
        )
        attack_legend.setObjectName("graphLegend")
        attack_toolbar_layout.addWidget(attack_legend)
        attack_layout.addWidget(attack_toolbar)

        attack_brief = QFrame()
        attack_brief.setObjectName("graphBrief")
        attack_brief_layout = QVBoxLayout(attack_brief)
        attack_brief_layout.setContentsMargins(14, 13, 14, 13)
        probe_caption = QLabel("Operation brief")
        probe_caption.setObjectName("graphBriefTitle")
        attack_brief_layout.addWidget(probe_caption)
        self.probe_plan_label = QLabel("Probe plan: not recorded")
        self.probe_plan_label.setWordWrap(True)
        self.probe_plan_label.setObjectName("opsSecondary")
        attack_brief_layout.addWidget(self.probe_plan_label)
        self.probe_plan_table = QTableWidget(0, 2)
        self.probe_plan_table.setHorizontalHeaderLabels(["Reason not proposed", "Surfaces"])
        self.probe_plan_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.probe_plan_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.probe_plan_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.probe_plan_table.setMinimumHeight(180)
        attack_brief_layout.addWidget(self.probe_plan_table, 1)

        self.attack_graph_view = QWebEngineView()
        self.attack_graph_view.page().setBackgroundColor(QColor("#0a0f14"))
        self.attack_graph_view.setMinimumSize(0, 0)
        attack_splitter = QSplitter(Qt.Horizontal)
        attack_splitter.setObjectName("graphSplitter")
        attack_splitter.addWidget(self.attack_graph_view)
        attack_splitter.addWidget(attack_brief)
        attack_splitter.setStretchFactor(0, 1)
        attack_splitter.setCollapsible(0, False)
        attack_splitter.setCollapsible(1, False)
        attack_splitter.setSizes([900, 320])
        attack_layout.addWidget(attack_splitter, 1)
        self.attack_graph_splitter = attack_splitter
        tabs.addTab(attack_widget, "Attack Graph")

        layout.addWidget(tabs, 1)
        return page

    def generate_attack_plan(self):
        self.run_module_action("attack_planner")

    def _attack_plan_path(self) -> Path:
        target = self._target_output_name()
        return self._assessment_dir() / f"{target}_attack_plan.md"

    def refresh_graph(self):
        self._load_graph(self.current_assets)

    def _sync_graph_filter(self, combo: QComboBox, label: str, values: list[str]) -> None:
        """Refresh a graph filter without losing the analyst's selection."""
        selected = str(combo.currentData() or "")
        combo.blockSignals(True)
        combo.clear()
        combo.addItem(label, "")
        for value in values:
            combo.addItem(value.replace("_", " ").title(), value)
        index = combo.findData(selected)
        combo.setCurrentIndex(index if index >= 0 else 0)
        combo.blockSignals(False)

    def _graph_brief_html(self, analysis: dict, filtered: bool) -> str:
        provenance = analysis.get("provenance") or {}
        pivots = analysis.get("pivots") or []
        relations = list((analysis.get("relations") or {}).items())[:4]
        types = list((analysis.get("types") or {}).items())[:5]
        pivot_rows = "".join(
            "<li><b>{}</b><br><span style='color:#82919e'>{} · {} links</span></li>".format(
                html_escape(str(pivot.get("label", ""))[:72]),
                html_escape(str(pivot.get("type", "unknown")).replace("_", " ")),
                int(pivot.get("degree", 0) or 0),
            )
            for pivot in pivots
        ) or "<li>No connected pivots in this view</li>"
        relation_text = ", ".join(
            f"{html_escape(name.replace('_', ' ').lower())} ({count})"
            for name, count in relations
        ) or "none"
        type_text = ", ".join(
            f"{html_escape(name.replace('_', ' '))} ({count})"
            for name, count in types
        ) or "none"
        scope_note = (
            "<p style='color:#fbbf24'><b>Focused view</b><br>One-hop context is retained around matching entities.</p>"
            if filtered else ""
        )
        return (
            scope_note
            + "<p><b>Structure</b><br>"
            + f"{analysis.get('components', 0)} component(s) · "
            + f"{analysis.get('isolated', 0)} isolated · "
            + f"density {float(analysis.get('density', 0.0)):.3f}</p>"
            + "<p><b>Provenance</b><br>"
            + f"{provenance.get('observed', 0)} observed · "
            + f"{provenance.get('inferred', 0)} inferred · "
            + f"{provenance.get('proposed', 0)} proposed</p>"
            + "<p><b>Evidence coverage</b><br>"
            + f"{analysis.get('source_count', 0)} distinct sources · "
            + f"{analysis.get('affected', 0)} affected entities · "
            + f"<span style='color:#f87171'>{analysis.get('high_risk', 0)} high-risk</span></p>"
            + f"<p><b>Entity mix</b><br>{type_text}</p>"
            + f"<p><b>Relations</b><br>{relation_text}</p>"
            + f"<p><b>Priority pivots</b></p><ol>{pivot_rows}</ol>"
        )

    def _load_graph(self, assets: dict):
        query = self.graph_search.text().strip()
        raw_graph = build_display_graph(
            assets,
            aggregate=False,
            aggregate_threshold=10,
            # Annotate from the filtered set so the graph's "what hurts
            # here" markers match what the triage table is showing.
            findings=self._filtered_findings,
        )
        self._sync_graph_filter(
            self.graph_type_filter,
            "All entity types",
            sorted({str(node.get("type")) for node in raw_graph["nodes"] if node.get("type")}),
        )
        self._sync_graph_filter(
            self.graph_relation_filter,
            "All relations",
            sorted({str(edge.get("type")) for edge in raw_graph["edges"] if edge.get("type")}),
        )
        asset_type = str(self.graph_type_filter.currentData() or "")
        relation = str(self.graph_relation_filter.currentData() or "")
        provenance = str(self.graph_provenance_filter.currentData() or "all")
        # Focused entity searches must inspect real entities, not aggregate
        # placeholders. Outside a focus search the operator controls grouping.
        aggregate = self.graph_aggregate_check.isChecked() and not (query or asset_type)
        graph = build_display_graph(
            assets,
            aggregate=aggregate,
            aggregate_threshold=10,
            findings=self._filtered_findings,
        )
        graph = filter_display_graph(
            graph,
            query=query,
            asset_type=asset_type,
            relation=relation,
            provenance=provenance,
        )
        nodes = graph["nodes"]
        edges = graph["edges"]
        meta = graph.get("meta", {})
        raw_nodes = len(raw_graph["nodes"])
        raw_edges = len(raw_graph["edges"])
        analysis = analyze_display_graph(graph)
        self.graph_summary.setText(
            f"Intelligence picture: {raw_nodes} entities · {raw_edges} relations  |  "
            f"View: {len(nodes)} entities · {len(edges)} relations · "
            f"{analysis['components']} component(s)"
        )
        self.graph_brief.setText(
            self._graph_brief_html(analysis, bool(meta.get("filtered")))
        )

        if not nodes:
            self.graph_view.setHtml(
                EMPTY_GRAPH_HTML.format(
                    message=(
                        "No entities match the current intelligence filters."
                        if raw_nodes else "No asset graph available yet. Run collection first."
                    )
                )
            )
            self._graph_render_key = None
            return

        # Skip identical re-renders (load_results runs on many events) and
        # defer the paint so startup/refresh work doesn't block the UI thread.
        render_key = (
            hash(json.dumps(graph, sort_keys=True, default=str)),
            self.graph_labels_check.isChecked(),
            self.graph_edges_check.isChecked(),
            aggregate,
        )
        if getattr(self, "_graph_render_key", None) == render_key:
            return
        self._graph_render_key = render_key
        html = render_gravis_html(
            graph,
            show_labels=self.graph_labels_check.isChecked(),
            show_edges=self.graph_edges_check.isChecked(),
            height=max(640, self.graph_view.height() - 20),
        )
        QTimer.singleShot(
            0,
            lambda: self.graph_view.setHtml(
                html, QUrl.fromLocalFile(str(ROOT_DIR))
            ),
        )

    def _attack_graph_path(self) -> Path:
        target = self._target_output_name()
        return self._assessment_dir() / "attack_graph.json"

    def _load_attack_graph(self):
        if not hasattr(self, "attack_graph_view"):
            return
        data = self._read_json(self._attack_graph_path(), {})
        self.current_attack_graph = data if isinstance(data, dict) else {}
        self.refresh_attack_graph()

    def refresh_attack_graph(self):
        if not hasattr(self, "attack_graph_view"):
            return
        graph = self.current_attack_graph if isinstance(self.current_attack_graph, dict) else {}
        nodes = graph.get("nodes") or []
        edges = graph.get("edges") or []
        plan = graph.get("probe_plan") or {}

        if not nodes:
            self.attack_graph_summary.setText("No attack graph loaded")
            self.probe_plan_label.setText(
                "Probe plan: not recorded — enable Engagement → Attack graph "
                "(--pentest) and run."
            )
            self.probe_plan_table.setRowCount(0)
            self.attack_graph_view.setHtml(
                EMPTY_GRAPH_HTML.format(
                    message="No attack graph yet. Enable Engagement → Attack graph "
                            "(--pentest) and run the target."
                )
            )
            self._attack_render_key = None
            return

        proposed = sum(1 for edge in edges if (edge.get("attrs") or {}).get("proposed"))
        inferred = sum(1 for edge in edges if (edge.get("attrs") or {}).get("inferred"))
        vulnerabilities = sum(
            1 for node in nodes if str(node.get("type", "")).lower() == "vuln"
        )
        goals = sum(
            1 for node in nodes if str(node.get("type", "")).lower() == "goal"
        )
        self.attack_graph_summary.setText(
            f"Attack model: {len(nodes)} entities · {len(edges)} transitions  |  "
            f"{len(edges) - proposed - inferred} established · {inferred} inferred · "
            f"{proposed} proposed · {vulnerabilities} vulnerabilities · {goals} objectives"
        )
        if plan:
            self.probe_plan_label.setText(
                f"ceiling {plan.get('risk_ceiling', '?')} | "
                f"{plan.get('surfaces_considered', 0)} surfaces considered | "
                f"{plan.get('probes_proposed', 0)} probes proposed | "
                f"cap {plan.get('capped_at', '-')}"
            )
            reasons = sorted(
                (plan.get("not_proposed") or {}).items(),
                key=lambda kv: -int(kv[1] or 0),
            )
        else:
            self.probe_plan_label.setText("Probe plan: not recorded in this artifact")
            reasons = []
        self.probe_plan_table.setRowCount(len(reasons))
        for row, (reason, count) in enumerate(reasons):
            self.probe_plan_table.setItem(row, 0, QTableWidgetItem(str(reason)))
            count_item = QTableWidgetItem(str(count))
            count_item.setData(Qt.UserRole, int(count))
            self.probe_plan_table.setItem(row, 1, count_item)

        html = render_attack_html(
            graph,
            show_labels=len(nodes) <= 40,
            height=max(560, self.attack_graph_view.height() - 20),
        )
        render_key = (
            len(nodes),
            len(edges),
            str(nodes[0].get("id", "")) if nodes else "",
            str(nodes[-1].get("id", "")) if nodes else "",
        )
        if getattr(self, "_attack_render_key", None) == render_key:
            return
        self._attack_render_key = render_key
        QTimer.singleShot(
            0,
            lambda: self.attack_graph_view.setHtml(
                html, QUrl.fromLocalFile(str(ROOT_DIR))
            ),
        )
