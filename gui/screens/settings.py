"""LLM / runtime / scanner / tools / keys / config settings panel.

Mixin for gui.app.MainWindow; see that class for composition.
"""
from __future__ import annotations

from gui._shared import *  # noqa: F401,F403


class SettingsScreenMixin:

    def _build_settings_panel(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        settings_tabs = QTabWidget()
        settings_tabs.setDocumentMode(True)
        settings_tabs.tabBar().setUsesScrollButtons(True)
        # Fusion draws CE_TabBarBase with the light palette — a stray white
        # line across the strip; we style the pane border instead.
        settings_tabs.tabBar().setDrawBase(False)
        settings_tabs.addTab(self._build_llm_settings_tab(), "LLM")
        settings_tabs.addTab(self._build_runtime_settings_tab(), "Runtime")
        settings_tabs.addTab(self._build_scanner_settings_tab(), "Scanner")
        settings_tabs.addTab(self._build_actions_settings_tab(), "Actions")
        settings_tabs.addTab(self._build_tools_settings_tab(), "Tools")
        settings_tabs.addTab(self._build_keys_settings_tab(), "API Keys")
        settings_tabs.addTab(self._build_raw_config_tab(), "Raw YAML")
        layout.addWidget(settings_tabs, 1)

        # Filter: the Scanner/Actions tabs are long; typing narrows the
        # group boxes across every tab by title so options stay reachable.
        self.settings_search = QLineEdit()
        self.settings_search.setPlaceholderText(
            "Filter settings by section name (e.g. proxy, retries, keys)"
        )
        self.settings_search.setClearButtonEnabled(True)
        self.settings_search.textChanged.connect(
            lambda text: self._apply_settings_filter(settings_tabs, text)
        )
        layout.addWidget(self.settings_search)
        self.settings_tabs = settings_tabs
        return panel

    @staticmethod
    def _apply_settings_filter(tabs: QTabWidget, query: str):
        """Show only group boxes whose title matches `query` (case-insensitive)."""
        needle = (query or "").strip().lower()
        for index in range(tabs.count()):
            page = tabs.widget(index)
            visible = 0
            for box in page.findChildren(QGroupBox):
                match = not needle or needle in box.title().lower()
                box.setVisible(match)
                if match:
                    visible += 1
            tabs.setTabVisible(index, bool(visible) or not needle)

    def _build_llm_settings_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        llm_box = QGroupBox("LLM Provider")
        form = QFormLayout(llm_box)
        form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.llm_model_combo = QComboBox()
        self.llm_model_combo.setEditable(True)
        self.llm_model_combo.addItems([
            "",
            "deepseek/deepseek-chat",
            "deepseek/deepseek-reasoner",
            "openai/gpt-4o",
            "openai/gpt-4.1",
            "openai/o4-mini",
            "anthropic/claude-sonnet-4-20250514",
            "groq/llama-3.3-70b-versatile",
            "openrouter/openai/gpt-4o",
            "ollama/llama3.1",
            "ollama/nemotron-3-super:cloud",
            "lm_studio/local-model",
        ])
        self.llm_model_combo.lineEdit().setPlaceholderText("provider/model or shortcut")
        self.llm_api_key_input = QLineEdit()
        self.llm_api_key_input.setEchoMode(QLineEdit.Password)
        self.llm_api_key_input.setPlaceholderText("Stored in config.yaml; env vars still work")
        self.llm_temperature_spin = QDoubleSpinBox()
        self.llm_temperature_spin.setRange(0.0, 2.0)
        self.llm_temperature_spin.setSingleStep(0.1)
        self.llm_temperature_spin.setDecimals(2)
        self.llm_max_tokens_spin = QSpinBox()
        self.llm_max_tokens_spin.setRange(256, 128000)
        self.llm_max_tokens_spin.setSingleStep(256)
        form.addRow("Model", self.llm_model_combo)
        form.addRow("API key", self.llm_api_key_input)
        form.addRow("Temperature", self.llm_temperature_spin)
        form.addRow("Max tokens", self.llm_max_tokens_spin)
        layout.addWidget(llm_box)

        status_box = QGroupBox("LLM Status")
        status_layout = QVBoxLayout(status_box)
        self.llm_settings_status = QLabel("Not checked")
        self.llm_settings_status.setObjectName("assistantStatus")
        self.llm_settings_status.setWordWrap(True)
        status_layout.addWidget(self.llm_settings_status)
        button_row = QHBoxLayout()
        self.save_llm_button = QPushButton("Save LLM Settings")
        self.save_llm_button.clicked.connect(self._save_settings_form)
        self.reload_llm_button = QPushButton("Reload")
        self.reload_llm_button.clicked.connect(self._load_settings_form)
        self.refresh_llm_status_button = QPushButton("Refresh Status")
        self.refresh_llm_status_button.clicked.connect(self._update_operation_context)
        button_row.addWidget(self.save_llm_button)
        button_row.addWidget(self.reload_llm_button)
        button_row.addWidget(self.refresh_llm_status_button)
        status_layout.addLayout(button_row)
        layout.addWidget(status_box)
        layout.addStretch(1)
        return tab

    def _build_runtime_settings_tab(self) -> QWidget:
        tab = QWidget()
        outer = QVBoxLayout(tab)
        outer.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        body = QWidget()
        layout = QVBoxLayout(body)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        target_box = QGroupBox("Target Defaults")
        target_form = QFormLayout(target_box)
        target_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.config_target_domain_input = QLineEdit()
        self.config_target_domain_input.setPlaceholderText("Default target when CLI does not override")
        self.config_mode_combo = QComboBox()
        self.config_mode_combo.addItems(["passive", "active", "deep"])
        target_form.addRow("Domain", self.config_target_domain_input)
        target_form.addRow("Mode", self.config_mode_combo)
        layout.addWidget(target_box)

        backend_box = QGroupBox("Toolchain Backend")
        backend_form = QFormLayout(backend_box)
        backend_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.tools_backend_combo = QComboBox()
        self.tools_backend_combo.addItems(["local", "docker"])
        self.tools_backend_combo.setToolTip(
            "local: use binaries installed on this machine. "
            "docker: run every baked binary inside the toolchain image "
            "(teammates need only Python + Docker)."
        )
        self.tools_image_input = QLineEdit()
        self.tools_image_input.setPlaceholderText("osint-tools:latest")
        backend_hint = QLabel(
            "Env OSINT_TOOLS_BACKEND / OSINT_TOOLS_IMAGE wins over this file. "
            "Build once: docker build -f docker/Dockerfile.tools -t osint-tools:latest ."
        )
        backend_hint.setWordWrap(True)
        backend_hint.setObjectName("opsSecondary")
        backend_form.addRow("Backend", self.tools_backend_combo)
        backend_form.addRow("Image", self.tools_image_input)
        backend_form.addRow("Note", backend_hint)
        layout.addWidget(backend_box)

        detectability_box = QGroupBox("Detectability")
        detectability_form = QFormLayout(detectability_box)
        self.config_default_detectability_combo = QComboBox()
        self.config_default_detectability_combo.addItems(["low", "medium", "high"])
        detectability_form.addRow("Default", self.config_default_detectability_combo)
        layout.addWidget(detectability_box)

        module_box = QGroupBox("Module Behavior")
        module_form = QFormLayout(module_box)
        self.config_auto_run_check = QCheckBox("Auto-run module chain")
        self.config_record_http_evidence_check = QCheckBox("Record HTTP evidence")
        self.config_max_empty_spin = QSpinBox()
        self.config_max_empty_spin.setRange(0, 100)
        module_form.addRow("", self.config_auto_run_check)
        module_form.addRow("", self.config_record_http_evidence_check)
        module_form.addRow("Max empty modules", self.config_max_empty_spin)
        layout.addWidget(module_box)

        rate_box = QGroupBox("Rate Limits")
        rate_layout = QGridLayout(rate_box)
        rate_layout.addWidget(QLabel("Scope"), 0, 0)
        rate_layout.addWidget(QLabel("Concurrent"), 0, 1)
        rate_layout.addWidget(QLabel("Per minute"), 0, 2)
        self.rate_limit_inputs = {}
        for row, name in enumerate(["default", "dns", "http", "scan"], start=1):
            concurrent = QSpinBox()
            concurrent.setRange(1, 500)
            per_minute = QSpinBox()
            per_minute.setRange(1, 10000)
            self.rate_limit_inputs[name] = {"concurrent": concurrent, "per_minute": per_minute}
            rate_layout.addWidget(QLabel(name), row, 0)
            rate_layout.addWidget(concurrent, row, 1)
            rate_layout.addWidget(per_minute, row, 2)
        layout.addWidget(rate_box)

        limits_box = QGroupBox("Run Limits")
        limits_form = QFormLayout(limits_box)
        limits_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.module_timeout_spin = QSpinBox()
        self.module_timeout_spin.setRange(10, 7200)
        self.module_timeout_spin.setSuffix(" s")
        self.budget_requests_spin = QSpinBox()
        self.budget_requests_spin.setRange(0, 10_000_000)
        self.budget_requests_spin.setSpecialValueText("unlimited")
        self.budget_wall_clock_spin = QSpinBox()
        self.budget_wall_clock_spin.setRange(0, 86400)
        self.budget_wall_clock_spin.setSuffix(" s")
        self.budget_wall_clock_spin.setSpecialValueText("unlimited")
        self.budget_llm_spin = QSpinBox()
        self.budget_llm_spin.setRange(0, 1_000_000)
        self.budget_llm_spin.setSpecialValueText("unlimited")
        self.budget_external_commands_spin = QSpinBox()
        self.budget_external_commands_spin.setRange(0, 1_000_000)
        self.budget_external_commands_spin.setSpecialValueText("unlimited")
        limits_form.addRow("Module timeout", self.module_timeout_spin)
        limits_form.addRow("Max requests", self.budget_requests_spin)
        limits_form.addRow("Max wall clock", self.budget_wall_clock_spin)
        limits_form.addRow("Max LLM calls", self.budget_llm_spin)
        limits_form.addRow("Max external commands",
                           self.budget_external_commands_spin)
        layout.addWidget(limits_box)

        button_row = QHBoxLayout()
        save_button = QPushButton("Save Runtime Settings")
        save_button.clicked.connect(self._save_settings_form)
        reload_button = QPushButton("Reload")
        reload_button.clicked.connect(self._load_settings_form)
        button_row.addStretch(1)
        button_row.addWidget(reload_button)
        button_row.addWidget(save_button)
        layout.addLayout(button_row)
        layout.addStretch(1)

        scroll.setWidget(body)
        outer.addWidget(scroll, 1)
        return tab

    def _build_scanner_settings_tab(self) -> QWidget:
        tab = QWidget()
        outer = QVBoxLayout(tab)
        outer.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        body = QWidget()
        layout = QVBoxLayout(body)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        auth_box = QGroupBox("Authenticated Testing")
        auth_form = QFormLayout(auth_box)
        auth_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.auth_bearer_input = QLineEdit()
        self.auth_bearer_input.setEchoMode(QLineEdit.Password)
        self.auth_bearer_input.setPlaceholderText("Bearer token applied to HTTP/browser probes")
        self.auth_cookie_input = QLineEdit()
        self.auth_cookie_input.setEchoMode(QLineEdit.Password)
        self.auth_cookie_input.setPlaceholderText("session=...; other=...")
        self.auth_headers_input = QPlainTextEdit()
        self.auth_headers_input.setPlaceholderText("One header per line, for example:\nAuthorization: Bearer ...\nX-API-Key: ...")
        self.auth_headers_input.setMaximumHeight(110)
        self.auth_probe_backoff_spin = QSpinBox()
        self.auth_probe_backoff_spin.setRange(0, 3600)
        auth_form.addRow("Bearer token", self.auth_bearer_input)
        auth_form.addRow("Cookie header", self.auth_cookie_input)
        auth_form.addRow("Headers", self.auth_headers_input)
        auth_form.addRow("Auth probe backoff", self.auth_probe_backoff_spin)
        layout.addWidget(auth_box)

        identities_box = QGroupBox("Test Identities (auth.identities)")
        identities_layout = QVBoxLayout(identities_box)
        self.identities_table = QTableWidget(0, 6)
        self.identities_table.setHorizontalHeaderLabels(
            ["Name", "Bearer token", "Cookies", "Verify URL", "Success marker", "Role"]
        )
        identities_header = self.identities_table.horizontalHeader()
        identities_header.setSectionResizeMode(1, QHeaderView.Stretch)
        identities_header.setSectionResizeMode(2, QHeaderView.Stretch)
        identities_header.setSectionResizeMode(3, QHeaderView.Stretch)
        identities_header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        identities_header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        identities_header.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.identities_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.identities_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.identities_table.setMaximumHeight(180)
        identities_layout.addWidget(self.identities_table)
        identity_buttons = QHBoxLayout()
        add_identity_button = QPushButton("Add Identity")
        add_identity_button.clicked.connect(self._add_identity_row)
        remove_identity_button = QPushButton("Remove Selected")
        remove_identity_button.clicked.connect(self._remove_identity_rows)
        identity_buttons.addStretch(1)
        identity_buttons.addWidget(add_identity_button)
        identity_buttons.addWidget(remove_identity_button)
        identities_layout.addLayout(identity_buttons)
        identities_hint = QLabel(
            "Two verified identities are what idor_differ needs for horizontal "
            "comparison. Extra fields (headers, login, owner_id) are preserved; "
            "edit those in Raw YAML."
        )
        identities_hint.setWordWrap(True)
        identities_hint.setObjectName("opsSecondary")
        identities_layout.addWidget(identities_hint)
        layout.addWidget(identities_box)

        xss_box = QGroupBox("XSS Detection")
        xss_form = QFormLayout(xss_box)
        self.xss_browser_confirm_check = QCheckBox("Confirm execution with Playwright/Chromium")
        self.xss_max_points_spin = QSpinBox()
        self.xss_max_points_spin.setRange(1, 5000)
        self.xss_dalfox_timeout_spin = QSpinBox()
        self.xss_dalfox_timeout_spin.setRange(30, 7200)
        self.xss_dalfox_blind_oob_check = QCheckBox("Dalfox runs its own OOB session (stays FIRM)")
        self.xss_dalfox_blind_oob_check.setToolTip(
            "Uses dalfox --blind-oob on the public mesh instead of the "
            "framework-owned callback. No pollable session, so findings "
            "cannot reach CONFIRMED."
        )
        self.xss_dalfox_rate_spin = QSpinBox()
        self.xss_dalfox_rate_spin.setRange(0, 100000)
        self.xss_dalfox_rate_spin.setSpecialValueText("unlimited")
        self.xss_dalfox_rate_spin.setToolTip(
            "Global outbound cap for dalfox in requests/second."
        )
        xss_form.addRow("", self.xss_browser_confirm_check)
        xss_form.addRow("Max injection points", self.xss_max_points_spin)
        xss_form.addRow("Dalfox timeout", self.xss_dalfox_timeout_spin)
        xss_form.addRow("", self.xss_dalfox_blind_oob_check)
        xss_form.addRow("Dalfox rate limit", self.xss_dalfox_rate_spin)
        layout.addWidget(xss_box)

        nuclei_box = QGroupBox("Nuclei")
        nuclei_form = QFormLayout(nuclei_box)
        self.nuclei_full_cve_check = QCheckBox("Run full CVE pass only on confirmed apex")
        self.nuclei_update_check = QCheckBox("Refresh templates before scanning")
        self.nuclei_update_check.setToolTip(
            "Downloads hundreds of MB from GitHub; off by default."
        )
        self.nuclei_max_age_spin = QSpinBox()
        self.nuclei_max_age_spin.setRange(1, 365)
        self.nuclei_max_age_spin.setValue(30)
        self.nuclei_max_age_spin.setSuffix(" d")
        self.nuclei_max_age_spin.setToolTip("Warn past this template age.")
        self.nuclei_batch_seconds_spin = QSpinBox()
        self.nuclei_batch_seconds_spin.setRange(30, 1200)
        self.nuclei_batch_seconds_spin.setValue(150)
        self.nuclei_batch_seconds_spin.setSuffix(" s")
        self.nuclei_batch_seconds_spin.setToolTip("Time-box per template batch.")
        self.nuclei_max_seconds_spin = QSpinBox()
        self.nuclei_max_seconds_spin.setRange(0, 3600)
        self.nuclei_max_seconds_spin.setValue(0)
        self.nuclei_max_seconds_spin.setSuffix(" s")
        self.nuclei_max_seconds_spin.setToolTip("Whole-pass time-box (0 = module deadline minus 60s).")
        nuclei_form.addRow("", self.nuclei_full_cve_check)
        nuclei_form.addRow("", self.nuclei_update_check)
        nuclei_form.addRow("Max template age", self.nuclei_max_age_spin)
        nuclei_form.addRow("Batch seconds", self.nuclei_batch_seconds_spin)
        nuclei_form.addRow("Max seconds (0=auto)", self.nuclei_max_seconds_spin)
        layout.addWidget(nuclei_box)

        sqli_box = QGroupBox("Blind SQLi (OAST)")
        sqli_form = QFormLayout(sqli_box)
        self.sqli_oast_check = QCheckBox("Hand sqlmap an OOB server for blind proof")
        self.sqli_oast_check.setToolTip(
            "Promotes only the exact URL that produced a callback. "
            "Needs oob server_url (wrapper mode) — a callback domain alone is not enough."
        )
        sqli_form.addRow("", self.sqli_oast_check)
        layout.addWidget(sqli_box)

        kr_box = QGroupBox("API Discovery (kiterunner)")
        kr_form = QFormLayout(kr_box)
        kr_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.kr_enabled_check = QCheckBox("Brute-force API routes (assetnote wordlists)")
        self.kr_enabled_check.setChecked(True)
        self.kr_wordlist_input = QLineEdit()
        self.kr_wordlist_input.setPlaceholderText("apiroutes-260227")
        self.kr_wordlist_input.setToolTip(
            "Remote list name; see `kr wordlist list` for current names."
        )
        self.kr_max_routes_spin = QSpinBox()
        self.kr_max_routes_spin.setRange(1, 20000)
        self.kr_max_routes_spin.setValue(1500)
        self.kr_max_routes_spin.setToolTip("Routes tried per target.")
        self.kr_max_targets_spin = QSpinBox()
        self.kr_max_targets_spin.setRange(1, 10)
        self.kr_max_targets_spin.setValue(2)
        self.kr_max_targets_spin.setToolTip(
            "Base URL plus api_endpoint origins, capped."
        )
        self.kr_delay_spin = QSpinBox()
        self.kr_delay_spin.setRange(0, 60000)
        self.kr_delay_spin.setValue(100)
        self.kr_delay_spin.setSuffix(" ms")
        self.kr_delay_spin.setToolTip(
            "Delay between requests to one host. Use 1000 with 1 "
            "connection (~1 req/s) against live scopes."
        )
        self.kr_connections_spin = QSpinBox()
        self.kr_connections_spin.setRange(1, 10)
        self.kr_connections_spin.setValue(3)
        self.kr_connections_spin.setToolTip(
            "Parallel connections per host. Use 1 on live scopes."
        )
        kr_form.addRow("", self.kr_enabled_check)
        kr_form.addRow("Wordlist", self.kr_wordlist_input)
        kr_form.addRow("Max routes", self.kr_max_routes_spin)
        kr_form.addRow("Max targets", self.kr_max_targets_spin)
        kr_form.addRow("Delay", self.kr_delay_spin)
        kr_form.addRow("Connections", self.kr_connections_spin)
        layout.addWidget(kr_box)

        semgrep_box = QGroupBox("Semgrep SAST")
        semgrep_form = QFormLayout(semgrep_box)
        semgrep_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.semgrep_enabled_check = QCheckBox("Scan JS bundles (repo-local rules)")
        self.semgrep_enabled_check.setChecked(True)
        self.semgrep_enabled_check.setToolTip(
            "Static only: taint flows file as MEDIUM/TENTATIVE, "
            "sinks as LOW. Never execution proof."
        )
        self.semgrep_rules_input = QLineEdit()
        self.semgrep_rules_input.setPlaceholderText("rules/semgrep")
        semgrep_form.addRow("", self.semgrep_enabled_check)
        semgrep_form.addRow("Rules", self.semgrep_rules_input)
        layout.addWidget(semgrep_box)

        ssrf_box = QGroupBox("SSRF Scan")
        ssrf_form = QFormLayout(ssrf_box)
        ssrf_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.ssrf_enabled_check = QCheckBox("Probe URL parameters (OOB-graded)")
        self.ssrf_enabled_check.setChecked(True)
        self.ssrf_enabled_check.setToolTip(
            "HTTP callback files HIGH/CONFIRMED, DNS-only MEDIUM/FIRM. "
            "Without an OOB channel nothing is probed."
        )
        self.ssrf_max_points_spin = QSpinBox()
        self.ssrf_max_points_spin.setRange(1, 30)
        self.ssrf_max_points_spin.setValue(6)
        self.ssrf_max_points_spin.setToolTip("URL parameters probed per run.")
        ssrf_form.addRow("", self.ssrf_enabled_check)
        ssrf_form.addRow("Max points", self.ssrf_max_points_spin)
        layout.addWidget(ssrf_box)

        crawl_box = QGroupBox("Browser Crawl")
        crawl_form = QFormLayout(crawl_box)
        crawl_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.crawl_enabled_check = QCheckBox("Render pages (one context per identity)")
        self.crawl_enabled_check.setChecked(True)
        self.crawl_enabled_check.setToolTip(
            "Verified identities render authenticated; anonymous always runs."
        )
        self.crawl_max_pages_spin = QSpinBox()
        self.crawl_max_pages_spin.setRange(1, 50)
        self.crawl_max_pages_spin.setValue(8)
        self.crawl_max_pages_spin.setToolTip("Pages rendered per context.")
        self.crawl_depth_spin = QSpinBox()
        self.crawl_depth_spin.setRange(0, 3)
        self.crawl_depth_spin.setValue(1)
        self.crawl_depth_spin.setToolTip("Same-origin link-following depth.")
        self.crawl_max_identities_spin = QSpinBox()
        self.crawl_max_identities_spin.setRange(0, 5)
        self.crawl_max_identities_spin.setValue(2)
        self.crawl_wait_ms_spin = QSpinBox()
        self.crawl_wait_ms_spin.setRange(0, 10000)
        self.crawl_wait_ms_spin.setValue(1500)
        self.crawl_wait_ms_spin.setSuffix(" ms")
        self.crawl_wait_ms_spin.setToolTip("Render wait per page (clamped at 10s).")
        crawl_form.addRow("", self.crawl_enabled_check)
        crawl_form.addRow("Max pages", self.crawl_max_pages_spin)
        crawl_form.addRow("Depth", self.crawl_depth_spin)
        crawl_form.addRow("Max identities", self.crawl_max_identities_spin)
        crawl_form.addRow("Render wait", self.crawl_wait_ms_spin)
        layout.addWidget(crawl_box)

        logic_box = QGroupBox("Business Logic")
        logic_form = QFormLayout(logic_box)
        logic_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.logic_enabled_check = QCheckBox("Probe own-account cart logic")
        self.logic_enabled_check.setChecked(True)
        self.logic_enabled_check.setToolTip(
            "Differential proof only; every probe restored. "
            "Needs a verified identity."
        )
        self.logic_max_probes_spin = QSpinBox()
        self.logic_max_probes_spin.setRange(1, 40)
        self.logic_max_probes_spin.setValue(12)
        self.logic_endpoints_text = QPlainTextEdit()
        self.logic_endpoints_text.setPlaceholderText("Cart/order endpoints, one per line (empty = recon)")
        self.logic_endpoints_text.setMaximumHeight(70)
        logic_form.addRow("", self.logic_enabled_check)
        logic_form.addRow("Max probes", self.logic_max_probes_spin)
        logic_form.addRow("Endpoints", self.logic_endpoints_text)
        layout.addWidget(logic_box)

        idor_box = QGroupBox("IDOR (cross-account)")
        idor_form = QFormLayout(idor_box)
        idor_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.idor_endpoints_text = QPlainTextEdit()
        self.idor_endpoints_text.setPlaceholderText("Object endpoints, one per line (empty = derive from recon)")
        self.idor_endpoints_text.setMaximumHeight(70)
        self.idor_max_probes_spin = QSpinBox()
        self.idor_max_probes_spin.setRange(1, 100)
        self.idor_max_probes_spin.setValue(15)
        self.idor_max_probes_spin.setToolTip("Cross-account probes per endpoint template.")
        self.idor_object_probe_check = QCheckBox("Probe unlisted object shapes")
        self.idor_object_probe_check.setChecked(True)
        self.idor_object_probe_check.setToolTip("Fetch disclosed references against shapes with no listing endpoint.")
        self.idor_probe_collections_check = QCheckBox("Probe built-in collection wordlist")
        self.idor_probe_collections_check.setChecked(True)
        self.idor_max_collections_spin = QSpinBox()
        self.idor_max_collections_spin.setRange(0, 500)
        self.idor_max_collections_spin.setValue(60)
        self.idor_test_anonymous_check = QCheckBox("Also test with no session")
        self.idor_test_anonymous_check.setToolTip("Widens the surface beyond your accounts. Off by default.")
        self.idor_write_methods_text = QLineEdit()
        self.idor_write_methods_text.setPlaceholderText("e.g. PATCH, PUT (empty = read-only)")
        self.idor_write_methods_text.setToolTip("Mutating verbs echoed back safely; DELETE is never sent without the flag below.")
        self.idor_allow_destructive_check = QCheckBox("Allow DELETE (destructive)")
        self.idor_allow_destructive_check.setToolTip("Sends real DELETEs. Only with explicit authorisation.")
        self.idor_id_probing_check = QCheckBox("Probe neighbouring IDs (other people's records)")
        self.idor_id_probing_check.setToolTip("Opt-in and bounded; reaches data belonging to accounts you do not control.")
        self.idor_probe_radius_spin = QSpinBox()
        self.idor_probe_radius_spin.setRange(1, 50)
        self.idor_probe_radius_spin.setValue(3)
        self.idor_probe_radius_spin.setToolTip("How far from each known reference to try.")
        self.idor_probe_max_spin = QSpinBox()
        self.idor_probe_max_spin.setRange(1, 500)
        self.idor_probe_max_spin.setValue(20)
        self.idor_probe_max_spin.setToolTip("Hard ceiling on neighbouring-ID requests.")
        self.idor_refs_spin = QSpinBox()
        self.idor_refs_spin.setRange(1, 100)
        self.idor_refs_spin.setValue(12)
        self.idor_refs_spin.setToolTip("References tried per unlisted shape.")
        self.idor_fetches_spin = QSpinBox()
        self.idor_fetches_spin.setRange(1, 200)
        self.idor_fetches_spin.setValue(24)
        self.idor_total_fetches_spin = QSpinBox()
        self.idor_total_fetches_spin.setRange(1, 2000)
        self.idor_total_fetches_spin.setValue(240)
        self.idor_misses_spin = QSpinBox()
        self.idor_misses_spin.setRange(1, 100)
        self.idor_misses_spin.setValue(6)
        self.idor_misses_spin.setToolTip("Consecutive unknown IDs, then move on.")
        self.idor_collection_paths_text = QPlainTextEdit()
        self.idor_collection_paths_text.setPlaceholderText("Extra collection paths, one per line")
        self.idor_collection_paths_text.setMaximumHeight(60)
        self.idor_api_prefixes_text = QLineEdit()
        self.idor_api_prefixes_text.setPlaceholderText("e.g. /api, /api/v1 (empty = built-in)")
        self.idor_account_endpoint_text = QLineEdit()
        self.idor_account_endpoint_text.setPlaceholderText("Page identifying the requesting account")
        self.idor_resources_text = QPlainTextEdit()
        self.idor_resources_text.setPlaceholderText("Resource names, one per line (empty = built-in)")
        self.idor_resources_text.setMaximumHeight(60)
        idor_form.addRow("Endpoints", self.idor_endpoints_text)
        idor_form.addRow("Max probes/template", self.idor_max_probes_spin)
        idor_form.addRow("", self.idor_object_probe_check)
        idor_form.addRow("Probe refs/shape", self.idor_refs_spin)
        idor_form.addRow("Fetches/shape", self.idor_fetches_spin)
        idor_form.addRow("Total fetches", self.idor_total_fetches_spin)
        idor_form.addRow("Stop after misses", self.idor_misses_spin)
        idor_form.addRow("", self.idor_probe_collections_check)
        idor_form.addRow("Max collections", self.idor_max_collections_spin)
        idor_form.addRow("Collection paths", self.idor_collection_paths_text)
        idor_form.addRow("API prefixes", self.idor_api_prefixes_text)
        idor_form.addRow("Resources", self.idor_resources_text)
        idor_form.addRow("Account endpoint", self.idor_account_endpoint_text)
        idor_form.addRow("", self.idor_test_anonymous_check)
        idor_form.addRow("Write methods", self.idor_write_methods_text)
        idor_form.addRow("", self.idor_allow_destructive_check)
        idor_form.addRow("", self.idor_id_probing_check)
        idor_form.addRow("Probe radius", self.idor_probe_radius_spin)
        idor_form.addRow("Probe max", self.idor_probe_max_spin)
        layout.addWidget(idor_box)

        mass_box = QGroupBox("Mass Assignment (own account writes)")
        mass_form = QFormLayout(mass_box)
        mass_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.mass_enabled_check = QCheckBox("Enable write probes")
        self.mass_enabled_check.setToolTip("Writes to YOUR account only, then restores. Off unless you turn it on.")
        self.mass_endpoints_text = QPlainTextEdit()
        self.mass_endpoints_text.setPlaceholderText("Object URLs, one per line (empty = /me shapes)")
        self.mass_endpoints_text.setMaximumHeight(70)
        self.mass_write_endpoint_input = QLineEdit()
        self.mass_write_endpoint_input.setPlaceholderText("Optional separate update URL")
        self.mass_method_combo = QComboBox()
        self.mass_method_combo.addItems(["PATCH", "PUT", "POST"])
        self.mass_fields_text = QLineEdit()
        self.mass_fields_text.setPlaceholderText("Comma-separated (empty = privilege-bearing defaults)")
        self.mass_probe_type_combo = QComboBox()
        self.mass_probe_type_combo.addItems(["bool", "int", "string"])
        mass_form.addRow("", self.mass_enabled_check)
        mass_form.addRow("Endpoints", self.mass_endpoints_text)
        mass_form.addRow("Write endpoint", self.mass_write_endpoint_input)
        mass_form.addRow("Method", self.mass_method_combo)
        mass_form.addRow("Fields", self.mass_fields_text)
        mass_form.addRow("Probe type", self.mass_probe_type_combo)
        layout.addWidget(mass_box)

        proto_box = QGroupBox("Prototype Pollution")
        proto_form = QFormLayout(proto_box)
        proto_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.proto_enabled_check = QCheckBox("Send canary properties")
        self.proto_enabled_check.setChecked(True)
        self.proto_enabled_check.setToolTip("Inert canary, unique per run; a handful of POSTs.")
        self.proto_endpoints_text = QPlainTextEdit()
        self.proto_endpoints_text.setPlaceholderText("JSON endpoints, one per line (empty = usual shapes)")
        self.proto_endpoints_text.setMaximumHeight(70)
        self.proto_reflect_input = QLineEdit()
        self.proto_reflect_input.setPlaceholderText("Proof endpoint returning a fresh object")
        self.proto_methods_text = QLineEdit()
        self.proto_methods_text.setPlaceholderText("e.g. POST, PUT (empty = defaults)")
        self.proto_payloads_text = QPlainTextEdit()
        self.proto_payloads_text.setPlaceholderText("Payloads, one per line (empty = built-in)")
        self.proto_payloads_text.setMaximumHeight(60)
        proto_form.addRow("", self.proto_enabled_check)
        proto_form.addRow("Endpoints", self.proto_endpoints_text)
        proto_form.addRow("Reflect endpoint", self.proto_reflect_input)
        proto_form.addRow("Methods", self.proto_methods_text)
        proto_form.addRow("Payloads", self.proto_payloads_text)
        layout.addWidget(proto_box)

        misconfig_box = QGroupBox("Misconfiguration Probes")
        misconfig_form = QFormLayout(misconfig_box)
        self.misconfig_timeout_spin = QSpinBox()
        self.misconfig_timeout_spin.setRange(1, 60)
        self.misconfig_timeout_spin.setValue(5)
        self.misconfig_timeout_spin.setSuffix(" s")
        self.misconfig_concurrency_spin = QSpinBox()
        self.misconfig_concurrency_spin.setRange(1, 50)
        self.misconfig_concurrency_spin.setValue(12)
        self.misconfig_max_paths_spin = QSpinBox()
        self.misconfig_max_paths_spin.setRange(1, 2000)
        self.misconfig_max_paths_spin.setValue(160)
        self.misconfig_max_empty_spin = QSpinBox()
        self.misconfig_max_empty_spin.setRange(1, 500)
        self.misconfig_max_empty_spin.setValue(60)
        self.misconfig_max_empty_spin.setToolTip("Stop after N consecutive misses.")
        self.misconfig_progress_spin = QSpinBox()
        self.misconfig_progress_spin.setRange(1, 500)
        self.misconfig_progress_spin.setValue(25)
        self.misconfig_progress_spin.setToolTip("Log progress every N paths.")
        misconfig_form.addRow("Timeout", self.misconfig_timeout_spin)
        misconfig_form.addRow("Concurrency", self.misconfig_concurrency_spin)
        misconfig_form.addRow("Max paths", self.misconfig_max_paths_spin)
        misconfig_form.addRow("Max empty", self.misconfig_max_empty_spin)
        misconfig_form.addRow("Progress every", self.misconfig_progress_spin)
        layout.addWidget(misconfig_box)

        injection_box = QGroupBox("Injection Probes (SSTI/NoSQL/DOM/Params)")
        injection_form = QFormLayout(injection_box)
        self.ssti_max_points_spin = QSpinBox()
        self.ssti_max_points_spin.setRange(1, 200)
        self.ssti_max_points_spin.setValue(40)
        self.nosql_max_points_spin = QSpinBox()
        self.nosql_max_points_spin.setRange(1, 200)
        self.nosql_max_points_spin.setValue(40)
        self.dom_max_pages_spin = QSpinBox()
        self.dom_max_pages_spin.setRange(1, 200)
        self.dom_max_pages_spin.setValue(25)
        self.param_seed_check = QCheckBox("Seed reflection probes when none discovered")
        self.param_seed_check.setChecked(True)
        self.param_seed_targets_spin = QSpinBox()
        self.param_seed_targets_spin.setRange(1, 100)
        self.param_seed_targets_spin.setValue(10)
        self.param_seed_params_text = QLineEdit()
        self.param_seed_params_text.setPlaceholderText("Extra names, comma-separated")
        injection_form.addRow("SSTI max points", self.ssti_max_points_spin)
        injection_form.addRow("NoSQL max points", self.nosql_max_points_spin)
        injection_form.addRow("DOM max pages", self.dom_max_pages_spin)
        injection_form.addRow("", self.param_seed_check)
        injection_form.addRow("Seed targets", self.param_seed_targets_spin)
        injection_form.addRow("Seed params", self.param_seed_params_text)
        layout.addWidget(injection_box)

        smuggling_box = QGroupBox("HTTP Smuggling")
        smuggling_form = QFormLayout(smuggling_box)
        self.smuggling_enabled_check = QCheckBox("Run smuggler corroboration")
        self.smuggling_enabled_check.setChecked(True)
        self.smuggling_enabled_check.setToolTip("Results stay TENTATIVE: single-host checks cannot prove desync.")
        self.smuggling_max_targets_spin = QSpinBox()
        self.smuggling_max_targets_spin.setRange(1, 100)
        self.smuggling_max_targets_spin.setValue(10)
        smuggling_form.addRow("", self.smuggling_enabled_check)
        smuggling_form.addRow("Max targets", self.smuggling_max_targets_spin)
        layout.addWidget(smuggling_box)

        redirect_box = QGroupBox("Open Redirect")
        redirect_form = QFormLayout(redirect_box)
        redirect_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.redirect_enabled_check = QCheckBox("Test redirect parameters")
        self.redirect_enabled_check.setChecked(True)
        self.redirect_params_text = QLineEdit()
        self.redirect_params_text.setPlaceholderText("Comma-separated (empty = common names + recon)")
        self.redirect_endpoints_text = QPlainTextEdit()
        self.redirect_endpoints_text.setPlaceholderText("Endpoints, one per line (empty = recon + sign-in shapes)")
        self.redirect_endpoints_text.setMaximumHeight(70)
        self.redirect_max_targets_spin = QSpinBox()
        self.redirect_max_targets_spin.setRange(1, 200)
        self.redirect_max_targets_spin.setValue(40)
        self.redirect_max_targets_spin.setToolTip("Endpoint/parameter pairs — the real request bound.")
        redirect_form.addRow("", self.redirect_enabled_check)
        redirect_form.addRow("Params", self.redirect_params_text)
        redirect_form.addRow("Endpoints", self.redirect_endpoints_text)
        redirect_form.addRow("Max targets", self.redirect_max_targets_spin)
        layout.addWidget(redirect_box)

        cms_box = QGroupBox("CMS Deep Scan")
        cms_form = QFormLayout(cms_box)
        self.cms_enabled_check = QCheckBox("Run WPScan/droopescan")
        self.cms_enabled_check.setChecked(True)
        self.cms_enabled_check.setToolTip("Slow: up to five minutes per scanner per target.")
        self.cms_max_targets_spin = QSpinBox()
        self.cms_max_targets_spin.setRange(1, 20)
        self.cms_max_targets_spin.setValue(5)
        cms_form.addRow("", self.cms_enabled_check)
        cms_form.addRow("Max targets", self.cms_max_targets_spin)
        layout.addWidget(cms_box)

        content_box = QGroupBox("Content Discovery")
        content_form = QFormLayout(content_box)
        self.content_enabled_check = QCheckBox("Run ffuf + kiterunner passes")
        self.content_enabled_check.setChecked(True)
        content_form.addRow("", self.content_enabled_check)
        layout.addWidget(content_box)

        cors_box = QGroupBox("CORS Audit")
        cors_form = QFormLayout(cors_box)
        cors_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.cors_enabled_check = QCheckBox("Probe origins")
        self.cors_enabled_check.setChecked(True)
        self.cors_endpoints_text = QPlainTextEdit()
        self.cors_endpoints_text.setPlaceholderText("Endpoints, one per line (empty = recon + common shapes)")
        self.cors_endpoints_text.setMaximumHeight(70)
        self.cors_max_endpoints_spin = QSpinBox()
        self.cors_max_endpoints_spin.setRange(1, 100)
        self.cors_max_endpoints_spin.setValue(20)
        cors_form.addRow("", self.cors_enabled_check)
        cors_form.addRow("Endpoints", self.cors_endpoints_text)
        cors_form.addRow("Max endpoints", self.cors_max_endpoints_spin)
        layout.addWidget(cors_box)

        auth_box = QGroupBox("Auth (opt-in writes)")
        auth_form = QFormLayout(auth_box)
        self.auth_test_password_check = QCheckBox("Prove missing-current-password flaws by writing")
        self.auth_test_password_check.setToolTip("Writes to your test account. Off unless you turn it on.")
        self.auth_test_register_check = QCheckBox("Registration oracle (creates one real account)")
        self.auth_test_register_check.setToolTip("User-enumeration differential. Creates an account — needs authorisation.")
        auth_form.addRow("", self.auth_test_password_check)
        auth_form.addRow("", self.auth_test_register_check)
        layout.addWidget(auth_box)

        fast_scan_box = QGroupBox("Fast Exposure Scan")
        fast_scan_form = QFormLayout(fast_scan_box)
        fast_scan_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.fast_scan_paths_input = QPlainTextEdit()
        self.fast_scan_paths_input.setPlaceholderText("High-signal paths, one per line")
        self.fast_scan_paths_input.setMaximumHeight(120)
        self.fast_scan_timeout_spin = QSpinBox()
        self.fast_scan_timeout_spin.setRange(1, 30)
        self.fast_scan_concurrency_spin = QSpinBox()
        self.fast_scan_concurrency_spin.setRange(1, 50)
        self.fast_scan_max_paths_spin = QSpinBox()
        self.fast_scan_max_paths_spin.setRange(1, 500)
        fast_scan_form.addRow("Paths", self.fast_scan_paths_input)
        fast_scan_form.addRow("Timeout", self.fast_scan_timeout_spin)
        fast_scan_form.addRow("Concurrency", self.fast_scan_concurrency_spin)
        fast_scan_form.addRow("Max paths", self.fast_scan_max_paths_spin)
        layout.addWidget(fast_scan_box)

        oob_box = QGroupBox("OOB Callback Infrastructure")
        oob_form = QFormLayout(oob_box)
        oob_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.oob_mode_combo = QComboBox()
        self.oob_mode_combo.addItem("Disabled", "")
        self.oob_mode_combo.addItem("public (free interactsh, own assets only)", "public")
        self.oob_mode_combo.addItem("wrapper (self-hosted shim)", "wrapper")
        self.oob_mode_combo.setToolTip(
            "public: multiplexed session, needs only the interactsh-client "
            "binary (baked into the docker image). wrapper: your own "
            "interactsh-compatible HTTP shim, needs a domain + wildcard DNS."
        )
        self.oob_enabled_check = QCheckBox("Enable OOB checks")
        self.oob_enabled_check.setChecked(True)
        self.oob_enabled_check.setToolTip(
            "Off turns OOB off everywhere without deleting the settings."
        )
        self.oob_callback_domain_input = QLineEdit()
        self.oob_callback_domain_input.setPlaceholderText("oob.example.com")
        self.oob_server_url_input = QLineEdit()
        self.oob_server_url_input.setPlaceholderText("https://interactsh-wrapper.example")
        self.oob_poll_url_input = QLineEdit()
        self.oob_poll_url_input.setPlaceholderText("https://interactsh-wrapper.example/interactions")
        self.oob_token_input = QLineEdit()
        self.oob_token_input.setEchoMode(QLineEdit.Password)
        self.oob_poll_interval_spin = QSpinBox()
        self.oob_poll_interval_spin.setRange(1, 300)
        self.oob_poll_timeout_spin = QSpinBox()
        self.oob_poll_timeout_spin.setRange(1, 3600)
        oob_form.addRow("Mode", self.oob_mode_combo)
        oob_form.addRow("", self.oob_enabled_check)
        oob_form.addRow("Callback domain", self.oob_callback_domain_input)
        oob_form.addRow("Server URL", self.oob_server_url_input)
        oob_form.addRow("Poll URL", self.oob_poll_url_input)
        oob_form.addRow("Token", self.oob_token_input)
        oob_form.addRow("Poll interval", self.oob_poll_interval_spin)
        oob_form.addRow("Poll timeout", self.oob_poll_timeout_spin)
        layout.addWidget(oob_box)

        button_row = QHBoxLayout()
        save_button = QPushButton("Save Scanner Settings")
        save_button.clicked.connect(self._save_settings_form)
        reload_button = QPushButton("Reload")
        reload_button.clicked.connect(self._load_settings_form)
        button_row.addStretch(1)
        button_row.addWidget(reload_button)
        button_row.addWidget(save_button)
        layout.addLayout(button_row)
        layout.addStretch(1)

        scroll.setWidget(body)
        outer.addWidget(scroll, 1)
        return tab

    def _build_actions_settings_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        actions_box = QGroupBox("Registered Actions")
        actions_layout = QVBoxLayout(actions_box)
        self.actions_table = QTableWidget(0, 5)
        self.actions_table.setHorizontalHeaderLabels(
            ["Action", "Risk", "Detectability", "Requires", "Description"]
        )
        actions_header = self.actions_table.horizontalHeader()
        actions_header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        actions_header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        actions_header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        actions_header.setSectionResizeMode(4, QHeaderView.Stretch)
        self.actions_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        actions_layout.addWidget(self.actions_table)
        layout.addWidget(actions_box, 1)

        hint = QLabel(
            "The risk ceiling (--max-risk / Engagement → Risk ceiling) admits "
            "actions at or below the selected level; SAFE and LOW admit nothing "
            "that sends an injection payload."
        )
        hint.setWordWrap(True)
        hint.setObjectName("opsSecondary")
        layout.addWidget(hint)
        self._refresh_actions_table()
        return tab

    def _build_tools_settings_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        tools_box = QGroupBox("External Tool Readiness")
        tools_layout = QVBoxLayout(tools_box)
        self.tools_backend_label = QLabel("Backend: local")
        self.tools_backend_label.setWordWrap(True)
        self.tools_backend_label.setObjectName("opsSecondary")
        tools_layout.addWidget(self.tools_backend_label)
        self.tools_table = QTableWidget(0, 5)
        self.tools_table.setHorizontalHeaderLabels(
            ["Tool", "Ready", "Runs via", "Categories", "Purpose"]
        )
        self.tools_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.tools_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.tools_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.tools_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.tools_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        tools_layout.addWidget(self.tools_table)
        tool_buttons = QHBoxLayout()
        self.refresh_tools_button = QPushButton("Refresh Tools")
        self.refresh_tools_button.clicked.connect(self._refresh_tools_status)
        self.open_tools_requirements_button = QPushButton("Open Requirements")
        self.open_tools_requirements_button.clicked.connect(self.open_tools_requirements)
        self.install_tools_button = QPushButton("Install Missing")
        self.install_tools_button.clicked.connect(self.install_missing_tools)
        tool_buttons.addStretch(1)
        tool_buttons.addWidget(self.refresh_tools_button)
        tool_buttons.addWidget(self.install_tools_button)
        tool_buttons.addWidget(self.open_tools_requirements_button)
        tools_layout.addLayout(tool_buttons)
        layout.addWidget(tools_box, 2)

        requirements_box = QGroupBox("tools_requirements.txt")
        requirements_layout = QVBoxLayout(requirements_box)
        self.tools_requirements_preview = QPlainTextEdit()
        self.tools_requirements_preview.setReadOnly(True)
        self.tools_requirements_preview.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.tools_requirements_preview.setFont(code_font(11))
        requirements_layout.addWidget(self.tools_requirements_preview)
        layout.addWidget(requirements_box, 1)
        return tab

    def _build_keys_settings_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        readiness_box = QGroupBox("Access Readiness")
        readiness_layout = QVBoxLayout(readiness_box)
        self.keys_table = QTableWidget(0, 3)
        self.keys_table.setHorizontalHeaderLabels(["Service", "Ready", "Key"])
        self.keys_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.keys_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.keys_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.keys_table.setMinimumWidth(0)
        self.keys_table.setMaximumHeight(180)
        readiness_layout.addWidget(self.keys_table)
        self.refresh_keys_button = QPushButton("Refresh Keys")
        self.refresh_keys_button.clicked.connect(self._refresh_key_status)
        readiness_layout.addWidget(self.refresh_keys_button)
        layout.addWidget(readiness_box)

        key_box = QGroupBox("Service API Keys")
        key_layout = QGridLayout(key_box)
        key_layout.addWidget(QLabel("Service"), 0, 0)
        key_layout.addWidget(QLabel("Config value"), 0, 1)
        key_layout.addWidget(QLabel("Environment fallback"), 0, 2)
        self.api_key_inputs = {}
        for row, (service, spec) in enumerate(sorted(KEY_SPECS.items()), start=1):
            key_input = QLineEdit()
            key_input.setEchoMode(QLineEdit.Password)
            key_input.setPlaceholderText("leave blank to use env")
            self.api_key_inputs[service] = key_input
            env_label = QLabel(", ".join(spec.env))
            env_label.setWordWrap(True)
            key_layout.addWidget(QLabel(spec.label), row, 0)
            key_layout.addWidget(key_input, row, 1)
            key_layout.addWidget(env_label, row, 2)
        key_layout.setColumnStretch(1, 2)
        key_layout.setColumnStretch(2, 2)
        layout.addWidget(key_box)

        button_row = QHBoxLayout()
        save_button = QPushButton("Save API Keys")
        save_button.clicked.connect(self._save_settings_form)
        reload_button = QPushButton("Reload")
        reload_button.clicked.connect(self._load_settings_form)
        button_row.addStretch(1)
        button_row.addWidget(reload_button)
        button_row.addWidget(save_button)
        layout.addLayout(button_row)
        layout.addStretch(1)
        return tab

    def _build_raw_config_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        self.raw_config_editor = QPlainTextEdit()
        self.raw_config_editor.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.raw_config_editor.setFont(code_font(12))
        layout.addWidget(self.raw_config_editor, 1)
        button_row = QHBoxLayout()
        validate_button = QPushButton("Apply Raw YAML")
        validate_button.clicked.connect(self._save_raw_config_editor)
        reload_button = QPushButton("Reload Raw")
        reload_button.clicked.connect(self._load_raw_config_editor)
        button_row.addStretch(1)
        button_row.addWidget(reload_button)
        button_row.addWidget(validate_button)
        layout.addLayout(button_row)
        return tab

    def _open_raw_settings(self):
        self.show_screen(self._screen_index("settings"))
        if hasattr(self, "settings_tabs"):
            for index in range(self.settings_tabs.count()):
                if self.settings_tabs.tabText(index) == "Raw YAML":
                    self.settings_tabs.setCurrentIndex(index)
                    break

    def _llm_status(self) -> tuple[bool, str]:
        llm = get_llm_config(self._read_config())
        model = llm.get("model", "")
        local_prefixes = ("ollama/", "lm_studio/", "hosted_vllm/")
        needs_key = bool(model) and not model.startswith(local_prefixes)
        ready = bool(model) and (bool(llm.get("api_key")) or not needs_key)
        if ready:
            return True, f"LLM ready: {model}"
        return False, f"LLM key missing for {model or 'configured model'}"

    def choose_config_file(self):
        selected, _ = QFileDialog.getOpenFileName(
            self,
            "Config File",
            str(self.config_path.parent),
            "YAML (*.yaml *.yml);;All files (*)",
        )
        if not selected:
            return
        self._load_config_path(Path(selected))

    def _load_config_path(self, path: Path):
        """Point the app at a config file (file dialog or drag & drop)."""
        self.config_path = path
        self._load_settings_form()
        self._update_operation_context()
        self._set_status("ok", f"Config: {self.config_path.name}")

    def _write_r10xm_config(self) -> Path | None:
        """Lay the r10xM preset over the operator's config into a derived file.

        The operator's own config.yaml is never modified; the engine runs off
        the generated sibling instead. Returns its path, or None on write
        failure (the caller aborts the run).
        """
        merged = r10xm_config_overlay(self._read_config())
        path = self.config_path.parent / R10XM_CONFIG_NAME
        try:
            path.write_text(yaml.safe_dump(merged, sort_keys=False))
        except OSError as exc:
            QMessageBox.warning(
                self, "r10xM Config Failed",
                f"Could not write the derived config:\n{exc}")
            return None
        return path

    def _refresh_identities_table(self):
        if not hasattr(self, "identities_table"):
            return
        self.identities_table.setRowCount(len(self._identity_records))
        for row, record in enumerate(self._identity_records):
            for col, value in enumerate(self._identity_row_values(record)):
                self.identities_table.setItem(row, col, QTableWidgetItem(str(value)))

    @staticmethod
    def _identity_row_values(record: dict) -> list[str]:
        cookies = record.get("cookies") or {}
        if isinstance(cookies, dict):
            cookie_text = "; ".join(f"{key}={value}" for key, value in cookies.items())
        else:
            cookie_text = str(cookies)
        token = str(record.get("bearer_token") or record.get("token") or "")
        return [
            str(record.get("name", "")),
            token,
            cookie_text,
            str(record.get("verify_url", "")),
            str(record.get("success_marker", "")),
            str(record.get("role", "")),
        ]

    def _add_identity_row(self):
        # Table cells are edited without a binding model; sync first so a
        # rename typed into a row survives the table refresh below.
        self._sync_identity_records()
        used = {str(record.get("name", "")) for record in self._identity_records}
        index = len(self._identity_records) + 1
        name = f"identity_{index}"
        while name in used:
            index += 1
            name = f"identity_{index}"
        self._identity_records.append({"name": name})
        self._refresh_identities_table()
        self.identities_table.selectRow(len(self._identity_records) - 1)

    def _remove_identity_rows(self):
        self._sync_identity_records()
        rows = sorted(
            {index.row() for index in self.identities_table.selectedIndexes()},
            reverse=True,
        )
        for row in rows:
            if 0 <= row < len(self._identity_records):
                self._identity_records.pop(row)
        if rows:
            self._refresh_identities_table()

    def _sync_identity_records(self):
        """Read the table back into records, preserving unknown record keys."""
        records = []
        for row in range(self.identities_table.rowCount()):
            def cell(col: int) -> str:
                item = self.identities_table.item(row, col)
                return item.text().strip() if item else ""

            name = cell(0)
            if row < len(self._identity_records) and isinstance(self._identity_records[row], dict):
                record = dict(self._identity_records[row])
            else:
                record = {}
            # Keep one record per table row (even nameless ones) so row
            # indices stay aligned; save filters the empty ones out.
            record["name"] = name

            token = cell(1)
            if token:
                record["bearer_token"] = token
            else:
                record.pop("bearer_token", None)
                record.pop("token", None)

            cookies_text = cell(2)
            if cookies_text:
                cookies = {}
                for pair in cookies_text.split(";"):
                    if "=" in pair:
                        key, value = pair.split("=", 1)
                        cookies[key.strip()] = value.strip()
                if cookies:
                    record["cookies"] = cookies
                else:
                    record.pop("cookies", None)
            else:
                record.pop("cookies", None)

            for key, value in (
                ("verify_url", cell(3)),
                ("success_marker", cell(4)),
                ("role", cell(5)),
            ):
                if value:
                    record[key] = value
                else:
                    record.pop(key, None)
            records.append(record)
        self._identity_records = records

    def _load_raw_config_editor(self):
        if not hasattr(self, "raw_config_editor"):
            return
        if self.config_path.exists():
            self.raw_config_editor.setPlainText(self.config_path.read_text(errors="replace"))
        else:
            self.raw_config_editor.setPlainText("")

    def _save_raw_config_editor(self):
        text = self.raw_config_editor.toPlainText()
        try:
            parsed = yaml.safe_load(text) or {}
        except yaml.YAMLError as exc:
            QMessageBox.warning(self, "Invalid YAML", str(exc))
            return
        if not isinstance(parsed, dict):
            QMessageBox.warning(self, "Invalid YAML", "Config root must be a mapping.")
            return
        try:
            self.config_path.write_text(text)
        except OSError as exc:
            QMessageBox.warning(self, "Save Failed", str(exc))
            return
        self._load_settings_form()
        self._set_status("ok", "Raw config applied")

    def _write_config(self, config: dict) -> bool:
        try:
            self.config_path.write_text(yaml.safe_dump(config, sort_keys=False))
            return True
        except OSError as exc:
            QMessageBox.warning(self, "Save Failed", str(exc))
            return False

    def _read_config(self) -> dict:
        if not self.config_path.exists():
            return {}
        try:
            return yaml.safe_load(self.config_path.read_text()) or {}
        except (yaml.YAMLError, OSError):
            return {}

    def _refresh_key_status(self):
        vault = KeyVault(self._read_config())
        presence = vault.presence()
        self.keys_table.setRowCount(len(presence))
        for row, (service, info) in enumerate(presence.items()):
            values = [
                info.get("label", service),
                "yes" if info.get("present") else "no",
                info.get("masked", ""),
            ]
            for col, value in enumerate(values):
                self.keys_table.setItem(row, col, QTableWidgetItem(value))
