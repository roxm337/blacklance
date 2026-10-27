"""I5 ORM / filter leak screen.

Mixin for gui.app.MainWindow; see that class for composition.
"""
from __future__ import annotations

from gui._shared import *  # noqa: F401,F403


class OrmScreenMixin:

    # ---- I5 screen data ---------------------------------------------------

    MAX_ORM_REPORTS = 40

    def _load_orm_view(self):
        """Fill the I5 screen from the stores load_results just read."""
        evidence_items = (self.current_evidence.get("items", [])
                          if isinstance(self.current_evidence, dict) else [])
        if not isinstance(evidence_items, list):
            evidence_items = []
        reports, unreadable, truncated = self._orm_reports(evidence_items)
        self._orm_report_count = len(reports)
        surfaces = self._orm_surface_rows(reports)
        candidates = self._orm_candidate_rows(reports)
        canaries = self._orm_canary_rows(reports)
        gaps = self._orm_gaps(reports, surfaces)
        self._orm_surface_rows_cache = surfaces
        self._orm_candidate_rows_cache = candidates
        self._orm_canary_rows_cache = canaries
        self._orm_gap_rows = gaps

        driven = {key for report in reports for key in self._orm_driven_keys(report)}
        proofs = {(row["evidence_id"], row["name"]) for row in canaries
                  if row["tier"] == "PROOF"}
        self.orm_planned_value.setText(str(len(surfaces)))
        self.orm_probed_value.setText(str(len(driven)))
        self.orm_candidates_value.setText(str(len(candidates)))
        self.orm_proofs_value.setText(str(len(proofs)))
        self.orm_cleanup_value.setText(str(sum(
            1 for row in canaries if row["cleanup"] != ORM_CLEANUP_VERIFIED)))
        self.orm_gap_value.setText(str(len(gaps)))
        modules = sorted({row["module"] for row in surfaces if row["module"]})
        if modules:
            self.orm_run_label.setText(
                f"ORM run loaded from {', '.join(modules)} · "
                f"{len(proofs)} seeded-record proof(s)")
        else:
            self.orm_run_label.setText("no orm run loaded")
        self._render_orm_surfaces()
        self._render_orm_candidates()
        self._render_orm_canaries()
        self._render_orm_gaps()
        self._refresh_orm_badge()
        notes = []
        if truncated:
            notes.append(
                f"only the first {self.MAX_ORM_REPORTS} ORM report(s) parsed")
        if unreadable:
            notes.append(f"{unreadable} ORM payload(s) unreadable")
        # Silence is deliberate when no run exists at all: every screen that
        # loaded a message would leave only the last one readable, and
        # "no orm run loaded" is already on the strip.
        if notes:
            self.statusBar().showMessage(
                "ORM view is partial: " + "; ".join(notes), 8000)

    @staticmethod
    def _orm_surface_label(url: str) -> str:
        """Tables show the path, not the whole URL: one run has one origin, so
        four full URLs elide into four identical "https://…" cells."""
        return urlparse(url).path or url

    @staticmethod
    def _orm_driven_keys(report: dict) -> set:
        """(url, param) pairs whose filter values actually went out.

        A candidate probe and a no-signal observation are the only two
        records that prove a surface was driven; anything else on the screen
        is a claim about a surface the run never touched.
        """
        return {(str(entry.get("surface") or ""), str(entry.get("param") or ""))
                for key in ("probes", "observations")
                for entry in report[key] if isinstance(entry, dict)}

    def _orm_reports(self, evidence_items: list) -> tuple[list[dict], int, bool]:
        relevant = [item for item in evidence_items
                    if isinstance(item, dict)
                    and item.get("type") == ORM_EVIDENCE_TYPE]
        truncated = len(relevant) > self.MAX_ORM_REPORTS
        docs, unreadable = self._read_evidence_payloads(
            relevant, ORM_EVIDENCE_TYPE, self.MAX_ORM_REPORTS)
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
                "surfaces": data.get("surfaces")
                if isinstance(data.get("surfaces"), list) else [],
                "probes": data.get("probes")
                if isinstance(data.get("probes"), list) else [],
                "observations": data.get("observations")
                if isinstance(data.get("observations"), list) else [],
                "canaries": data.get("canaries")
                if isinstance(data.get("canaries"), list) else [],
                "untested": data.get("untested")
                if isinstance(data.get("untested"), list) else [],
            })
        return reports, unreadable, truncated

    def _orm_canary_evidence(self, evidence_items: list) -> dict:
        """Proven canaries as their own evidence records, keyed by name.

        The report row is the run's account; this is the artifact the operator
        opens, so the detail pane links whichever one exists.
        """
        relevant = [item for item in evidence_items
                    if isinstance(item, dict)
                    and item.get("type") == ORM_CANARY_EVIDENCE_TYPE]
        docs, _ = self._read_evidence_payloads(
            relevant, ORM_CANARY_EVIDENCE_TYPE, self.MAX_ORM_REPORTS)
        by_name: dict[str, dict] = {}
        for entry in docs:
            data = entry["doc"].get("data")
            payload = data if isinstance(data, dict) else entry["doc"]
            item = entry["item"]
            key = str(payload.get("name") or item.get("id") or "")
            if key:
                by_name.setdefault(key, {
                    "evidence_id": str(item.get("id") or ""),
                    "evidence_path": str(item.get("path") or ""),
                    "module": str(item.get("module_id") or ""),
                    "param": str(payload.get("param") or ""),
                    "mut_id": str(payload.get("mut_id") or ""),
                    "cleanup_status": str(payload.get("cleanup_status") or ""),
                })
        return by_name

    @staticmethod
    def _orm_finding_index(findings: list) -> tuple[dict, dict]:
        """Candidates cite surface+param, proofs cite the canary name — the two
        keys are indexed separately because one finding never carries both."""
        by_surface: dict[tuple, dict] = {}
        by_canary: dict[str, dict] = {}
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            if str(finding.get("category") or "") != ORM_FINDING_CATEGORY:
                continue
            entries = [str(entry) for entry in finding.get("evidence") or []]
            url = next((text.split(":", 1)[1] for text in entries
                        if text.startswith("surface:")), "")
            param = next((text.split(":", 1)[1] for text in entries
                          if text.startswith("param:")), "")
            if url and param:
                by_surface.setdefault((url, param), finding)
            for text in entries:
                if text.startswith("canary:"):
                    by_canary.setdefault(text.split(":", 1)[1], finding)
        return by_surface, by_canary

    def _orm_finding_pair(self) -> tuple[dict, dict]:
        findings = self.current_findings if isinstance(self.current_findings,
                                                       list) else []
        return self._orm_finding_index(findings)

    @staticmethod
    def _orm_surface_key(entry: dict) -> tuple:
        return (str(entry.get("surface") or ""), str(entry.get("param") or ""))

    def _orm_surface_rows(self, reports: list[dict]) -> list[dict]:
        by_surface_finding, _ = self._orm_finding_pair()
        rows: list[dict] = []
        seen: set = set()
        for report in reports:
            untested_urls = {str(entry.get("surface") or "")
                             for entry in report["untested"]
                             if isinstance(entry, dict)}
            untested_reason = {str(entry.get("surface") or ""):
                               str(entry.get("reason") or "-")
                               for entry in report["untested"]
                               if isinstance(entry, dict)}
            probes: dict[tuple, list] = {}
            for entry in report["probes"]:
                if isinstance(entry, dict):
                    probes.setdefault(self._orm_surface_key(entry), []).append(entry)
            observations: dict[tuple, dict] = {}
            for entry in report["observations"]:
                if isinstance(entry, dict):
                    observations.setdefault(self._orm_surface_key(entry),
                                            entry)
            for surface in report["surfaces"]:
                if not isinstance(surface, dict):
                    continue
                url = str(surface.get("url") or "")
                param = str(surface.get("param") or "")
                key = (url, param)
                # The same surface in a later run is a second row on purpose:
                # each row is one report's account, not a merged history.
                dedupe = (report["evidence_id"], key)
                if dedupe in seen:
                    continue
                seen.add(dedupe)
                matched = probes.get(key, [])
                observation = observations.get(key)
                if matched:
                    tier = "CANDIDATE"
                    outcome = (f"{len(matched)} filter value(s) returned "
                               "cross-identity rows")
                elif observation is not None:
                    tier = "HEALTHY"
                    outcome = (f"driven against {observation.get('values_tried', 0)} "
                               "value(s), no cross-identity rows")
                elif url in untested_urls:
                    tier = ""
                    outcome = f"not driven — {untested_reason.get(url, '-')}"
                else:
                    tier = ""
                    outcome = "planned, never driven — see Coverage"
                finding = by_surface_finding.get(key)
                rows.append({
                    "kind": "surface", "tier": tier, "key": key,
                    "url": url, "label": self._orm_surface_label(url),
                    "param": param,
                    "vector": str(surface.get("vector") or ""),
                    "source": str(surface.get("source") or ""),
                    "method": str(surface.get("method") or "GET"),
                    "identity": str((matched[0] if matched else observation
                                     or {}).get("identity") or "-"),
                    "outcome": outcome,
                    "probes": matched, "observation": observation,
                    "module": report["module"],
                    "run_token": report["run_token"],
                    "evidence_id": report["evidence_id"],
                    "evidence_path": report["evidence_path"],
                    "finding_id": str(finding.get("id") or "") if finding else "",
                    "finding_title": str(finding.get("title") or "") if finding else "",
                })
        rows.sort(key=lambda row: (ORM_TIER_RANK.get(row["tier"], 9),
                                   row["url"], row["param"]))
        return rows

    def _orm_candidate_rows(self, reports: list[dict]) -> list[dict]:
        by_surface_finding, _ = self._orm_finding_pair()
        rows: list[dict] = []
        for report in reports:
            vectors: dict[tuple, str] = {
                (str(s.get("url") or ""), str(s.get("param") or "")):
                    str(s.get("vector") or "")
                for s in report["surfaces"] if isinstance(s, dict)}
            for entry in report["probes"]:
                if not isinstance(entry, dict):
                    continue
                key = self._orm_surface_key(entry)
                finding = by_surface_finding.get(key)
                rows.append({
                    "kind": "candidate", "tier": "CANDIDATE", "key": key,
                    "url": key[0], "label": self._orm_surface_label(key[0]),
                    "param": key[1],
                    "vector": vectors.get(key, ""),
                    "identity": str(entry.get("identity") or "-"),
                    "state": str(entry.get("state") or ""),
                    "row_delta": entry.get("row_delta", 0),
                    "markers": entry.get("attributed_markers", 0),
                    "note": str(entry.get("note") or ""),
                    "module": report["module"],
                    "run_token": report["run_token"],
                    "evidence_id": report["evidence_id"],
                    "evidence_path": report["evidence_path"],
                    "finding_id": str(finding.get("id") or "") if finding else "",
                    "finding_title": str(finding.get("title") or "") if finding else "",
                })
        rows.sort(key=lambda row: (-int(row["markers"] or 0), row["url"],
                                   row["param"]))
        return rows

    def _orm_canary_rows(self, reports: list[dict]) -> list[dict]:
        evidence_items = (self.current_evidence.get("items", [])
                          if isinstance(self.current_evidence, dict) else [])
        artifacts = self._orm_canary_evidence(
            evidence_items if isinstance(evidence_items, list) else [])
        _, by_canary_finding = self._orm_finding_pair()
        rows: list[dict] = []
        for report in reports:
            for entry in report["canaries"]:
                if not isinstance(entry, dict):
                    continue
                name = str(entry.get("name") or "canary")
                cleanup = str(entry.get("cleanup_status") or "")
                # observed is only populated when the seed came back, so a
                # non-empty value here is the leak signal itself.
                leaked = entry.get("observed") not in (None, "")
                if entry.get("proven"):
                    tier = "PROOF"
                elif cleanup == ORM_CLEANUP_VERIFIED and not leaked \
                        and entry.get("reason") is None \
                        and entry.get("error") is None:
                    # A clean negative only if the record this pass created is
                    # verifiably gone; otherwise the target still holds it.
                    tier = "HEALTHY"
                else:
                    tier = "OBSERVATION"
                artifact = artifacts.get(name) or {}
                finding = by_canary_finding.get(name)
                path = str(artifact.get("evidence_path")
                           or report["evidence_path"])
                rows.append({
                    "kind": "canary", "tier": tier, "name": name,
                    "owner": str(entry.get("created_by") or "-"),
                    "reader": str(entry.get("read_by") or "-"),
                    "param": str(entry.get("param") or ""),
                    "direct_status": entry.get("direct_read_status", ""),
                    "seed_intact": entry.get("seed_intact"),
                    "baseline": entry.get("baseline_contains"),
                    "absent": entry.get("absent_contains"),
                    "owner_positive": entry.get("owner_positive"),
                    "leaked": leaked,
                    "cleanup": cleanup,
                    "mut_id": str(entry.get("mut_id") or ""),
                    "reason": str(entry.get("reason") or ""),
                    "error": str(entry.get("error") or ""),
                    "run_token": report["run_token"],
                    "module": report["module"],
                    "evidence_id": str(artifact.get("evidence_id")
                                       or report["evidence_id"]),
                    "evidence_path": path,
                    "finding_id": str(finding.get("id") or "") if finding else "",
                    "finding_title": str(finding.get("title") or "") if finding else "",
                })
        rows.sort(key=lambda row: (ORM_TIER_RANK.get(row["tier"], 9),
                                   row["name"]))
        return rows

    def _orm_gaps(self, reports: list[dict], surfaces: list[dict]) -> list[dict]:
        rows: list[dict] = []
        for report in reports:
            for entry in report["untested"]:
                if not isinstance(entry, dict):
                    continue
                rows.append({
                    "kind": "gap",
                    "surface": str(entry.get("surface") or "-"),
                    "reason": str(entry.get("reason") or "-"),
                    "module": report["module"],
                    "run_token": report["run_token"],
                    "evidence_id": report["evidence_id"],
                    "evidence_path": report["evidence_path"],
                })
        # A surface the run planned and never drove is a gap even when the
        # engine named only the lane: without this row the card would read
        # "not tested: 0" over a screen of undriven surfaces.
        named = {row["surface"] for row in rows}
        for row in surfaces:
            if row["tier"] or row["url"] in named:
                continue
            rows.append({
                "kind": "gap", "surface": row["url"],
                "reason": f"parameter '{row['param']}' was never sent a value",
                "module": row["module"], "run_token": row["run_token"],
                "evidence_id": row["evidence_id"],
                "evidence_path": row["evidence_path"],
            })
            named.add(row["url"])
        return rows

    @staticmethod
    def _orm_tier_item(row: dict, value: str) -> QTableWidgetItem:
        """A tier cell: bold, coloured, and selectable even when the tier is
        empty — an undriven surface still has to be clickable for the detail."""
        item = QTableWidgetItem(value)
        color = ORM_TIER_COLORS.get(row["tier"])
        font = item.font()
        font.setBold(True)
        item.setFont(font)
        item.setForeground(QColor(color or "#5b7181"))
        item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
        return item

    def _render_orm_surfaces(self, *_args):
        table = self.orm_surfaces_table
        query = self.orm_search.text().strip().lower()
        tier = (self.orm_tier_combo.currentText()
                if self.orm_tier_combo.currentIndex() > 0 else "")
        rows = getattr(self, "_orm_surface_rows_cache", [])
        visible = [
            row for row in rows
            if (not tier or row["tier"] == tier)
            and (not query or query in " ".join((
                row["url"], row["label"], row["param"], row["vector"],
                row["source"], row["identity"], row["outcome"])).lower())
        ]
        # The filtered slice has to be remembered: detail lookup is by row.
        self._orm_visible_surfaces = visible
        table.setRowCount(len(visible))
        for index, row in enumerate(visible):
            values = (row["tier"] or "-", row["label"], row["param"],
                      row["vector"], row["source"], row["identity"],
                      row["outcome"])
            for column, value in enumerate(values):
                item = (self._orm_tier_item(row, value) if column == 0
                        else QTableWidgetItem(value))
                # The path is the cell; the full URL stays one hover away.
                item.setToolTip(row["url"] if column == 1 else value)
                table.setItem(index, column, item)
        self.orm_count_label.setText(f"{len(visible)} of {len(rows)}")
        if not visible:
            self._render_orm_detail(None)

    def _render_orm_candidates(self, *_args):
        table = self.orm_candidates_table
        rows = getattr(self, "_orm_candidate_rows_cache", [])
        table.setRowCount(len(rows))
        for index, row in enumerate(rows):
            values = (row["label"], row["param"], row["identity"],
                      str(row["row_delta"]), str(row["markers"]),
                      row["note"] or "-")
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 4:
                    item.setForeground(QColor("#fdba74"))
                    font = item.font()
                    font.setBold(True)
                    item.setFont(font)
                item.setToolTip(row["url"] if column == 0 else value)
                table.setItem(index, column, item)
        if not rows:
            self._render_orm_detail(None)

    @staticmethod
    def _orm_control_text(row: dict) -> str:
        """Both controls have to be negative or the leak means nothing."""
        if row["baseline"] is None and row["absent"] is None:
            return "not run"
        baseline = ("baseline not run" if row["baseline"] is None else
                    f"baseline {'HIT' if row['baseline'] else 'clean'}")
        absent = ("absent not run" if row["absent"] is None else
                  f"absent {'HIT' if row['absent'] else 'clean'}")
        return f"{baseline}, {absent}"

    @staticmethod
    def _orm_yes_no(value, unknown: str = "not run") -> str:
        if value is None:
            return unknown
        return "yes" if value else "no"

    def _render_orm_canaries(self, *_args):
        table = self.orm_canaries_table
        rows = getattr(self, "_orm_canary_rows_cache", [])
        table.setRowCount(len(rows))
        for index, row in enumerate(rows):
            direct = self._orm_direct_short(row["direct_status"])
            values = (
                row["tier"], row["name"],
                f"{row['owner']} → {row['reader']}", row["param"] or "-",
                direct, self._orm_control_text(row),
                self._orm_yes_no(row["owner_positive"]),
                row["cleanup"] or "not run",
            )
            for column, value in enumerate(values):
                item = (self._orm_tier_item(row, value) if column == 0
                        else QTableWidgetItem(value))
                if column == 4:
                    item.setForeground(QColor(
                        "#4ade80" if direct.startswith("denied ") else "#fdba74"))
                if column in (5, 6, 7):
                    bad = ((column == 5 and ("HIT" in value
                                             or value in ("not run",)))
                           or (column == 6 and value != "yes")
                           or (column == 7 and value != ORM_CLEANUP_VERIFIED))
                    item.setForeground(QColor("#fdba74" if bad else "#4ade80"))
                item.setToolTip(value)
                table.setItem(index, column, item)
        if not rows:
            self._render_orm_detail(None)

    def _render_orm_gaps(self, *_args):
        table = self.orm_gap_table
        rows = getattr(self, "_orm_gap_rows", [])
        table.setRowCount(len(rows))
        for index, row in enumerate(rows):
            values = (self._orm_surface_label(row["surface"]), row["reason"])
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 1:
                    item.setForeground(QColor("#fdba74"))
                item.setToolTip(row["surface"] if column == 0 else value)
                table.setItem(index, column, item)
        if not getattr(self, "_orm_report_count", 0):
            tone = "warn"
            text = "no ORM run loaded — nothing has been tested yet"
        elif not rows:
            tone = "ok"
            text = "nothing left untested by the last run"
        else:
            tone = "warn"
            text = (f"{len(rows)} surface(s) or lane(s) the last run never "
                    "drove")
        self.orm_gap_note.setProperty("tone", tone)
        self.orm_gap_note.setText(text)
        self.orm_gap_note.style().unpolish(self.orm_gap_note)
        self.orm_gap_note.style().polish(self.orm_gap_note)

    def _on_orm_surface_changed(self, row: int, *_args):
        rows = getattr(self, "_orm_visible_surfaces", [])
        self._render_orm_detail(rows[row] if 0 <= row < len(rows) else None)

    def _on_orm_candidate_changed(self, row: int, *_args):
        rows = getattr(self, "_orm_candidate_rows_cache", [])
        if not (0 <= row < len(rows)):
            self._render_orm_detail(None)
            return
        candidate = rows[row]
        match = next((surface for surface in
                      getattr(self, "_orm_surface_rows_cache", [])
                      if surface["key"] == candidate["key"]), None)
        self._render_orm_detail(match or candidate)

    def _on_orm_canary_changed(self, row: int, *_args):
        rows = getattr(self, "_orm_canary_rows_cache", [])
        self._render_orm_detail(rows[row] if 0 <= row < len(rows) else None)

    def _on_orm_gap_changed(self, row: int, *_args):
        rows = getattr(self, "_orm_gap_rows", [])
        self._render_orm_detail(rows[row] if 0 <= row < len(rows) else None)

    def _render_orm_detail(self, row: dict | None):
        self._orm_detail_row = row
        if not row:
            self.orm_detail_title.setText("No surface selected")
            self.orm_detail_body.clear()
            self.orm_open_evidence_button.setEnabled(False)
            self.orm_open_finding_button.setEnabled(False)
            return
        kind = row.get("kind", "surface")
        tier = row.get("tier") or ""
        color = ORM_TIER_COLORS.get(tier, "#5b7181")
        if kind == "canary":
            title = f"{tier or 'CANARY'} · {row['name']} · {row['owner']} → {row['reader']}"
        elif kind == "gap":
            title = f"untested · {row['surface']}"
        else:
            title = (f"{tier or 'PLANNED'} · {row['param']} on {row['url']}"
                     if kind == "candidate" else
                     f"{tier or 'NOT DRIVEN'} · {row['param']} on {row['url']}")
        self.orm_detail_title.setText(title)
        parts = []
        if tier:
            parts.append(f"<b style='color:{color}'>{html_escape(tier)}</b> — "
                         f"{html_escape(ORM_TIER_MEANING.get(tier, ''))}")
        elif kind == "gap":
            parts.append("<b style='color:#fdba74'>NOT TESTED</b> — this is "
                         "not a negative result; nothing was observed here")
        else:
            parts.append("<b style='color:#fdba74'>NOT DRIVEN</b> — the "
                         "surface was planned but no filter value reached it, "
                         "so it proves nothing about the target")
        parts.append("")
        parts.append(f"<b>Module</b> {html_escape(row.get('module') or '-')}")
        if kind == "canary":
            parts += self._orm_canary_detail_lines(row)
        elif kind == "gap":
            parts += [
                f"<b>Surface or lane</b> {html_escape(row['surface'])}",
                f"<b>Why</b> {html_escape(row['reason'])}",
            ]
        elif kind == "candidate":
            parts += [
                f"<b>Surface</b> {html_escape(row['url'])}",
                f"<b>Parameter</b> {html_escape(row['param'])}",
                f"<b>Vector</b> {html_escape(row['vector'] or '-')}",
                f"<b>Probed as</b> {html_escape(row['identity'])}",
                f"<b>Rows returned</b> {html_escape(str(row['row_delta']))}",
                f"<b>Markers attributed</b> "
                f"{html_escape(str(row['markers']))}",
                f"<b>Note</b> {html_escape(row['note'] or '-')}",
            ]
        else:
            parts += self._orm_surface_detail_lines(row)
        parts += ["", f"<b>Run token</b> {html_escape(row.get('run_token') or '-')}"]
        finding_line = (
            f"{html_escape(row.get('finding_id') or '')} — "
            f"{html_escape(row.get('finding_title') or '')}"
            if row.get("finding_id") else "none filed")
        parts += [f"<b>Finding</b> {finding_line}", ""]
        parts += [f"<b>Evidence</b> {html_escape(row.get('evidence_path') or '-')}"]
        next_step = self._orm_next_step(row)
        if next_step:
            parts.append(f"<b>Still needed</b> {html_escape(next_step)}")
        self.orm_detail_body.setHtml("<br>".join(parts))
        self.orm_open_evidence_button.setEnabled(bool(row.get("evidence_path")))
        self.orm_open_finding_button.setEnabled(bool(row.get("finding_id")))

    def _orm_surface_detail_lines(self, row: dict) -> list:
        vector = row["vector"] or ""
        parts = [
            f"<b>Surface</b> {html_escape(row['url'])}",
            f"<b>Parameter</b> {html_escape(row['param'])}",
            f"<b>Vector</b> {html_escape(vector or '-')} — "
            f"{html_escape(ORM_VECTOR_MEANING.get(vector, 'unknown vector'))}",
            f"<b>Found from</b> {html_escape(row['source'] or '-')}",
            f"<b>Method</b> {html_escape(row['method'] or 'GET')}",
            f"<b>Probed as</b> {html_escape(row['identity'] or '-')}",
            f"<b>Outcome</b> {html_escape(row['outcome'])}",
        ]
        observation = row.get("observation")
        if isinstance(observation, dict):
            parts.append(
                f"<b>Values tried</b> "
                f"{html_escape(str(observation.get('values_tried', 0)))} — "
                "the filter was answered and no row belonged to another "
                "identity")
        for index, probe in enumerate(row.get("probes") or [], start=1):
            parts.append(
                f"<b>Probe {index}</b> {html_escape(str(probe.get('row_delta')))} "
                f"row(s), {html_escape(str(probe.get('attributed_markers')))} "
                f"marker(s) attributed to another identity — "
                f"{html_escape(str(probe.get('note') or ''))}")
        return parts

    def _orm_canary_detail_lines(self, row: dict) -> list:
        parts = [
            f"<b>Canary</b> {html_escape(row['name'])}",
            f"<b>Seeded by</b> {html_escape(row['owner'])}",
            f"<b>Read back by</b> {html_escape(row['reader'])}",
            f"<b>Filter parameter</b> {html_escape(row['param'] or '-')}",
            f"<b>Direct read</b> {html_escape(self._orm_direct_text(row))}",
            f"<b>Seed intact</b> "
            f"{html_escape(self._orm_yes_no(row['seed_intact']))}",
            f"<b>Controls</b> {html_escape(self._orm_control_text(row))}",
            f"<b>Owner positive</b> "
            f"{html_escape(self._orm_yes_no(row['owner_positive']))}",
            f"<b>Seed read back through filter</b> "
            f"{html_escape('yes' if row['leaked'] else 'no')}",
            f"<b>Cleanup</b> {html_escape(row['cleanup'] or 'not run')}",
            f"<b>Mutation</b> {html_escape(row['mut_id'] or '-')}",
        ]
        if row["reason"]:
            parts.append(f"<b>Why not a proof</b> {html_escape(row['reason'])}")
        if row["error"]:
            parts.append(f"<b>Error</b> {html_escape(row['error'])}")
        return parts

    @staticmethod
    def _orm_direct_short(status) -> str:
        """A direct-read result in lane terms, not status-code terms: only the
        denial codes satisfy the prerequisite, and a 0 never ran."""
        text = "" if status is None else str(status)
        if not text.isdigit():
            return text or "not run"
        code = int(text)
        if code == 0:
            return "no response"
        if code in (401, 403, 404, 410):
            return f"denied {text}"
        if 200 <= code < 300:
            return f"ALLOWED {text}"
        return f"not denied {text}"

    @staticmethod
    def _orm_direct_text(row: dict) -> str:
        status = "" if row["direct_status"] is None \
            else str(row["direct_status"])
        short = OrmScreenMixin._orm_direct_short(status)
        if not status.isdigit():
            return short
        code = int(status)
        if code == 0:
            return ("no response — the direct-read prerequisite never ran, so "
                    "this is not a filter leak")
        if code in (401, 403, 404, 410):
            return (f"{short} — denied, which is what a filter leak needs")
        if 200 <= code < 300:
            return (f"{short} — allowed, so this is the direct-read lane, not "
                    "a filter leak")
        return (f"{short} — not a denial, so the direct-read prerequisite "
                "fails")

    def _orm_next_step(self, row: dict) -> str:
        """What would move this row up a tier — empty when the row is already
        finished (a proof, or a clean negative that cleaned up after itself)."""
        kind, tier = row.get("kind"), row.get("tier")
        if kind == "gap":
            return ("give the run more wall budget or fewer surfaces, set "
                    "vector_values, or configure a second identity — until "
                    "then this row is coverage, not a result")
        if kind == "canary":
            if tier == "PROOF":
                return ""
            if row["cleanup"] != ORM_CLEANUP_VERIFIED:
                return ("verify cleanup on the mutation ledger: the record "
                        "this pass created on the target is still there, and "
                        "an unverified cleanup disqualifies the proof")
            if row["leaked"]:
                return ("the seed came back but a control was dirty (baseline "
                        "or absent-value already showed it) — point "
                        "canary.read.extract at a field only the seeded "
                        "record carries")
            if row["reason"] or row["error"]:
                return ("fix the prerequisite: the owner must read the seeded "
                        "record directly and the forbidden identity must be "
                        "denied that same read")
            return ""
        if tier == "CANDIDATE":
            return ("a seeded canary on the same parameter: real records "
                    "attributed to another identity are a candidate, and only "
                    "the module's own record read back through the filter is "
                    "a proof")
        if tier == "HEALTHY":
            return ""
        return ("set modules.orm_filter_audit.vector_values (or let traffic "
                "capture supply surfaces) so this parameter actually gets "
                "probed")

    def _orm_selected_detail_row(self) -> dict | None:
        """Whatever the detail pane is currently showing."""
        return getattr(self, "_orm_detail_row", None)

    def _open_orm_evidence(self):
        row = self._orm_selected_detail_row()
        if not row or not row.get("evidence_path"):
            return
        path = self._assessment_dir() / row["evidence_path"]
        if path.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))
        else:
            self.statusBar().showMessage("Evidence file is gone", 3000)

    def _open_orm_finding(self):
        row = self._orm_selected_detail_row()
        if not row or not row.get("finding_id"):
            return
        self.finding_search.setText(row["finding_id"])
        self.show_screen(self._screen_index("triage"))

    def _refresh_orm_badge(self):
        index = self._screen_index("orm")
        count = sum(
            1 for row in getattr(self, "_orm_surface_rows_cache", [])
            if row["tier"] == "CANDIDATE") + sum(
            1 for row in getattr(self, "_orm_canary_rows_cache", [])
            if row["tier"] in ("PROOF", "OBSERVATION"))
        if 0 <= index < len(self.nav_buttons):
            self._set_nav_badge(index, count, "ORM row(s) worth a look")

    # ---- I5 plan: config round trip and run -------------------------------

    def _apply_orm_plan(self, config: dict):
        cfg = self._module_section(config or {}, ORM_MODULE_ID)
        # Cached for the checkbox handlers: this panel edits scalars only, so
        # the nested canary spec it reports on stays valid until the next
        # config load.
        self._orm_section = cfg
        self.orm_enabled_check.setChecked(bool(cfg.get("enabled")))
        self.orm_traffic_check.setChecked(
            bool(cfg.get("traffic_surfaces", True)))
        self.orm_augment_check.setChecked(
            bool(cfg.get("augment_collections", True)))
        self.orm_source_check.setChecked(
            bool((cfg.get("source_rules") or {}).get("enabled")))
        canary = cfg.get("canary")
        canary = canary if isinstance(canary, dict) else {}
        # The engine runs canaries only when the key is present and true, so
        # the checkbox must not default to on over an absent section.
        self.orm_canary_check.setChecked(bool(canary.get("enabled")))
        for spin, key, default, label in (
            (self.orm_max_surfaces_spin, "max_surfaces", 8,
             "orm_filter_audit max_surfaces"),
            (self.orm_max_probes_spin, "max_payloads", 12,
             "orm_filter_audit max_payloads"),
            (self.orm_max_seconds_spin, "max_seconds", 300,
             "orm_filter_audit max_seconds"),
        ):
            self._note_spin_clamp(
                self._set_spin(spin, cfg.get(key), default), label)
        self._note_spin_clamp(
            self._set_spin(self.orm_canary_max_spin, canary.get("max"), 2),
            "orm_filter_audit canary.max")
        self._orm_populate_identity_choices(
            str(canary.get("owner_identity") or ""),
            str(canary.get("forbidden_identity") or ""))
        self._render_orm_depth(cfg)
        self._update_orm_state_label()

    def _orm_identity_choices(self) -> list[str]:
        names = [str(record.get("name")) for record in self._identity_records
                 if isinstance(record, dict) and record.get("name")]
        # The engine treats "anonymous" as a real lane (request_anonymous),
        # so it has to be selectable even with no identity configured.
        return names + [name for name in ["anonymous"] if name not in names]

    def _orm_populate_identity_choices(self, owner: str, forbidden: str) -> None:
        choices = self._orm_identity_choices()
        for combo, current in ((self.orm_owner_combo, owner),
                               (self.orm_forbidden_combo, forbidden)):
            combo.blockSignals(True)
            combo.clear()
            items = choices if current else [""] + choices
            combo.addItems(items)
            if current:
                combo.setCurrentText(current)
            combo.blockSignals(False)

    def _orm_combo_value(self, combo: QComboBox) -> str:
        """The blank first item is "not configured" — the empty string the
        engine checks before it will run a canary."""
        return combo.currentText().strip()

    def _render_orm_depth(self, cfg: dict) -> None:
        """What the panel deliberately does not edit — and whether the proof
        path exists at all."""
        values = cfg.get("vector_values")
        values = [str(v) for v in values if str(v)] \
            if isinstance(values, list) else []
        self.orm_values_label.setText(
            f"Filter values: {', '.join(values[:6])}"
            + (f" (+{len(values) - 6})" if len(values) > 6 else "")
            if values else
            "Filter values: none — modules.orm_filter_audit.vector_values is "
            "empty, so no filter value is ever sent")
        self.orm_values_label.setProperty("tone", "ok" if values else "warn")

        names = cfg.get("filter_names")
        names = [str(n) for n in names if str(n)] \
            if isinstance(names, list) else []
        self.orm_names_label.setText(
            f"Parameter names: {len(names)} configured — "
            + ", ".join(names[:4]) if names else
            "Parameter names: engine defaults (q, search, owner_id, "
            "filter[owner_id], include, fields)")
        self.orm_names_label.setProperty("tone", "ok" if names else "warn")

        surfaces = cfg.get("surfaces")
        count = len(surfaces) if isinstance(surfaces, list) else 0
        self.orm_surfaces_label.setText(
            f"Explicit surfaces: {count} configured"
            if count else
            "Explicit surfaces: none — discovered from traffic capture and "
            "collection endpoints")
        self.orm_surfaces_label.setProperty("tone", "ok" if count else "warn")

        canary = cfg.get("canary")
        canary = canary if isinstance(canary, dict) else {}
        record = canary.get("record")
        record = record if isinstance(record, dict) else {}
        read = canary.get("read")
        read = read if isinstance(read, dict) else {}
        probes = canary.get("probes")
        probes = probes if isinstance(probes, list) else []
        spec_ready = bool(record.get("url_template"))
        detail = (f"{len(probes)} probe(s)" if probes else "no probes")
        self.orm_spec_label.setText(
            f"Seeded-record spec: create {record.get('method', 'POST')} "
            f"{record.get('url_template')} with {detail}"
            if spec_ready else
            "Seeded-record spec: canary.record.url_template is not set — "
            "nothing on this screen can reach PROOF")
        self.orm_spec_label.setProperty("tone", "ok" if spec_ready else "warn")

        root = (cfg.get("source_rules") or {}).get("root") \
            if isinstance(cfg.get("source_rules"), dict) else ""
        self.orm_root_label.setText(
            f"Source rules root: {root}" if root else
            "Source rules root: not set — the offline importer has nothing "
            "to read")
        self.orm_root_label.setProperty("tone", "ok" if root else "warn")

        owner = self._orm_combo_value(self.orm_owner_combo)
        forbidden = self._orm_combo_value(self.orm_forbidden_combo)
        direct = bool(read.get("direct_url_template"))
        if not owner or not forbidden or owner == forbidden:
            self.orm_identity_label.setText(
                "Owner / forbidden reader: not a usable pair — a canary needs "
                "two different identities")
            self.orm_identity_label.setProperty("tone", "warn")
        elif not direct:
            self.orm_identity_label.setText(
                f"Owner {owner} → reader {forbidden}: set, but "
                "canary.read.direct_url_template is missing, so the "
                "direct-read denial that makes a proof cannot be checked")
            self.orm_identity_label.setProperty("tone", "warn")
        else:
            self.orm_identity_label.setText(
                f"Owner {owner} → reader {forbidden}: direct read lane "
                "configured")
            self.orm_identity_label.setProperty("tone", "ok")
        for label in (self.orm_values_label, self.orm_names_label,
                      self.orm_surfaces_label, self.orm_spec_label,
                      self.orm_root_label, self.orm_identity_label):
            label.style().unpolish(label)
            label.style().polish(label)

    def _orm_proof_ready(self, section: dict | None = None) -> bool:
        """A proof needs the canary switch, a create template, a direct-read
        template, two different identities and at least one probe spec — all
        of them, or nothing here can ever leave CANDIDATE."""
        section = section if section is not None \
            else getattr(self, "_orm_section", {})
        return not self._orm_missing_proof_steps(section)

    def _orm_missing_proof_steps(self, section: dict | None = None) -> list[str]:
        """Named one by one, because "no proof path" on its own tells the
        operator nothing about which of the four gates they are missing."""
        section = section if section is not None \
            else getattr(self, "_orm_section", {})
        canary = section.get("canary")
        canary = canary if isinstance(canary, dict) else {}
        record = canary.get("record")
        record = record if isinstance(record, dict) else {}
        read = canary.get("read")
        read = read if isinstance(read, dict) else {}
        owner = self._orm_combo_value(self.orm_owner_combo)
        forbidden = self._orm_combo_value(self.orm_forbidden_combo)
        missing = []
        if not self.orm_canary_check.isChecked():
            missing.append("canary.enabled is off")
        if not record.get("url_template"):
            missing.append("canary.record.url_template")
        if not read.get("direct_url_template"):
            missing.append("canary.read.direct_url_template")
        if not owner or not forbidden or owner == forbidden:
            missing.append("two different identities")
        if not canary.get("probes"):
            missing.append("canary.probes")
        return missing

    def _update_orm_state_label(self, *_args):
        enabled = self.orm_enabled_check.isChecked()
        if not enabled:
            text, state = "module disabled", "idle"
        elif self._orm_proof_ready():
            text, state = "module enabled", "ok"
        else:
            # Enabled but with no seeded-record path: the strip has to say so,
            # or a screen full of candidates reads as "close to a proof".
            text, state = "module enabled · candidates only", "ok"
        self.orm_state_label.setText(text)
        self.orm_state_label.setProperty("state", state)
        self.orm_state_label.style().unpolish(self.orm_state_label)
        self.orm_state_label.style().polish(self.orm_state_label)
        # The depth labels read the combos and the canary switch, so they
        # refresh here instead of only on a config load.
        self._render_orm_depth(getattr(self, "_orm_section", {}))

    def _save_orm_plan(self) -> bool:
        owner = self._orm_combo_value(self.orm_owner_combo)
        forbidden = self._orm_combo_value(self.orm_forbidden_combo)
        if self.orm_canary_check.isChecked() and self.orm_canary_max_spin.value() \
                and owner and forbidden and owner == forbidden:
            QMessageBox.warning(
                self, "Same Identity Both Ways",
                "The canary owner and the forbidden reader are both "
                f"{owner!r}. The module would create a record and read it "
                "back as the same identity, which proves nothing — pick two "
                "different identities, or turn the canary off.",
            )
            return False
        config = self._read_config()
        section = self._ensure_module_section(config, ORM_MODULE_ID)
        section["enabled"] = self.orm_enabled_check.isChecked()
        section["max_surfaces"] = self.orm_max_surfaces_spin.value()
        section["max_payloads"] = self.orm_max_probes_spin.value()
        section["max_seconds"] = self.orm_max_seconds_spin.value()
        section["traffic_surfaces"] = self.orm_traffic_check.isChecked()
        section["augment_collections"] = self.orm_augment_check.isChecked()
        # Read-modify-write: root is nested and belongs to the operator's YAML.
        source_rules = section.get("source_rules")
        source_rules = source_rules if isinstance(source_rules, dict) else {}
        source_rules["enabled"] = self.orm_source_check.isChecked()
        section["source_rules"] = source_rules
        # Same here: record/read/cleanup/probes are the structured spec.
        canary = section.get("canary")
        canary = canary if isinstance(canary, dict) else {}
        canary["enabled"] = self.orm_canary_check.isChecked()
        canary["max"] = self.orm_canary_max_spin.value()
        if owner:
            canary["owner_identity"] = owner
        if forbidden:
            canary["forbidden_identity"] = forbidden
        section["canary"] = canary
        missing = self._orm_missing_proof_steps()
        caveat = ""
        if missing:
            caveat = (" — no proof path yet: " + "; ".join(missing)
                      + " (modules.orm_filter_audit in Raw YAML)")
        if not self._write_config(config):
            return False
        self._orm_section = section
        self._update_orm_state_label()
        self.statusBar().showMessage(
            f"ORM plan saved to {self.config_path.name}{caveat}", 9000)
        return True

    def _run_orm_pass(self):
        if self.process and self.process.state() != QProcess.NotRunning:
            self.statusBar().showMessage(
                "Already running — wait for the current process", 3000)
            return
        if not self.orm_enabled_check.isChecked():
            QMessageBox.warning(
                self, "Gate Off",
                "modules.orm_filter_audit.enabled is off, so the module skips "
                "itself before it touches the target. Tick the gate and save "
                "the plan first.",
            )
            return
        section = self._module_section(self._read_config(), ORM_MODULE_ID)
        raw_values = section.get("vector_values")
        values = [str(v) for v in raw_values if str(v)] \
            if isinstance(raw_values, list) else []
        canary_on = self.orm_canary_check.isChecked()
        absent = self._orm_missing_proof_steps(section) if canary_on else []
        if not values and (not canary_on or absent):
            # Only block when there is nothing to do at all: with no values
            # the candidate lane sends nothing, and with no usable canary
            # spec there is no proof lane either. A configured canary on its
            # own is still a real run.
            QMessageBox.warning(
                self, "Nothing To Send",
                "modules.orm_filter_audit.vector_values is empty, so the run "
                "would book surfaces and send no filter value to any of them, "
                "and there is no seeded canary to run instead. Set at least "
                "one filter value, or configure canary.record / canary.read / "
                "canary.probes under Raw YAML.",
            )
            return
        sources = " ".join(filter(None, (
            "traffic" if self.orm_traffic_check.isChecked() else "",
            "collections" if self.orm_augment_check.isChecked() else "",
            "source rules" if self.orm_source_check.isChecked() else "",
        ))) or "configured endpoints only"
        canary_line = "Canary: on" if canary_on else \
            "Canary: OFF — nothing on this screen can reach PROOF"
        if absent:
            canary_line += "\nNo proof path yet: " + "; ".join(absent)
        if not values:
            canary_line += ("\nCandidate probing: no vector_values, so every "
                            "surface will be reported untested — only the "
                            "canary runs.")
        answer = QMessageBox.question(
            self, "This Run Writes To The Target",
            "orm_filter_audit reads collections as one identity with filter "
            "values that name another, and — with the canary on — CREATES a "
            "record on the target, reads it back as somebody else, then "
            "deletes it. Every create is booked on the mutation ledger (R8) "
            "before it happens.\n\n"
            f"Plan: up to {self.orm_max_surfaces_spin.value()} surface(s), "
            f"{self.orm_max_probes_spin.value()} probe(s), "
            f"{self.orm_canary_max_spin.value()} seeded record(s), wall "
            f"budget {self.orm_max_seconds_spin.value()}s, surfaces from "
            f"{sources}.\n\n"
            f"{canary_line}\n\n"
            "Run it now?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            self.statusBar().showMessage("ORM run cancelled", 4000)
            return
        if not self._save_orm_plan():
            return
        if not self._select_single_module(ORM_MODULE_ID):
            QMessageBox.warning(
                self, "Module Unavailable",
                "orm_filter_audit is not in the module picker — check the "
                "stage filter on the run screen.",
            )
            return
        self.show_screen(self._screen_index("run"))
        self.start_scan()

    # ---- I5 ORM / filter leak screen --------------------------------------

    def _build_orm_screen(self) -> QWidget:
        """Screen 8: what was probed, what came back, and what was seeded."""
        page = QWidget()
        page.setObjectName("screenOrm")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        layout.addWidget(self._build_orm_strip())

        results = QWidget()
        results.setObjectName("ormResults")
        results.setMinimumWidth(0)
        results_layout = QVBoxLayout(results)
        results_layout.setContentsMargins(0, 0, 0, 0)
        results_layout.setSpacing(6)

        self.orm_tabs = QTabWidget()
        self.orm_tabs.setObjectName("ormViews")
        self.orm_tabs.addTab(self._build_orm_surfaces_tab(), "Filter surfaces")
        self.orm_tabs.addTab(self._build_orm_candidates_tab(),
                             "Cross-identity rows")
        self.orm_tabs.addTab(self._build_orm_canaries_tab(), "Seeded canaries")
        self.orm_tabs.addTab(self._build_orm_coverage_tab(), "Coverage")
        results_layout.addWidget(self.orm_tabs, 3)
        results_layout.addWidget(self._build_orm_detail(), 2)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setObjectName("ormSplitter")
        splitter.addWidget(self._build_orm_plan_panel())
        splitter.addWidget(results)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setCollapsible(0, False)
        splitter.setCollapsible(1, False)
        splitter.setSizes([340, 880])
        layout.addWidget(splitter, 1)
        return page

    def _build_orm_strip(self) -> QFrame:
        strip = QFrame()
        strip.setObjectName("ormStrip")
        layout = QVBoxLayout(strip)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(9)

        head = QHBoxLayout()
        head.setSpacing(8)
        caption = QLabel("I5 · ORM / FILTER LEAK")
        caption.setObjectName("ormCaption")
        self.orm_state_label = QLabel("module disabled")
        self.orm_state_label.setObjectName("ormState")
        self.orm_state_label.setProperty("state", "idle")
        self.orm_state_label.setToolTip(
            "modules.orm_filter_audit.enabled — the module skips while it is "
            "off because a canary seeds records on the target")
        self.orm_run_label = QLabel("no orm run loaded")
        self.orm_run_label.setObjectName("ormTool")
        self.orm_run_label.setWordWrap(True)
        self.orm_run_label.setMinimumWidth(0)
        head.addWidget(caption)
        head.addWidget(self.orm_state_label)
        head.addWidget(self.orm_run_label, 1)
        layout.addLayout(head)

        self.orm_planned_value = QLabel("-")
        self.orm_probed_value = QLabel("-")
        self.orm_candidates_value = QLabel("-")
        self.orm_proofs_value = QLabel("-")
        self.orm_cleanup_value = QLabel("-")
        self.orm_gap_value = QLabel("-")
        cards = [
            ("Surfaces planned", self.orm_planned_value, "info"),
            ("Surfaces probed", self.orm_probed_value, "info"),
            ("Cross-identity rows", self.orm_candidates_value, "warning"),
            ("Canary proofs", self.orm_proofs_value, "success"),
            ("Cleanup to check", self.orm_cleanup_value, "warning"),
            ("Not tested", self.orm_gap_value, "warning"),
        ]
        grid = QGridLayout()
        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(8)
        for index, (label, value_label, tone) in enumerate(cards):
            grid.addWidget(self._metric_card(label, value_label, tone),
                           index // 3, index % 3)
        layout.addLayout(grid)

        self.orm_legend_label = QLabel(
            "<span style='color:#5b7181'>●</span> HEALTHY — driven and clean: "
            "no cross-identity rows through the filter, or a seeded record "
            "that stayed private with verified cleanup &nbsp;·&nbsp; "
            "<span style='color:#93c5fd'>●</span> OBSERVATION — a canary ran "
            "but is not a clean negative: a prerequisite failed or its cleanup "
            "is unverified &nbsp;·&nbsp; "
            "<span style='color:#fdba74'>●</span> CANDIDATE — a filter value "
            "returned rows attributable to another identity "
            "&nbsp;·&nbsp; "
            "<span style='color:#4ade80'>●</span> PROOF — a record seeded for "
            "its owner came back through the filter to an identity whose "
            "direct read was denied, and cleanup was verified &nbsp;·&nbsp; "
            "<span style='color:#5b7181'>–</span> no tier — planned but never "
            "driven, so it says nothing about the target (see Coverage)"
        )
        self.orm_legend_label.setObjectName("ormLegend")
        self.orm_legend_label.setTextFormat(Qt.RichText)
        self.orm_legend_label.setWordWrap(True)
        layout.addWidget(self.orm_legend_label)
        return strip

    def _orm_table(self, headers: list, stretch: tuple = ()) -> QTableWidget:
        """One read-only table that selects whole rows.

        The four ORM tables differ only in headers, so the boilerplate lives
        here once instead of four times.
        """
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        header = table.horizontalHeader()
        for column in range(len(headers)):
            header.setSectionResizeMode(
                column,
                QHeaderView.Stretch if column in stretch
                else QHeaderView.ResizeToContents)
        header.setStretchLastSection(False)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setSortingEnabled(False)
        table.verticalHeader().setVisible(False)
        return table

    def _build_orm_surfaces_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 6, 0, 0)
        layout.setSpacing(6)

        bar = QWidget()
        row = QHBoxLayout(bar)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(6)
        self.orm_search = QLineEdit()
        self.orm_search.setPlaceholderText(
            "Filter surface, parameter, vector, source or identity")
        self.orm_search.setClearButtonEnabled(True)
        self.orm_search.setMinimumWidth(0)
        self.orm_tier_combo = QComboBox()
        self.orm_tier_combo.setObjectName("filterCombo")
        self.orm_tier_combo.addItems(["All tiers"] + list(ORM_TIERS))
        self.orm_count_label = QLabel("0 of 0")
        self.orm_count_label.setObjectName("opsSecondary")
        reset_button = QPushButton("Reset")
        reset_button.setObjectName("btnGhost")
        reset_button.clicked.connect(self._reset_orm_filter)
        self.orm_search.textChanged.connect(self._render_orm_surfaces)
        self.orm_tier_combo.currentIndexChanged.connect(
            self._render_orm_surfaces)
        row.addWidget(self.orm_search, 1)
        row.addWidget(self.orm_tier_combo)
        row.addWidget(reset_button)
        row.addWidget(self.orm_count_label)
        layout.addWidget(bar)

        self.orm_surfaces_table = self._orm_table(
            ["Tier", "Surface", "Param", "Vector", "Source", "Probed as",
             "Outcome"], stretch=(1,))
        self.orm_surfaces_table.currentCellChanged.connect(
            self._on_orm_surface_changed)
        layout.addWidget(self.orm_surfaces_table, 1)
        return page

    def _reset_orm_filter(self):
        self.orm_search.clear()
        self.orm_tier_combo.setCurrentIndex(0)

    def _build_orm_candidates_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 6, 0, 0)
        layout.setSpacing(6)
        note = QLabel(
            "Rows that belong to another identity came back through a filter "
            "value. This tier never exceeds candidate: the module stores "
            "marker counts, not values, so a seeded canary is what confirms "
            "or clears it.")
        note.setObjectName("ormWarning")
        note.setWordWrap(True)
        layout.addWidget(note)
        self.orm_candidates_table = self._orm_table(
            ["Surface", "Param", "Probed as", "Rows returned",
             "Markers attributed", "Note"], stretch=(0,))
        self.orm_candidates_table.currentCellChanged.connect(
            self._on_orm_candidate_changed)
        layout.addWidget(self.orm_candidates_table, 1)
        return page

    def _build_orm_canaries_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 6, 0, 0)
        layout.setSpacing(6)
        note = QLabel(
            "The seeded-record protocol: create as the owner, confirm the "
            "forbidden identity is denied the direct read, then try to reach "
            "the same record through a filter. A proof needs all of that, plus "
            "a verified cleanup of the record this pass created.")
        note.setObjectName("ormWarning")
        note.setWordWrap(True)
        layout.addWidget(note)
        self.orm_canaries_table = self._orm_table(
            ["Tier", "Canary", "Owner → reader", "Param", "Direct read",
             "Controls", "Owner positive", "Cleanup"], stretch=(1,))
        self.orm_canaries_table.currentCellChanged.connect(
            self._on_orm_canary_changed)
        layout.addWidget(self.orm_canaries_table, 1)
        return page

    def _build_orm_coverage_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 6, 0, 0)
        layout.setSpacing(6)
        note = QLabel(
            "Surfaces and lanes the last run did not drive. A screen with no "
            "rows here and no rows above means nothing was tested, not that "
            "the target is clean.")
        note.setObjectName("ormWarning")
        note.setWordWrap(True)
        layout.addWidget(note)
        self.orm_gap_table = self._orm_table(["Surface", "Why"], stretch=(0,))
        self.orm_gap_table.currentCellChanged.connect(
            self._on_orm_gap_changed)
        self.orm_gap_note = QLabel(
            "no ORM run loaded — nothing has been tested yet")
        self.orm_gap_note.setObjectName("ormProofState")
        self.orm_gap_note.setProperty("tone", "ok")
        self.orm_gap_note.setWordWrap(True)
        layout.addWidget(self.orm_gap_note)
        layout.addWidget(self.orm_gap_table, 1)
        return page

    def _build_orm_plan_panel(self) -> QWidget:
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

        gate_box = QGroupBox("Seeding gate")
        gate_layout = QVBoxLayout(gate_box)
        gate_layout.setSpacing(6)
        self.orm_enabled_check = QCheckBox(
            "ORM / filter leak audit (orm_filter_audit)")
        self.orm_enabled_check.setToolTip("modules.orm_filter_audit.enabled")
        self.orm_enabled_check.toggled.connect(self._update_orm_state_label)
        gate_layout.addWidget(self.orm_enabled_check)
        gate_warning = QLabel(
            "Unlike the read-only screens, this one writes: a canary creates a "
            "record on the target, reads it back as somebody else, then "
            "deletes it. Every create is booked on the mutation ledger (R8) "
            "before it happens and cleanup is verified by a fresh read.")
        gate_warning.setObjectName("ormWarning")
        gate_warning.setWordWrap(True)
        gate_layout.addWidget(gate_warning)
        layout.addWidget(gate_box)

        plan_box = QGroupBox("Run plan")
        plan_form = QFormLayout(plan_box)
        plan_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.orm_max_surfaces_spin = QSpinBox()
        self.orm_max_surfaces_spin.setRange(1, 50)
        self.orm_max_surfaces_spin.setValue(8)
        self.orm_max_surfaces_spin.setToolTip(
            "modules.orm_filter_audit.max_surfaces — filter surfaces probed "
            "per run; anything past the cap is reported as untested")
        self.orm_max_probes_spin = QSpinBox()
        self.orm_max_probes_spin.setRange(1, 100)
        self.orm_max_probes_spin.setValue(12)
        self.orm_max_probes_spin.setToolTip(
            "modules.orm_filter_audit.max_payloads — candidate probes per run, "
            "shared across surfaces")
        self.orm_max_seconds_spin = QSpinBox()
        self.orm_max_seconds_spin.setRange(30, 1800)
        self.orm_max_seconds_spin.setSingleStep(30)
        self.orm_max_seconds_spin.setValue(300)
        self.orm_max_seconds_spin.setToolTip(
            "modules.orm_filter_audit.max_seconds — wall budget; the run stops "
            "early and names what it never reached")
        self.orm_canary_max_spin = QSpinBox()
        self.orm_canary_max_spin.setRange(0, 10)
        self.orm_canary_max_spin.setValue(2)
        self.orm_canary_max_spin.setToolTip(
            "modules.orm_filter_audit.canary.max — seeded records created on "
            "the target per run")
        plan_form.addRow("Max surfaces", self.orm_max_surfaces_spin)
        plan_form.addRow("Max probes", self.orm_max_probes_spin)
        plan_form.addRow("Wall budget (s)", self.orm_max_seconds_spin)
        plan_form.addRow("Seeds per run", self.orm_canary_max_spin)
        layout.addWidget(plan_box)

        source_box = QGroupBox("Where surfaces come from")
        source_layout = QVBoxLayout(source_box)
        source_layout.setSpacing(6)
        self.orm_traffic_check = QCheckBox("Mine captured traffic")
        self.orm_traffic_check.setToolTip(
            "modules.orm_filter_audit.traffic_surfaces — needs a browser "
            "capture pass first")
        self.orm_augment_check = QCheckBox("Try default names on collections")
        self.orm_augment_check.setToolTip(
            "modules.orm_filter_audit.augment_collections — applies "
            "filter_names to collection endpoints")
        self.orm_source_check = QCheckBox("Offline framework source rules")
        self.orm_source_check.setToolTip(
            "modules.orm_filter_audit.source_rules.enabled — reads a "
            "directory the operator supplied; never fetches source")
        for widget in (self.orm_traffic_check, self.orm_augment_check,
                       self.orm_source_check):
            widget.toggled.connect(self._update_orm_state_label)
            source_layout.addWidget(widget)
        layout.addWidget(source_box)

        canary_box = QGroupBox("Seeded canary (the only path to PROOF)")
        canary_form = QFormLayout(canary_box)
        canary_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.orm_canary_check = QCheckBox("Run canaries")
        self.orm_canary_check.setToolTip(
            "modules.orm_filter_audit.canary.enabled — off means this screen "
            "can only ever show candidates")
        self.orm_canary_check.toggled.connect(self._update_orm_state_label)
        self.orm_owner_combo = QComboBox()
        self.orm_owner_combo.setObjectName("ormIdentity")
        self.orm_owner_combo.setToolTip(
            "modules.orm_filter_audit.canary.owner_identity — the identity "
            "that creates the record")
        self.orm_forbidden_combo = QComboBox()
        self.orm_forbidden_combo.setObjectName("ormIdentity")
        self.orm_forbidden_combo.setToolTip(
            "modules.orm_filter_audit.canary.forbidden_identity — the identity "
            "that must be denied the direct read and still reach it through "
            "the filter")
        for combo in (self.orm_owner_combo, self.orm_forbidden_combo):
            combo.currentIndexChanged.connect(self._update_orm_state_label)
        canary_form.addRow(self.orm_canary_check)
        canary_form.addRow("Owner", self.orm_owner_combo)
        canary_form.addRow("Forbidden reader", self.orm_forbidden_combo)
        layout.addWidget(canary_box)

        depth_box = QGroupBox("Configured depth")
        depth_layout = QVBoxLayout(depth_box)
        depth_layout.setSpacing(6)
        self.orm_values_label = QLabel("-")
        self.orm_names_label = QLabel("-")
        self.orm_surfaces_label = QLabel("-")
        self.orm_spec_label = QLabel("-")
        self.orm_root_label = QLabel("-")
        self.orm_identity_label = QLabel("-")
        for widget in (self.orm_values_label, self.orm_names_label,
                       self.orm_surfaces_label, self.orm_spec_label,
                       self.orm_root_label, self.orm_identity_label):
            widget.setObjectName("ormProofState")
            widget.setWordWrap(True)
            widget.setTextInteractionFlags(Qt.TextSelectableByMouse)
            depth_layout.addWidget(widget)
        depth_hint = QLabel(
            "Filter values, parameter names, surfaces and the seeded-record "
            "templates are structured YAML — edit them on the Raw YAML screen.")
        depth_hint.setObjectName("ormWarning")
        depth_hint.setWordWrap(True)
        depth_layout.addWidget(depth_hint)
        layout.addWidget(depth_box)

        actions_box = QGroupBox("Actions")
        actions_layout = QVBoxLayout(actions_box)
        actions_layout.setSpacing(6)
        self.orm_save_button = QPushButton("Save ORM plan")
        self.orm_save_button.setObjectName("btnPrimary")
        self.orm_save_button.clicked.connect(self._save_orm_plan)
        actions_layout.addWidget(self.orm_save_button)
        self.orm_run_button = QPushButton("Run ORM audit")
        self.orm_run_button.setObjectName("btnDanger")
        self.orm_run_button.clicked.connect(self._run_orm_pass)
        actions_layout.addWidget(self.orm_run_button)
        settings_button = QPushButton("Open seeded-record spec")
        settings_button.setObjectName("btnGhost")
        settings_button.setToolTip(
            "Jump to Raw YAML for filter values, surfaces and the "
            "create/read/cleanup templates")
        settings_button.clicked.connect(self._open_raw_settings)
        actions_layout.addWidget(settings_button)
        layout.addWidget(actions_box)
        layout.addStretch(1)

        outer.addWidget(scroll)
        return panel

    def _build_orm_detail(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("ormDetail")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(8)

        head = QHBoxLayout()
        head.setSpacing(8)
        self.orm_detail_title = QLabel("No surface selected")
        self.orm_detail_title.setObjectName("ormDetailTitle")
        self.orm_detail_title.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.orm_open_evidence_button = QPushButton("Open evidence")
        self.orm_open_evidence_button.setObjectName("btnGhost")
        self.orm_open_evidence_button.setEnabled(False)
        self.orm_open_evidence_button.clicked.connect(
            self._open_orm_evidence)
        self.orm_open_finding_button = QPushButton("Open in Triage")
        self.orm_open_finding_button.setObjectName("btnGhost")
        self.orm_open_finding_button.setEnabled(False)
        self.orm_open_finding_button.clicked.connect(self._open_orm_finding)
        head.addWidget(self.orm_detail_title, 1)
        head.addWidget(self.orm_open_evidence_button)
        head.addWidget(self.orm_open_finding_button)
        layout.addLayout(head)

        self.orm_detail_body = QTextEdit()
        self.orm_detail_body.setReadOnly(True)
        self.orm_detail_body.setObjectName("ormDetailBody")
        self.orm_detail_body.setFont(code_font(12))
        self.orm_detail_body.setPlaceholderText(
            "Select a row to see what was asked, what came back, and what "
            "that does — and does not — prove.")
        layout.addWidget(self.orm_detail_body, 1)
        return frame

    @staticmethod
    def _format_elapsed(seconds: float) -> str:
        total = int(max(0, seconds))
        return f"{total // 60:02d}:{total % 60:02d}"

    def _load_settings_form(self):
        config = self._read_config()
        llm = config.get("llm", {})
        if hasattr(self, "llm_model_combo"):
            self.llm_model_combo.setCurrentText(str(llm.get("model", "")))
            self.llm_api_key_input.setText(str(llm.get("api_key", "")))
            self.llm_temperature_spin.setValue(float(llm.get("temperature", 0.1) or 0.1))
            self.llm_max_tokens_spin.setValue(int(llm.get("max_tokens", 2000) or 2000))

        target = config.get("target", {})
        if hasattr(self, "config_target_domain_input"):
            self.config_target_domain_input.setText(str(target.get("domain", "")))
            self._set_combo_value(self.config_mode_combo, str(target.get("mode", "passive")))

        tools_cfg = config.get("tools", {}) if isinstance(config.get("tools"), dict) else {}
        if hasattr(self, "tools_backend_combo"):
            backend = str(tools_cfg.get("backend", "local") or "local").strip().lower()
            index = self.tools_backend_combo.findText(backend)
            self.tools_backend_combo.setCurrentIndex(index if index >= 0 else 0)
            self.tools_image_input.setText(str(tools_cfg.get("image", "") or ""))

        detectability = config.get("detectability", {})
        if hasattr(self, "config_default_detectability_combo"):
            self._set_combo_value(
                self.config_default_detectability_combo,
                str(detectability.get("default", "low")),
            )

        modules = config.get("modules", {})
        if hasattr(self, "config_auto_run_check"):
            self.config_auto_run_check.setChecked(bool(modules.get("auto_run", True)))
            self.config_record_http_evidence_check.setChecked(bool(modules.get("record_http_evidence", True)))
            self.config_max_empty_spin.setValue(int(modules.get("max_consecutive_empty", 5) or 0))

        if hasattr(self, "module_timeout_spin"):
            self.module_timeout_spin.setValue(int(config.get("module_timeout", 300) or 300))
            budget = config.get("budget_limits") or {}
            self.budget_requests_spin.setValue(int(budget.get("max_requests", 0) or 0))
            self.budget_wall_clock_spin.setValue(int(budget.get("max_wall_clock_seconds", 0) or 0))
            self.budget_llm_spin.setValue(int(budget.get("max_llm_calls", 0) or 0))
            self.budget_external_commands_spin.setValue(int(
                budget.get("max_external_commands", 0) or 0))

        rate_limits = config.get("rate_limits", {})
        if hasattr(self, "rate_limit_inputs"):
            for name, fields in self.rate_limit_inputs.items():
                values = rate_limits.get(name, {})
                fields["concurrent"].setValue(int(values.get("concurrent", 1) or 1))
                fields["per_minute"].setValue(int(values.get("per_minute", 60) or 60))

        api_keys = config.get("api_keys", {})
        if hasattr(self, "api_key_inputs"):
            for service, key_input in self.api_key_inputs.items():
                key_input.setText(str(api_keys.get(service, "")))

        auth = config.get("auth", {})
        if hasattr(self, "auth_bearer_input"):
            self.auth_bearer_input.setText(str(auth.get("bearer_token", "")))
            self.auth_cookie_input.setText(str(auth.get("cookie", "")))
            self.auth_headers_input.setPlainText(self._headers_to_text(auth.get("headers", {})))
            self.auth_probe_backoff_spin.setValue(int(auth.get("probe_backoff_seconds", 10) or 0))

        if hasattr(self, "identities_table"):
            entries = auth.get("identities") or []
            if isinstance(entries, dict):
                entries = [
                    {"name": key, **value}
                    for key, value in entries.items()
                    if isinstance(value, dict)
                ]
            self._identity_records = [
                dict(entry) for entry in entries if isinstance(entry, dict)
            ]
            self._refresh_identities_table()

        if hasattr(self, "schema_enabled_check"):
            self._apply_schema_plan(
                self._module_section(config, "api_workflows"))
            self._update_schema_state_label()

        if hasattr(self, "authz_gate_checks"):
            self._apply_authz_plan(config)

        if hasattr(self, "cspt_enabled_check"):
            self._apply_cspt_plan(config)

        if hasattr(self, "orm_enabled_check"):
            self._apply_orm_plan(config)

        xss = self._module_section(config, "xss_scan")
        if hasattr(self, "xss_browser_confirm_check"):
            self.xss_browser_confirm_check.setChecked(bool(xss.get("browser_confirm", True)))
            self.xss_max_points_spin.setValue(int(xss.get("max_points", 80) or 80))
            self.xss_dalfox_timeout_spin.setValue(int(xss.get("dalfox_timeout", 600) or 600))
            if hasattr(self, "xss_dalfox_blind_oob_check"):
                self.xss_dalfox_blind_oob_check.setChecked(bool(xss.get("dalfox_blind_oob", False)))
                try:
                    self.xss_dalfox_rate_spin.setValue(int(xss.get("dalfox_rate_limit", 0) or 0))
                except (TypeError, ValueError):
                    self.xss_dalfox_rate_spin.setValue(0)

        nuclei = self._module_section(config, "nuclei_scan")
        if hasattr(self, "nuclei_full_cve_check"):
            self.nuclei_full_cve_check.setChecked(bool(nuclei.get("full_cve_on_confirmed_apex", True)))
            if hasattr(self, "nuclei_update_check"):
                self.nuclei_update_check.setChecked(bool(nuclei.get("update_templates", False)))
                try:
                    self.nuclei_max_age_spin.setValue(int(nuclei.get("max_age_days", 30) or 30))
                except (TypeError, ValueError):
                    self.nuclei_max_age_spin.setValue(30)
            if hasattr(self, "nuclei_batch_seconds_spin"):
                try:
                    self.nuclei_batch_seconds_spin.setValue(int(nuclei.get("batch_seconds", 150) or 150))
                except (TypeError, ValueError):
                    self.nuclei_batch_seconds_spin.setValue(150)
                try:
                    self.nuclei_max_seconds_spin.setValue(int(nuclei.get("max_seconds") or 0))
                except (TypeError, ValueError):
                    self.nuclei_max_seconds_spin.setValue(0)

        kr_cfg = ((config.get("modules", {}) or {}).get("content_discovery", {})
                  or {}).get("kiterunner", {})
        kr_cfg = kr_cfg if isinstance(kr_cfg, dict) else {}
        if hasattr(self, "kr_enabled_check"):
            self.kr_enabled_check.setChecked(bool(kr_cfg.get("enabled", True)))
            self.kr_wordlist_input.setText(str(kr_cfg.get("wordlist", "") or ""))
            try:
                self.kr_max_routes_spin.setValue(int(kr_cfg.get("max_routes", 1500) or 1500))
            except (TypeError, ValueError):
                self.kr_max_routes_spin.setValue(1500)
            try:
                self.kr_max_targets_spin.setValue(int(kr_cfg.get("max_targets", 2) or 2))
            except (TypeError, ValueError):
                self.kr_max_targets_spin.setValue(2)
            if hasattr(self, "kr_delay_spin"):
                try:
                    self.kr_delay_spin.setValue(int(kr_cfg.get("delay_ms", 100) or 0))
                except (TypeError, ValueError):
                    self.kr_delay_spin.setValue(100)
                try:
                    self.kr_connections_spin.setValue(int(kr_cfg.get("connections", 3) or 3))
                except (TypeError, ValueError):
                    self.kr_connections_spin.setValue(3)

        sast_cfg = config.get("semgrep", {})
        sast_cfg = sast_cfg if isinstance(sast_cfg, dict) else {}
        if hasattr(self, "semgrep_enabled_check"):
            self.semgrep_enabled_check.setChecked(bool(sast_cfg.get("enabled", True)))
            self.semgrep_rules_input.setText(str(sast_cfg.get("rules", "") or ""))

        ssrf_cfg = ((config.get("modules", {}) or {}).get("ssrf_scan", {})
                    or {})
        ssrf_cfg = ssrf_cfg if isinstance(ssrf_cfg, dict) else {}
        if hasattr(self, "ssrf_enabled_check"):
            self.ssrf_enabled_check.setChecked(bool(ssrf_cfg.get("enabled", True)))
            try:
                self.ssrf_max_points_spin.setValue(int(ssrf_cfg.get("max_points", 6) or 6))
            except (TypeError, ValueError):
                self.ssrf_max_points_spin.setValue(6)

        crawl_cfg = ((config.get("crawl", {}) or {}).get("browser", {}) or {})
        crawl_cfg = crawl_cfg if isinstance(crawl_cfg, dict) else {}
        if hasattr(self, "crawl_enabled_check"):
            self.crawl_enabled_check.setChecked(bool(crawl_cfg.get("enabled", True)))
            for widget, key, default in (
                    (self.crawl_max_pages_spin, "max_targets", 8),
                    (self.crawl_depth_spin, "depth", 1),
                    (self.crawl_max_identities_spin, "max_identities", 2),
                    (self.crawl_wait_ms_spin, "wait_ms", 1500)):
                try:
                    widget.setValue(int(crawl_cfg.get(key, default) or default))
                except (TypeError, ValueError):
                    widget.setValue(default)

        logic_cfg = ((config.get("modules", {}) or {}).get("business_logic", {})
                     or {})
        logic_cfg = logic_cfg if isinstance(logic_cfg, dict) else {}
        if hasattr(self, "logic_enabled_check"):
            self.logic_enabled_check.setChecked(bool(logic_cfg.get("enabled", True)))
            try:
                self.logic_max_probes_spin.setValue(int(logic_cfg.get("max_probes", 12) or 12))
            except (TypeError, ValueError):
                self.logic_max_probes_spin.setValue(12)
            if hasattr(self, "logic_endpoints_text"):
                self.logic_endpoints_text.setPlainText(self._list_to_text(logic_cfg.get("endpoints", [])))

        if hasattr(self, "idor_endpoints_text"):
            idor_cfg = self._module_section(config, "idor_differ")
            self.idor_endpoints_text.setPlainText(self._list_to_text(idor_cfg.get("endpoints", [])))
            self._note_spin_clamp(self._set_spin(self.idor_max_probes_spin, idor_cfg.get("max_probes_per_template"), 15), "idor max_probes_per_template")
            obj_probe = idor_cfg.get("object_probe", {})
            obj_probe = obj_probe if isinstance(obj_probe, dict) else {}
            self.idor_object_probe_check.setChecked(bool(obj_probe.get("enabled", True)))
            self.idor_probe_collections_check.setChecked(bool(idor_cfg.get("probe_collections", True)))
            self._note_spin_clamp(self._set_spin(self.idor_max_collections_spin, idor_cfg.get("max_collections"), 60), "idor max_collections")
            self.idor_test_anonymous_check.setChecked(bool(idor_cfg.get("test_anonymous", False)))
            methods = idor_cfg.get("test_write_methods", [])
            self.idor_write_methods_text.setText(", ".join(str(m) for m in (methods or [])))
            self.idor_allow_destructive_check.setChecked(bool(idor_cfg.get("allow_destructive", False)))
            id_probing = idor_cfg.get("id_probing", {})
            id_probing = id_probing if isinstance(id_probing, dict) else {}
            self.idor_id_probing_check.setChecked(bool(id_probing.get("enabled", False)))
            if hasattr(self, "idor_probe_radius_spin"):
                try:
                    self.idor_probe_radius_spin.setValue(int(id_probing.get("radius", 3) or 3))
                except (TypeError, ValueError):
                    self.idor_probe_radius_spin.setValue(3)
                try:
                    self.idor_probe_max_spin.setValue(int(id_probing.get("max", 20) or 20))
                except (TypeError, ValueError):
                    self.idor_probe_max_spin.setValue(20)
                self._note_spin_clamp(self._set_spin(self.idor_refs_spin, obj_probe.get("max_refs"), 12), "idor object_probe.max_refs")
                self._note_spin_clamp(self._set_spin(self.idor_fetches_spin, obj_probe.get("max_fetches"), 24), "idor object_probe.max_fetches")
                self._note_spin_clamp(self._set_spin(self.idor_total_fetches_spin, obj_probe.get("max_total_fetches"), 240), "idor object_probe.max_total_fetches")
                self._note_spin_clamp(self._set_spin(self.idor_misses_spin, obj_probe.get("stop_after_misses"), 6), "idor object_probe.stop_after_misses")
                self.idor_collection_paths_text.setPlainText(self._list_to_text(idor_cfg.get("collection_paths", [])))
                prefixes = idor_cfg.get("api_prefixes", [])
                self.idor_api_prefixes_text.setText(", ".join(str(p) for p in (prefixes or [])))
                self.idor_account_endpoint_text.setText(str(idor_cfg.get("account_endpoint", "") or ""))
                self.idor_resources_text.setPlainText(self._list_to_text(idor_cfg.get("resources", [])))

        if hasattr(self, "mass_enabled_check"):
            mass_cfg = self._module_section(config, "mass_assignment")
            self.mass_enabled_check.setChecked(bool(mass_cfg.get("enabled", False)))
            self.mass_endpoints_text.setPlainText(self._list_to_text(mass_cfg.get("endpoints", [])))
            self.mass_write_endpoint_input.setText(str(mass_cfg.get("write_endpoint", "") or ""))
            self._set_combo_value(self.mass_method_combo, str(mass_cfg.get("method", "PATCH") or "PATCH"))
            fields = mass_cfg.get("fields", [])
            self.mass_fields_text.setText(", ".join(str(f) for f in (fields or [])))
            self._set_combo_value(self.mass_probe_type_combo, str(mass_cfg.get("probe_type", "bool") or "bool"))

        if hasattr(self, "proto_enabled_check"):
            proto_cfg = self._module_section(config, "prototype_pollution")
            self.proto_enabled_check.setChecked(bool(proto_cfg.get("enabled", True)))
            self.proto_endpoints_text.setPlainText(self._list_to_text(proto_cfg.get("endpoints", [])))
            if hasattr(self, "proto_reflect_input"):
                self.proto_reflect_input.setText(str(proto_cfg.get("reflect_endpoint", "") or ""))
                methods = proto_cfg.get("methods", [])
                self.proto_methods_text.setText(", ".join(str(m) for m in (methods or [])))
                self.proto_payloads_text.setPlainText(self._list_to_text(proto_cfg.get("payloads", [])))

        if hasattr(self, "misconfig_timeout_spin"):
            mis_cfg = self._module_section(config, "misconfig_probes")
            for widget, key, default in (
                    (self.misconfig_timeout_spin, "timeout", 5),
                    (self.misconfig_concurrency_spin, "concurrency", 12),
                    (self.misconfig_max_paths_spin, "max_paths", 160),
                    (self.misconfig_max_empty_spin, "max_consecutive_empty", 60),
                    (self.misconfig_progress_spin, "progress_every", 25)):
                try:
                    widget.setValue(int(mis_cfg.get(key, default) or default))
                except (TypeError, ValueError):
                    widget.setValue(default)

        if hasattr(self, "ssti_max_points_spin"):
            ssti_cfg = self._module_section(config, "ssti_scan")
            nosql_cfg = self._module_section(config, "nosql_scan")
            dom_cfg = self._module_section(config, "dom_xss_scan")
            param_cfg = self._module_section(config, "parameter_discovery")
            try:
                self.ssti_max_points_spin.setValue(int(ssti_cfg.get("max_points", 40) or 40))
            except (TypeError, ValueError):
                self.ssti_max_points_spin.setValue(40)
            try:
                self.nosql_max_points_spin.setValue(int(nosql_cfg.get("max_points", 40) or 40))
            except (TypeError, ValueError):
                self.nosql_max_points_spin.setValue(40)
            try:
                self.dom_max_pages_spin.setValue(int(dom_cfg.get("max_pages", 25) or 25))
            except (TypeError, ValueError):
                self.dom_max_pages_spin.setValue(25)
            self.param_seed_check.setChecked(bool(param_cfg.get("seed_when_empty", True)))
            try:
                self.param_seed_targets_spin.setValue(int(param_cfg.get("seed_targets", 10) or 10))
            except (TypeError, ValueError):
                self.param_seed_targets_spin.setValue(10)
            seed_params = param_cfg.get("seed_params", [])
            self.param_seed_params_text.setText(", ".join(str(p) for p in (seed_params or [])))

        if hasattr(self, "smuggling_enabled_check"):
            smuggling_cfg = self._module_section(config, "http_smuggling")
            self.smuggling_enabled_check.setChecked(bool(smuggling_cfg.get("enabled", True)))
            self._note_spin_clamp(self._set_spin(self.smuggling_max_targets_spin, smuggling_cfg.get("max_targets"), 10), "http_smuggling max_targets")

        if hasattr(self, "redirect_enabled_check"):
            redirect_cfg = self._module_section(config, "open_redirect")
            self.redirect_enabled_check.setChecked(bool(redirect_cfg.get("enabled", True)))
            params = redirect_cfg.get("params", [])
            self.redirect_params_text.setText(", ".join(str(p) for p in (params or [])))
            self.redirect_endpoints_text.setPlainText(self._list_to_text(redirect_cfg.get("endpoints", [])))
            self._note_spin_clamp(self._set_spin(self.redirect_max_targets_spin, redirect_cfg.get("max_targets"), 40), "open_redirect max_targets")

        if hasattr(self, "cms_enabled_check"):
            cms_cfg = self._module_section(config, "cms_deep_scan")
            self.cms_enabled_check.setChecked(bool(cms_cfg.get("enabled", True)))
            self._note_spin_clamp(self._set_spin(self.cms_max_targets_spin, cms_cfg.get("max_targets"), 5), "cms max_targets")

        if hasattr(self, "content_enabled_check"):
            content_cfg = self._module_section(config, "content_discovery")
            self.content_enabled_check.setChecked(bool(content_cfg.get("enabled", True)))

        if hasattr(self, "cors_enabled_check"):
            cors_cfg = self._module_section(config, "cors_audit")
            self.cors_enabled_check.setChecked(bool(cors_cfg.get("enabled", True)))
            self.cors_endpoints_text.setPlainText(self._list_to_text(cors_cfg.get("endpoints", [])))
            self._note_spin_clamp(self._set_spin(self.cors_max_endpoints_spin, cors_cfg.get("max_endpoints"), 20), "cors max_endpoints")

        if hasattr(self, "auth_test_password_check"):
            auth_cfg = self._module_section(config, "auth_audit")
            self.auth_test_password_check.setChecked(bool(auth_cfg.get("test_password_change", False)))
            self.auth_test_register_check.setChecked(bool(auth_cfg.get("test_registration_oracle", False)))

        sqli_scan = config.get("modules", {}).get("sqli_scan", {})
        if hasattr(self, "sqli_oast_check") and isinstance(sqli_scan, dict):
            self.sqli_oast_check.setChecked(bool(sqli_scan.get("oast", True)))

        fast_scan = self._module_section(config, "fast_exposure_scan")
        if hasattr(self, "fast_scan_paths_input"):
            self.fast_scan_paths_input.setPlainText(self._list_to_text(fast_scan.get("paths", [])))
            self.fast_scan_timeout_spin.setValue(int(fast_scan.get("timeout", 4) or 4))
            self.fast_scan_concurrency_spin.setValue(int(fast_scan.get("concurrency", 8) or 8))
            self.fast_scan_max_paths_spin.setValue(int(fast_scan.get("max_paths", 20) or 20))

        oob = config.get("oob", {})
        if hasattr(self, "oob_callback_domain_input"):
            if hasattr(self, "oob_mode_combo"):
                mode_index = self.oob_mode_combo.findData(str(oob.get("mode", "") or ""))
                self.oob_mode_combo.setCurrentIndex(mode_index if mode_index >= 0 else 0)
            if hasattr(self, "oob_enabled_check"):
                # Absent key means enabled (engine default); only an
                # explicit false disables.
                self.oob_enabled_check.setChecked(bool(oob.get("enabled", True)))
            self.oob_callback_domain_input.setText(str(oob.get("callback_domain", "")))
            self.oob_server_url_input.setText(str(oob.get("server_url", "")))
            self.oob_poll_url_input.setText(str(oob.get("poll_url", "")))
            self.oob_token_input.setText(str(oob.get("token", "")))
            self.oob_poll_interval_spin.setValue(int(oob.get("poll_interval", 2) or 2))
            self.oob_poll_timeout_spin.setValue(int(oob.get("poll_timeout", 30) or 30))

        self._load_raw_config_editor()
        self._load_tools_requirements_preview()
        self._refresh_key_status()
        self._refresh_tools_status()
        self._update_operation_context()
        self._report_spin_clamps()

    def _save_settings_form(self):
        config = self._read_config()

        if hasattr(self, "llm_model_combo"):
            config.setdefault("llm", {})
            config["llm"].update({
                "model": self.llm_model_combo.currentText().strip(),
                "api_key": self.llm_api_key_input.text().strip(),
                "temperature": self.llm_temperature_spin.value(),
                "max_tokens": self.llm_max_tokens_spin.value(),
            })

        if hasattr(self, "config_target_domain_input"):
            config.setdefault("target", {})
            config["target"].update({
                "domain": self.config_target_domain_input.text().strip(),
                "mode": self.config_mode_combo.currentText(),
            })

        if hasattr(self, "tools_backend_combo"):
            config.setdefault("tools", {})
            config["tools"].update({
                "backend": self.tools_backend_combo.currentText(),
                "image": self.tools_image_input.text().strip() or "osint-tools:latest",
            })

        if hasattr(self, "config_default_detectability_combo"):
            config.setdefault("detectability", {})
            config["detectability"].update({
                "default": self.config_default_detectability_combo.currentText(),
            })

        if hasattr(self, "config_auto_run_check"):
            config.setdefault("modules", {})
            config["modules"].update({
                "auto_run": self.config_auto_run_check.isChecked(),
                "max_consecutive_empty": self.config_max_empty_spin.value(),
                "record_http_evidence": self.config_record_http_evidence_check.isChecked(),
            })

        if hasattr(self, "module_timeout_spin"):
            config["module_timeout"] = self.module_timeout_spin.value()
            budget_limits = dict(
                config.get("budget_limits") if isinstance(config.get("budget_limits"), dict) else {}
            )
            budget_limits.update({
                "max_requests": self.budget_requests_spin.value(),
                "max_wall_clock_seconds": self.budget_wall_clock_spin.value(),
                "max_llm_calls": self.budget_llm_spin.value(),
                "max_external_commands":
                    self.budget_external_commands_spin.value(),
            })
            config["budget_limits"] = budget_limits

        if hasattr(self, "rate_limit_inputs"):
            config.setdefault("rate_limits", {})
            for name, fields in self.rate_limit_inputs.items():
                config["rate_limits"][name] = {
                    "concurrent": fields["concurrent"].value(),
                    "per_minute": fields["per_minute"].value(),
                }

        if hasattr(self, "api_key_inputs"):
            config.setdefault("api_keys", {})
            for service, key_input in self.api_key_inputs.items():
                config["api_keys"][service] = key_input.text().strip()

        if hasattr(self, "auth_bearer_input"):
            config.setdefault("auth", {})
            config["auth"].update({
                "headers": self._text_to_headers(self.auth_headers_input.toPlainText()),
                "cookie": self.auth_cookie_input.text().strip(),
                "bearer_token": self.auth_bearer_input.text().strip(),
                "probe_backoff_seconds": self.auth_probe_backoff_spin.value(),
            })
            if hasattr(self, "identities_table"):
                self._sync_identity_records()
                config["auth"]["identities"] = [
                    record for record in self._identity_records if record.get("name")
                ]

        if hasattr(self, "schema_enabled_check"):
            # Only the scalar plan keys: impact_probe and cleanup stay as the
            # operator wrote them in Raw YAML.
            self._ensure_module_section(
                config, "api_workflows").update(self._read_schema_plan())

        if hasattr(self, "xss_browser_confirm_check"):
            xss_cfg = self._ensure_module_section(config, "xss_scan")
            xss_cfg.update({
                "browser_confirm": self.xss_browser_confirm_check.isChecked(),
                "max_points": self.xss_max_points_spin.value(),
                "dalfox_timeout": self.xss_dalfox_timeout_spin.value(),
            })
            if hasattr(self, "xss_dalfox_blind_oob_check"):
                xss_cfg.update({
                    "dalfox_blind_oob": self.xss_dalfox_blind_oob_check.isChecked(),
                    "dalfox_rate_limit": self.xss_dalfox_rate_spin.value(),
                })

        if hasattr(self, "nuclei_full_cve_check"):
            nuclei_cfg = self._ensure_module_section(config, "nuclei_scan")
            nuclei_cfg.update({
                "full_cve_on_confirmed_apex": self.nuclei_full_cve_check.isChecked(),
            })
            if hasattr(self, "nuclei_update_check"):
                nuclei_cfg.update({
                    "update_templates": self.nuclei_update_check.isChecked(),
                    "max_age_days": self.nuclei_max_age_spin.value(),
                })
            if hasattr(self, "nuclei_batch_seconds_spin"):
                nuclei_cfg.update({
                    "batch_seconds": self.nuclei_batch_seconds_spin.value(),
                })
                if self.nuclei_max_seconds_spin.value():
                    nuclei_cfg["max_seconds"] = self.nuclei_max_seconds_spin.value()
                else:
                    nuclei_cfg.pop("max_seconds", None)

        if hasattr(self, "sqli_oast_check"):
            config.setdefault("modules", {})
            modules_cfg = config["modules"]
            if not isinstance(modules_cfg, dict):
                modules_cfg = config["modules"] = {}
            sqli_cfg = modules_cfg.get("sqli_scan")
            if not isinstance(sqli_cfg, dict):
                sqli_cfg = modules_cfg["sqli_scan"] = {}
            sqli_cfg["oast"] = self.sqli_oast_check.isChecked()

        if hasattr(self, "fast_scan_paths_input"):
            fast_cfg = self._ensure_module_section(config, "fast_exposure_scan")
            fast_cfg.update({
                "paths": self._text_to_list(self.fast_scan_paths_input.toPlainText()),
                "timeout": self.fast_scan_timeout_spin.value(),
                "concurrency": self.fast_scan_concurrency_spin.value(),
                "max_paths": self.fast_scan_max_paths_spin.value(),
            })

        if hasattr(self, "oob_callback_domain_input"):
            config.setdefault("oob", {})
            config["oob"].update({
                "mode": self.oob_mode_combo.currentData() if hasattr(self, "oob_mode_combo") else "",
                "enabled": self.oob_enabled_check.isChecked() if hasattr(self, "oob_enabled_check") else True,
                "callback_domain": self.oob_callback_domain_input.text().strip(),
                "server_url": self.oob_server_url_input.text().strip(),
                "poll_url": self.oob_poll_url_input.text().strip(),
                "token": self.oob_token_input.text().strip(),
                "poll_interval": self.oob_poll_interval_spin.value(),
                "poll_timeout": self.oob_poll_timeout_spin.value(),
            })

        if hasattr(self, "kr_enabled_check"):
            config.setdefault("modules", {})
            modules_cfg = config["modules"]
            if not isinstance(modules_cfg, dict):
                modules_cfg = config["modules"] = {}
            cd_cfg = modules_cfg.get("content_discovery")
            if not isinstance(cd_cfg, dict):
                cd_cfg = modules_cfg["content_discovery"] = {}
            kr_cfg = cd_cfg.get("kiterunner")
            if not isinstance(kr_cfg, dict):
                kr_cfg = cd_cfg["kiterunner"] = {}
            kr_cfg.update({
                "enabled": self.kr_enabled_check.isChecked(),
                "wordlist": self.kr_wordlist_input.text().strip() or "apiroutes-260227",
                "max_routes": self.kr_max_routes_spin.value(),
                "max_targets": self.kr_max_targets_spin.value(),
            })
            if hasattr(self, "kr_delay_spin"):
                kr_cfg.update({
                    "delay_ms": self.kr_delay_spin.value(),
                    "connections": self.kr_connections_spin.value(),
                })

        if hasattr(self, "semgrep_enabled_check"):
            config.setdefault("semgrep", {})
            config["semgrep"].update({
                "enabled": self.semgrep_enabled_check.isChecked(),
                "rules": self.semgrep_rules_input.text().strip() or "rules/semgrep",
            })

        if hasattr(self, "ssrf_enabled_check"):
            config.setdefault("modules", {})
            modules_cfg = config["modules"]
            if not isinstance(modules_cfg, dict):
                modules_cfg = config["modules"] = {}
            ssrf_cfg = modules_cfg.get("ssrf_scan")
            if not isinstance(ssrf_cfg, dict):
                ssrf_cfg = modules_cfg["ssrf_scan"] = {}
            ssrf_cfg.update({
                "enabled": self.ssrf_enabled_check.isChecked(),
                "max_points": self.ssrf_max_points_spin.value(),
            })

        if hasattr(self, "crawl_enabled_check"):
            config.setdefault("crawl", {})
            crawl_cfg = config["crawl"]
            if not isinstance(crawl_cfg, dict):
                crawl_cfg = config["crawl"] = {}
            browser_cfg = crawl_cfg.get("browser")
            if not isinstance(browser_cfg, dict):
                browser_cfg = crawl_cfg["browser"] = {}
            browser_cfg.update({
                "enabled": self.crawl_enabled_check.isChecked(),
                "max_targets": self.crawl_max_pages_spin.value(),
                "depth": self.crawl_depth_spin.value(),
                "max_identities": self.crawl_max_identities_spin.value(),
            })
            if hasattr(self, "crawl_wait_ms_spin"):
                browser_cfg["wait_ms"] = self.crawl_wait_ms_spin.value()

        if hasattr(self, "logic_enabled_check"):
            config.setdefault("modules", {})
            modules_cfg = config["modules"]
            if not isinstance(modules_cfg, dict):
                modules_cfg = config["modules"] = {}
            logic_cfg = modules_cfg.get("business_logic")
            if not isinstance(logic_cfg, dict):
                logic_cfg = modules_cfg["business_logic"] = {}
            logic_cfg.update({
                "enabled": self.logic_enabled_check.isChecked(),
                "max_probes": self.logic_max_probes_spin.value(),
            })
            if hasattr(self, "logic_endpoints_text"):
                logic_cfg["endpoints"] = self._text_to_list(
                    self.logic_endpoints_text.toPlainText())

        if hasattr(self, "idor_endpoints_text"):
            idor_cfg = self._ensure_module_section(config, "idor_differ")
            idor_cfg.update({
                "endpoints": self._text_to_list(self.idor_endpoints_text.toPlainText()),
                "max_probes_per_template": self.idor_max_probes_spin.value(),
                "probe_collections": self.idor_probe_collections_check.isChecked(),
                "max_collections": self.idor_max_collections_spin.value(),
                "test_anonymous": self.idor_test_anonymous_check.isChecked(),
                "test_write_methods": [m.strip().upper() for m in
                                       self.idor_write_methods_text.text().split(",")
                                       if m.strip()],
                "allow_destructive": self.idor_allow_destructive_check.isChecked(),
            })
            obj_probe = idor_cfg.get("object_probe")
            if not isinstance(obj_probe, dict):
                obj_probe = idor_cfg["object_probe"] = {}
            obj_probe["enabled"] = self.idor_object_probe_check.isChecked()
            if hasattr(self, "idor_refs_spin"):
                obj_probe.update({
                    "max_refs": self.idor_refs_spin.value(),
                    "max_fetches": self.idor_fetches_spin.value(),
                    "max_total_fetches": self.idor_total_fetches_spin.value(),
                    "stop_after_misses": self.idor_misses_spin.value(),
                })
                idor_cfg["collection_paths"] = self._text_to_list(
                    self.idor_collection_paths_text.toPlainText())
                prefixes = [p.strip() for p in
                            self.idor_api_prefixes_text.text().split(",")
                            if p.strip()]
                if prefixes:
                    idor_cfg["api_prefixes"] = prefixes
                else:
                    idor_cfg.pop("api_prefixes", None)
                account = self.idor_account_endpoint_text.text().strip()
                if account:
                    idor_cfg["account_endpoint"] = account
                else:
                    idor_cfg.pop("account_endpoint", None)
                resources = self._text_to_list(
                    self.idor_resources_text.toPlainText())
                if resources:
                    idor_cfg["resources"] = resources
                else:
                    idor_cfg.pop("resources", None)
            id_probing = idor_cfg.get("id_probing")
            if not isinstance(id_probing, dict):
                id_probing = idor_cfg["id_probing"] = {}
            id_probing["enabled"] = self.idor_id_probing_check.isChecked()
            if hasattr(self, "idor_probe_radius_spin"):
                id_probing["radius"] = self.idor_probe_radius_spin.value()
                id_probing["max"] = self.idor_probe_max_spin.value()

        if hasattr(self, "mass_enabled_check"):
            mass_cfg = self._ensure_module_section(config, "mass_assignment")
            mass_cfg.update({
                "enabled": self.mass_enabled_check.isChecked(),
                "endpoints": self._text_to_list(self.mass_endpoints_text.toPlainText()),
                "write_endpoint": self.mass_write_endpoint_input.text().strip(),
                "method": self.mass_method_combo.currentText(),
                "fields": [f.strip() for f in
                           self.mass_fields_text.text().split(",") if f.strip()],
                "probe_type": self.mass_probe_type_combo.currentText(),
            })

        if hasattr(self, "proto_enabled_check"):
            proto_cfg = self._ensure_module_section(config, "prototype_pollution")
            proto_cfg.update({
                "enabled": self.proto_enabled_check.isChecked(),
                "endpoints": self._text_to_list(self.proto_endpoints_text.toPlainText()),
            })
            if hasattr(self, "proto_reflect_input"):
                reflect = self.proto_reflect_input.text().strip()
                if reflect:
                    proto_cfg["reflect_endpoint"] = reflect
                else:
                    proto_cfg.pop("reflect_endpoint", None)
                methods = [m.strip().upper() for m in
                           self.proto_methods_text.text().split(",") if m.strip()]
                if methods:
                    proto_cfg["methods"] = methods
                else:
                    proto_cfg.pop("methods", None)
                payloads = self._text_to_list(self.proto_payloads_text.toPlainText())
                if payloads:
                    proto_cfg["payloads"] = payloads
                else:
                    proto_cfg.pop("payloads", None)

        if hasattr(self, "misconfig_timeout_spin"):
            mis_cfg = self._ensure_module_section(config, "misconfig_probes")
            mis_cfg.update({
                "timeout": self.misconfig_timeout_spin.value(),
                "concurrency": self.misconfig_concurrency_spin.value(),
                "max_paths": self.misconfig_max_paths_spin.value(),
                "max_consecutive_empty": self.misconfig_max_empty_spin.value(),
                "progress_every": self.misconfig_progress_spin.value(),
            })

        if hasattr(self, "ssti_max_points_spin"):
            ssti_cfg = self._ensure_module_section(config, "ssti_scan")
            ssti_cfg["max_points"] = self.ssti_max_points_spin.value()
            nosql_cfg = self._ensure_module_section(config, "nosql_scan")
            nosql_cfg["max_points"] = self.nosql_max_points_spin.value()
            dom_cfg = self._ensure_module_section(config, "dom_xss_scan")
            dom_cfg["max_pages"] = self.dom_max_pages_spin.value()
            param_cfg = self._ensure_module_section(config, "parameter_discovery")
            param_cfg["seed_when_empty"] = self.param_seed_check.isChecked()
            param_cfg["seed_targets"] = self.param_seed_targets_spin.value()
            seed_params = [p.strip() for p in
                           self.param_seed_params_text.text().split(",")
                           if p.strip()]
            if seed_params:
                param_cfg["seed_params"] = seed_params
            else:
                param_cfg.pop("seed_params", None)

        if hasattr(self, "smuggling_enabled_check"):
            smuggling_cfg = self._ensure_module_section(config, "http_smuggling")
            smuggling_cfg.update({
                "enabled": self.smuggling_enabled_check.isChecked(),
                "max_targets": self.smuggling_max_targets_spin.value(),
            })

        if hasattr(self, "redirect_enabled_check"):
            redirect_cfg = self._ensure_module_section(config, "open_redirect")
            redirect_cfg.update({
                "enabled": self.redirect_enabled_check.isChecked(),
                "params": [p.strip() for p in
                           self.redirect_params_text.text().split(",") if p.strip()],
                "endpoints": self._text_to_list(self.redirect_endpoints_text.toPlainText()),
                "max_targets": self.redirect_max_targets_spin.value(),
            })

        if hasattr(self, "cms_enabled_check"):
            cms_cfg = self._ensure_module_section(config, "cms_deep_scan")
            cms_cfg.update({
                "enabled": self.cms_enabled_check.isChecked(),
                "max_targets": self.cms_max_targets_spin.value(),
            })

        if hasattr(self, "content_enabled_check"):
            content_cfg = self._ensure_module_section(config, "content_discovery")
            content_cfg.update({
                "enabled": self.content_enabled_check.isChecked(),
            })

        if hasattr(self, "cors_enabled_check"):
            cors_cfg = self._ensure_module_section(config, "cors_audit")
            cors_cfg.update({
                "enabled": self.cors_enabled_check.isChecked(),
                "endpoints": self._text_to_list(self.cors_endpoints_text.toPlainText()),
                "max_endpoints": self.cors_max_endpoints_spin.value(),
            })

        if hasattr(self, "auth_test_password_check"):
            auth_cfg = self._ensure_module_section(config, "auth_audit")
            auth_cfg.update({
                "test_password_change": self.auth_test_password_check.isChecked(),
                "test_registration_oracle": self.auth_test_register_check.isChecked(),
            })

        if self._write_config(config):
            self._load_raw_config_editor()
            self._refresh_key_status()
            self._refresh_tools_status()
            self._update_operation_context()
            self._set_status("ok", "Settings saved")
