"""State Manager — typed asset graph with confidence ladders."""

import json
import hashlib
import logging
import uuid
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Union

from core.persistence import atomic_json, file_lock, valid_snapshot

logger = logging.getLogger("osint-agent")

CONFIDENCE_ORDER = {"TENTATIVE": 0, "FIRM": 1, "CONFIRMED": 2}
SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class StateConflictError(RuntimeError):
    """Another writer committed after this investigation was loaded."""


def _finding_host(asset_keys) -> str:
    """The host a finding names in its asset keys, or "" if none.

    Asset keys look like "webapp:https://euro2c.com", "url:https://e/x" or
    "email_domain:euro2c.com". Pull the first host out of them. Many posture
    findings carry no host-bearing asset; the caller supplies the run's
    primary host as the fallback so that two reports of one class — one
    tagged `webapp:…`, one untagged — still collapse within a single-target
    run instead of splitting on a missing asset key.
    """
    from urllib.parse import urlparse
    for key in asset_keys or []:
        _, _, rest = str(key).partition(":")
        rest = rest.strip()
        if not rest:
            continue
        if rest.startswith(("http://", "https://")):
            host = urlparse(rest).hostname
            if host:
                return host.lower()
        elif "/" not in rest and " " not in rest:
            return rest.lower()
    return ""


def _merge_intelligence(existing: dict, incoming: dict) -> dict:
    """Union vulnerability intel without letting a weaker claim win.

    KEV is sticky (once exploited, always exploited); CVSS and EPSS take the
    stronger value. Everything else keeps the first value so a later module
    cannot overwrite a named CVE with a guess.
    """
    merged = dict(existing or {})
    for key, value in (incoming or {}).items():
        if key == "kev":
            merged["kev"] = bool(merged.get("kev")) or bool(value)
        elif key in ("cvss", "epss"):
            try:
                merged[key] = max(float(merged.get(key) or 0), float(value or 0))
            except (TypeError, ValueError):
                merged[key] = max(merged.get(key) or 0, value or 0)
        elif key == "cves":
            seen = list(merged.get("cves") or [])
            for cve in value or []:
                if cve not in seen:
                    seen.append(cve)
            merged["cves"] = seen
        elif key not in merged:
            merged[key] = value
    return merged


def _clean_evidence(evidence) -> list:
    """Drop empty and whitespace-only evidence lines.

    Conditional evidence appends (`f"..." if x else ""`) used to leave
    blank rows in findings and reports. A cleaner with no opinion about
    content, only about emptiness.
    """
    cleaned = []
    for item in evidence or []:
        text = item if isinstance(item, str) else str(item or "")
        if text.strip():
            cleaned.append(item)
    return cleaned


class StateManager:
    """Persistent state for a single target investigation."""

    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.state_dir = self.output_dir / "state"
        self.state_dir.mkdir(parents=True, exist_ok=True)

        self.assets_file = self.state_dir / "assets.json"
        self.findings_file = self.state_dir / "findings.json"
        self.module_file = self.state_dir / "module.json"
        self.evidence_file = self.state_dir / "evidence.json"
        self.evidence_dir = self.state_dir / "evidence"
        self.evidence_dir.mkdir(exist_ok=True)

        self.snapshot_file = self.state_dir / "snapshot.json"
        self.lock_file = self.state_dir / "state.lock"
        snapshot = self._load_snapshot()
        self._revision = snapshot.get("revision", 0) if snapshot else 0
        self._loaded_snapshot = snapshot

        self.assets = self._read_json(self.assets_file, {"nodes": [], "edges": []})
        self.findings = self._read_json(self.findings_file, {"findings": []})
        self.evidence = self._read_json(self.evidence_file, {"items": []})
        self.module = self._read_json(self.module_file, {
            "current": None,
            "completed": [],
            "skipped": [],
            "blocked": [],
            "runs": [],
            "completed_checks": [],
            "waf": {
                "detected": False,
                "vendor": None,
                "blocks": [],
                "allows": [],
                "rate_limit": None,
            },
            "stats": {
                "total_requests": 0,
                "total_assets": 0,
                "total_findings": 0,
                "started_at": self._now(),
                "last_action": self._now(),
            }
        })
        self._loaded_snapshot = None
        # Migrate old tuple format (module_id, reason) -> dict format
        for key in ("skipped", "blocked"):
            migrated = []
            for entry in self.module.get(key, []):
                if isinstance(entry, (list, tuple)) and len(entry) == 2:
                    migrated.append({"module_id": entry[0], "reason": entry[1]})
                elif isinstance(entry, dict):
                    migrated.append(entry)
            self.module[key] = migrated
        self.module.setdefault("runs", [])
        self.module.setdefault("completed_checks", [])
        self.findings.setdefault("findings", [])
        self.evidence.setdefault("items", [])
        self.module.setdefault("investigation_id", uuid.uuid4().hex)
        self._dirty = False

    # ── Asset Management ──────────────────────────────────────────

    def add_asset(self, asset_type: str, key: str, value: str,
                  confidence: str = "TENTATIVE",
                  sources: Optional[list] = None,
                  attrs: Optional[dict] = None) -> dict:
        """Add or upgrade an asset in the graph."""
        node = self._find_node(key)
        if node:
            old_confidence = CONFIDENCE_ORDER.get(node.get("confidence", "TENTATIVE"), 0)
            new_confidence = CONFIDENCE_ORDER.get(confidence, 0)
            if new_confidence > old_confidence:
                node["confidence"] = confidence
            if sources:
                existing = set(node.get("sources", []))
                node["sources"] = list(existing | set(sources))
            if attrs:
                node["attrs"] = {**node.get("attrs", {}), **attrs}
            node["last_seen"] = self._now()
            self._dirty = True
            return node

        node = {
            "type": asset_type,
            "key": key,
            "value": value,
            "confidence": confidence,
            "sources": sources or [],
            "attrs": attrs or {},
            "first_seen": self._now(),
            "last_seen": self._now(),
        }
        self.assets["nodes"].append(node)
        self.module["stats"]["total_assets"] = len(self.assets["nodes"])
        self._dirty = True
        return node

    def add_edge(self, source_key: str, target_key: str, edge_type: str,
                 attrs: Optional[dict] = None):
        """Add a typed edge between two assets."""
        edge = {
            "source": source_key,
            "target": target_key,
            "type": edge_type,
            "attrs": attrs or {},
            "seen_at": self._now(),
        }
        # Dedup
        for existing in self.assets["edges"]:
            if (existing["source"] == source_key
                    and existing["target"] == target_key
                    and existing["type"] == edge_type):
                return
        self.assets["edges"].append(edge)
        self._dirty = True

    def get_assets_by_type(self, asset_type: str) -> list:
        return [n for n in self.assets["nodes"] if n["type"] == asset_type]

    def get_assets_by_confidence(self, confidence: str) -> list:
        return [n for n in self.assets["nodes"] if n["confidence"] == confidence]

    # ── Finding Management ────────────────────────────────────────

    def _next_finding_id(self) -> str:
        """Monotonic finding ID — a pruned finding's number is never reissued.

        IDs used to be positional (`FINDING-{len+1}`), so `begin_module_run`
        pruning one module's findings could hand the next new finding the
        ID of an unrelated survivor: two rows shared one ID, and triage
        verdicts silently attached to the wrong finding after a re-run.
        The sequence persists in findings.json and only moves forward;
        legacy states migrate by taking the highest suffix already on disk.
        """
        if "id_seq" not in self.findings:
            highest = 0
            for finding in self.findings["findings"]:
                suffix = str(finding.get("id") or "")
                if suffix.startswith("FINDING-") and suffix[8:].isdigit():
                    highest = max(highest, int(suffix[8:]))
            self.findings["id_seq"] = highest
        existing = {str(f.get("id")) for f in self.findings["findings"]}
        while True:
            self.findings["id_seq"] = int(self.findings["id_seq"]) + 1
            candidate = f"FINDING-{self.findings['id_seq']:04d}"
            if candidate not in existing:
                self._dirty = True
                return candidate

    def _next_evidence_id(self) -> str:
        """Monotonic evidence ID (same rationale as _next_finding_id).

        Evidence is never pruned today, so collisions never happened — but
        the length-based scheme would break the day pruning is added, and
        a reused evidence ID would silently swap one finding's proof with
        another's.
        """
        if "id_seq" not in self.evidence:
            highest = 0
            for item in self.evidence["items"]:
                suffix = str(item.get("id") or "")
                if suffix.startswith("EVIDENCE-") and suffix[9:].isdigit():
                    highest = max(highest, int(suffix[9:]))
            self.evidence["id_seq"] = highest
        existing = {str(item.get("id")) for item in self.evidence["items"]}
        while True:
            self.evidence["id_seq"] = int(self.evidence["id_seq"]) + 1
            candidate = f"EVIDENCE-{self.evidence['id_seq']:04d}"
            if candidate not in existing:
                self._dirty = True
                return candidate

    def prune_module_findings(self, module_id: str) -> int:
        """Remove findings previously emitted by this module.

        Called at the start of a re-run so stale findings from the last code
        version don't survive alongside fresh ones. Evidence files are left
        alone — they're historical, and evidence_refs are resolved per run.
        Returns the number of findings removed.
        """
        if not module_id:
            return 0
        before = len(self.findings["findings"])
        self.findings["findings"] = [
            f for f in self.findings["findings"]
            if f.get("module_id") != module_id
        ]
        removed = before - len(self.findings["findings"])
        if removed:
            self.module["stats"]["total_findings"] = len(self.findings["findings"])
            self._dirty = True
        return removed
    def _primary_host(self) -> str:
        """The run's target host, used as the host-scope fallback for posture
        findings that carry no host-bearing asset key. The report directory
        is named for the target (reports/<domain>/), so its basename is the
        host; falls back to a constant when that is unavailable."""
        from urllib.parse import urlsplit
        assessment = self.module.get("assessment") or {}
        host = urlsplit(assessment.get("origin", "")).hostname
        if host:
            return host.lower()
        name = str(getattr(self.output_dir, "name", "") or "").lower()
        if name and name not in ("state", ""):
            return name
        return "__target__"

    def add_finding(self, title: str, severity: str, confidence: str,
                    category: str, description: str,
                    evidence: Optional[list] = None,
                    remediation: str = "",
                    asset_keys: Optional[list] = None,
                    evidence_refs: Optional[list] = None,
                    risk_score: Optional[int] = None,
                    verified: bool = False,
                    verification: Optional[dict] = None,
                    cwe: Optional[list] = None,
                    owasp: Optional[str] = None,
                    intelligence: Optional[dict] = None) -> str:
        from core.scoring import score_finding
        from core.taxonomy import classify
        if risk_score is None:
            risk_score = score_finding(
                severity, confidence, asset_keys, category,
                verified=verified,
            )
        if cwe is None or owasp is None:
            taxonomy = classify(category)
            if cwe is None:
                cwe = taxonomy["cwe"]
            if owasp is None:
                owasp = taxonomy["owasp"]
        # Tag with the module currently running so future re-runs can replace it.
        current_module = self.module.get("current") or ""
        # Same claim, same category, same assets: one finding, not N. The
        # chain executor used to file one "Proven: ..." finding per graph
        # edge, so a JS bundle reachable from two chains showed up twice
        # with identical text; re-runs stacked a third copy on top. Merging
        # keeps the strongest severity/confidence and unions the evidence
        # instead. Asset keys are part of the key: two endpoints with the
        # same/title-shaped claim (IDOR on baskets/200 vs invoices/200) are
        # two findings, not one.
        dedupe_key = (str(title or "").strip().lower(),
                      str(category or "").strip().lower(),
                      tuple(sorted(str(k) for k in (asset_keys or []))))
        # Second, coarser key: the vulnerability *class* on a host. This folds
        # the WP user-enumeration triplicate (three titles, one weakness) and
        # similar host-posture duplicates that the exact key cannot see.
        # Point-scoped classes (injection, IDOR) return no class, so they
        # never reach this path and stay one-per-endpoint.
        from core.taxonomy import vuln_class
        incoming_class, host_scoped = vuln_class(title, category)
        incoming_host = (_finding_host(asset_keys) or self._primary_host()) \
            if host_scoped else None
        if dedupe_key[0]:
            for existing in self.findings["findings"]:
                exact = (str(existing.get("title", "")).strip().lower(),
                         str(existing.get("category", "")).strip().lower(),
                         tuple(sorted(str(k) for k in (existing.get("asset_keys") or [])))) == dedupe_key
                semantic = False
                if host_scoped and incoming_class:
                    ex_class, ex_host_scoped = vuln_class(
                        existing.get("title", ""), existing.get("category", ""))
                    semantic = (ex_host_scoped and ex_class == incoming_class
                                and (_finding_host(existing.get("asset_keys"))
                                     or self._primary_host()) == incoming_host)
                if exact or semantic:
                    self._merge_finding(
                        existing, severity, confidence, risk_score,
                        description, evidence, remediation, asset_keys,
                        evidence_refs, verified, verification,
                        current_module, intelligence,
                    )
                    self._dirty = True
                    return existing["id"]
        fid = self._next_finding_id()
        now = self._now()
        finding = {
            "id": fid,
            "module_id": current_module,
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "risk_score": risk_score,
            "category": category,
            "cwe": list(cwe or []),
            "owasp": owasp or "",
            "description": description,
            "evidence": _clean_evidence(evidence),
            "evidence_refs": evidence_refs or [],
            "remediation": remediation,
            "asset_keys": asset_keys or [],
            "created_at": now,
            "first_seen": now,
            "last_seen": now,
            "verified": bool(verified),
            "verification": verification or {},
        }
        if intelligence:
            finding["intelligence"] = dict(intelligence)
        self.findings["findings"].append(finding)
        self.module["stats"]["total_findings"] = len(self.findings["findings"])
        self._dirty = True
        return fid

    def _merge_finding(self, existing: dict, severity: str, confidence: str,
                       risk_score: int, description: str,
                       evidence: Optional[list], remediation: str,
                       asset_keys: Optional[list],
                       evidence_refs: Optional[list], verified: bool,
                       verification: Optional[dict],
                       current_module: str,
                       intelligence: Optional[dict] = None) -> None:
        """Fold a duplicate claim into the finding already on record."""
        existing["last_seen"] = self._now()
        if int(risk_score or 0) > int(existing.get("risk_score") or 0):
            existing["severity"] = severity
            existing["confidence"] = confidence
            existing["risk_score"] = risk_score
            if description and not existing.get("description"):
                existing["description"] = description
        if verified:
            existing["verified"] = True
        if current_module and not existing.get("module_id"):
            existing["module_id"] = current_module
        if remediation and not existing.get("remediation"):
            existing["remediation"] = remediation
        for key, items in (("evidence", evidence or []),
                           ("evidence_refs", evidence_refs or []),
                           ("asset_keys", asset_keys or [])):
            merged = list(existing.get(key) or [])
            for item in items:
                if item not in merged:
                    merged.append(item)
            if key == "evidence":
                merged = _clean_evidence(merged)
            existing[key] = merged[:50]
        if verification:
            merged_verification = dict(verification)
            merged_verification.update(existing.get("verification") or {})
            existing["verification"] = merged_verification
        if intelligence:
            existing["intelligence"] = _merge_intelligence(
                existing.get("intelligence") or {}, intelligence)

    def confirm_finding(self, finding_id: str, *,
                        confidence: str = "CONFIRMED",
                        verification: Optional[dict] = None,
                        evidence: Optional[list] = None) -> bool:
        """Promote an existing finding with the proof a re-run produced.

        The agent path filed a finding from the exploitation result and then
        verified it in the blackboard only, so the report still showed an
        unverified claim after a successful confirmation. This writes the
        proof back to the finding the report and every export read.
        """
        from core.scoring import score_finding
        for finding in self.findings["findings"]:
            if finding.get("id") != finding_id:
                continue
            finding["confidence"] = confidence
            finding["verified"] = True
            merged = dict(finding.get("verification") or {})
            merged.update(verification or {})
            finding["verification"] = merged
            if evidence:
                current = list(finding.get("evidence") or [])
                for item in evidence:
                    text = str(item)
                    if text and text not in current:
                        current.append(text)
                finding["evidence"] = _clean_evidence(current)[:50]
            finding["risk_score"] = score_finding(
                finding.get("severity", "INFO"), confidence,
                finding.get("asset_keys"), finding.get("category", ""),
                verified=True,
            )
            finding["last_seen"] = self._now()
            self._dirty = True
            return True
        return False

    def get_findings_by_severity(self, severity: str) -> list:
        return [f for f in self.findings["findings"] if f["severity"] == severity]

    # ── Module State ──────────────────────────────────────────────

    def set_module(self, module_id: str):
        self.module["current"] = module_id
        self._dirty = True

    def begin_module_run(self, module_id: str, detectability: str = "",
                         stage: int = 0) -> str:
        # Findings from a previous run of this module are stale — the fresh
        # run will regenerate them. Drop them before the new run starts so
        # the state reflects the current code, not the last code.
        self.prune_module_findings(module_id)
        # A previous success must not survive a failed or skipped retest.
        self.module["completed"] = [mid for mid in self.module["completed"]
                                    if mid != module_id]
        for key in ("skipped", "blocked"):
            self.module[key] = [item for item in self.module.get(key, [])
                                if item.get("module_id") != module_id]

        run_id = f"RUN-{len(self.module.get('runs', [])) + 1:04d}"
        run = {
            "id": run_id,
            "module_id": module_id,
            "stage": stage,
            "detectability": detectability,
            "status": "running",
            "started_at": self._now(),
            "finished_at": None,
            "requests_before": self.module["stats"]["total_requests"],
            "requests_after": None,
            "requests": 0,
            "assets_before": len(self.assets["nodes"]),
            "assets_after": None,
            "assets_added": 0,
            "findings_before": len(self.findings["findings"]),
            "findings_after": None,
            "findings_added": 0,
            "error": "",
        }
        self.module.setdefault("runs", []).append(run)
        self.module["current"] = module_id
        self._dirty = True
        return run_id

    def finish_module_run(self, run_id: str, status: str, error: str = ""):
        for run in reversed(self.module.get("runs", [])):
            if run.get("id") == run_id:
                run["status"] = status
                run["finished_at"] = self._now()
                run["requests_after"] = self.module["stats"]["total_requests"]
                run["requests"] = (
                    run["requests_after"] - run.get("requests_before", 0)
                )
                run["assets_after"] = len(self.assets["nodes"])
                run["assets_added"] = (
                    run["assets_after"] - run.get("assets_before", 0)
                )
                run["findings_after"] = len(self.findings["findings"])
                run["findings_added"] = (
                    run["findings_after"] - run.get("findings_before", 0)
                )
                run["error"] = error
                if status not in ("done", "completed"):
                    self.module["completed"] = [
                        mid for mid in self.module["completed"]
                        if mid != run.get("module_id")]
                break
        self.module["current"] = None
        self._dirty = True

    def complete_module(self, module_id: str):
        if module_id not in self.module["completed"]:
            self.module["completed"].append(module_id)
        self.module["current"] = None
        self._dirty = True

    @property
    def mutations(self):
        """Per-assessment mutation ledger (R8), created on first use.

        The orchestrator shares its instance by assigning ``_mutations``
        before any module runs; standalone module tests get a fresh ledger
        in the same state dir.
        """
        ledger = getattr(self, "_mutations", None)
        if ledger is None:
            from core.mutations import MutationLedger
            ledger = MutationLedger(self.state_dir / "mutations.jsonl")
            self._mutations = ledger
        return ledger

    def annotate_module_run(self, run_id: str, op_row: Optional[dict] = None):
        """Merge operations-ledger accounting into a finished run record."""
        if not op_row:
            return
        accounting = op_row.get("accounting") or {}
        for run in reversed(self.module.get("runs", [])):
            if run.get("id") == run_id:
                run["op_id"] = op_row.get("op_id")
                run["outcome"] = op_row.get("outcome")
                run["commands"] = accounting.get("commands", 0)
                run["wall_ms"] = accounting.get("wall_ms", 0)
                run["containers_removed"] = accounting.get(
                    "containers_removed", 0)
                break
        self._dirty = True

    def recover_interrupted_runs(self) -> list[str]:
        """Called only after an executor acquires a resumed assessment's lease."""
        unfinished = [run["id"] for run in self.module.get("runs", [])
                      if run.get("status") == "running"]
        for run_id in unfinished:
            self.finish_module_run(run_id, "interrupted", "Previous executor stopped; module requires rerun")
        return unfinished

    def skip_module(self, module_id: str, reason: str = ""):
        if not any(s.get("module_id") == module_id for s in self.module["skipped"]):
            self.module["skipped"].append({"module_id": module_id, "reason": reason})
            logger.warning(f"Module {module_id} skipped: {reason or 'no reason recorded'}")
        self.module["current"] = None
        self._dirty = True

    def block_module(self, module_id: str, reason: str = ""):
        if not any(b.get("module_id") == module_id for b in self.module["blocked"]):
            self.module["blocked"].append({"module_id": module_id, "reason": reason})
            logger.warning(f"Module {module_id} blocked: {reason or 'no reason recorded'}")
        self.module["current"] = None
        self._dirty = True

    def add_check(self, check_name: str, count_request: bool = True):
        if check_name not in self.module["completed_checks"]:
            self.module["completed_checks"].append(check_name)
        self.module["stats"]["last_action"] = self._now()
        if count_request:
            self.module["stats"]["total_requests"] += 1
        self._dirty = True

    def record_request(self) -> None:
        """Count one wire request without inventing a completed check.

        Raw `curl` calls used to be invisible to run telemetry: a module
        could send 1,000 requests and report zero because only `http_get`
        incremented the counter. The wrapper calls this observer instead.
        """
        self.module["stats"]["last_action"] = self._now()
        self.module["stats"]["total_requests"] += 1
        self._dirty = True

    def is_check_done(self, check_name: str) -> bool:
        return check_name in self.module["completed_checks"]

    def is_module_complete(self, module_id: str) -> bool:
        return module_id in self.module["completed"]

    # ── WAF Tracking ──────────────────────────────────────────────

    def record_waf_block(self, path: str, code: int):
        block = {"path": path, "code": code}
        if block not in self.module["waf"]["blocks"]:
            self.module["waf"]["blocks"].append(block)
        self.module["waf"]["detected"] = True
        self._dirty = True

    def record_waf_allow(self, path: str, code: int):
        allow = {"path": path, "code": code}
        if allow not in self.module["waf"]["allows"]:
            self.module["waf"]["allows"].append(allow)
        self._dirty = True

    def waf_limit_hit(self, threshold: int = 5) -> bool:
        blocks = self.module["waf"]["blocks"]
        return len(blocks) >= threshold

    # ── Evidence Management ───────────────────────────────────────

    def add_evidence(self, module_id: str, evidence_type: str, subject: str,
                     data: Union[dict, list, str]) -> str:
        eid = self._next_evidence_id()
        # Stale managers can allocate the same display ID before save detects
        # their conflict. Never let either overwrite the other's proof bytes.
        path = self.evidence_dir / f"{eid}-{uuid.uuid4().hex}.json"
        item = {
            "id": eid,
            "module_id": module_id,
            "type": evidence_type,
            "subject": subject,
            "path": str(path.relative_to(self.output_dir)),
            "created_at": self._now(),
        }
        self._write_json(path, {
            "schema_version": 1,
            "id": eid,
            "module_id": module_id,
            "type": evidence_type,
            "subject": subject,
            "created_at": item["created_at"],
            "data": data,
        })
        item.update({"schema_version": 1,
                     "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                     "size_bytes": path.stat().st_size})
        self.evidence["items"].append(item)
        audit = getattr(self, "audit", None)
        if audit is not None:
            audit.record("evidence.created", item)
        self._dirty = True
        return eid

    def verify_evidence(self, evidence_id: str) -> dict:
        """Check the stored bytes against the indexed digest, without rewriting them."""
        item = next((entry for entry in self.evidence["items"]
                     if entry.get("id") == evidence_id), None)
        if not item:
            return {"ok": False, "reason": "unknown evidence"}
        if not item.get("sha256"):
            return {"ok": False, "reason": "legacy evidence has no digest"}
        try:
            path = (self.output_dir / item["path"]).resolve()
            if not path.is_relative_to(self.evidence_dir.resolve()):
                return {"ok": False, "reason": "invalid evidence path"}
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            return {"ok": False, "reason": "missing or unreadable evidence"}
        return {"ok": actual == item["sha256"], "sha256": actual}

    # ── Persistence ───────────────────────────────────────────────

    def save(self):
        if not self._dirty:
            return
        with file_lock(self.lock_file):
            self.check_revision()
            revision = self._revision
            snapshot = {"schema_version": 1, "revision": revision + 1,
                        "assets": self.assets, "findings": self.findings,
                        "module": self.module, "evidence": self.evidence}
            if not valid_snapshot(snapshot):
                raise ValueError("Cannot commit an invalid investigation snapshot")
            # This one replace is the commit point for all four stores.
            self._write_json(self.snapshot_file, snapshot)
            self._revision = revision + 1
            self._dirty = False
            # Compatibility views are not the transaction source of truth.
            # A failed export must not make a successful commit look lost.
            for path, data in ((self.assets_file, self.assets),
                               (self.findings_file, self.findings),
                               (self.module_file, self.module),
                               (self.evidence_file, self.evidence)):
                try:
                    self._write_json(path, data)
                except OSError as exc:
                    logger.warning("State committed; compatibility export %s failed: %s", path.name, exc)

    def check_revision(self):
        """Reject stale mutations/exports; caller holds state.lock for a transaction."""
        current = self._load_snapshot()
        revision = current.get("revision", 0) if current else 0
        if revision != self._revision:
            raise StateConflictError(
                "Investigation changed in another process; reload state or use "
                "a separate output directory. Unsaved changes were not overwritten.")

    def summary(self) -> dict:
        return {
            "target": str(self.output_dir),
            "assets": len(self.assets["nodes"]),
            "edges": len(self.assets["edges"]),
            "findings": len(self.findings["findings"]),
            "evidence": len(self.evidence["items"]),
            "findings_by_severity": {
                s: len(self.get_findings_by_severity(s))
                for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            },
            "modules_completed": self.module["completed"],
            "modules_skipped": [s["module_id"] for s in self.module["skipped"]],
            "modules_blocked": [b["module_id"] for b in self.module["blocked"]],
            "waf_detected": self.module["waf"]["detected"],
            "total_requests": self.module["stats"]["total_requests"],
            "module_runs": self.module.get("runs", []),
            "started_at": self.module["stats"]["started_at"],
            "last_action": self.module["stats"]["last_action"],
        }

    # ── Internals ─────────────────────────────────────────────────

    def _find_node(self, key: str) -> Optional[dict]:
        for node in self.assets["nodes"]:
            if node["key"] == key:
                return node
        return None

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _read_json(self, path: Path, default: dict) -> dict:
        snapshot = getattr(self, "_loaded_snapshot", None)
        if snapshot is not None:
            return snapshot[path.stem]
        if path.exists():
            data = json.loads(path.read_text())
            if not isinstance(data, dict):
                raise ValueError(f"Invalid investigation data: {path}")
            return data
        return default

    def _load_snapshot(self):
        if not self.snapshot_file.exists():
            return None
        data = json.loads(self.snapshot_file.read_text())
        if not valid_snapshot(data):
            raise ValueError(f"Invalid investigation snapshot: {self.snapshot_file}")
        return data

    def _write_json(self, path: Path, data: dict):
        atomic_json(path, data)
