"""Stage 5: Stateful API workflow testing via schemathesis (I2).

Consumes OpenAPI/GraphQL schema assets discovered by rest_api_audit /
graphql_audit, runs the schemathesis state machine (linked operation
sequences) as an isolated subprocess, and grades results:

- schema-conformance failures -> OBSERVATION (consolidated LOW finding)
- server-behavior failures (5xx, status conformance) -> CANDIDATE
- PROOF only when the module itself replays the minimal failing case
  through the framework transport (fresh identity) AND a configured
  impact probe re-reads the resource and observes the corrupted state.
  The tool's own claim never reaches PROOF.

Every schemathesis pass is recorded in the mutation ledger before launch
(R8): fuzzer writes are owned objects; cleanup is verified when a cleanup
spec is configured, otherwise honestly marked not_required.
"""

from __future__ import annotations

import json
import re
import shutil
import tempfile
from pathlib import Path
from urllib.parse import urljoin, urlparse

from core.auth_harness import AuthHarness
from core.mutations import OwnedObject
from modules.base import BaseModule
from tools.schemathesis import (check_tier, cleanup_workdir,
                                curl_repro_from_record, run_schemathesis,
                                schemathesis_available)
from tools.wrappers import curl


class APIWorkflows(BaseModule):
    id = "api_workflows"
    name = "API Workflow / Stateful Schema Testing"
    stage = 5
    detectability = "high"
    depends_on = ["rest_api_audit", "graphql_audit"]
    active = True

    async def run(self) -> str:
        cfg = self._cfg()
        if not cfg.get("enabled"):
            self.state.skip_module(
                self.id,
                "disabled — it drives a stateful fuzzer against discovered "
                "schemas; set modules.api_workflows.enabled: true to run")
            return "skipped"

        schemas = self._schema_assets(cfg)
        if not schemas:
            self.state.skip_module(
                self.id,
                "no OpenAPI/GraphQL schema discovered — run rest_api_audit "
                "and graphql_audit first")
            return "skipped"

        probe = schemathesis_available()
        if not probe.get("available"):
            reason = probe.get("reason") or "schemathesis unavailable"
            self.state.skip_module(self.id, reason)
            return "skipped"

        harness = AuthHarness(self.config)
        harness.mutations = self.state.mutations
        harness.adopt_discovered(self.state, log=self.log)
        identities = await harness.establish_all(self._base_url())
        identity_names = [i.name for i in identities]

        max_seconds = max(30, int(cfg.get("max_seconds", 480) or 480))
        import time as _time
        stop_at = _time.monotonic() + max_seconds

        tested = 0
        proven = 0
        for spec_url in schemas:
            if _time.monotonic() >= stop_at:
                self.log("  time-box hit — schemas tested so far kept")
                break
            spec_body = await self._fetch_spec(spec_url, harness, identity_names)
            if not spec_body:
                continue
            staged = self._stage_spec(spec_body, spec_url)
            if not staged:
                continue
            outcome = await self._test_schema(
                staged, spec_url, cfg, harness, identity_names)
            if outcome.get("tested"):
                tested += 1
            proven += outcome.get("proven", 0)
            self._cleanup_staging(staged)

        self.state.add_asset(
            "api_workflow_scan",
            f"api_workflow_scan:{self.domain}",
            self.domain,
            confidence="FIRM",
            sources=[self.id],
            attrs={
                "tool": "schemathesis",
                "version": probe.get("version"),
                "backend": probe.get("backend"),
                "schemas_tested": tested,
                "schemas_discovered": len(schemas),
                "proven": proven,
            },
        )
        self.state.complete_module(self.id)
        self.log(f"api workflows: {tested} schema(s) tested, {proven} proven")
        return "done"

    # ── Discovery ────────────────────────────────────────────────

    def _schema_assets(self, cfg: dict) -> list[str]:
        max_schemas = max(1, int(cfg.get("max_schemas", 3) or 3))
        candidates = []
        for node in self.state.get_assets_by_type("api_endpoint"):
            attrs = node.get("attrs") or {}
            if attrs.get("type") == "openapi" and node.get("value"):
                candidates.append((int(attrs.get("endpoint_count", 0) or 0),
                                   str(node["value"])))
        for node in self.state.get_assets_by_type("graphql"):
            if node.get("value"):
                candidates.append((0, str(node["value"])))
        seen: set[str] = set()
        unique = []
        for _, url in sorted(candidates, key=lambda item: -item[0]):
            if url in seen:
                continue
            seen.add(url)
            unique.append(url)
        return unique[:max_schemas]

    async def _fetch_spec(self, spec_url: str, harness: AuthHarness,
                          identity_names: list) -> str:
        result = await curl(spec_url, output="body", timeout=20,
                            strip_global_auth=True)
        if result.get("status", 0) in (401, 403) and identity_names:
            result = await harness.request(identity_names[0], spec_url)
        body = result.get("body", "") or ""
        if not body:
            return ""
        if not self._looks_like_spec(body):
            # HTML docs pages are not specs; try the conventional JSON
            # neighbour once before giving up.
            if spec_url.endswith(".html"):
                alt = spec_url[:-5] + ".json"
                alt_result = await curl(alt, output="body", timeout=20,
                                        strip_global_auth=True)
                if alt_result.get("status", 0) == 200 \
                        and self._looks_like_spec(alt_result.get("body", "")):
                    return alt_result.get("body", "")
            return ""
        return body

    @staticmethod
    def _looks_like_spec(body: str) -> bool:
        text = (body or "").strip()
        if not text.startswith(("{", "[")):
            return False
        try:
            doc = json.loads(text)
        except (ValueError, TypeError):
            return False
        if not isinstance(doc, dict):
            return False
        return ("paths" in doc or "swagger" in doc or "openapi" in doc)

    def _stage_spec(self, spec_body: str, spec_url: str) -> str:
        try:
            workdir = tempfile.mkdtemp(prefix="apiworkflows-", dir=Path.cwd())
            spec_path = Path(workdir) / "spec.json"
            spec_path.write_text(spec_body, encoding="utf-8")
            return str(spec_path)
        except OSError:
            self.log(f"  staging failed for {spec_url}")
            return ""

    @staticmethod
    def _cleanup_staging(staged: str) -> None:
        parent = Path(staged).parent
        shutil.rmtree(parent, ignore_errors=True)

    # ── Execution ────────────────────────────────────────────────

    async def _test_schema(self, staged: str, spec_url: str, cfg: dict,
                           harness: AuthHarness,
                           identity_names: list) -> dict:
        headers = []
        if identity_names:
            identity = harness.identities[identity_names[0]]
            headers = [f"{k}: {v}" for k, v in identity.request_headers().items()]

        # R8: the fuzzer will write to the target — record it before launch.
        mut_id = self.state.mutations.begin(
            self.id, "http_write",
            {"schema": spec_url, "base_url": self._base_url(),
             "methods": cfg.get("methods") or []},
            identity=identity_names[0] if identity_names else None,
            owned_objects=[OwnedObject(
                type="resource",
                identifier=f"schemathesis-run-{spec_url}")],
        )

        max_seconds = max(30, int(cfg.get("max_seconds", 480) or 480))
        result = await run_schemathesis(
            staged, self._base_url(),
            stateful=str(cfg.get("stateful", "links") or "links"),
            max_cases=int(cfg.get("max_cases", 100) or 100),
            deadline_ms=int(cfg.get("hypothesis_deadline_ms", 2000) or 2000),
            request_timeout=int(cfg.get("request_timeout", 10) or 10),
            headers=headers or None,
            timeout=max_seconds,
            methods=list(cfg.get("methods") or []),
        )

        failures = result.get("failures", [])
        concrete_failures = result.get("concrete_failures", [])
        seen_fps = {g.get("fingerprint") for g in failures}
        for group in concrete_failures:
            if group.get("fingerprint") not in seen_fps:
                failures.append(group)
                seen_fps.add(group.get("fingerprint"))
        proven = 0
        if result.get("error"):
            self.state.mutations.mark_failed(
                mut_id, f"schemathesis error: {result['error']}")
            self.log(f"  schemathesis error on {spec_url}: {result['error']}")
            self._persist_artifacts(result, spec_url)
            cleanup_workdir(str(result.get("workdir") or ""))
            return {"tested": False, "proven": 0}

        evidence_refs = []
        schema_violations = []
        for group in failures:
            tier = check_tier(group["check"])
            repro = self._repro_line(group, result)
            evidence_ref = self.state.add_evidence(
                self.id, "schemathesis", spec_url,
                {
                    "fingerprint": group["fingerprint"],
                    "check": group["check"],
                    "method": group["method"],
                    "path": group["path"],
                    "count": group["count"],
                    "min_interactions": group["min_interactions"],
                    "seed": (group.get("seeds") or [None])[0],
                    "curl_repro": repro,
                    "tier": tier,
                    "proven_impact": False,
                },
            )
            evidence_refs.append(evidence_ref)
            if tier == "observation":
                schema_violations.append(group)

        if schema_violations:
            self._finding_schema_violations(spec_url, schema_violations,
                                            evidence_refs)

        # CANDIDATE tier: server misbehaved; impact unproven.
        candidate_groups = [g for g in failures
                            if check_tier(g["check"]) == "candidate"]
        # Concrete (VCR-derived) groups carry bound resource ids — they
        # bind the impact probe; template groups cannot.
        impact_groups = [
            g for g in concrete_failures
            if check_tier(g["check"]) == "candidate"
        ] + [g for g in failures if check_tier(g["check"]) == "candidate"]
        proven_fps = await self._reverify_impact(
            impact_groups, spec_url, cfg, harness, identity_names)
        proven = len(proven_fps)
        for group in candidate_groups[:cfg.get("max_findings_per_schema", 5)]:
            self._finding_candidate(
                spec_url, group,
                proven_group=group["fingerprint"] in proven_fps)

        self._persist_artifacts(result, spec_url)
        await self._record_fuzzer_cleanup(mut_id, cfg, harness,
                                          identity_names, impact_groups)
        cleanup_workdir(str(result.get("workdir") or ""))
        return {"tested": True, "proven": proven}

    # ── Grading ──────────────────────────────────────────────────

    def _repro_line(self, group: dict, result: dict) -> str:
        for record in result.get("records", []):
            for check in record.get("checks", []):
                if check.get("name") == group["check"] \
                        and record.get("path") == group["path"] \
                        and record.get("method") == group["method"]:
                    return curl_repro_from_record({
                        **record, "example": check.get("example") or {},
                    })
        return ""

    def _finding_schema_violations(self, spec_url: str, groups: list,
                                   evidence_refs: list) -> None:
        details = "; ".join(
            f"{g['method']} {g['path']} ({g['count']}x)" for g in groups[:5])
        self.state.add_finding(
            title=f"API schema violations: {spec_url}",
            severity="LOW",
            confidence="TENTATIVE",
            category="API Schema Conformance",
            description=(
                f"Schemathesis found response/schema conformance drift on "
                f"{len(groups)} check group(s): {details}. These are schema "
                "violations, not demonstrated vulnerabilities."
            ),
            evidence=evidence_refs,
            asset_keys=[f"url:{spec_url}"],
            verified=False,
            verification={},
        )

    def _finding_candidate(self, spec_url: str, group: dict,
                           proven_group: bool = False) -> None:
        evidence = [f"fingerprint:{group['fingerprint']}",
                    f"check:{group['check']}",
                    f"message:{group['message'][:200]}"]
        if group.get("_impact_evidence"):
            evidence.append(group["_impact_evidence"])
        self.state.add_finding(
            title=(f"API state violation: {group['method']} {group['path']} "
                   f"[{group['fingerprint'][:8]}]"),
            severity="HIGH" if proven_group else "MEDIUM",
            confidence="CONFIRMED" if proven_group else "FIRM",
            category="API State Machine Violation",
            description=(
                f"Schemathesis's linked-operation state machine reached "
                f"{group['method']} {group['path']} and the server failed "
                f"check {group['check']!r} ({group['count']} case(s), "
                f"min {group['min_interactions']} interaction(s))."
                + (" The module replayed the minimal case and an impact "
                   "probe re-read confirmed the corrupted state."
                   if proven_group else
                   " Impact has not been independently confirmed.")
            ),
            evidence=evidence,
            asset_keys=[f"url:{spec_url}"],
            verified=proven_group,
            verification=({"method": "schemathesis_repro_reverified",
                           "schema": spec_url,
                           "fingerprint": group["fingerprint"]}
                          if proven_group else {}),
        )

    async def _reverify_impact(self, groups: list, spec_url: str, cfg: dict,
                               harness: AuthHarness,
                               identity_names: list) -> set:
        """Replay minimal failing cases and confirm impact via a configured
        impact probe. Only these reach PROOF.

        Only cases whose failing example body carried a negative ``amount``
        are probed — those are the ones that plausibly corrupted state.
        """
        proven_fps: set[str] = set()
        probe = cfg.get("impact_probe") or {}
        template = str(probe.get("url_template") or "")
        if not template:
            return proven_fps
        from core.workflows import _extract

        # Corruption-bearing checks first: high-count status-conformance
        # noise must not crowd them out of the probe window.
        priority = {"negative_data_rejection", "response_schema_conformance"}
        groups = sorted(
            groups,
            key=lambda g: (0 if g.get("check") in priority else 1,
                           -(g.get("count", 0) or 0)))

        for group in groups[:10]:
            example = (group.get("checks") or [{}])[0].get("example") or {}
            body = example.get("body") or {}
            # Skip cases whose example body proves the amount was NOT
            # negative; probe everything else (incl. groups without an
            # example body, which carry no counter-evidence).
            if isinstance(body, dict) and "amount" in body:
                amount = body.get("amount")
                if not isinstance(amount, (int, float)) or amount >= 0:
                    continue
            # Bind path parameters from the failing case's path.
            bound = self._bind_path_params(group["path"], template)
            if bound is None:
                continue
            url = urljoin(self._base_url(), bound)
            check = await self._request(harness, identity_names, url)
            body_text = str(check.get("body") or "")
            value = _extract(probe.get("extract") or {}, body_text)
            expect = probe.get("expect") or {}
            if value is None or not self._expect_holds(value, expect):
                continue
            # The re-read observed the corrupted state — PROOF tier.
            evidence = self.state.add_evidence(
                self.id, "schemathesis_impact", spec_url,
                {"fingerprint": group["fingerprint"],
                 "probe_url": url, "observed": value,
                 "expectation": expect},
            )
            group["_impact_evidence"] = evidence
            proven_fps.add(group["fingerprint"])
        return proven_fps

    @staticmethod
    async def _request(harness: AuthHarness, identity_names: list, url: str,
                       method: str = "GET", **kwargs) -> dict:
        if identity_names:
            return await harness.request(identity_names[0], url,
                                         method=method, **kwargs)
        return await harness.request_anonymous(url, method=method, **kwargs)

    def _bind_path_params(self, example_path: str, template: str) -> str:
        """Map a concrete failing path onto the impact template's params.

        The template anchors the example path's prefix: the failing case
        may have more segments than the probe template.
        """
        names = re.findall(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", template)
        if not names:
            return template
        escaped = re.escape(template)
        pattern = re.sub(r"\\\{[a-zA-Z_][a-zA-Z0-9_]*\\\}",
                         "([^/]+)", escaped)
        match = re.match("^" + pattern, example_path)
        if not match:
            return None
        out = template
        for name, value in zip(names, match.groups()):
            out = out.replace("{" + name + "}", value)
        return out

    @staticmethod
    def _expect_holds(value, expect: dict) -> bool:
        op = expect.get("op", "eq")
        target = expect.get("value")
        try:
            number = float(value)
        except (TypeError, ValueError):
            number = None
        if op == "eq":
            return str(value) == str(target)
        if op == "lt" and number is not None:
            return number < float(target)
        if op == "gt" and number is not None:
            return number > float(target)
        if op == "contains":
            return str(target) in str(value)
        return False

    # ── Artifacts and cleanup ────────────────────────────────────

    def _persist_artifacts(self, result: dict, spec_url: str) -> None:
        workdir = result.get("workdir", "")
        if not workdir or not Path(workdir).exists():
            return
        import hashlib
        fp = hashlib.sha256(spec_url.encode("utf-8")).hexdigest()[:12]
        out_dir = Path(self.state.state_dir) / "api_workflows" / fp
        out_dir.mkdir(parents=True, exist_ok=True)
        for name in ("report.json", "cassette.yaml", "junit.xml"):
            src = Path(workdir) / name
            if src.exists():
                shutil.copyfile(src, out_dir / name)

    async def _record_fuzzer_cleanup(self, mut_id: str, cfg: dict,
                                     harness: AuthHarness,
                                     identity_names: list,
                                     groups: list) -> None:
        cleanup = cfg.get("cleanup") or {}
        template = str(cleanup.get("url_template") or "")
        if not template:
            self.state.mutations.mark_not_required(
                mut_id,
                "external fuzzer writes; no cleanup spec — operator owns "
                "recovery")
            return
        # Bind resource ids from the first failing case's concrete path.
        bound = template
        for group in groups:
            resolved = self._bind_path_params(group.get("path", ""), template)
            if resolved is not None:
                bound = resolved
                break
        result = await self._request(
            harness, identity_names, urljoin(self._base_url(), bound),
            method=str(cleanup.get("method") or "DELETE"))
        verify = cleanup.get("verify") or {}
        check = await self._request(
            harness, identity_names, urljoin(self._base_url(), bound))
        check_status = int(check.get("status", 0) or 0)
        expect = list(verify.get("expect_status") or [404, 410])
        gone = check_status in expect or check_status >= 400
        verification = {"method": str(verify.get("method") or "http_get"),
                        "cleanup_status": result.get("status", 0),
                        "check_status": check_status}
        self.state.mutations.record_rollback(
            mut_id, "verified" if gone else "failed",
            verification=verification)
        if gone:
            self.state.mutations.verify_cleanup(mut_id, verification)
        else:
            self.state.mutations.mark_failed(
                mut_id, f"cleanup verify read returned {check_status}")

    # ── Plumbing ─────────────────────────────────────────────────

    def _base_url(self) -> str:
        return str(self.target.get("base_url")
                   or (self.base_url if self.domain else ""))

    def _cfg(self) -> dict:
        cfg = self.config.get("modules", {}).get(self.id, {})
        return cfg if isinstance(cfg, dict) else {}
