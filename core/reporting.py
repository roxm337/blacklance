"""Report bundle builders and renderers for OSINT Agent."""

from collections import Counter, defaultdict
from datetime import datetime, timezone
import json
import hashlib
from pathlib import Path
from typing import Any

from core.fingerprints import fingerprint as _fingerprint
from core.fingerprints import finding_url as _finding_url
from core.history import (annotate, annotate_assets,
                          load as load_history, regression,
                          save as save_history)
from core.poc import write_pocs
from core.persistence import atomic_json, file_lock
from core.scoring import score_label

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
SEVERITY_RANK = {severity: rank for rank, severity in enumerate(SEVERITIES)}


def _finding_on_target(finding: dict, target: str) -> bool:
    """True unless every URL the finding names is off the engagement host."""
    from core.probe_targets import in_scope_url
    target_text = str(target or "").strip()
    if not target_text:
        return True
    base = target_text if "://" in target_text else f"https://{target_text}"
    urls = []
    for key in finding.get("asset_keys", []) or []:
        value = str(key)
        candidate = value.split(":", 1)[1] if ":" in value else value
        if candidate.startswith(("http://", "https://")):
            urls.append(candidate)
    verification = finding.get("verification") or {}
    if verification.get("url"):
        urls.append(str(verification["url"]))
    if not urls:
        return True
    return any(in_scope_url(url, base, target_text) for url in urls)


def build_report_bundle(state: Any, target: str) -> dict:
    """Build a structured report bundle from persisted investigation state."""
    summary = state.summary()
    findings_all = list(state.findings.get("findings", []))
    # A finding whose only URLs are on somebody else's host is contamination,
    # not a target result. Keep findings without URL assets (posture/TLS/email)
    # because their scope is the engagement itself.
    findings = [item for item in findings_all
                if _finding_on_target(item, target)]
    filtered = len(findings_all) - len(findings)
    assets = list(state.assets.get("nodes", []))
    edges = list(state.assets.get("edges", []))
    evidence = list(state.evidence.get("items", []))
    runs = list(state.module.get("runs", []))

    findings_sorted = sorted(
        findings,
        key=lambda item: (
            int(item.get("risk_score") or 0),
            _severity_sort_value(item.get("severity")),
            str(item.get("created_at", "")),
        ),
        reverse=True,
    )

    severity_counts = {
        severity: sum(1 for item in findings
                      if str(item.get("severity", "")).upper() == severity)
        for severity in SEVERITIES
    }
    risk_scores = [int(item.get("risk_score") or 0) for item in findings]
    asset_counts = Counter(str(item.get("type", "unknown")) for item in assets)
    module_status_counts = Counter(str(run.get("status", "unknown")) for run in runs)

    bundle = {
        "metadata": {
            "target": target,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "report_version": "2.0",
            "output_dir": str(state.output_dir),
        },
        "summary": {
            "assets": len(assets),
            "relations": len(edges),
            "findings": len(findings),
            "out_of_target_filtered": filtered,
            "evidence": len(evidence),
            "requests": summary["total_requests"],
            "waf_detected": summary["waf_detected"],
            "started_at": summary["started_at"],
            "last_action": summary["last_action"],
        },
        "risk": {
            "severity_counts": severity_counts,
            "max_score": max(risk_scores) if risk_scores else 0,
            "average_score": round(sum(risk_scores) / len(risk_scores), 1)
            if risk_scores
            else 0,
            "critical_high": severity_counts["CRITICAL"] + severity_counts["HIGH"],
            "top_findings": [_finding_digest(item) for item in findings_sorted[:10]],
        },
        "assets": {
            "counts_by_type": dict(sorted(asset_counts.items())),
            "high_value": _high_value_assets(assets),
            "samples_by_type": _asset_samples_by_type(assets),
        },
        "patterns": _derive_patterns(assets, edges, findings, summary),
        "recommendations": _derive_recommendations(findings_sorted, assets, summary),
        "modules": {
            "completed": list(summary["modules_completed"]),
            "skipped": list(summary["modules_skipped"]),
            "blocked": list(summary["modules_blocked"]),
            "status_counts": dict(sorted(module_status_counts.items())),
            "runs": [_run_digest(run) for run in runs],
        },
        "evidence": {
            "count": len(evidence),
            "items": [_evidence_digest(item) for item in evidence],
        },
        "findings": findings_sorted,
    }
    return bundle


def write_report_bundle(state: Any, target: str) -> dict:
    """Write markdown and JSON report artifacts into the state's output dir."""
    # Serializes history read-modify-write and matching report exports.
    with file_lock(Path(state.output_dir) / "report.lock"):
        with file_lock(Path(state.output_dir) / "state" / "state.lock"):
            check_revision = getattr(state, "check_revision", None)
            if check_revision:
                check_revision()
            return _write_report_bundle(state, target)


def _write_report_bundle(state: Any, target: str) -> dict:
    bundle = build_report_bundle(state, target)
    output_dir = Path(state.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    paths = {
        "report": output_dir / f"{target}_report.md",
        "executive_summary": output_dir / f"{target}_executive_summary.md",
        "summary": output_dir / f"{target}_summary.json",
        "findings": output_dir / f"{target}_findings.json",
        "sarif": output_dir / f"{target}.sarif",
        "defectdojo": output_dir / f"{target}_defectdojo.json",
    }
    # Reporting/prioritization themselves are not new target observations.
    # Re-exporting identical observed state must not inflate occurrence counts.
    observation = {
        "investigation": state.module.get("investigation_id", ""),
        "runs": [(r.get("id"), r.get("started_at"), r.get("finished_at"),
                  r.get("status")) for r in state.module.get("runs", [])
                 if r.get("module_id") not in
                 ("reporting", "risk_prioritization", "bounty_submission")],
        "findings": [(f.get("id"), f.get("last_seen"), f.get("created_at"))
                     for f in bundle["findings"]],
        "assets": [(a.get("key"), a.get("last_seen"))
                   for a in state.assets.get("nodes", [])],
    }
    observation_id = hashlib.sha256(json.dumps(
        observation, sort_keys=True, default=str).encode()).hexdigest()
    # An unrelated module/asset update must not count old findings as retested.
    # StateManager advances last_seen only when it observes that item again.
    investigation_id = state.module.get("investigation_id", "")
    finding_observations = {
        _fingerprint(f, _finding_url(f)): json.dumps(
            [investigation_id, f.get("last_seen") or f.get("created_at"), f.get("id")])
        for f in bundle["findings"]}
    asset_observations = {
        a.get("key"): json.dumps([investigation_id, a.get("last_seen"), a.get("key")])
        for a in state.assets.get("nodes", [])}
    history_path = output_dir / "findings_history.json"
    annotated, updated, diff = annotate(
        bundle["findings"], load_history(history_path, strict=True),
        run_id=observation_id, observation_ids=finding_observations)
    updated, asset_diff = annotate_assets(
        list(state.assets.get("nodes", [])), updated, run_id=observation_id,
        observation_ids=asset_observations)
    bundle["findings"] = annotated
    bundle["metadata"]["observation_id"] = observation_id
    paths["report"].write_text(render_markdown(bundle))
    paths["executive_summary"].write_text(render_executive_summary(bundle))
    atomic_json(paths["summary"], bundle)
    findings_payload = dict(state.findings)
    findings_payload["findings"] = list(bundle.get("findings") or [])
    atomic_json(paths["findings"], findings_payload)
    atomic_json(paths["sarif"], render_sarif(bundle))
    atomic_json(paths["defectdojo"], render_defectdojo(bundle))
    paths["regression"] = output_dir / f"{target}_regression.json"
    atomic_json(paths["regression"], regression(bundle, diff, asset_diff))
    paths["pocs"] = Path(write_pocs(state, target, bundle, output_dir)["dir"])
    save_history(history_path, updated)
    return {key: str(path) for key, path in paths.items()}


SARIF_LEVELS = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}


def _rule_id(category: str) -> str:
    slug = "".join(ch.lower() if ch.isalnum() else "-" for ch in
                   (category or "finding"))
    return "-".join(part for part in slug.split("-") if part) or "finding"


def render_sarif(bundle: dict) -> dict:
    """SARIF 2.1.0 for pipeline ingestion.

    One rule per finding category, one result per finding. The fingerprint
    is content-derived (category, title, URL) so a re-scan updates the same
    alert instead of opening a duplicate when finding IDs are renumbered.
    """
    findings = list(bundle.get("findings") or [])
    rules = {}
    results = []
    for finding in findings:
        category = str(finding.get("category") or "Uncategorised")
        rule_id = _rule_id(category)
        level = SARIF_LEVELS.get(str(finding.get("severity") or "").upper(),
                                 "note")
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": category,
            "shortDescription": {"text": category},
            "defaultConfiguration": {"level": level},
        })
        url = _finding_url(finding)
        message = str(finding.get("description") or finding.get("title") or "")
        result = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message},
            "partialFingerprints": {
                "osintAgent/v1": _fingerprint(finding, url)},
            "properties": {
                "severity": finding.get("severity"),
                "confidence": finding.get("confidence"),
                "verified": bool(finding.get("verified")),
                "risk_score": finding.get("risk_score"),
                "category": category,
            },
        }
        if url:
            result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": url},
                    "region": {"startLine": 1},
                }
            }]
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "OSINT Agent",
                    "version": "2.0",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }


DEFECTDOJO_SEVERITY = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "INFO": "Info",
}
DEFECTDOJO_RANK = {"Critical": "S0", "High": "S1", "Medium": "S2",
                   "Low": "S3", "Info": "S4"}


def render_defectdojo(bundle: dict) -> dict:
    """DefectDojo "Generic Findings Import" payload.

    `unique_id_from_tool` uses the same content fingerprint as SARIF, so the
    importer updates a finding across re-scans instead of duplicating it when
    finding IDs are renumbered.
    """
    findings = []
    for finding in bundle.get("findings") or []:
        url = _finding_url(finding)
        severity = DEFECTDOJO_SEVERITY.get(
            str(finding.get("severity") or "").upper(), "Info")
        verification = finding.get("verification") or {}
        description = str(finding.get("description") or "")
        if verification:
            description += "\n\nVerification: " + json.dumps(
                verification, default=str)
        evidence = finding.get("evidence") or []
        if evidence:
            description += "\n\nEvidence:\n" + "\n".join(
                f"- {str(item)[:400]}" for item in evidence[:10])
        item = {
            "title": str(finding.get("title") or "(untitled)"),
            "severity": severity,
            "numerical_severity": DEFECTDOJO_RANK[severity],
            "description": description.strip(),
            "active": True,
            "verified": bool(finding.get("verified")),
            "false_p": False,
            "duplicate": False,
            "dynamic_finding": bool(url),
            "static_finding": not bool(url),
            "unique_id_from_tool": _fingerprint(finding, url),
            "component_name": url or str(
                (bundle.get("metadata") or {}).get("target") or ""),
            "date": str(finding.get("created_at") or ""),
            "endpoints": [url] if url else [],
        }
        if finding.get("risk_score") is not None:
            item["tags"] = [f"risk:{finding['risk_score']}"]
        findings.append(item)
    return {
        "findings": findings,
        "metadata": {
            "generated_at": (bundle.get("metadata") or {}).get("generated_at"),
            "tool": "OSINT Agent",
            "target": (bundle.get("metadata") or {}).get("target"),
        },
    }


def render_markdown(bundle: dict) -> str:
    metadata = bundle["metadata"]
    summary = bundle["summary"]
    risk = bundle["risk"]
    findings_all = bundle["findings"]
    verified_count = sum(1 for f in findings_all if f.get("verified"))
    unverified_count = len(findings_all) - verified_count

    lines = [
        f"# OSINT Investigation Report: {metadata['target']}",
        "",
        f"**Generated:** {_format_iso(metadata['generated_at'])}",
        f"**Report Version:** {metadata['report_version']}",
        f"**Output Directory:** `{metadata['output_dir']}`",
        "",
        "## Executive Summary",
        "",
        _executive_narrative(bundle),
        "",
        "## Risk Overview",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Assets | {summary['assets']} |",
        f"| Relations | {summary['relations']} |",
        f"| Findings | {summary['findings']} |",
        f"| └ Verified | {verified_count} |",
        f"| └ Unverified | {unverified_count} |",
        f"| Evidence Items | {summary['evidence']} |",
        f"| Requests Made | {summary['requests']} |",
        f"| WAF Detected | {_yes_no(summary['waf_detected'])} |",
        f"| Max Risk Score | {risk['max_score']}/100 ({score_label(risk['max_score'])}) |",
        f"| Average Risk Score | {risk['average_score']}/100 |",
        f"| Critical/High Findings | {risk['critical_high']} |",
        "",
        "### Severity Distribution",
        "",
        "| Severity | Count |",
        "|---|---:|",
    ]
    for severity in SEVERITIES:
        lines.append(f"| {severity} | {risk['severity_counts'].get(severity, 0)} |")

    lines.extend([
        "",
        "## Signal Quality",
        "",
        f"- **Verified findings:** {verified_count} — active confirmation ran; "
        f"the method is recorded per finding.",
        f"- **Unverified findings:** {unverified_count} — signal only; "
        f"validate manually before submitting to a bounty program.",
        "",
        "Verified findings passed at least one active check: response-body match, "
        "differential response diff, real DNS zone-transfer records returned, "
        "HTTP 200 with content, platform-specific signature match, or similar. "
        "Unverified findings are strong heuristics that warrant manual triage.",
        "",
    ])

    lines.extend([
        "",
        "## Top Findings",
        "",
    ])
    if risk["top_findings"]:
        lines.extend([
            "| ID | Verified | Severity | Score | Title | Category |",
            "|---|---|---|---:|---|---|",
        ])
        for item in risk["top_findings"]:
            verified = bool(item.get("verified", False))
            tag = "✔" if verified else "○"
            lines.append(
                f"| {_cell(item['id'])} | {tag} | {_cell(item['severity'])} | "
                f"{item['risk_score']} | {_cell(item['title'])} | "
                f"{_cell(item['category'])} |"
            )
    else:
        lines.append("No findings were recorded.")

    lines.extend([
        "",
        "## Prioritized Recommendations",
        "",
    ])
    for recommendation in bundle["recommendations"]:
        lines.append(f"- {recommendation}")

    lines.extend([
        "",
        "## Attack Surface Patterns",
        "",
    ])
    if bundle["patterns"]:
        for pattern in bundle["patterns"]:
            lines.append(f"- **{_escape_text(pattern['title'])}:** {_escape_text(pattern['detail'])}")
    else:
        lines.append("- No notable cross-asset patterns were identified.")

    lines.extend([
        "",
        "## Detailed Findings",
        "",
    ])
    if bundle["findings"]:
        for severity in SEVERITIES:
            findings = [
                item for item in bundle["findings"]
                if str(item.get("severity", "")).upper() == severity
            ]
            if not findings:
                continue
            lines.extend([f"### {severity}", ""])
            # Verified findings first within each severity bucket.
            findings.sort(key=lambda f: bool(f.get("verified")), reverse=True)
            for finding in findings:
                lines.extend(_render_finding(finding, bundle["evidence"]["items"]))
    else:
        lines.append("No detailed findings were recorded.")

    lines.extend(_render_evidence_index(bundle["evidence"]["items"]))
    lines.extend(_render_module_ledger(bundle["modules"]))
    lines.extend(_render_visual_evidence(bundle["assets"]))
    lines.extend(_render_asset_inventory(bundle["assets"]))
    lines.extend([
        "",
        "---",
        "",
        f"*Generated by OSINT Agent at {_format_iso(metadata['generated_at'])}*",
        "",
    ])
    return "\n".join(lines)


def render_executive_summary(bundle: dict) -> str:
    metadata = bundle["metadata"]
    risk = bundle["risk"]
    lines = [
        f"# Executive Summary: {metadata['target']}",
        "",
        _executive_narrative(bundle),
        "",
        "## Immediate Priorities",
        "",
    ]
    for recommendation in bundle["recommendations"][:5]:
        lines.append(f"- {recommendation}")
    lines.extend([
        "",
        "## Highest-Risk Findings",
        "",
    ])
    if risk["top_findings"]:
        for item in risk["top_findings"][:5]:
            lines.append(
                f"- {item['id']} [{item['severity']} {item['risk_score']}/100]: "
                f"{_escape_text(item['title'])}"
            )
    else:
        lines.append("- No findings were recorded.")
    lines.append("")
    return "\n".join(lines)


def _render_finding(finding: dict, evidence_items: list[dict]) -> list[str]:
    evidence_by_id = {item.get("id"): item for item in evidence_items}
    risk_score = int(finding.get("risk_score") or 0)
    verified = bool(finding.get("verified", False))
    tag = "✔ VERIFIED" if verified else "○ UNVERIFIED"
    lines = [
        f"#### [{tag}] {_escape_text(finding.get('id', 'FINDING'))}: "
        f"{_escape_text(finding.get('title', 'Untitled Finding'))}",
        "",
        f"- **Verification:** {tag}",
        f"- **Risk Score:** {risk_score}/100 ({score_label(risk_score)})",
        f"- **Confidence:** {_escape_text(finding.get('confidence', ''))}",
        f"- **Category:** {_escape_text(finding.get('category', ''))}",
        f"- **Description:** {_escape_text(finding.get('description', ''))}",
    ]
    cwe = finding.get("cwe") or []
    if cwe:
        lines.append(f"- **CWE:** {', '.join(_escape_text(str(c)) for c in cwe)}")
    if finding.get("owasp"):
        lines.append(f"- **OWASP:** {_escape_text(finding.get('owasp'))}")
    if finding.get("first_seen") or finding.get("last_seen"):
        lines.append(
            f"- **Observed:** first {_escape_text(str(finding.get('first_seen', '-')))} / "
            f"last {_escape_text(str(finding.get('last_seen', '-')))}")
    if finding.get("verification"):
        v = finding["verification"]
        # Chain-executor proofs record action_id/selected_because/url/param;
        # module proofs record method. Render whichever shape is present —
        # previously only `method` was read, so executor proofs rendered
        # as verified-with-no-method-shown.
        method = (v.get("method") or v.get("action_id") or "").strip()
        if method:
            lines.append(f"- **Verification Method:** `{_escape_text(method)}`")
        if v.get("selected_because"):
            lines.append(f"- **Selected Because:** {_escape_text(v['selected_because'])}")
        if v.get("url"):
            lines.append(f"- **Verified URL:** `{_escape_text(v['url'])}`")
        if v.get("param"):
            lines.append(f"- **Verified Parameter:** `{_escape_text(v['param'])}`")
    if finding.get("asset_keys"):
        lines.append("- **Affected Assets:**")
        for asset_key in finding["asset_keys"]:
            lines.append(f"  - `{_escape_text(asset_key)}`")
    if finding.get("evidence"):
        lines.append("- **Evidence:**")
        for evidence in finding["evidence"]:
            lines.append(f"  - {_escape_text(evidence)}")
    if finding.get("evidence_refs"):
        lines.append("- **Evidence Files:**")
        for evidence_ref in finding["evidence_refs"]:
            item = evidence_by_id.get(evidence_ref, {})
            path = item.get("path", evidence_ref)
            lines.append(f"  - `{_escape_text(path)}`")
    reproduce = _reproduce_lines(finding)
    if reproduce:
        lines.append("- **Reproduce:**")
        lines.extend(f"  - {_escape_text(line)}" if line else "  -"
                     for line in reproduce)
    if finding.get("remediation"):
        lines.append(f"- **Remediation:** {_escape_text(finding['remediation'])}")
    lines.append("")
    return lines


def _reproduce_lines(finding: dict) -> list[str]:
    """One re-run command per finding, read-only by construction.

    The bounty index already renders per-category PoCs; the main report
    showed the proof shape but never the command. A verified finding
    without a re-run line is a claim the reader cannot check, so this
    mirrors the same sources: verification URL first, then the first
    http asset key as fallback. Unverified findings get nothing — there
    is nothing proven to reproduce.
    """
    if not finding.get("verified"):
        return []
    verification = finding.get("verification") or {}
    url = str(verification.get("url") or "").strip()
    if not url:
        for key in finding.get("asset_keys", []) or []:
            candidate = str(key).split(":", 1)[1] if ":" in str(key) else ""
            if candidate.startswith(("http://", "https://")):
                url = candidate
                break
    if not url:
        return []
    method = str(verification.get("method") or verification.get("action_id")
                 or "").strip()
    param = str(verification.get("param") or "").strip()
    if param and "?" not in url:
        return [f"curl -i -sS --max-time 25 '{url}?{param}=PROBE'  # {method}"]
    if method.startswith("batch_"):
        return [f"curl -sS --max-time 25 -X POST -H 'Content-Type: application/json' "
                f"-d '[{{\"query\":\"{{ __typename }}\"}},{{\"query\":\"{{ __typename }}\"}}]' "
                f"'{url}'  # {method}"]
    if "introspection" in method or "graphql" in method or "get_query" in method \
            or "field_suggestion" in method:
        return [f"curl -sS --max-time 25 -X POST -H 'Content-Type: application/json' "
                f"-d '{{\"query\":\"{{ __typename }}\"}}' '{url}'  # {method}"]
    if method:
        return [f"curl -i -sS --max-time 25 '{url}'  # {method}"]
    return [f"curl -i -sS --max-time 25 '{url}'"]


def _render_evidence_index(items: list[dict]) -> list[str]:
    lines = ["", "## Evidence Index", ""]
    if not items:
        lines.append("No evidence files were recorded.")
        return lines
    lines.extend([
        "| ID | Module | Type | Subject | Path |",
        "|---|---|---|---|---|",
    ])
    for item in items:
        lines.append(
            f"| {_cell(item.get('id', ''))} | {_cell(item.get('module_id', ''))} | "
            f"{_cell(item.get('type', ''))} | {_cell(item.get('subject', ''))} | "
            f"`{_cell(item.get('path', ''))}` |"
        )
    return lines


def _render_module_ledger(modules: dict) -> list[str]:
    lines = [
        "",
        "## Module Run Ledger",
        "",
        f"**Completed:** {_join_or_dash(modules['completed'])}",
        f"**Skipped:** {_join_or_dash(modules['skipped'])}",
        f"**Blocked:** {_join_or_dash(modules['blocked'])}",
        "",
    ]
    runs = modules["runs"]
    if not runs:
        lines.append("No module run ledger entries were recorded.")
        return lines
    lines.extend([
        "| Run | Stage | Module | Status | Requests | Assets Added | Findings Added | Duration |",
        "|---|---:|---|---|---:|---:|---:|---:|",
    ])
    for run in runs:
        lines.append(
            f"| {_cell(run.get('id', ''))} | {run.get('stage', 0)} | "
            f"{_cell(run.get('module_id', ''))} | {_cell(run.get('status', ''))} | "
            f"{run.get('requests', 0)} | {run.get('assets_added', 0)} | "
            f"{run.get('findings_added', 0)} | {_cell(run.get('duration', ''))} |"
        )
    return lines


def _render_asset_inventory(assets: dict) -> list[str]:
    lines = ["", "## Asset Inventory", ""]
    if not assets["counts_by_type"]:
        lines.append("No assets were recorded.")
        return lines
    lines.extend([
        "### Counts by Type",
        "",
        "| Type | Count |",
        "|---|---:|",
    ])
    for asset_type, count in assets["counts_by_type"].items():
        lines.append(f"| {_cell(asset_type)} | {count} |")
    lines.extend(["", "### Representative Assets", ""])
    for asset_type, samples in assets["samples_by_type"].items():
        lines.append(f"**{_escape_text(asset_type)}**")
        for sample in samples:
            lines.append(f"- `{_escape_text(sample)}`")
        lines.append("")
    return lines


def _render_visual_evidence(assets: dict) -> list[str]:
    screenshots = assets["samples_by_type"].get("screenshot_target", [])
    if not screenshots:
        return []
    lines = ["", "## Visual Evidence", ""]
    for target in screenshots[:20]:
        lines.append(f"- `{_escape_text(target)}`")
    return lines


def _derive_recommendations(findings: list[dict], assets: list[dict], summary: dict) -> list[str]:
    recommendations = []
    high_risk = [
        item for item in findings
        if int(item.get("risk_score") or 0) >= 70
        or str(item.get("severity", "")).upper() in {"CRITICAL", "HIGH"}
    ]
    if high_risk:
        recommendations.append(
            "Prioritize validation and remediation of critical/high findings before "
            "expanding active testing."
        )
    if summary["waf_detected"]:
        recommendations.append(
            "Review WAF/rate-limit behavior before active modules to avoid noisy or blocked scans."
        )
    if any(str(item.get("type")) in {"webapp", "url"} for item in assets):
        recommendations.append(
            "Run crawl and parameter discovery against live web applications to convert paths into test cases."
        )
    if any(str(item.get("type")) in {"bucket", "cloud"} for item in assets):
        recommendations.append(
            "Validate cloud storage exposure and ownership before creating a bounty submission."
        )
    if any("takeover" in str(item.get("category", "")).lower() for item in findings):
        recommendations.append(
            "Confirm dangling DNS or takeover candidates with non-destructive proof before escalation."
        )
    if not recommendations:
        recommendations.append(
            "Continue enrichment with passive APIs and evidence collection before intrusive testing."
        )
    return recommendations


def _derive_patterns(
    assets: list[dict], edges: list[dict], findings: list[dict], summary: dict
) -> list[dict]:
    asset_counts = Counter(str(item.get("type", "unknown")) for item in assets)
    edge_counts = Counter(str(item.get("type", "unknown")) for item in edges)
    categories = Counter(str(item.get("category", "Unknown")) for item in findings)
    patterns = []

    if asset_counts.get("subdomain", 0) >= 20:
        patterns.append({
            "title": "Large subdomain surface",
            "detail": f"{asset_counts['subdomain']} subdomains discovered; prioritize live services and ownership validation.",
        })
    if asset_counts.get("webapp", 0) or asset_counts.get("url", 0):
        patterns.append({
            "title": "Web application concentration",
            "detail": "Live web assets are present; crawl, parameter discovery, and screenshot triage should be next.",
        })
    if edge_counts:
        strongest = edge_counts.most_common(1)[0]
        patterns.append({
            "title": "Dominant relationship type",
            "detail": f"`{strongest[0]}` relationships account for {strongest[1]} graph edges.",
        })
    for category, count in categories.most_common(3):
        if count:
            patterns.append({
                "title": f"{category} finding cluster",
                "detail": f"{count} finding(s) share this category.",
            })
    if summary["modules_blocked"]:
        patterns.append({
            "title": "Blocked coverage",
            "detail": f"{len(summary['modules_blocked'])} module(s) were blocked and may hide untested surface.",
        })
    return patterns


def _asset_samples_by_type(assets: list[dict]) -> dict:
    grouped = defaultdict(list)
    for asset in assets:
        asset_type = str(asset.get("type", "unknown"))
        if len(grouped[asset_type]) < 10:
            grouped[asset_type].append(str(asset.get("value", asset.get("key", ""))))
    return dict(sorted(grouped.items()))


def _high_value_assets(assets: list[dict]) -> list[dict]:
    high_value_types = {"webapp", "url", "ip", "bucket", "cloud", "dns_takeover"}
    selected = []
    for asset in assets:
        if str(asset.get("type")) in high_value_types:
            selected.append({
                "type": asset.get("type", ""),
                "key": asset.get("key", ""),
                "value": asset.get("value", ""),
                "confidence": asset.get("confidence", ""),
            })
        if len(selected) >= 25:
            break
    return selected


def _finding_digest(finding: dict) -> dict:
    return {
        "id": finding.get("id", ""),
        "title": finding.get("title", ""),
        "severity": finding.get("severity", ""),
        "confidence": finding.get("confidence", ""),
        "risk_score": int(finding.get("risk_score") or 0),
        "category": finding.get("category", ""),
        "verified": bool(finding.get("verified", False)),
        "asset_keys": list(finding.get("asset_keys", [])),
        "evidence_refs": list(finding.get("evidence_refs", [])),
    }


def _run_digest(run: dict) -> dict:
    started_at = run.get("started_at")
    finished_at = run.get("finished_at")
    return {
        "id": run.get("id", ""),
        "module_id": run.get("module_id", ""),
        "stage": run.get("stage", 0),
        "detectability": run.get("detectability", ""),
        "status": run.get("status", ""),
        "requests": run.get("requests", 0),
        "assets_added": run.get("assets_added", 0),
        "findings_added": run.get("findings_added", 0),
        "started_at": started_at,
        "finished_at": finished_at,
        "duration": _duration(started_at, finished_at),
        "error": run.get("error", ""),
    }


def _evidence_digest(item: dict) -> dict:
    return {
        "id": item.get("id", ""),
        "module_id": item.get("module_id", ""),
        "type": item.get("type", ""),
        "subject": item.get("subject", ""),
        "path": item.get("path", ""),
        "created_at": item.get("created_at", ""),
        "schema_version": item.get("schema_version"),
        "sha256": item.get("sha256", ""),
        "size_bytes": item.get("size_bytes"),
    }


def _executive_narrative(bundle: dict) -> str:
    summary = bundle["summary"]
    risk = bundle["risk"]
    target = bundle["metadata"]["target"]
    return (
        f"The investigation for `{_escape_text(target)}` identified "
        f"{summary['assets']} assets, {summary['relations']} relations, "
        f"{summary['findings']} findings, and {summary['evidence']} evidence items. "
        f"The highest current risk score is {risk['max_score']}/100 "
        f"({score_label(risk['max_score'])}), with {risk['critical_high']} "
        "critical/high finding(s) requiring priority review."
    )


def _duration(started_at: str | None, finished_at: str | None) -> str:
    if not started_at or not finished_at:
        return ""
    try:
        started = datetime.fromisoformat(started_at)
        finished = datetime.fromisoformat(finished_at)
    except ValueError:
        return ""
    seconds = int((finished - started).total_seconds())
    if seconds < 0:
        return ""
    return f"{seconds}s"


def _severity_sort_value(severity: str | None) -> int:
    value = str(severity or "INFO").upper()
    return len(SEVERITIES) - SEVERITY_RANK.get(value, len(SEVERITIES) - 1)


def _format_iso(value: str) -> str:
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return value
    return dt.strftime("%Y-%m-%d %H:%M UTC")


def _join_or_dash(values: list[str]) -> str:
    return ", ".join(values) if values else "-"


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


def _cell(value: Any) -> str:
    return _escape_text(value).replace("|", "\\|").replace("\n", " ")


def _escape_text(value: Any) -> str:
    return str(value).replace("\r", " ").strip()
