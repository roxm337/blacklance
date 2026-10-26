"""Schemathesis adapter (I2): isolated-process stateful API schema testing.

Runs the schemathesis CLI as an isolated subprocess (local or docker
backend via ``tools.external.run_command``) against discovered OpenAPI /
GraphQL schemas with linked operation sequences, parses its report, and
maps results to typed result kinds:

- tool missing / version below minimum -> ``unsupported``
- exit >1 / unparseable report -> ``error``
- server-error checks (not_a_server_error, status_code_conformance) -> ``candidate``
- success-response schema checks only -> ``observation`` (schema violation,
  not a vulnerability)
- ``proof`` is NEVER produced by the tool alone — the calling module must
  independently re-verify a persisted state change.

Credentials never appear on argv: they are written to a 0600 TOML config
file consumed via ``--config`` (schemathesis >= 3.21). The config and temp
dir are deleted in ``finally``; cassettes and the report are copied out and
redacted before persistence.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from core.validators import redact_for_log
from tools.external import run_command, tool_backend

MIN_VERSION = (3, 21, 0)

# Exit code semantics: 0 = clean, 1 = failures found (normal), >1 = tool error.
EXIT_FINDINGS = 1

# Checks that observe the SERVER misbehaving (candidates).
SERVER_BEHAVIOR_CHECKS = frozenset({
    "not_a_server_error", "status_code_conformance",
})

# Checks that only observe schema-conformance drift (observations).
SCHEMA_CHECKS = frozenset({
    "response_schema_conformance", "content_type_conformance",
    "json_schema", "positive_data_acceptance",
})


def parse_schemathesis_version(text: str) -> Optional[tuple]:
    """Parse ``schemathesis --version`` output like ``4.32.5``."""
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", str(text or ""))
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


# v4 failure-type codes -> normalized check names (v3 names kept where
# they match the check vocabulary the tiers are written against).
_V4_CHECK_MAP = {
    "AcceptedNegativeData": "negative_data_rejection",
    "UndefinedStatusCode": "status_code_conformance",
    "AllowHeaderMismatch": "allow_header_conformance",
    "MissingContentType": "content_type_conformance",
    "ResponseSchemaMismatch": "response_schema_conformance",
    "ServerError": "not_a_server_error",
    "UseAfterFreeCheck": "use_after_free",
}


def _as_list(payload: Any) -> list:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("results", "records", "items", "checks"):
            if isinstance(payload.get(key), list):
                return payload[key]
        # A bare dict only counts as one record when it carries record
        # fields; error envelopes degrade to nothing.
        if any(key in payload for key in ("path", "method", "endpoint",
                                          "status")):
            return [payload]
        return []
    return []


def parse_schemathesis_report(payload: Any) -> list[dict]:
    """Parse a schemathesis JSON run report into typed endpoint records.

    Supports the v3 per-endpoint shape and the v4 failure-group shape
    (``failures: [{type, code, count, operations: ["POST /path/{p}"]}]``).
    Tolerant of drift: unknown shapes degrade to empty records. Record
    schema::

        {"path", "method", "status", "seed", "interactions",
         "checks": [{"name", "value", "message", "response": {...},
                     "example": {...}}]}
    """
    if isinstance(payload, dict) and isinstance(payload.get("failures"), list):
        records = []
        for group in payload["failures"]:
            if not isinstance(group, dict):
                continue
            check_name = _V4_CHECK_MAP.get(
                str(group.get("type") or ""), str(group.get("type") or ""))
            for operation in group.get("operations") or []:
                parts = [p for p in str(operation).split(" ") if p]
                if len(parts) < 2:
                    continue
                records.append({
                    "path": parts[1],
                    "method": parts[0].upper(),
                    "status": "failure",
                    "seed": payload.get("seed"),
                    "interactions": int(group.get("count", 0) or 0),
                    "checks": [{
                        "name": check_name,
                        "value": "FAIL",
                        "message": str(group.get("title") or "")[:500],
                        "response": {},
                        "example": {},
                    }],
                })
        return records
    records: list[dict] = []
    for item in _as_list(payload):
        if not isinstance(item, dict):
            continue
        checks_raw = item.get("checks") or item.get("results") or []
        checks = []
        for check in checks_raw if isinstance(checks_raw, list) else []:
            if not isinstance(check, dict):
                continue
            checks.append({
                "name": str(check.get("name") or ""),
                "value": str(check.get("value") or ""),
                "message": redact_for_log(str(check.get("message") or ""))[:500],
                "response": check.get("response") or {},
                "example": check.get("example") or {},
            })
        records.append({
            "path": str(item.get("path") or item.get("endpoint") or ""),
            "method": str(item.get("method") or "").upper(),
            "status": str(item.get("status") or ""),
            "seed": item.get("seed"),
            "interactions": int(item.get("interactions") or 0),
            "checks": checks,
        })
    return records


def parse_schemathesis_vcr(text: str) -> list[dict]:
    """Parse a schemathesis v4 VCR cassette into CONCRETE failure records.

    Each record carries the real request URI (resource ids bound), the
    request body, the response status, and the failed check names — the
    material the impact re-verification needs.
    """
    try:
        import yaml
        doc = yaml.safe_load(str(text or ""))
    except Exception:
        return []
    if not isinstance(doc, dict):
        return []
    interactions = doc.get("http_interactions") or []
    records: list[dict] = []
    for item in interactions:
        if not isinstance(item, dict):
            continue
        failed_checks = [
            c for c in (item.get("checks") or [])
            if isinstance(c, dict) and c.get("status") in ("FAILURE", "FAIL")
        ]
        if not failed_checks:
            continue
        request = item.get("request") or {}
        uri = str(request.get("uri") or "")
        parsed = urlparse(uri)
        body = request.get("body") or {}
        body_text = str(body.get("string") or "") if isinstance(body, dict) \
            else str(body or "")
        try:
            body_obj = json.loads(body_text) if body_text else {}
        except (ValueError, TypeError):
            body_obj = body_text
        response = item.get("response") or {}
        status = response.get("status") or {}
        code = status.get("code") if isinstance(status, dict) else status
        records.append({
            "path": parsed.path,
            "method": str(request.get("method") or "").upper(),
            "status": "failure",
            "seed": doc.get("seed"),
            "interactions": int(item.get("generation", {}).get("time", 0) or 0)
            or 1,
            "phase": str((item.get("phase") or {}).get("name") or ""),
            "mode": str((item.get("generation") or {}).get("mode") or ""),
            "checks": [{
                "name": str(c.get("name") or ""),
                "value": "FAIL",
                "message": redact_for_log(str(c.get("message") or ""))[:500],
                "response": {"status_code": code},
                "example": {"path": parsed.path,
                            "method": str(request.get("method") or "").upper(),
                            "body": body_obj},
            } for c in failed_checks],
        })
    return records


def parse_schemathesis_junit(text: str) -> list[dict]:
    """Fallback parser for schemathesis junit-xml output."""
    records: list[dict] = []
    for case in re.finditer(
            r"<testcase[^>]*classname=\"([^\"]+)\"[^>]*>"
            r"(.*?)</testcase>", str(text or ""), re.DOTALL):
        classname, inner = case.group(1), case.group(2)
        failure = re.search(r"<failure[^>]*>(.*?)</failure>", inner, re.DOTALL)
        if not failure:
            continue
        parts = [p for p in classname.split(" ") if p]
        path = parts[0] if parts else classname
        method = parts[1] if len(parts) > 1 else ""
        records.append({
            "path": path,
            "method": method.upper(),
            "status": "failure",
            "seed": None,
            "interactions": 0,
            "checks": [{
                "name": "",
                "value": "FAIL",
                "message": redact_for_log(
                    re.sub(r"\s+", " ", failure.group(1)))[:500],
                "response": {},
                "example": {},
            }],
        })
    return records


def summarize_failures(records: list[dict], schema_url: str = "") -> list[dict]:
    """Group failure records by (path, method, check) with stable
    fingerprints for finding dedupe."""
    grouped: dict[tuple, dict] = {}
    for record in records:
        if record.get("status") != "failure":
            continue
        for check in record.get("checks", []):
            if check.get("value") != "FAIL":
                continue
            key = (record.get("path"), record.get("method"), check.get("name"))
            bucket = grouped.setdefault(key, {
                "path": key[0], "method": key[1], "check": key[2],
                "count": 0, "seeds": [], "min_interactions": None,
                "message": "", "fingerprint": "",
            })
            bucket["count"] += 1
            if record.get("seed") is not None:
                bucket["seeds"].append(record["seed"])
            if record.get("interactions"):
                if bucket["min_interactions"] is None \
                        or record["interactions"] < bucket["min_interactions"]:
                    bucket["min_interactions"] = record["interactions"]
                    bucket["message"] = check.get("message") or ""
            elif not bucket["message"]:
                bucket["message"] = check.get("message") or ""
    for bucket in grouped.values():
        base = f"{schema_url}|{bucket['path']}|{bucket['method']}|{bucket['check']}"
        bucket["fingerprint"] = hashlib.sha256(
            base.encode("utf-8")).hexdigest()[:16]
    return sorted(grouped.values(),
                  key=lambda item: -item["count"])


def check_tier(check_name: str) -> str:
    """candidate | observation | other for a failed check name."""
    if check_name in SERVER_BEHAVIOR_CHECKS:
        return "candidate"
    if check_name in SCHEMA_CHECKS:
        return "observation"
    return "candidate"


def schemathesis_available() -> dict:
    """Probe the local/docker tool and version-gate it."""
    import shutil as _shutil
    import sys as _sys
    binary = _shutil.which("schemathesis")
    if not binary:
        venv_bin = Path(_sys.executable).parent / "schemathesis"
        if venv_bin.exists():
            binary = str(venv_bin)
    if not binary:
        from tools.external import tool_backend
        if tool_backend() == "docker":
            return {"available": True, "backend": "docker",
                    "version": None, "unsupported": False,
                    "binary": "schemathesis"}
        return {"available": False, "version": None,
                "unsupported": False, "reason": "schemathesis not installed"}
    import subprocess
    try:
        proc = subprocess.run([binary, "--version"], capture_output=True,
                              text=True, timeout=15)
        version = parse_schemathesis_version(proc.stdout)
    except (OSError, subprocess.TimeoutExpired):
        return {"available": False, "version": None,
                "unsupported": False, "reason": "version probe failed"}
    if version is None:
        return {"available": False, "version": None,
                "unsupported": True, "reason": "unparseable version output"}
    if version < MIN_VERSION:
        return {"available": False, "version": ".".join(map(str, version)),
                "unsupported": True,
                "reason": f"schemathesis {'.'.join(map(str, version))} < "
                          f"{'.'.join(map(str, MIN_VERSION))} "
                          f"(auth config unsupported)"}
    return {"available": True, "backend": "local",
            "version": ".".join(map(str, version)), "unsupported": False,
            "binary": binary}


def write_auth_config(directory: str | Path, headers: list[str],
                      version: Optional[tuple] = None) -> str:
    """Write a 0600 TOML config carrying ONLY request headers (session
    material, never login credentials). Returns the path.

    v4 expects a flat ``headers = {"Name" = "value"}`` object at the root;
    v3 expects a ``[tool.schemathesis]`` table with a list of
    ``"Name: value"`` strings.
    """
    path = Path(directory) / "auth.toml"
    if version and version >= (4, 0, 0):
        pairs = {}
        for line in headers:
            name, _, value = str(line).partition(":")
            if name.strip():
                pairs[name.strip()] = value.strip()
        body = "headers = {" + ", ".join(
            f"{json.dumps(k)} = {json.dumps(v)}" for k, v in pairs.items()
        ) + "}\n"
    else:
        lines = ['[tool.schemathesis]', 'headers = ['] + [
            f'  {json.dumps(line)},' for line in headers
        ] + [']']
        body = "\n".join(lines) + "\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(body)
    return str(path)


async def run_schemathesis(spec_path: str | Path, base_url: str, *,
                           stateful: str = "links",
                           max_cases: int = 100,
                           deadline_ms: int = 2000,
                           request_timeout: int = 10,
                           headers: Optional[list[str]] = None,
                           timeout: int = 480,
                           extra_checks: Optional[list[str]] = None,
                           methods: Optional[list[str]] = None) -> dict:
    """Run one schemathesis pass; returns a typed adapter result.

    Result keys: ``available``, ``backend``, ``version``, ``exit_code``,
    ``records``, ``failures``, ``unsupported``, ``error``, ``report_path``,
    ``cassette_dir``, ``tool_output_tail``.
    """
    probe = schemathesis_available()
    if not probe.get("available"):
        probe["exit_code"] = None
        probe["records"] = []
        return probe

    spec_path = str(spec_path)
    workdir = tempfile.mkdtemp(prefix="schemathesis-", dir=os.getcwd())
    # Stage the spec inside the workdir so the docker backend's /work mount
    # sees it and report/cassette paths are predictable.
    staged_spec = Path(workdir) / "schema.json"
    shutil.copyfile(spec_path, staged_spec)
    report_path = Path(workdir) / "report.json"
    cassette_path = Path(workdir) / "cassette.yaml"
    config_path = ""
    version = probe.get("version")
    version_tuple = parse_schemathesis_version(version) if version else None
    if headers:
        config_path = write_auth_config(workdir, headers, version_tuple)

    # Resolve the binary: run_command does not search the venv bin dir, so
    # the local backend gets the absolute path from the probe. The docker
    # backend keeps the bare name (the image provides it).
    binary = probe.get("binary") or "schemathesis"
    if probe.get("backend") != "local":
        binary = "schemathesis"

    run_args = [
        binary, "run", str(staged_spec),
        ("--url" if version_tuple and version_tuple >= (4, 0, 0)
         else "--base-url"), base_url,
        "--checks", "all",
        "--max-examples", str(max_cases),
        "--max-time", str(timeout),
        "--request-timeout", str(request_timeout),
        "--report", "json", "--report-json-path", str(report_path),
        "--report", "vcr", "--report-vcr-path", str(cassette_path),
        "--report", "junit", "--report-junit-path",
        str(Path(workdir) / "junit.xml"),
        "--workers", "1",
    ]
    if stateful and stateful != "none":
        # v4: links is the stateful phase's native mode; no "links" phase
        # exists. v3 took --stateful links.
        if version_tuple and version_tuple >= (4, 0, 0):
            run_args += ["--phases", "coverage,fuzzing,stateful"]
        else:
            run_args += ["--stateful", stateful]
    if extra_checks:
        run_args += ["--checks", *extra_checks]
    if methods:
        for method in methods:
            run_args += ["--include-method", method.upper()]

    argv = []
    if config_path:
        # --config-file is a GLOBAL option in v4 (before the subcommand);
        # v3 took --config as a run option. Both stay off the argv secret
        # surface either way — the file carries the session material.
        argv = [binary, "--config-file", config_path] + run_args[1:]
    else:
        argv = run_args
    result = await run_command(argv, timeout=timeout + 30)

    exit_code = int(result.get("exit_code", 0) or 0)
    records: list[dict] = []
    error = result.get("error")
    if report_path.exists():
        try:
            records = parse_schemathesis_report(
                json.loads(report_path.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError):
            records = []
    concrete_records: list[dict] = []
    if cassette_path.exists():
        concrete_records = parse_schemathesis_vcr(
            cassette_path.read_text(encoding="utf-8", errors="replace"))
    if not records and not concrete_records and exit_code != 0:
        # Fall back to junit when neither report is available.
        junit = Path(workdir) / "junit.xml"
        if junit.exists():
            records = parse_schemathesis_junit(
                junit.read_text(encoding="utf-8", errors="replace"))

    failures = summarize_failures(records, base_url)
    concrete_failures = summarize_failures(concrete_records, base_url)
    payload = {
        "available": True,
        "backend": tool_backend(),
        "version": probe.get("version"),
        "exit_code": exit_code,
        "records": records,
        "concrete_records": concrete_records,
        "failures": failures,
        "concrete_failures": concrete_failures,
        "unsupported": False,
        "error": None if exit_code <= EXIT_FINDINGS else (
            error or f"schemathesis exited {exit_code}"),
        "report_path": str(report_path) if report_path.exists() else "",
        "cassette_path": str(cassette_path) if cassette_path.exists() else "",
        "workdir": workdir,
        "tool_output_tail": (result.get("stderr", "") or "")[-1000:],
    }
    return payload


def curl_repro_from_record(record: dict) -> str:
    """Best-effort curl reproduction line from a failure record's example.

    Credentials are scrubbed through redact_for_log; the module must
    re-verify independently before any finding claims impact.
    """
    example = record.get("example") or {}
    path = record.get("path") or example.get("path") or ""
    method = (record.get("method") or example.get("method") or "GET").upper()
    body = example.get("body")
    data = ""
    if isinstance(body, (dict, list)):
        from core.redaction import sanitize
        data = json.dumps(sanitize(body))
    elif body is not None:
        data = str(body)
    parts = ["curl", "-X", method, path]
    if data:
        parts += ["--data", redact_for_log(data)[:2000]]
    return " ".join(parts)


def cleanup_workdir(workdir: str) -> None:
    shutil.rmtree(workdir, ignore_errors=True)
