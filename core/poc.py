"""Re-runnable proof-of-concept artifacts for verified findings.

The report already carried a one-line curl. That is enough to show the shape of
a request but not enough to hand someone a working reproduction: the method,
body, headers and the value that proves the result were missing, and the line
was assembled from a heuristic that ignored the evidence it had captured.

This module turns a verified finding into a directory of artifacts — a shell
script, a dependency-free Python script, and a short markdown note — using the
request data the verification and evidence actually recorded. Credentials are
deliberately not copied into the scripts: a PoC that leaks a live session token
is a second finding, so auth is left to the operator.
"""

import json
import shlex
from dataclasses import dataclass, field
from pathlib import Path

from core.redaction import sensitive_key
from core.validators import inject_param, redact_for_log

URL_KEYS = ("url", "test_url", "probe_url", "payload_url", "target", "endpoint")
BODY_KEYS = ("body", "data", "payload_body", "post_data")
SAFE_HEADER_KEYS = ("content-type", "accept", "accept-language", "origin",
                    "referer", "user-agent", "x-requested-with")
SECRET_HEADER_HINTS = ("authorization", "cookie", "token", "secret", "key")


@dataclass
class RequestSpec:
    url: str = ""
    method: str = "GET"
    headers: dict = field(default_factory=dict)
    body: str = ""
    param: str = ""
    payload: str = ""
    marker: str = ""
    note: str = ""


def _load_evidence(state, finding: dict) -> list:
    """Read the evidence files this finding references, if they exist."""
    items = {str(item.get("id")): item
             for item in (state.evidence.get("items") or [])}
    data = []
    for ref in finding.get("evidence_refs") or []:
        item = items.get(str(ref))
        if not item:
            continue
        try:
            doc = json.loads((Path(state.output_dir) / item["path"]).read_text())
        except (OSError, ValueError, KeyError):
            continue
        if isinstance(doc.get("data"), (dict, list, str)):
            data.append(doc["data"])
    return data


def _first_url(blobs: list, fallback: str = "") -> str:
    for blob in blobs:
        if not isinstance(blob, dict):
            continue
        for key in URL_KEYS:
            value = blob.get(key)
            if isinstance(value, str) and value.startswith(("http://", "https://")):
                return value
    return fallback


def _safe_headers(value) -> dict:
    if isinstance(value, str):
        parsed = {}
        for line in value.splitlines():
            if ":" in line:
                name, _, header_value = line.partition(":")
                parsed[name.strip()] = header_value.strip()
        value = parsed
    if not isinstance(value, dict):
        return {}
    headers = {}
    for name, header_value in value.items():
        lowered = str(name).lower()
        if lowered not in SAFE_HEADER_KEYS:
            continue
        if any(hint in lowered for hint in SECRET_HEADER_HINTS):
            continue
        headers[str(name)] = str(header_value)
    return headers


def _merged_blob(finding: dict, evidence: list) -> dict:
    blob = dict(finding.get("verification") or {})
    for extra in evidence:
        if isinstance(extra, dict):
            for key, value in extra.items():
                blob.setdefault(key, value)
    return blob


def build_request(finding: dict, evidence: list | None = None) -> RequestSpec:
    """Assemble the most specific request the recorded data supports."""
    blob = _merged_blob(finding, evidence or [])

    url = _first_url([blob])
    if not url:
        for key in finding.get("asset_keys") or []:
            candidate = str(key).split(":", 1)[1] if ":" in str(key) else ""
            if candidate.startswith(("http://", "https://")):
                url = candidate
                break

    param = str(blob.get("param") or "").strip()
    payload = str(blob.get("payload") or "").strip()
    if url and param and payload:
        url = inject_param(url, param, payload)
    # Evidence may retain a session token in a query string. Strip it like
    # every other persisted artifact, but keep a payload the finding is
    # deliberately testing even when its parameter name looks sensitive.
    url = redact_for_log(url)
    if url and param and payload and sensitive_key(param):
        url = inject_param(url, param, payload)

    method = str(blob.get("method") or blob.get("http_method") or "").upper()
    body = ""
    for key in BODY_KEYS:
        value = blob.get(key)
        if isinstance(value, str):
            body = value
            break
    if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"):
        method = "POST" if body else "GET"

    marker = str(blob.get("marker") or "").strip()
    return RequestSpec(
        url=url, method=method, headers=_safe_headers(blob.get("headers")),
        body=body, param=param, payload=payload,
        marker=marker or payload,
        note=str(blob.get("method") or ""),
    )


def render_shell(finding: dict, spec: RequestSpec) -> str:
    lines = [
        "#!/usr/bin/env bash",
        f"# PoC for {finding.get('id')}: {finding.get('title')}",
        f"# Verification: {spec.note or 'see report'}",
        "# Add any required authentication yourself; the generator",
        "# deliberately does not copy cookies or bearer tokens.",
    ]
    if spec.marker:
        lines.append(f"# Expected proof: the response contains {spec.marker!r}")
    lines += ["set -euo pipefail", ""]
    command = f"curl -i -sS --max-time 25 -X {spec.method}"
    for name, value in spec.headers.items():
        command += f" -H {shlex.quote(f'{name}: {value}')}"
    if spec.body:
        command += f" --data-raw {shlex.quote(spec.body)}"
    command += " " + shlex.quote(spec.url)
    lines.append(command)
    return "\n".join(lines) + "\n"


def render_python(finding: dict, spec: RequestSpec) -> str:
    data = f"{spec.body!r}.encode()" if spec.body else "None"
    headers = json.dumps(spec.headers, indent=4)
    marker = json.dumps(spec.marker)
    return f'''#!/usr/bin/env python3
"""PoC for {finding.get('id')}: {finding.get('title')}

Verification: {spec.note or 'see report'}
Add authentication yourself; no cookies or tokens are embedded.
"""

import json
import urllib.error
import urllib.request

URL = {spec.url!r}
METHOD = {spec.method!r}
HEADERS = {headers}
DATA = {data}
EXPECTED = {marker}

request = urllib.request.Request(URL, data=DATA, headers=HEADERS,
                                 method=METHOD)
try:
    with urllib.request.urlopen(request, timeout=25) as response:
        status = response.status
        body = response.read().decode("utf-8", "replace")
except urllib.error.HTTPError as error:
    status = error.code
    body = error.read().decode("utf-8", "replace")

print(f"HTTP {{status}}")
print(body[:2000])
if EXPECTED and EXPECTED in body:
    print(f"PoC reproduced: response contains {{EXPECTED!r}}")
else:
    print("Expected marker not found; the finding may be stale.")
'''


def render_markdown(finding: dict, spec: RequestSpec) -> str:
    lines = [
        f"# {finding.get('id')}: {finding.get('title')}",
        "",
        f"- Severity: {finding.get('severity')}",
        f"- Confidence: {finding.get('confidence')}",
        f"- Verification: {spec.note or 'see report'}",
        f"- Request: `{spec.method} {spec.url}`",
    ]
    if spec.param:
        lines.append(f"- Parameter: `{spec.param}`")
    if spec.marker:
        lines.append(f"- Expected proof: response contains `{spec.marker}`")
    if spec.body:
        lines += ["", "## Body", "", "```", spec.body, "```"]
    lines += ["", "## Reproduce", "",
              "```bash", f"./{finding.get('id')}.sh", "```"]
    return "\n".join(lines) + "\n"


def write_pocs(state, target: str, bundle: dict, output_dir: Path) -> dict:
    """Write one PoC directory per verified finding and a manifest."""
    target = str(target)
    root = Path(output_dir) / f"{_slug(target)}_pocs"
    root.mkdir(parents=True, exist_ok=True)
    manifest = []
    for finding in bundle.get("findings") or []:
        if not finding.get("verified"):
            continue
        spec = build_request(finding, _load_evidence(state, finding))
        if not spec.url:
            continue
        stem = _slug(str(finding.get("id") or "finding"))
        (root / f"{stem}.sh").write_text(render_shell(finding, spec))
        (root / f"{stem}.py").write_text(render_python(finding, spec))
        (root / f"{stem}.md").write_text(render_markdown(finding, spec))
        manifest.append({
            "id": finding.get("id"),
            "title": finding.get("title"),
            "severity": finding.get("severity"),
            "url": spec.url,
            "method": spec.method,
            "files": [f"{stem}.sh", f"{stem}.py", f"{stem}.md"],
        })
    (root / "index.json").write_text(json.dumps(
        {"target": target, "count": len(manifest), "pocs": manifest},
        indent=2, default=str))
    return {"dir": str(root), "count": len(manifest)}


def _slug(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in "-_." else "-"
                      for ch in value)
    return "-".join(part for part in cleaned.split("-") if part) or "poc"
