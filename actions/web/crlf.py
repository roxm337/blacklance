"""CRLF / response splitting — prove header injection, not reflection.

A CRLF finding is only a finding when the injected sequence reaches the
response *headers*: a decoded `%0d%0a` echoed in the body is reflection, and
the action must not promote it. The check therefore looks for our probe header
in the header block, never in the body, and reproduces before confirming.

Baseline first, with a value that cannot contain the marker, so a page that
already sets `X-Bhs-Probe` is excluded rather than counted as injectable.
"""

import secrets

from actions.registry import action, ActionContext, ActionResult
from actions.web.http_util import (body as _body, dedupe_param, session_headers,
                                   status as _status)
from tools.wrappers import curl

_BASELINE = "zz_bhs_9f8"
_PROBE_HEADER = "X-Bhs-Probe"


def _headers_blob(raw: dict) -> str:
    return str(raw.get("headers") or "").lower()


@action(
    id="web.crlf.detect",
    risk="MEDIUM",
    detectability="medium",
    requires=["url", "param"],
    produces="VulnCandidate",
    idempotent=True,
    description=(
        "Prove CRLF/response splitting by injecting a probe header through a "
        "parameter and requiring it in the response header block, twice. A "
        "body reflection is rejected."
    ),
    category="web",
)
async def crlf_detect(ctx: ActionContext) -> ActionResult:
    url = str(ctx.params.get("url") or ctx.target or "").strip()
    param = str(ctx.params.get("param") or "").strip()
    if not url or not param:
        return ActionResult(False, error="url and param are required")
    headers = session_headers(ctx)
    method = str(ctx.params.get("method") or "GET").upper()

    baseline = await curl(dedupe_param(url, param, _BASELINE), method=method,
                          headers=headers, output="full",
                          follow_redirects=False)
    if not (200 <= _status(baseline) < 400):
        return ActionResult(
            False, confidence="TENTATIVE",
            error=f"baseline unreachable (HTTP {_status(baseline)})")
    if _PROBE_HEADER.lower() in _headers_blob(baseline):
        return ActionResult(
            False, confidence="TENTATIVE",
            error="baseline already sets the probe header; not injectable")

    token = secrets.token_hex(6)
    # Literal CR/LF: dedupe_param URL-encodes them to %0D%0A.
    payload = f"1\r\n{_PROBE_HEADER}: {token}"
    probe_url = dedupe_param(url, param, payload)

    raw = await curl(probe_url, method=method, headers=headers, output="full",
                     follow_redirects=False)
    header_blob = _headers_blob(raw)
    if _PROBE_HEADER.lower() not in header_blob or token not in header_blob:
        return ActionResult(
            False, confidence="TENTATIVE",
            error=("injected header not present in the response; a body "
                   "reflection is not response splitting"),
            evidence={"body_reflected": token in _body(raw)})

    again = await curl(probe_url, method=method, headers=headers,
                       output="full", follow_redirects=False)
    again_blob = _headers_blob(again)
    if _PROBE_HEADER.lower() not in again_blob or token not in again_blob:
        return ActionResult(
            False, confidence="FIRM",
            error="header injection did not reproduce")

    return ActionResult(
        True, confidence="CONFIRMED",
        data={"url": probe_url, "param": param, "header": _PROBE_HEADER,
              "status": _status(raw)},
        evidence={"action": "web.crlf.detect", "param": param,
                  "injected_header": _PROBE_HEADER},
    )
