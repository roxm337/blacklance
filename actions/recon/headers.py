"""Security headers — re-prove a hardening finding from the live response.

"Hardening Deficiency" and "Security Misconfiguration" findings come from
header checks, but no action could re-read the response, so the graph had no
prover for them. This action fetches the URL twice and reports only headers
that are missing both times; the threshold avoids promoting a single
deliberately-omitted header (common on static hosts) into a finding.

`recon` had no actions at all; this is its first, and it is read-only.
"""

from actions.registry import action, ActionContext, ActionResult
from tools.wrappers import curl

# Baseline set. A missing entries count is reported, and three or more is the
# threshold: one missing header is configuration taste, not a finding.
_CORE = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
)
_THRESHOLD = 3


def _header_names(raw: dict) -> set:
    """Header names from the raw header block, lowercased."""
    names = set()
    for line in str(raw.get("headers") or "").splitlines():
        if not line.strip() or line.lower().startswith("http/"):
            continue
        head, sep, _value = line.partition(":")
        if sep:
            names.add(head.strip().lower())
    return names


def _missing(names: set) -> list:
    return [name for name in _CORE if name not in names]


@action(
    id="recon.security_headers",
    risk="SAFE",
    detectability="low",
    requires=["url"],
    produces="VulnCandidate",
    idempotent=True,
    description=(
        "Prove a hardening deficiency by fetching the URL twice and reporting "
        "security headers absent from both responses (three or more)."
    ),
    category="recon",
)
async def security_headers(ctx: ActionContext) -> ActionResult:
    url = str(ctx.params.get("url") or ctx.target or "").strip()
    if not url:
        return ActionResult(False, error="url is required")
    headers = {"User-Agent": "Mozilla/5.0 (compatible; bhs-probe)"}
    if isinstance(ctx.params.get("headers"), dict):
        headers.update(ctx.params["headers"])

    first = await curl(url, headers=headers, output="full",
                       follow_redirects=False)
    status = int(first.get("status") or 0)
    if not (200 <= status < 400):
        return ActionResult(
            False, confidence="TENTATIVE",
            error=f"endpoint unreachable (HTTP {status})")
    missing = _missing(_header_names(first))
    if len(missing) < _THRESHOLD:
        return ActionResult(
            False, confidence="TENTATIVE",
            error=f"only {len(missing)} core security headers missing",
            data={"missing": missing})

    second = await curl(url, headers=headers, output="full",
                        follow_redirects=False)
    if _missing(_header_names(second)) != missing:
        return ActionResult(
            False, confidence="FIRM",
            error="header set changed between fetches")

    return ActionResult(
        True, confidence="CONFIRMED",
        data={"url": url, "missing": missing,
              "present": [n for n in _CORE if n not in missing]},
        evidence={"action": "recon.security_headers", "missing": missing},
    )
