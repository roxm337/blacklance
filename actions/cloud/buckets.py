"""Cloud storage — prove that a bucket lists its objects anonymously.

"Cloud Exposure" findings were observations with no prover: the bucket module
reported a readable listing, but no action could re-read it, so the claim was
never promoted and no chain could use it. This action asks anonymously (the
target's session credentials are stripped, or an authenticated client would
"prove" a private bucket), and recognises the listing shapes of the three
providers instead of trusting a 200.

An empty-but-listing response is not data exposure; at least one object name
must be returned, twice.
"""

import json
import re

from actions.registry import action, ActionContext, ActionResult
from tools.wrappers import curl

_GCS_JSON_KIND = "storage#objects"


def _body(raw: dict) -> str:
    return str(raw.get("body") or "")


def _status(raw: dict) -> int:
    return int(raw.get("status") or 0)


def _object_names(body: str) -> list:
    """Object keys in a listing, across S3/GCS XML and GCS JSON."""
    text = body.strip()
    if text.startswith("{") or text.startswith("["):
        try:
            parsed = json.loads(text)
        except (TypeError, ValueError):
            return []
        items = parsed.get("items") if isinstance(parsed, dict) else parsed
        if not isinstance(items, list):
            return []
        names = []
        for item in items[:1000]:
            if isinstance(item, dict):
                name = item.get("name") or item.get("key")
                if name:
                    names.append(str(name))
        return names
    names = [m.group(1) for m in re.finditer(r"<Key>([^<]+)</Key>", body)]
    names += [m.group(1) for m in re.finditer(r"<Name>([^<]+)</Name>", body)]
    return names[:1000]


def _is_listing(body: str) -> bool:
    if _GCS_JSON_KIND in body or "<EnumerationResults" in body:
        return True
    # S3 and GCS-XML share the ListBucketResult root, including an empty
    # listing (no <Contents>), which is still a public bucket.
    return "<ListBucketResult" in body


@action(
    id="cloud.bucket.list",
    risk="SAFE",
    detectability="low",
    requires=["url"],
    produces="VulnCandidate",
    idempotent=True,
    description=(
        "Prove anonymous bucket listing: fetch the bucket URL without session "
        "credentials, recognise S3/GCS/Azure listing shapes, and require at "
        "least one object name twice."
    ),
    category="cloud",
)
async def bucket_list(ctx: ActionContext) -> ActionResult:
    url = str(ctx.params.get("url") or ctx.target or "").strip()
    if not url:
        return ActionResult(False, error="url is required")

    headers = {"User-Agent": "Mozilla/5.0 (compatible; bhs-probe)"}
    if isinstance(ctx.params.get("headers"), dict):
        headers.update(ctx.params["headers"])

    raw = await curl(url, headers=headers, output="full", no_session=True)
    body = _body(raw)
    if _status(raw) != 200:
        return ActionResult(
            False, confidence="TENTATIVE",
            error=f"anonymous listing denied (HTTP {_status(raw)})")
    if not _is_listing(body):
        return ActionResult(
            False, confidence="TENTATIVE",
            error="response is not a bucket listing")

    names = _object_names(body)
    if not names:
        return ActionResult(
            False, confidence="TENTATIVE",
            error="listing is public but contains no object names")

    again = await curl(url, headers=headers, output="full", no_session=True)
    again_names = _object_names(_body(again))
    if not again_names:
        return ActionResult(
            False, confidence="FIRM",
            error="anonymous listing did not reproduce")

    return ActionResult(
        True, confidence="CONFIRMED",
        data={"bucket": url, "object_count": len(again_names),
              "objects": again_names[:25]},
        evidence={"action": "cloud.bucket.list", "object_count": len(again_names),
                  "sample": again_names[:5]},
    )
