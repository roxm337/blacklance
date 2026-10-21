"""Stage 4: Web cache poisoning probe.

A cache serves one stored response to many users. If the application reflects
an *unkeyed* request input — a header the cache ignores when computing its key
— into a cacheable response, an attacker poisons that cached entry for every
subsequent visitor (redirect to attacker host, injected script, broken page).

The check is the PortSwigger methodology, made black-box-safe:
  1. baseline GET — record what the response reflects and whether it is
     cacheable (Cache-Control, Age, X-Cache, CDN cache headers).
  2. resend with an unkeyed header (X-Forwarded-Host/Scheme/…) carrying a
     unique marker.
  3. a finding fires only when the *unique marker* comes back in the body or a
     redirect target AND the response is cacheable — reflection alone is not
     poisoning, and a cacheable-but-unreflected response is not either.

Every probe is a GET; nothing is actually left poisoned (the marker host does
not resolve), and the module does not hammer — a handful of headers once.
"""

import re
import uuid

from core.site_profile import get_profile
from modules.base import BaseModule
from tools.wrappers import curl, curl_with_status

# Unkeyed inputs a cache commonly ignores but an app commonly trusts.
UNKEYED_HEADERS = (
    "X-Forwarded-Host",
    "X-Forwarded-Scheme",
    "X-Forwarded-Server",
    "X-Host",
    "X-Forwarded-Port",
    "X-Original-URL",
)

# Header substrings that mark a response as cache-served/cacheable.
_CACHE_SIGNALS = (
    "x-cache", "age:", "cf-cache-status", "x-vercel-cache", "x-drupal-cache",
    "x-proxy-cache", "x-varnish", "cache-control: public",
    "cache-control: max-age", "cache-control: s-maxage",
)


def cacheable_signals(headers_text: str) -> list:
    """Cache indicators present in a response's headers (lowercased hits)."""
    low = (headers_text or "").lower()
    return [s for s in _CACHE_SIGNALS if s in low]


class CacheAudit(BaseModule):
    id = "cache_audit"
    name = "Web Cache Poisoning Probe"
    stage = 4
    detectability = "low"
    depends_on = ["tech_detection"]

    async def run(self) -> str:
        base = self.base_url
        self._profile = await self._baseline(base)

        targets = self._targets(base)
        tested = 0
        for url in targets[:8]:
            if self.should_stop(reserve=8):
                break
            tested += 1
            await self._probe(url)

        self.state.complete_module(self.id)
        self.log(f"Cache poisoning probe: {tested} URL(s)")
        return "done"

    def _targets(self, base: str) -> list:
        urls = [base]
        for atype in ("webapp", "url"):
            for asset in self.state.get_assets_by_type(atype):
                v = str(asset.get("value", "")).strip()
                if v.startswith(("http://", "https://")) and v not in urls:
                    urls.append(v)
        return urls

    async def _baseline(self, base: str):
        async def fetch(path: str):
            r = await curl_with_status(base.rstrip("/") + path,
                                       follow_redirects=True)
            return (r.get("status", 0), r.get("body", "") or "",
                    r.get("content_type", "") or "")
        try:
            return await get_profile(base, fetch)
        except Exception:  # noqa: BLE001
            return None

    async def _probe(self, url: str) -> None:
        try:
            base_resp = await curl(url, output="full", timeout=12)
        except Exception:  # noqa: BLE001
            return
        base_headers = str(base_resp.get("headers", ""))
        signals = cacheable_signals(base_headers)
        if not signals:
            return  # not cacheable → poisoning does not persist; skip the noise

        for header in UNKEYED_HEADERS:
            if self.should_stop(reserve=6):
                break
            marker = f"wcp{uuid.uuid4().hex[:10]}.example"
            try:
                resp = await curl(url, output="full", timeout=12,
                                  headers={header: marker})
            except Exception:  # noqa: BLE001
                continue
            body = resp.get("body", "") or ""
            headers_text = str(resp.get("headers", ""))
            location = ""
            for line in headers_text.splitlines():
                if line.lower().startswith("location:"):
                    location = line.split(":", 1)[1].strip()
                    break
            # The unique marker came back somewhere a victim would act on it.
            reflected_in = ("redirect Location" if marker in location
                            else "response body" if marker in body else "")
            if not reflected_in:
                continue
            self.state.add_finding(
                title="Web cache poisoning via unkeyed header",
                severity="HIGH", confidence="FIRM",
                category="Security Misconfiguration",
                description=f"The response reflects the unkeyed request header "
                            f"{header} into the {reflected_in}, and the response "
                            f"is cacheable ({', '.join(signals[:3])}). An "
                            f"attacker can poison the shared cache entry for "
                            f"every visitor of this URL.",
                evidence=[f"URL: {url}",
                          f"{header}: <marker> reflected in {reflected_in}",
                          f"cache signals: {', '.join(signals[:4])}"],
                remediation="Do not reflect forwarding headers into responses; "
                            "include them in the cache key or strip them at the "
                            "edge; set Cache-Control: private where appropriate.",
                asset_keys=[f"webapp:{self.base_url}"],
                verification={"method": "cache_poison_unkeyed_header",
                              "url": url, "header": header})
            return  # one confirmed vector per URL is enough
