"""Stage 4: Observability / metrics endpoint exposure.

An unauthenticated metrics or debug endpoint leaks internal state — route
names, memory, request counts, sometimes tokens or SQL in labels. Each probe
is content-gated to that endpoint's signature (Prometheus exposition format,
Go expvar memstats, an Apache status page), so a generic 200 is never a
finding.
"""

import re

from core.site_profile import get_profile
from modules.base import BaseModule
from tools.wrappers import curl_with_status

# path -> (title suffix, signature regex the real endpoint must match)
_ENDPOINTS = (
    ("/metrics", "Prometheus metrics",
     re.compile(r"(?m)^# (?:HELP|TYPE) |^[a-zA-Z_:][a-zA-Z0-9_:]*\{[^}]*\}\s+[0-9]")),
    ("/actuator/prometheus", "Spring Prometheus metrics",
     re.compile(r"(?m)^# (?:HELP|TYPE) ")),
    ("/debug/vars", "Go expvar debug",
     re.compile(r'"memstats"|"cmdline"')),
    ("/debug/pprof/", "Go pprof profiler",
     re.compile(r"Types of profiles|full goroutine stack dump|/debug/pprof/heap")),
    ("/server-status", "Apache mod_status",
     re.compile(r"Apache Server Status|Scoreboard:")),
    ("/nginx_status", "nginx stub_status",
     re.compile(r"Active connections:\s*\d+")),
)


class MetricsExposure(BaseModule):
    id = "metrics_exposure"
    name = "Observability Endpoint Exposure"
    stage = 4
    detectability = "low"
    depends_on = ["tech_detection"]

    async def run(self) -> str:
        base = self.base_url
        self._profile = await self._baseline(base)
        found = 0
        for path, label, sig in _ENDPOINTS:
            if self.should_stop(reserve=8):
                break
            url = base.rstrip("/") + path
            try:
                r = await curl_with_status(url, timeout=10)
            except Exception:  # noqa: BLE001
                continue
            body = r.get("body", "") or ""
            if r.get("status") != 200 or self._catch_all(r.get("status", 0), body):
                continue
            if not sig.search(body):
                continue
            found += 1
            self.state.add_finding(
                title=f"Observability endpoint exposed: {path}",
                severity="MEDIUM", confidence="FIRM",
                category="Information Disclosure",
                description=f"{label} is reachable without authentication at "
                            f"{path}, leaking internal runtime state (routes, "
                            f"memory, request counts) useful for targeting.",
                evidence=[f"GET {url} → 200, {label} signature matched"],
                remediation="Bind metrics/debug endpoints to localhost or require "
                            "authentication; never expose them publicly.",
                asset_keys=[f"webapp:{base}"],
                verification={"method": "observability_signature", "url": url})
        self.state.complete_module(self.id)
        self.log(f"Observability exposure: {found} endpoint(s)")
        return "done"

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

    def _catch_all(self, status: int, body: str) -> bool:
        prof = getattr(self, "_profile", None)
        if prof is None:
            return False
        try:
            from core.response_fingerprint import fingerprint
            return prof.baseline.catch_all(fingerprint(status, body, ""))
        except Exception:  # noqa: BLE001
            return False
