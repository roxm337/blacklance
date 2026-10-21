"""Stage 5: CRLF injection / HTTP response header injection.

If a parameter is copied into a response header (a redirect `Location`, a
`Set-Cookie`, a reflected custom header) without stripping CR/LF, an attacker
injects their own headers — session fixation via `Set-Cookie`, cache poisoning,
or full response splitting. Proof is unambiguous: a *unique* header the payload
injected shows up as a real header in the response. A reflected body or a 200
is never enough.

A light HTTP-parameter-pollution check rides along on the same parameters:
when a duplicated parameter is pollutable it is surfaced as a lead, since HPP
is the usual precursor to WAF/auth-filter bypass.
"""

import re
import uuid

from modules.base import BaseModule
from tools.wrappers import curl

# CR/LF in the encodings servers decode but filters miss.
_CRLF_SEQS = ("%0d%0a", "%0D%0A", "%0a", "%E5%98%8D%E5%98%8A", "\r\n")
# Parameters most likely to reach a response header.
_HEADER_PARAMS = (
    "url", "redirect", "redirect_uri", "redirect_url", "next", "return",
    "returnurl", "return_url", "goto", "dest", "destination", "continue",
    "location", "lang", "language", "locale", "callback", "path", "page",
)


def header_injected(headers_text: str, marker: str) -> str:
    """Return the injected header line if the marker appears as a real response
    header (own line `key: ...marker`), else ''."""
    for line in (headers_text or "").splitlines():
        low = line.lower()
        if (low.startswith("x-crlf-") or low.startswith("set-cookie:")) \
                and marker in line:
            return line.strip()
    return ""


class CRLFAudit(BaseModule):
    id = "crlf_audit"
    name = "CRLF / Header Injection"
    stage = 5
    detectability = "medium"
    depends_on = ["parameter_discovery"]
    active = True

    async def run(self) -> str:
        points = self._points()
        if not points:
            self.state.skip_module(self.id, "no parameters to test")
            return "skipped"

        crlf = hpp = 0
        for url, param in points[:25]:
            if self.should_stop(reserve=8):
                break
            if await self._probe_crlf(url, param):
                crlf += 1
            elif await self._probe_hpp(url, param):
                hpp += 1

        self.state.complete_module(self.id)
        self.log(f"CRLF/HPP: {crlf} CRLF injection(s), {hpp} HPP lead(s) "
                 f"across {len(points)} parameter(s)")
        return "done"

    def _points(self) -> list:
        seen, prime, other = set(), [], []
        for asset in self.state.get_assets_by_type("parameter"):
            attrs = asset.get("attrs", {}) or {}
            name = str(asset.get("value", "") or attrs.get("parameter", ""))
            url = str(attrs.get("url", "") or "")
            if not (name and url.startswith(("http://", "https://"))):
                continue
            key = (url, name)
            if key in seen:
                continue
            seen.add(key)
            (prime if name.lower() in _HEADER_PARAMS else other).append((url, name))
        # Header-reaching params first; a capped tail of the rest.
        return prime + other[:10]

    async def _probe_crlf(self, url: str, param: str) -> bool:
        from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
        marker = uuid.uuid4().hex[:10]
        parsed = urlparse(url)
        for seq in _CRLF_SEQS:
            if self.should_stop(reserve=6):
                break
            # Build the raw query by hand: urlencode would re-encode the CR/LF
            # we are deliberately testing the server's decoding of.
            injected = f"{param}=x{seq}X-CRLF-{marker}:{marker}"
            probe = urlunparse(parsed._replace(query=injected))
            try:
                r = await curl(probe, output="full", follow_redirects=False,
                               timeout=12)
            except Exception:  # noqa: BLE001
                continue
            line = header_injected(str(r.get("headers", "")), marker)
            if line:
                self.state.add_finding(
                    title="CRLF / HTTP response header injection",
                    severity="HIGH", confidence="CONFIRMED",
                    category="CRLF Injection",
                    description=f"The '{param}' parameter injects CR/LF into the "
                                f"response headers — an attacker can set arbitrary "
                                f"response headers (session fixation via Set-Cookie, "
                                f"cache poisoning, response splitting).",
                    evidence=[f"{probe}", f"injected header: {line}"],
                    remediation="Strip CR/LF from any user input copied into a "
                                "response header; use the framework's header API.",
                    asset_keys=[f"webapp:{self.base_url}"],
                    verification={"method": "crlf_injected_header",
                                  "url": probe})
                return True
        return False

    async def _probe_hpp(self, url: str, param: str) -> bool:
        from urllib.parse import urlparse, urlunparse
        m1, m2 = uuid.uuid4().hex[:8], uuid.uuid4().hex[:8]
        parsed = urlparse(url)
        probe = urlunparse(parsed._replace(query=f"{param}={m1}&{param}={m2}"))
        try:
            r = await curl(probe, output="body", timeout=12)
        except Exception:  # noqa: BLE001
            return False
        body = r.get("body", "") or ""
        # Both polluted values reflected → the app concatenates/accepts both,
        # the classic HPP filter-bypass precursor. One value alone is normal.
        if m1 in body and m2 in body:
            self.state.add_finding(
                title="HTTP parameter pollution (both values reflected)",
                severity="LOW", confidence="TENTATIVE",
                category="Security Misconfiguration",
                description=f"Duplicating '{param}' reflected both values — the "
                            f"endpoint accepts polluted parameters, a common "
                            f"precursor to WAF/authorization-filter bypass.",
                evidence=[f"{probe} → both injected values present in response"],
                remediation="Reject or canonicalise duplicate parameters server-side.",
                asset_keys=[f"webapp:{self.base_url}"],
                verification={"method": "hpp_both_reflected", "url": probe})
            return True
        return False
