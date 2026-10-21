"""Stage 5: Stored / persistent XSS.

Reflected and DOM XSS are covered by xss_scan / dom_xss_scan; the remaining
class is stored XSS — a payload written once and served back to every later
viewer. It is write-then-read, so it needs a writable endpoint and a render
location, and usually a session. This submits a unique, self-identifying
payload to writable collection endpoints (using a configured identity when
there is one, anonymously otherwise), re-reads the collection, and confirms
only when the payload comes back with its angle brackets intact — stored and
unescaped. An entity-encoded echo (`&lt;img`) is storage working correctly and
is never reported.
"""

import re
import uuid

from core.auth_harness import AuthHarness
from modules.base import BaseModule
from tools.wrappers import curl, curl_with_status

# Common text fields a record stores and later renders.
_TEXT_FIELDS = ("comment", "message", "text", "content", "body", "review",
                "description", "title", "name", "feedback", "note")
# Collection endpoints that typically store user content.
_WRITE_HINTS = ("feedback", "comment", "review", "complaint", "message",
                "post", "note", "memory", "product")


def stored_reflection(body: str, marker: str) -> bool:
    """True iff the raw (unescaped) XSS payload for `marker` is served back."""
    body = body or ""
    raw = f"<img src=x onerror=xss{marker}>"
    if raw in body:
        return True
    # Also accept a bare unescaped tag carrying the marker.
    return bool(re.search(r"<[a-z]+[^>]*xss" + re.escape(marker), body, re.I))


class StoredXSS(BaseModule):
    id = "stored_xss"
    name = "Stored / Persistent XSS"
    stage = 5
    detectability = "high"
    depends_on = ["tech_detection"]
    active = True

    async def run(self) -> str:
        base = self.base_url
        harness = AuthHarness(self.config)
        headers = {}
        if harness.identities:
            await harness.establish_all(base)
            ident = harness.usable[0] if harness.usable else None
            if ident:
                headers = ident.request_headers()
                self.log(f"  using identity '{ident.name}' for authenticated writes")

        targets = self._collections(base)
        if not targets:
            self.state.skip_module(self.id, "no writable collection endpoints")
            return "skipped"

        confirmed = 0
        for url in targets[:12]:
            if self.should_stop(reserve=12):
                break
            if await self._probe(base, url, headers):
                confirmed += 1

        self.state.complete_module(self.id)
        self.log(f"Stored XSS: {confirmed} confirmed across "
                 f"{len(targets)} collection(s)"
                 + ("" if headers else " (anonymous — configure auth.identities "
                    "for the authenticated write surface)"))
        return "done"

    def _collections(self, base: str) -> list:
        from urllib.parse import urlparse
        seen, out = set(), []
        for atype in ("api_endpoint", "url", "endpoint"):
            for a in self.state.get_assets_by_type(atype):
                v = str(a.get("value", "")).strip()
                if not v.startswith(("http://", "https://")):
                    continue
                path = urlparse(v).path.lower()
                if re.match(r"^/(?:api|rest)/[a-z][a-z0-9_-]+/?$", path) and \
                        any(h in path for h in _WRITE_HINTS):
                    key = v.rstrip("/")
                    if key not in seen:
                        seen.add(key)
                        out.append(key)
        return out

    async def _probe(self, base: str, url: str, headers: dict) -> bool:
        marker = uuid.uuid4().hex[:10]
        payload = f'"><img src=x onerror=xss{marker}>'
        for field in _TEXT_FIELDS[:4]:
            if self.should_stop(reserve=8):
                break
            body = '{"%s":%s,"rating":1,"captcha":"0"}' % (field, _j(payload))
            try:
                await curl(url, method="POST", output="status", timeout=12,
                           data=body,
                           headers={"Content-Type": "application/json", **headers})
            except Exception:  # noqa: BLE001
                continue
            # Re-read the collection and look for the unescaped payload.
            try:
                r = await curl_with_status(url, timeout=12,
                                           headers=headers or None)
            except Exception:  # noqa: BLE001
                continue
            if stored_reflection(r.get("body", ""), marker):
                self.state.add_finding(
                    title="Stored / persistent XSS",
                    severity="HIGH", confidence="CONFIRMED",
                    category="Injection",
                    description=f"A payload submitted to the '{field}' field of "
                                f"{url} is stored and served back with its markup "
                                f"intact (not HTML-encoded) — it executes in the "
                                f"browser of every viewer of this content.",
                    evidence=[f"POST {url} {field}=<img onerror> payload",
                              f"GET {url} → payload returned unescaped"],
                    remediation="Output-encode stored content for the HTML "
                                "context on render; validate/sanitise on input.",
                    asset_keys=[f"webapp:{base}"],
                    verification={"method": "stored_xss_unescaped_reflection",
                                  "url": url})
                return True
        return False


def _j(value: str) -> str:
    import json
    return json.dumps(value)
