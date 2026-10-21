"""Stage 4: Broken function/object-level authorization — unauthenticated
API data exposure.

OWASP API1/API5: a REST collection that returns records to an anonymous
request is broken authorization, and it is invisible to the IDOR differ (which
needs two accounts and object-id templates). This probes discovered API
collections with no session and flags the ones that hand back structured
records — scoring by whether the collection name implies user/personal data,
and corroborated by sibling collections that *do* require auth (the
inconsistency that proves it is a gap, not a public feed).
"""

import json
import re

from core.site_profile import get_profile
from modules.base import BaseModule
from tools.wrappers import curl_with_status

# Collection names whose records are sensitive — exposing these unauth is high.
_SENSITIVE = (
    "user", "feedback", "order", "card", "payment", "wallet", "address",
    "complaint", "memory", "review", "message", "basket", "invoice",
    "ticket", "account", "profile", "credential", "token", "secret",
)
_COLLECTION_RE = re.compile(r"^(/(?:api|rest)/[A-Za-z][A-Za-z0-9_-]+)/?$")


def returns_records(body: str) -> int:
    """How many record-like objects a JSON body carries (0 if not data).

    Handles a bare array of objects and the common `{"data": [...]}` /
    `{"status":"success","data":[...]}` envelope. A page of text or an empty
    list returns 0.
    """
    try:
        data = json.loads(body or "")
    except (json.JSONDecodeError, ValueError, TypeError):
        return 0
    if isinstance(data, dict):
        data = data.get("data", data.get("results", data.get("items")))
    if isinstance(data, list):
        return sum(1 for x in data if isinstance(x, dict))
    return 0


def is_sensitive_collection(path: str) -> bool:
    low = path.lower()
    return any(name in low for name in _SENSITIVE)


class BFLAAudit(BaseModule):
    id = "bfla_audit"
    name = "Broken Authorization (unauth API data)"
    stage = 4
    detectability = "low"
    depends_on = ["tech_detection"]

    async def run(self) -> str:
        base = self.base_url
        self._profile = await self._baseline(base)
        collections = self._collections(base)
        if not collections:
            self.state.skip_module(self.id, "no API collection endpoints")
            return "skipped"

        open_c, protected = [], 0
        for url, path in collections[:30]:
            if self.should_stop(reserve=8):
                break
            try:
                r = await curl_with_status(url, no_session=True, timeout=10)
            except Exception:  # noqa: BLE001
                continue
            status = r.get("status", 0)
            body = r.get("body", "") or ""
            if status in (401, 403):
                protected += 1
                continue
            if status != 200 or self._catch_all(status, body):
                continue
            n = returns_records(body)
            if n > 0:
                open_c.append((url, path, n))

        for url, path, n in open_c:
            sensitive = is_sensitive_collection(path)
            self.state.add_finding(
                title=f"Unauthenticated API data exposure: {path}",
                severity="HIGH" if sensitive else "LOW",
                confidence="FIRM",
                category="Broken Access Control",
                description=f"{path} returns {n} record(s) to an anonymous "
                            f"request"
                            + (f", and {protected} sibling collection(s) require "
                               f"authentication — inconsistent authorization "
                               f"exposing data." if protected else ".")
                            + (" The collection name implies user/personal data."
                               if sensitive else " Confirm the data is intended "
                               "to be public."),
                evidence=[f"GET {url} (no auth) → 200, {n} records"]
                         + ([f"{protected} sibling collection(s) → 401/403"]
                            if protected else []),
                remediation="Enforce authentication/authorization on every data "
                            "collection; return only the caller's own records.",
                asset_keys=[f"webapp:{base}"],
                verification={"method": "unauth_collection_records", "url": url})

        self.state.complete_module(self.id)
        self.log(f"BFLA: {len(open_c)} unauth data collection(s), "
                 f"{protected} protected, from {len(collections)} candidate(s)")
        return "done"

    def _collections(self, base: str) -> list:
        from urllib.parse import urlparse
        seen, out = set(), []
        for atype in ("api_endpoint", "url", "web_path", "endpoint"):
            for a in self.state.get_assets_by_type(atype):
                v = str(a.get("value", "")).strip()
                if not v.startswith(("http://", "https://")):
                    continue
                parsed = urlparse(v)
                m = _COLLECTION_RE.match(parsed.path)
                if not m:
                    continue
                coll = m.group(1)
                key = (parsed.netloc, coll)
                if key not in seen:
                    seen.add(key)
                    out.append((f"{parsed.scheme}://{parsed.netloc}{coll}", coll))
        return out

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
