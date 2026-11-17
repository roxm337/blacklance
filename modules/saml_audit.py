"""Stage 5: SAML surface audit — discovery plus metadata analysis.

SAML is where enterprise identity actually breaks, and the repo had no SAML
support at all. This module does the part that needs no captured session:

  * find the SP/IdP metadata and the ACS endpoints a target publishes;
  * read the metadata for the configuration that decides whether the SP can
    be attacked at all — `WantAssertionsSigned`, plaintext ACS URLs, whether
    a signing key is published at all.

Everything here is a **configuration observation**. Metadata states what an
SP asks for; only a replay against the ACS shows what it enforces, so the
finding is TENTATIVE and says so. The structural analysis of an actual SAML
response is `core/saml.py::analyze`, exposed as `auth.saml.analyze` for the
chain step that has one.
"""

from core.saml import SamlError, analyze_metadata, looks_like_saml
from modules.base import BaseModule

METADATA_PATHS = (
    "/saml/metadata",
    "/saml2/metadata",
    "/SAML/metadata",
    "/sso/saml/metadata",
    "/auth/saml/metadata",
    "/simplesaml/module.php/saml/sp/metadata.php",
    "/FederationMetadata/2007-06/FederationMetadata.xml",
    "/adfs/ls/IdP/metadata",
)

ENDPOINT_PATHS = (
    "/saml/acs",
    "/saml2/acs",
    "/SAML/ACS",
    "/sso/saml/acs",
    "/adfs/ls/",
)

_SNIPPET = 1200


class SamlAudit(BaseModule):
    id = "saml_audit"
    name = "SAML Surface Audit"
    stage = 5
    detectability = "medium"
    depends_on = ["tech_detection"]
    active = True

    async def run(self) -> str:
        cfg = self._cfg()
        if cfg.get("enabled", True) is False:
            self.state.skip_module(self.id, "disabled in config")
            return "skipped"

        base = self.base_url.rstrip("/")
        paths = METADATA_PATHS + ENDPOINT_PATHS
        limit = int(cfg.get("max_endpoints", 0) or 0)
        if limit > 0:
            paths = paths[:limit]

        found = 0
        reported = 0
        seen_entities = set()
        for path in paths:
            url = base + path
            try:
                result = await self.http_get(url, output="full", timeout=8)
            except Exception as exc:  # noqa: BLE001 - a dead path is data
                self.log(f"  {url}: probe failed ({exc})")
                continue
            status = int(result.get("status", 0) or 0)
            body = str(result.get("body") or "")
            content_type = ""
            for line in str(result.get("headers") or "").splitlines():
                if line.lower().startswith("content-type:"):
                    content_type = line.partition(":")[2].strip()
                    break
            if status in (0, 404):
                continue
            if not looks_like_saml(body, content_type):
                continue

            found += 1
            evidence_id = self.state.add_evidence(
                self.id, "saml_endpoint", url,
                {"status": status, "content_type": content_type,
                 "length": len(body), "snippet": body[:_SNIPPET]},
            )
            self.log(f"  SAML surface: {url} (HTTP {status})")

            analysis = None
            if body.lstrip().startswith("<"):
                try:
                    analysis = analyze_metadata(body.encode("utf-8"))
                except SamlError:
                    analysis = None
            if analysis is None:
                self.state.add_asset(
                    "saml_endpoint", url, url, confidence="TENTATIVE",
                    sources=[self.id], attrs={"content_type": content_type})
                continue
            if analysis["role"] == "unknown" and not analysis["codes"]:
                continue
            entity = analysis.get("entity_id") or url
            if entity in seen_entities:
                continue
            seen_entities.add(entity)

            self.state.add_asset(
                "saml_endpoint", url, url, confidence="TENTATIVE",
                sources=[self.id],
                attrs={"role": analysis["role"],
                       "entity_id": analysis.get("entity_id", ""),
                       "acs": [entry["location"]
                               for entry in analysis.get("acs", [])]})

            actionable = [finding for finding in analysis["findings"]
                          if finding["severity"] in ("HIGH", "MEDIUM")]
            if not actionable:
                continue
            reported += 1
            # Clamp: metadata describes what the SP asks for, not what it
            # enforces. HIGH here would overstate a configuration gap.
            severity = ("MEDIUM" if analysis["severity"] in
                        ("HIGH", "MEDIUM") else "LOW")
            self.state.add_finding(
                title=f"SAML configuration weakness: {url}",
                severity=severity,
                confidence="TENTATIVE",
                category="SAML",
                description=(
                    f"{analysis['role'].upper()} metadata at {url} "
                    f"(entity {analysis.get('entity_id') or 'unset'}) has "
                    f"{len(actionable)} weak setting(s): "
                    + "; ".join(finding["code"] for finding in actionable)
                    + ". Metadata is a request, not an enforcement decision: "
                    "confirm by replaying the affected message against the "
                    "ACS before treating any of it as exploitable."
                ),
                evidence=[finding["detail"] for finding in actionable],
                evidence_refs=[evidence_id],
                remediation=(
                    "Require signed assertions (WantAssertionsSigned=\"true\"), "
                    "publish and enforce a signing certificate, and serve every "
                    "ACS over HTTPS only."
                ),
                verified=False,
            )

        self.state.complete_module(self.id)
        self.log(f"SAML audit: {found} surface(s) found, "
                 f"{reported} configuration weakness(es) reported")
        return "done"

    def _cfg(self) -> dict:
        cfg = self.config.get("modules", {}).get(self.id, {})
        return cfg if isinstance(cfg, dict) else {}
