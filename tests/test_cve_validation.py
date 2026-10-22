"""Capability-tiered CVE validation playbooks.

A probe may confirm; a version match may only be FIRM; an unknown stays
silent. These tests pin the tier boundaries, because an over-eager
version match on a KEV CVE turns every unpatched-looking banner into a
false CRITICAL.
"""

import asyncio
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import modules.cve_validation as cve_validation
from core.prioritization import prioritize_findings
from modules.cve_validation import CVEValidation
from state.manager import StateManager

KEV = {"CVE-2026-63030", "CVE-2026-60137", "CVE-2026-50522",
       "CVE-2026-21962"}


def _state(assets=()):
    st = StateManager(str(Path(tempfile.mkdtemp()) / "acme.com"))
    st.add_asset("webapp", "webapp:https://acme.com", "https://acme.com",
                 confidence="CONFIRMED", sources=["t"], attrs={})
    for asset_type, value in assets:
        st.add_asset(asset_type, f"{asset_type}:{value}", value,
                     confidence="FIRM", sources=["t"], attrs={})
    return st


def _run(monkeypatch, handler, assets=()):
    st = _state(assets)

    async def fake_get(self, url, **kw):
        return handler(url, kw)

    async def fake_kev(cves, config=None):
        return {cve: {"cve": cve} for cve in cves if cve in KEV}

    async def fake_epss(cves):
        return {cve: {"epss": 0.42} for cve in cves}

    monkeypatch.setattr(CVEValidation, "http_get", fake_get)
    monkeypatch.setattr(cve_validation, "kev_lookup_cves", fake_kev)
    monkeypatch.setattr(cve_validation, "epss_score", fake_epss)
    module = CVEValidation(st, {
        "target": {"domain": "acme.com", "active": True},
        "modules": {"cve_validation": {"delay_seconds": 0}},
        "paths": {}, "auth": {},
    })
    module.domain = "acme.com"
    asyncio.run(module.run())
    return st


def _findings(st):
    return st.findings["findings"]


def _wp_handler(differential=True):
    def handler(url, kw):
        data = kw.get("data") or ""
        if kw.get("method") == "POST" and "batch" in url:
            if json.loads(data).get("requests") == []:
                return {"status": 207, "headers": "", "body": "{}"}
            if "block-renderer" in data:
                return {"status": 207, "headers": "", "body": json.dumps(
                    {"responses": [{"body": {"code": "block_cannot_read"}}]})}
            rows = []
            if differential and "1%3D1" in data:
                rows = [{"id": 1}]
            body = {"responses": [{}, {"body": {"responses": [
                {}, {"body": rows}]}}, {}]}
            return {"status": 207, "headers": "", "body": json.dumps(body)}
        if url.rstrip("/") == "https://acme.com":
            return {"status": 200, "headers": "HTTP/1.1 200 OK\n",
                    "body": ('<meta name="generator" '
                             'content="WordPress 7.0.1">')}
        return {"status": 404, "headers": "", "body": ""}
    return handler


def test_wp2shell_probe_confirms_the_chain(monkeypatch):
    st = _run(monkeypatch, _wp_handler(differential=True))
    findings = _findings(st)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["verified"] is True
    assert finding["confidence"] == "CONFIRMED"
    assert finding["severity"] == "CRITICAL"
    assert "CVE-2026-60137" in finding["description"]
    assert finding["verification"]["method"].startswith("wp2shell_")
    assert finding["intelligence"]["kev"] is True
    assert finding["intelligence"]["epss"] == 0.42


def test_wp2shell_without_differential_claims_only_the_confusion(monkeypatch):
    st = _run(monkeypatch, _wp_handler(differential=False))
    finding = _findings(st)[0]
    assert finding["confidence"] == "CONFIRMED"
    assert finding["severity"] == "HIGH"
    assert "route confusion" in finding["title"].lower()
    assert "CVE-2026-60137" not in finding["title"]


def test_wp2shell_unreachable_batch_is_version_only(monkeypatch):
    def handler(url, kw):
        if url.rstrip("/") == "https://acme.com":
            return {"status": 200, "headers": "HTTP/1.1 200 OK\n",
                    "body": ('<meta name="generator" '
                             'content="WordPress 7.0.1">')}
        return {"status": 404, "headers": "", "body": ""}

    st = _run(monkeypatch, handler)
    finding = _findings(st)[0]
    assert finding["confidence"] == "FIRM"
    assert finding["verified"] is False
    assert finding["severity"] == "CRITICAL"
    assert finding["verification"]["method"] == "version_fingerprint"
    # KEV + CVSS keep it CRITICAL even without host proof.
    assert prioritize_findings(_findings(st))[0]["severity"] == "CRITICAL"


def test_wp2shell_patched_version_files_nothing(monkeypatch):
    def handler(url, kw):
        if url.rstrip("/") == "https://acme.com":
            return {"status": 200, "headers": "HTTP/1.1 200 OK\n",
                    "body": ('<meta name="generator" '
                             'content="WordPress 7.0.2">')}
        return {"status": 404, "headers": "", "body": ""}

    assert _findings(_run(monkeypatch, handler)) == []


def test_updraftplus_readme_version(monkeypatch):
    def handler(url, kw):
        if "updraftplus/readme.txt" in url:
            return {"status": 200, "headers": "HTTP/1.1 200 OK\n",
                    "body": "=== UpdraftPlus ===\nStable tag: 1.26.4\n"}
        return {"status": 404, "headers": "", "body": ""}

    st = _run(monkeypatch, handler)
    finding = _findings(st)[0]
    assert finding["severity"] == "HIGH"
    assert finding["confidence"] == "FIRM"
    assert finding["verified"] is False
    assert finding["verification"]["observed"] == "1.26.4"


def test_updraftplus_patched_version_is_clear(monkeypatch):
    def handler(url, kw):
        if "updraftplus/readme.txt" in url:
            return {"status": 200, "headers": "HTTP/1.1 200 OK\n",
                    "body": "=== UpdraftPlus ===\nStable tag: 1.26.5\n"}
        return {"status": 404, "headers": "", "body": ""}

    assert _findings(_run(monkeypatch, handler)) == []


def _sharepoint_handler(build):
    def handler(url, kw):
        if url.rstrip("/") == "https://acme.com":
            return {"status": 200,
                    "headers": ("HTTP/1.1 200 OK\n"
                                f"MicrosoftSharePointTeamServices: {build}\n"),
                    "body": ""}
        return {"status": 404, "headers": "", "body": ""}
    return handler


def test_sharepoint_branch_build_is_flagged_but_not_confirmed(monkeypatch):
    st = _run(monkeypatch, _sharepoint_handler("16.0.10417.20100"))
    finding = _findings(st)[0]
    assert "SharePoint Server 2019" in finding["title"]
    assert finding["confidence"] == "FIRM"
    assert finding["verified"] is False
    assert finding["intelligence"]["kev"] is True


def test_sharepoint_unmappable_build_is_not_guessed(monkeypatch):
    # 16.0.0.x is the legacy banner form: no edition, no fix mapping.
    assert _findings(_run(
        monkeypatch, _sharepoint_handler("16.0.0.10417"))) == []


def test_sharepoint_patched_build_is_clear(monkeypatch):
    assert _findings(_run(
        monkeypatch, _sharepoint_handler("16.0.10417.20175"))) == []


def test_oracle_exact_build_only(monkeypatch):
    def affected(url, kw):
        if url.rstrip("/") == "https://acme.com":
            return {"status": 200,
                    "headers": ("HTTP/1.1 200 OK\nServer: Oracle HTTP Server "
                                "12.2.1.4.0 (Apache/2.4)\n"),
                    "body": ""}
        return {"status": 404, "headers": "", "body": ""}

    finding = _findings(_run(monkeypatch, affected))[0]
    assert finding["severity"] == "CRITICAL"
    assert finding["verification"]["observed"] == "12.2.1.4.0"

    def other(url, kw):
        if url.rstrip("/") == "https://acme.com":
            return {"status": 200,
                    "headers": ("HTTP/1.1 200 OK\nServer: Oracle HTTP Server "
                                "12.2.1.4.1\n"),
                    "body": ""}
        return {"status": 404, "headers": "", "body": ""}

    assert _findings(_run(monkeypatch, other)) == []


def test_rails_version_match_downgrades_without_kev(monkeypatch):
    st = _run(monkeypatch, lambda url, kw: {"status": 404, "headers": "",
                                            "body": ""},
              assets=[("tech_stack", "Rails 8.0.5.0")])
    finding = _findings(st)[0]
    assert "CVE-2026-66066" in finding["title"]
    assert finding["verified"] is False
    assert "kev" not in finding["intelligence"]
    assert prioritize_findings(_findings(st))[0]["severity"] == "HIGH"


def test_rails_patched_version_is_clear(monkeypatch):
    st = _run(monkeypatch, lambda url, kw: {"status": 404, "headers": "",
                                            "body": ""},
              assets=[("tech_stack", "Rails 8.0.5.1")])
    assert _findings(st) == []
