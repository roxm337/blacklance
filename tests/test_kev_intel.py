"""KEV catalog joins and intelligence plumbing.

The two bugs this guards against: CVE ids compared against product names
(the KEV branch could never fire) and findings filed without intelligence
(so prioritization never saw KEV or EPSS and downgraded exploited
criticals to HIGH).
"""

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import modules.exploit_lookup as exploit_module
from core.kev import is_cve, lookup_cves, lookup_products, parse_catalog
from core.prioritization import prioritize_findings
from state.manager import StateManager

CATALOG = {
    "catalogVersion": "2026.10.21",
    "dateReleased": "2026-10-21",
    "vulnerabilities": [
        {"cveID": "CVE-2026-63030", "vendorProject": "WordPress",
         "product": "WordPress", "vulnerabilityName": "Route confusion",
         "dateAdded": "2026-07-21"},
        {"cveID": "CVE-2026-50522", "vendorProject": "Microsoft",
         "product": "SharePoint Server", "vulnerabilityName": "Deserialization",
         "dateAdded": "2026-07-22"},
        {"cveID": "CVE-2026-11111", "vendorProject": "Apache",
         "product": "Struts", "vulnerabilityName": "RCE"},
    ],
}


def test_parse_and_exact_cve_join_is_case_insensitive():
    catalog = parse_catalog(CATALOG)
    assert catalog["count"] == 3
    assert catalog["catalog_version"] == "2026.10.21"
    found = lookup_cves(catalog, ["cve-2026-63030", "CVE-1999-0001"])
    assert list(found) == ["CVE-2026-63030"]
    assert found["CVE-2026-63030"]["product"] == "WordPress"
    assert found["CVE-2026-63030"]["match_strength"] == "exact"


def test_is_cve_distinguishes_ids_from_products():
    assert is_cve("CVE-2026-60137") and is_cve("cve-2026-60137")
    assert not is_cve("WordPress") and not is_cve("CVE-26-1")


def test_product_match_strength_and_generic_vendor_dropped():
    catalog = parse_catalog(CATALOG)
    exact = lookup_products(catalog, ["SharePoint Server"])
    assert exact and exact[0]["match_strength"] == "exact"
    # "Apache" is a generic vendor token: a vendor-only match would drag
    # every Apache KEV entry onto an unrelated target.
    assert lookup_products(catalog, ["Apache"]) == []
    assert lookup_products(catalog, ["sharepoint"])[0]["match_strength"] == "substring"


def test_check_cisa_kev_uses_exact_join_for_cve_ids(monkeypatch):
    async def fake_fetch():
        return CATALOG

    monkeypatch.setattr(exploit_module, "_fetch_kev", fake_fetch)
    matched = asyncio.run(exploit_module.check_cisa_kev(
        ["CVE-2026-63030", "WordPress"]))
    cves = {m["cve"] for m in matched}
    assert "CVE-2026-63030" in cves
    assert any(m["match_strength"] == "exact" for m in matched)


def test_kev_catalog_caches_per_config(monkeypatch):
    calls = {"n": 0}

    async def fake_fetch():
        calls["n"] += 1
        return CATALOG

    monkeypatch.setattr(exploit_module, "_fetch_kev", fake_fetch)
    exploit_module._KEV_CACHE.update(path="", at=0.0, catalog=None)
    tmp = Path(tempfile.mkdtemp())
    config = {"paths": {"output_dir": str(tmp)},
              "modules": {"exploit_lookup": {"kev_cache_hours": 24}}}
    try:
        first = asyncio.run(exploit_module.kev_catalog(config))
        second = asyncio.run(exploit_module.kev_catalog(config))
        assert first["count"] == second["count"] == 3
        assert calls["n"] == 1, "second call must reuse the cached feed"
        assert (tmp / "cache" / "kev.json").exists()
    finally:
        exploit_module._KEV_CACHE.update(path="", at=0.0, catalog=None)


def _state():
    st = StateManager(str(Path(tempfile.mkdtemp()) / "acme.com"))
    st.add_asset("webapp", "webapp:https://acme.com", "https://acme.com",
                 confidence="CONFIRMED", sources=["t"], attrs={})
    return st


def _add(st, intelligence):
    return st.add_finding(
        title="WordPress wp2shell: pre-auth RCE chain",
        severity="CRITICAL", confidence="FIRM",
        category="Vulnerability Validation", description="d",
        asset_keys=["webapp:https://acme.com"], intelligence=intelligence)


def test_finding_keeps_and_merges_intelligence():
    st = _state()
    _add(st, {"kev": True, "cves": ["CVE-2026-63030"], "epss": 0.2})
    _add(st, {"cves": ["CVE-2026-60137"], "epss": 0.7, "cvss": 9.8})
    findings = st.findings["findings"]
    assert len(findings) == 1, "same claim must merge, not duplicate"
    intel = findings[0]["intelligence"]
    assert intel["kev"] is True
    assert intel["epss"] == 0.7
    assert intel["cvss"] == 9.8
    assert set(intel["cves"]) == {"CVE-2026-63030", "CVE-2026-60137"}


def test_kev_critical_survives_prioritization():
    st = _state()
    _add(st, {"kev": True, "cvss": 9.8})
    prioritized = prioritize_findings(st.findings["findings"])
    assert prioritized[0]["severity"] == "CRITICAL"
    assert prioritized[0]["priority_factors"]["kev"] is True

    st2 = _state()
    _add(st2, {})
    downgraded = prioritize_findings(st2.findings["findings"])[0]
    assert downgraded["severity"] == "HIGH", (
        "without intelligence a FIRM CRITICAL must not stay critical")
