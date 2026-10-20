"""End-to-end: detected versions become version-confirmed CVE findings."""

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import modules.exploit_lookup as mod
from modules.exploit_lookup import ExploitLookup, build_versioned_products
from state.manager import StateManager


def test_build_versioned_products_normalises_and_parses():
    triples = build_versioned_products([{"attrs": {
        "server": "nginx/1.18.0", "php_version": "PHP/7.2.34",
        "cms": "WordPress 5.4.9"}}])
    names = {t[1]: t[2] for t in triples}
    assert names["nginx"] == "1.18.0"
    assert names["php"] == "7.2.34"
    assert names["wordpress"] == "5.4.9"


def test_confirmed_cve_finding_from_version_in_range(monkeypatch, tmp_path):
    st = StateManager(str(tmp_path / "example.com"))
    st.add_asset("webapp", "webapp:https://example.com", "https://example.com",
                 confidence="FIRM", sources=["t"],
                 attrs={"server": "nginx/1.18.0"})

    async def fake_nvd(keyword, results_per_page=5):
        if keyword != "nginx":
            return []
        return [
            {   # applies: 1.18.0 < 1.21.0
                "id": "CVE-2021-AAAA", "cvss_score": 9.8,
                "description": "nginx resolver off-by-one",
                "cpe_ranges": [{"product": "nginx", "vendor": "nginx",
                                "exact": None, "start_incl": "0",
                                "end_excl": "1.21.0"}],
            },
            {   # patched: 1.18.0 not >= 1.25.0
                "id": "CVE-2024-BBBB", "cvss_score": 7.5,
                "description": "later-only bug",
                "cpe_ranges": [{"product": "nginx", "vendor": "nginx",
                                "exact": None, "start_incl": "1.25.0",
                                "end_excl": "1.27.0"}],
            },
        ]

    async def no_kev(terms):
        return []

    monkeypatch.setattr(mod, "nvd_cve_search", fake_nvd)
    monkeypatch.setattr(mod, "check_cisa_kev", no_kev)
    monkeypatch.setattr(mod, "tool_available", lambda name: False)

    m = ExploitLookup(st, {"target": {"domain": "example.com"},
                           "modules": {}, "paths": {}})
    m.domain = "example.com"
    asyncio.run(m.run())

    confirmed = [f for f in st.findings["findings"]
                 if f["title"].startswith("Version-Confirmed CVEs")]
    assert len(confirmed) == 1
    ev = " ".join(confirmed[0]["evidence"])
    assert "CVE-2021-AAAA" in ev        # in range → confirmed
    assert "CVE-2024-BBBB" not in ev    # patched version → excluded
    assert confirmed[0]["severity"] == "CRITICAL"   # CVSS 9.8
