"""OSV / GHSA advisory parsing — current, version-filtered CVE intel."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.cve_sources import (
    cvss_base_score,
    parse_osv_vulns,
    sort_advisories,
    worst_severity,
)


def test_cvss_base_score_from_vector():
    # Reflected XSS (scope changed) → 6.1 MEDIUM.
    assert cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1
    # Unauth RCE → 9.8 CRITICAL.
    assert cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    # Garbage → 0.0, not a crash.
    assert cvss_base_score("not-a-vector") == 0.0

_OSV = {"vulns": [
    {"id": "GHSA-aaaa", "aliases": ["CVE-2025-1111"],
     "summary": "Auth bypass in widget",
     "database_specific": {"severity": "CRITICAL"},
     "affected": [{"ranges": [{"events": [{"introduced": "0"},
                                          {"fixed": "1.4.2"}]}]}]},
    {"id": "GHSA-bbbb", "aliases": ["CVE-2026-2222"],
     "summary": "XSS in template",
     "severity": [{"type": "CVSS_V3",
                   "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}],
     "affected": [{"ranges": [{"events": [{"fixed": "1.5.0"}]}]}]},
    {"id": "GHSA-cccc", "aliases": [], "summary": "no cve, no sev"},
]}


def test_parse_osv_extracts_cve_fixed_and_severity():
    recs = parse_osv_vulns(_OSV)
    assert len(recs) == 3
    first = recs[0]
    assert first["cve"] == "CVE-2025-1111"
    assert first["severity"] == "CRITICAL"
    assert first["fixed"] == ["1.4.2"]
    # Severity derived from CVSS base score 6.1 → MEDIUM.
    assert recs[1]["severity"] == "MEDIUM"
    # No alias → falls back to GHSA id as the display id.
    assert recs[2]["cve"] == "" and recs[2]["id"] == "GHSA-cccc"


def test_sort_and_worst():
    recs = parse_osv_vulns(_OSV)
    ordered = sort_advisories(recs)
    assert ordered[0]["severity"] == "CRITICAL"
    assert worst_severity(recs) == "CRITICAL"


def test_empty_osv():
    assert parse_osv_vulns({}) == []
    assert worst_severity([]) == "UNKNOWN"
