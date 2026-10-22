"""Per-CVE nuclei targeting.

The whole `cve` tag set is thousands of templates. When we already have a
reason to believe a specific CVE applies, the scanner should be pointed at
that id — and `-id` is the selector that actually does that.
"""

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tools.external as external
from modules.nuclei_scan import NucleiScan
from state.manager import StateManager


def test_ids_reach_nuclei_via_id_flag(monkeypatch):
    captured = {}

    async def fake_run(args, **kwargs):
        captured["args"] = args
        return {"stdout": "", "stderr": "", "exit_code": 0}

    monkeypatch.setattr(external, "tool_available", lambda name: True)
    monkeypatch.setattr(external, "run_command", fake_run)
    asyncio.run(external.nuclei_scan(
        "https://acme.com", ids=["CVE-2026-63030", "CVE-2026-60137"]))
    args = captured["args"]
    assert "-id" in args
    assert args[args.index("-id") + 1] == "CVE-2026-63030,CVE-2026-60137"
    assert "cve" not in args, "targeted runs must not fall back to the tag set"


def _state():
    return StateManager(str(Path(tempfile.mkdtemp()) / "acme.com"))


def _module(st):
    return NucleiScan(st, {"target": {"domain": "acme.com"},
                           "modules": {"nuclei_scan": {}}, "paths": {},
                           "auth": {}})


def test_candidate_cves_come_from_findings_and_intelligence():
    st = _state()
    st.module["current"] = "cms_deep_scan"
    st.add_finding(
        title="WordPress 7.0.1 is vulnerable (CVE-2026-63030)",
        severity="HIGH", confidence="FIRM",
        category="Vulnerability Validation", description="version match",
        asset_keys=["webapp:https://acme.com"],
        intelligence={"cves": ["cve-2026-60137"]})
    candidates = _module(st)._candidate_cves()
    assert candidates == ["CVE-2026-60137", "CVE-2026-63030"]


def test_match_intel_marks_kev_and_keeps_the_id():
    intel = NucleiScan._match_intel(
        {"template_id": "CVE-2026-60137"},
        {"CVE-2026-60137": {"kev": True, "kev_name": "WP SQLi"}})
    assert intel["kev"] is True
    assert intel["kev_name"] == "WP SQLi"
    assert intel["cves"] == ["CVE-2026-60137"]
    assert NucleiScan._match_intel({"template_id": "tech-detect"}, {}) is None
