"""Semantic (vuln-class) finding dedup.

One run filed the one WordPress user list as three findings with
three titles and three severities. These pin that it now collapses to a
single HIGH finding with the evidence unioned — while proving the guard
that keeps point-scoped findings (XSS on different params) separate.
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.taxonomy import vuln_class
from state.manager import StateManager


def _state():
    return StateManager(str(Path(tempfile.mkdtemp()) / "example.com"))


# ── taxonomy ─────────────────────────────────────────────────────────

def test_user_enumeration_titles_share_a_host_scoped_class():
    for title in ("WP REST API: 2 Users Enumerated",
                  "WordPress REST User Enumeration",
                  "WordPress Author Enumeration: 4 usernames"):
        slug, host_scoped = vuln_class(title, "Information Disclosure")
        assert slug == "user-enumeration" and host_scoped, title


def test_injection_is_point_scoped_and_unclassified():
    for title in ("Reflected XSS", "SQL Injection", "IDOR on /api/baskets"):
        slug, host_scoped = vuln_class(title, "Injection")
        assert slug is None and not host_scoped, title


def test_dotfile_enumeration_is_not_user_enumeration():
    # Shares the word "enumeration" but has no user/author signal.
    slug, _ = vuln_class("Access-Controlled Dotfiles: 5 paths return 403",
                         "Enumeration")
    assert slug is None


# ── end-to-end dedup ─────────────────────────────────────────────────

def test_wp_user_enum_trio_collapses_to_one_high():
    st = _state()
    st.add_finding(
        title="WP REST API: 2 Users Enumerated", severity="HIGH",
        confidence="CONFIRMED", category="Information Disclosure",
        description="REST users", evidence=["Users: alexia_122, studio122"],
        asset_keys=[], verified=True)
    st.add_finding(
        title="WordPress Author Enumeration: 4 usernames", severity="LOW",
        confidence="CONFIRMED", category="Information Disclosure",
        description="authors", evidence=["User ID 8 -> laurent"],
        asset_keys=["webapp:https://example.com"], verified=True)
    st.add_finding(
        title="WordPress REST User Enumeration", severity="MEDIUM",
        confidence="CONFIRMED", category="Attack Surface",
        description="rest users", evidence=["Users: alexia_122, studio122"],
        asset_keys=["webapp:https://example.com"], verified=True)

    findings = st.findings["findings"]
    assert len(findings) == 1, [f["title"] for f in findings]
    f = findings[0]
    assert f["severity"] == "HIGH"          # strongest wins
    assert f["verified"] is True
    # Evidence from all three is unioned.
    joined = " ".join(f["evidence"])
    assert "alexia_122" in joined and "laurent" in joined


def test_distinct_xss_params_stay_separate():
    st = _state()
    st.add_finding(title="Reflected XSS", severity="HIGH",
                   confidence="FIRM", category="Injection",
                   description="xss", asset_keys=["param:https://x/a?q"])
    st.add_finding(title="Reflected XSS", severity="HIGH",
                   confidence="FIRM", category="Injection",
                   description="xss", asset_keys=["param:https://x/a?name"])
    assert len(st.findings["findings"]) == 2


def test_missing_headers_dedupes_across_modules():
    st = _state()
    st.add_finding(title="Missing Security Headers", severity="LOW",
                   confidence="CONFIRMED", category="Hardening Deficiency",
                   description="h", asset_keys=["webapp:https://example.com"])
    st.add_finding(title="Missing security headers on example.com",
                   severity="LOW", confidence="CONFIRMED",
                   category="Hardening Deficiency", description="h",
                   asset_keys=[])
    assert len(st.findings["findings"]) == 1
