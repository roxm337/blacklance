"""Version-aware CVE applicability — the matcher that turns 'confirm the
version' into a decided True/False/None."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.version_match import (
    cve_applies,
    nvd_cpe_ranges,
    parse_version,
    version_in_range,
)


# ── parsing ──────────────────────────────────────────────────────────

def test_parse_version_forms():
    assert parse_version("2.4.41") == (2, 4, 41)
    assert parse_version("nginx/1.18.0") == (1, 18, 0)
    assert parse_version("PHP/7.2.34-1ubuntu3") == (7, 2, 34)
    assert parse_version("v5.4") == (5, 4)
    assert parse_version("unknown") is None
    assert parse_version("") is None
    assert parse_version(None) is None


# ── range logic ──────────────────────────────────────────────────────

def test_version_in_range_bounds():
    # affected: < 1.21.0
    assert version_in_range("1.18.0", end_excl="1.21.0")
    assert not version_in_range("1.21.0", end_excl="1.21.0")
    assert not version_in_range("1.25.3", end_excl="1.21.0")
    # affected: >= 2.4.0, <= 2.4.49
    assert version_in_range("2.4.41", start_incl="2.4.0", end_incl="2.4.49")
    assert not version_in_range("2.4.50", start_incl="2.4.0", end_incl="2.4.49")
    assert not version_in_range("2.2.0", start_incl="2.4.0", end_incl="2.4.49")


def test_version_in_range_exact_and_padding():
    assert version_in_range("1.18", exact="1.18.0")   # (1,18)==(1,18,0)
    assert not version_in_range("1.18.1", exact="1.18.0")
    # No usable bounds → the range asserts nothing.
    assert not version_in_range("1.0.0")


# ── NVD CPE extraction + applicability ───────────────────────────────

_NVD_CVE = {
    "configurations": [{
        "nodes": [{
            "cpeMatch": [{
                "vulnerable": True,
                "criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
                "versionStartIncluding": "1.0.0",
                "versionEndExcluding": "1.21.0",
            }, {
                "vulnerable": False,  # must be ignored
                "criteria": "cpe:2.3:o:canonical:ubuntu_linux:*:*:*:*:*:*:*:*",
            }],
        }],
    }],
}


def test_nvd_cpe_ranges_pulls_only_vulnerable():
    ranges = nvd_cpe_ranges(_NVD_CVE)
    assert len(ranges) == 1
    r = ranges[0]
    assert r["product"] == "nginx"
    assert r["end_excl"] == "1.21.0"


def test_cve_applies_three_valued():
    ranges = nvd_cpe_ranges(_NVD_CVE)
    # In range → confirmed-applicable.
    assert cve_applies("nginx", "1.18.0", ranges) is True
    # Product matches, version patched → not applicable.
    assert cve_applies("nginx", "1.25.3", ranges) is False
    # Different product → undecided (stays a lead).
    assert cve_applies("apache", "2.4.41", ranges) is None
    # Unparseable version → undecided.
    assert cve_applies("nginx", "unknown", ranges) is None


def test_product_token_match_is_not_substring():
    # "php" must not match "phpmyadmin"; "bridge" must not match "meteobridge".
    ranges = [{"product": "phpmyadmin", "end_excl": "5.0.0"}]
    assert cve_applies("php", "7.2.34", ranges) is None
