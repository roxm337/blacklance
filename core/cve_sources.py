"""Current vulnerability intelligence from OSV / GitHub Security Advisories.

NVD keyword search is slow, name-matched and lags. For the stacks a modern app
is built from — npm (`next`, `react`, `express`), Packagist (`laravel/
framework`), PyPI (`django`), RubyGems (`rails`), Maven (Spring) — the live,
continuously-updated source is OSV, which aggregates GitHub Security Advisories
and the registries' own feeds. Querying OSV with the *exact detected version*
returns only the advisories that still affect that version, each with its CVE
alias and the release that fixes it.

That is the difference between "here are two CVEs we hard-coded" and "as of
today these are the N advisories that affect the version you are running, and
here is what to upgrade to." This module is the pure parser; the network call
is `tools.wrappers.osv_query`.
"""

import re

# Map a CVSS base score to a severity label when the advisory gives only a
# vector/score and no explicit label.
def _label_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "UNKNOWN"


import math

# CVSS v3.x metric weights (spec §7).
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}


def cvss_base_score(vector: str) -> float:
    """Compute the CVSS v3.0/3.1 base score from a vector string.

    OSV gives the CVSS vector, not a number, so the severity has to be
    computed — not guessed by scraping a digit out of the string (which reads
    the "3.1" in "CVSS:3.1" as the score). Returns 0.0 for a vector that can't
    be parsed; the formula is the published spec, rounded up to one decimal.
    """
    parts = dict(p.split(":", 1) for p in str(vector).split("/")
                 if ":" in p and not p.startswith("CVSS"))
    try:
        scope_changed = parts.get("S") == "C"
        av, ac, ui = _AV[parts["AV"]], _AC[parts["AC"]], _UI[parts["UI"]]
        pr = (_PR_C if scope_changed else _PR_U)[parts["PR"]]
        c, i, a = _CIA[parts["C"]], _CIA[parts["I"]], _CIA[parts["A"]]
    except (KeyError, ValueError):
        return 0.0
    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    raw = (1.08 if scope_changed else 1.0) * (impact + exploitability)
    return min(math.ceil(raw * 10) / 10.0, 10.0)


def _severity_of(vuln: dict) -> str:
    """Best severity label for an OSV vuln: explicit database_specific label
    first, else computed from a CVSS vector, else a bare numeric score."""
    ds = (vuln.get("database_specific") or {})
    label = str(ds.get("severity") or "").upper()
    if label in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return label
    for sev in vuln.get("severity") or []:
        score = sev.get("score", "")
        if isinstance(score, str) and score.upper().startswith("CVSS:"):
            computed = cvss_base_score(score)
            if computed > 0:
                return _label_from_cvss(computed)
            continue
        try:
            return _label_from_cvss(float(score))
        except (TypeError, ValueError):
            continue
    return "UNKNOWN"


def _fixed_versions(vuln: dict) -> list:
    """Every 'fixed' release named in the advisory's affected ranges."""
    fixed = []
    for affected in vuln.get("affected") or []:
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                if event.get("fixed"):
                    fixed.append(event["fixed"])
    # Preserve order, de-dup.
    seen = set()
    out = []
    for f in fixed:
        if f not in seen:
            seen.add(f)
            out.append(f)
    return out


def parse_osv_vulns(osv_json: dict) -> list:
    """Normalise an OSV /v1/query response into advisory records.

    Returns [{id, cve, aliases, summary, severity, fixed}], newest-looking
    first is not guaranteed by OSV, so callers sort by severity. When the
    query carried a version, every record here already affects that version.
    """
    records = []
    for vuln in (osv_json or {}).get("vulns") or []:
        aliases = vuln.get("aliases") or []
        cve = next((a for a in aliases if str(a).upper().startswith("CVE-")), "")
        records.append({
            "id": vuln.get("id", ""),
            "cve": cve,
            "aliases": aliases,
            "summary": (vuln.get("summary") or vuln.get("details") or "")[:200],
            "severity": _severity_of(vuln),
            "fixed": _fixed_versions(vuln),
        })
    return records


_SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


def sort_advisories(records: list) -> list:
    """Most severe first; stable for equal severity."""
    return sorted(records, key=lambda r: -_SEV_ORDER.get(r.get("severity"), 0))


def worst_severity(records: list) -> str:
    """The highest severity label across the records (UNKNOWN if empty)."""
    best = "UNKNOWN"
    for r in records:
        if _SEV_ORDER.get(r.get("severity"), 0) > _SEV_ORDER.get(best, 0):
            best = r["severity"]
    return best
