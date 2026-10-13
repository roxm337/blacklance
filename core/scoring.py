"""Finding risk scoring helpers."""

from typing import List, Optional

SEVERITY_BASE = {
    "INFO": 5,
    "LOW": 25,
    "MEDIUM": 50,
    "HIGH": 75,
    "CRITICAL": 95,
}


def score_finding(severity: str, confidence: str,
                  asset_keys: Optional[List[str]] = None,
                  category: str = "", verified: bool = False) -> int:
    """Return a stable 0-100 risk score from severity and context.

    Deliberately confidence-FREE: the single confidence discount lives in
    prioritization (CONFIDENCE_DISCOUNT). Baking a multiplier in here too
    double-discounted every TENTATIVE finding to ~0.36 weight. `confidence`
    is accepted (callers pass it) and ignored for the number; `verified`
    keeps its modest boost. File-time scores are pre-discount until the
    risk_prioritization module normalizes them.
    """
    sev = str(severity or "INFO").upper()
    score = SEVERITY_BASE.get(sev, 5)

    assets = asset_keys or []
    if assets:
        score += 3
    if any(k.startswith(("port:", "webapp:", "cloud:", "bucket:")) for k in assets):
        score += 7

    category_l = (category or "").lower()
    if any(term in category_l for term in ("credential", "exposure", "network")):
        score += 5

    # Verified findings get a modest boost — signal has been confirmed.
    if verified:
        score += 5

    return max(0, min(100, round(score)))

def score_label(score: int) -> str:
    # Display bands only: 95 here vs the 90 promotion gate in
    # prioritization is deliberate — a filed 90 reads "High" until
    # intelligence actually promotes it, so labels never pre-claim
    # what only the intel path may grant.
    if score >= 95:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    if score >= 15:
        return "Low"
    return "Informational"


def score_vulnerability(cvss: float = 0.0, epss: float = 0.0,
                        kev: bool = False, exposure: float = 0.0,
                        weights: Optional[dict] = None) -> int:
    """Score vulnerability intelligence using CVSS, EPSS, KEV, and exposure."""
    active_weights = {
        "cvss": 0.4,
        "epss": 0.3,
        "kev": 0.2,
        "exposure": 0.1,
    }
    if weights:
        active_weights.update(weights)

    cvss_component = max(0.0, min(float(cvss or 0.0), 10.0)) / 10.0
    epss_component = max(0.0, min(float(epss or 0.0), 1.0))
    kev_component = 1.0 if kev else 0.0
    exposure_component = max(0.0, min(float(exposure or 0.0), 1.0))

    weighted = (
        cvss_component * active_weights["cvss"]
        + epss_component * active_weights["epss"]
        + kev_component * active_weights["kev"]
        + exposure_component * active_weights["exposure"]
    )
    return max(0, min(100, round(weighted * 100)))
