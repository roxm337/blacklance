"""Content-derived finding identity, shared by every export.

Finding IDs are per-run counters, so they cannot anchor a regression diff.
Category, title and URL survive renumbering; the hash of those three is the
identity used by SARIF, DefectDojo and the history file.
"""

import hashlib


def finding_url(finding: dict) -> str:
    for key in finding.get("asset_keys") or []:
        text = str(key)
        if text.startswith("url:http"):
            return text[4:]
    verification = finding.get("verification") or {}
    for key in ("url", "bypass_url"):
        value = str(verification.get(key) or "")
        if value.startswith("http"):
            return value
    return ""


def fingerprint(finding: dict, url: str = "") -> str:
    material = "|".join([
        str(finding.get("category", "")),
        str(finding.get("title", "")),
        url or finding_url(finding),
    ])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()
