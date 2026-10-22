"""CISA Known Exploited Vulnerabilities: catalog parsing and lookup.

The catalog is a single feed of ~1,700 entries. Two lookups matter and they
answer different questions:

* by CVE id — "is the CVE our version match just produced exploited in the
  wild?" This is an exact join and the only one that may feed scoring.
* by product keyword — "is there KEV noise around a product we detected?"
  This is triage, not evidence, so each hit carries a match strength and only
  an exact product match can carry a critical claim.

Matching lives here, network and caching live in `modules.exploit_lookup`.
"""

import re

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)

# Broad vendor/platform tokens that sit over hundreds of unrelated KEV
# products. A vendor-only match on one of these is a catalogue-wide net,
# not evidence about the target, so it is dropped rather than demoted.
GENERIC_KEV_TERMS = {
    "apache", "php", "nginx", "microsoft", "google", "oracle", "ibm",
    "cisco", "adobe", "linux", "gnu", "debian", "ubuntu", "redhat",
    "canonical", "vmware", "atlassian", "wordpress", "automattic",
}


def is_cve(token: object) -> bool:
    """True when the token is a CVE id and not a product keyword."""
    return bool(CVE_RE.match(str(token or "").strip()))


def parse_catalog(payload: dict) -> dict:
    """Normalise the KEV feed into an id-indexed catalog.

    Returns {entries: {CVE: entry}, catalogVersion, dateReleased, count}.
    Duplicate CVE ids keep the first record; the feed should not contain
    duplicates, and silently overwriting would hide that.
    """
    entries = {}
    for vuln in (payload or {}).get("vulnerabilities") or []:
        cve = str(vuln.get("cveID") or "").strip().upper()
        if not cve:
            continue
        entries.setdefault(cve, {
            "cve": cve,
            "product": str(vuln.get("product") or ""),
            "vendor": str(vuln.get("vendorProject") or ""),
            "name": str(vuln.get("vulnerabilityName") or ""),
            "due_date": str(vuln.get("dueDate") or ""),
            "added": str(vuln.get("dateAdded") or ""),
            "ransomware": str(vuln.get("knownRansomwareCampaignUse") or ""),
            "short_desc": str(vuln.get("shortDescription") or "")[:200],
        })
    return {
        "entries": entries,
        "catalog_version": str((payload or {}).get("catalogVersion") or ""),
        "date_released": str((payload or {}).get("dateReleased") or ""),
        "count": len(entries),
    }


def lookup_cves(catalog: dict, cve_ids) -> dict:
    """Exact, case-insensitive CVE join. Unknown ids are simply absent."""
    entries = (catalog or {}).get("entries") or {}
    found = {}
    for cve in cve_ids or []:
        key = str(cve or "").strip().upper()
        if not key:
            continue
        entry = entries.get(key)
        if entry:
            found[key] = dict(entry, match_strength="exact", matched_term=key)
    return found


def lookup_products(catalog: dict, keywords) -> list:
    """Product-keyword matches with an explicit strength.

    "exact"     the keyword names the product itself
    "vendor"    the keyword names the vendor, the product is something else
    "substring" the keyword is a whole word inside the product name

    Only exact matches may carry a critical claim. A keyword that only
    equals a broad vendor token is dropped: one "Apache" token promoted
    every unrelated Apache KEV entry (Struts, Tomcat, OFBiz, ActiveMQ…)
    to a HIGH "known exploited" claim against a plain WordPress site.
    """
    wanted = [str(k or "").strip().lower() for k in keywords or []]
    wanted = [k for k in wanted if k]
    matches = []
    for entry in ((catalog or {}).get("entries") or {}).values():
        product = entry["product"].lower()
        vendor = entry["vendor"].lower()
        product_tokens = set(re.findall(r"[a-z0-9]+", product))
        for keyword in wanted:
            if keyword == product:
                strength = "exact"
            elif keyword == vendor:
                if keyword in GENERIC_KEV_TERMS:
                    continue
                strength = "vendor"
            elif len(keyword) >= 5 and keyword in product_tokens:
                # Whole-word only: "bridge" must not match "Meteobridge".
                strength = "substring"
            else:
                continue
            matches.append(dict(entry, match_strength=strength,
                                matched_term=keyword))
            break
    return matches
