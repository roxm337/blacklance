"""Version-aware CVE applicability.

The exploit-lookup engine used to stop at product names: it could say "there
are 17 KEV entries for products that look like yours, confirm the version"
but never took the next step. Yet detection already fingerprints versions —
`Server: nginx/1.18.0`, `WordPress 5.4.9`, `PHP/7.2.34`. This module closes
the loop: given a detected version and a CVE's affected-version ranges (from
NVD's CPE configurations or OSV's affected[].ranges), it decides whether the
CVE actually applies.

The decision is deliberately three-valued:
  True  — the version falls inside a vulnerable range: a confirmed lead.
  False — the product matches but the version is outside every range: patched.
  None  — can't tell (version unparseable, no CPE for this product): stays a
          lead to validate, never upgraded to a claim.

Conservatism is the whole point. A False that should be None silently drops a
real finding; so "unsure" always degrades to None, never to False.
"""

import re

_SEG = re.compile(r"\d+")


def parse_version(value) -> "tuple[int, ...] | None":
    """Numeric release segments of a version string, or None.

    "2.4.41" → (2,4,41); "nginx/1.18.0" → (1,18,0); "7.2.34-1ubuntu3" →
    (7,2,34); "v5.4" → (5,4). A string with no digits ("unknown", "") → None.
    Pre-release/build suffixes are dropped: range endpoints in CVE data are
    release versions, and comparing a suffix would only ever misfire.
    """
    if value is None:
        return None
    text = str(value).strip().lower()
    # Take the first dotted-number run so "nginx/1.18.0 (ubuntu)" → "1.18.0".
    match = re.search(r"\d+(?:\.\d+){0,5}", text)
    if not match:
        return None
    segs = _SEG.findall(match.group(0))
    if not segs:
        return None
    return tuple(int(s) for s in segs[:6])


def _cmp(a: tuple, b: tuple) -> int:
    """Compare two version tuples, zero-padding the shorter: (1,18)==(1,18,0)."""
    width = max(len(a), len(b))
    a = a + (0,) * (width - len(a))
    b = b + (0,) * (width - len(b))
    return (a > b) - (a < b)


def version_in_range(version, *, start_incl=None, start_excl=None,
                     end_incl=None, end_excl=None,
                     exact=None) -> bool:
    """Is `version` inside the range described by these bounds?

    Mirrors NVD/OSV semantics: *Including* bounds are closed, *Excluding*
    bounds are open, `exact` pins a single affected version. A bound that
    fails to parse is ignored (treated as absent) rather than crashing — a
    malformed endpoint must not take down a scan.
    """
    v = parse_version(version)
    if v is None:
        return False

    if exact is not None:
        e = parse_version(exact)
        if e is not None and _cmp(v, e) == 0:
            return True

    bounded = False
    for bound, op in ((start_incl, "ge"), (start_excl, "gt"),
                      (end_incl, "le"), (end_excl, "lt")):
        if bound in (None, "", "*", "-"):
            continue
        b = parse_version(bound)
        if b is None:
            continue
        bounded = True
        c = _cmp(v, b)
        if op == "ge" and c < 0:
            return False
        if op == "gt" and c <= 0:
            return False
        if op == "le" and c > 0:
            return False
        if op == "lt" and c >= 0:
            return False
    # With no usable bounds and no exact hit, the range says nothing.
    return bounded


def nvd_cpe_ranges(cve_json: dict) -> list:
    """Extract affected-version ranges from an NVD CVE's `configurations`.

    Returns one record per vulnerable cpeMatch:
    {product, vendor, exact, start_incl, start_excl, end_incl, end_excl}.
    Handles both the 2.0 schema (`configurations` is a list of {nodes}) and
    the older object form, and both `cpeMatch` and legacy `cpe_match` keys.
    """
    ranges = []
    configurations = cve_json.get("configurations", [])
    if isinstance(configurations, dict):
        configurations = configurations.get("nodes", [])
        configurations = [{"nodes": configurations}]

    def walk(node):
        for match in (node.get("cpeMatch") or node.get("cpe_match") or []):
            if not match.get("vulnerable", True):
                continue
            cpe = match.get("criteria") or match.get("cpe23Uri") or ""
            vendor, product, cpe_version = _cpe_parts(cpe)
            exact = cpe_version if cpe_version not in ("*", "-", "") else None
            ranges.append({
                "product": product,
                "vendor": vendor,
                "exact": exact,
                "start_incl": match.get("versionStartIncluding"),
                "start_excl": match.get("versionStartExcluding"),
                "end_incl": match.get("versionEndIncluding"),
                "end_excl": match.get("versionEndExcluding"),
            })
        for child in node.get("children", []) or []:
            walk(child)

    for config in configurations:
        for node in config.get("nodes", []) or []:
            walk(node)
    return ranges


def _cpe_parts(cpe: str) -> tuple:
    """(vendor, product, version) from a CPE 2.3 URI, lowercased."""
    # cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*
    parts = str(cpe).split(":")
    if len(parts) >= 6 and parts[0] == "cpe" and parts[1] == "2.3":
        return parts[3].lower(), parts[4].lower(), parts[5]
    if len(parts) >= 5 and parts[0] == "cpe":  # cpe:/a:vendor:product:version
        return parts[2].lower(), parts[3].lower(), (parts[4] if len(parts) > 4 else "*")
    return "", "", "*"


def cve_applies(product: str, version, ranges: list) -> "bool | None":
    """Does a CVE with these CPE `ranges` apply to our detected product/version?

    True  — a range for a product matching ours includes our version.
    False — a range for a matching product exists, but our version is outside
            all of them (i.e. we are on a fixed build).
    None  — no range names a product like ours, or our version won't parse:
            undecided, so the caller keeps it as a lead rather than a claim.
    """
    if parse_version(version) is None:
        return None
    needle = str(product or "").strip().lower()
    if not needle:
        return None

    product_matched = False
    for r in ranges:
        rp = str(r.get("product") or "")
        if not rp:
            continue
        # Whole-token product match in either direction: "nginx" ~ "nginx",
        # "http_server" range matches a detected "apache http server" token.
        if not _product_token_match(needle, rp):
            continue
        product_matched = True
        if version_in_range(
                version,
                start_incl=r.get("start_incl"), start_excl=r.get("start_excl"),
                end_incl=r.get("end_incl"), end_excl=r.get("end_excl"),
                exact=r.get("exact")):
            return True
    return False if product_matched else None


def _product_token_match(a: str, b: str) -> bool:
    """Loose product-name equivalence over alphanumeric tokens.

    NVD products use underscores ("http_server"); our fingerprints use spaces
    or slashes ("Apache HTTP Server", "nginx/1.18"). Compare token sets: a
    match requires one side's tokens to be a subset of the other's, so
    "nginx" matches "nginx" but "php" does not match "phpmyadmin".
    """
    ta = set(re.findall(r"[a-z0-9]+", a.lower()))
    tb = set(re.findall(r"[a-z0-9]+", b.lower()))
    if not ta or not tb:
        return False
    return ta <= tb or tb <= ta
