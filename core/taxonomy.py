"""Finding taxonomy: CWE + OWASP Top 10 mapping per category.

Clients triage by compliance mapping ("which OWASP category?") as often
as by severity, and inconsistent free-text categories make that
impossible. Every finding carries `cwe` and `owasp` resolved from its
category at creation time — keyword rules, specific before general, so
"Stored XSS" does not collapse into a generic bucket.

Intel categories (threat feeds, inventories, scan metadata) map to
nothing: a reputation note is not a weakness, and forcing a CWE onto
it would be the same inflation this file exists to prevent.
"""

# (keyword, cwe list, owasp label). First match wins.
CATEGORY_RULES = (
    ("sql injection", ["CWE-89"], "A03:2021 – Injection"),
    ("nosql", ["CWE-943"], "A03:2021 – Injection"),
    ("stored xss", ["CWE-79"], "A03:2021 – Injection"),
    ("xss", ["CWE-79"], "A03:2021 – Injection"),
    ("cross-site", ["CWE-79"], "A03:2021 – Injection"),
    ("client-side attack surface", ["CWE-79"], "A03:2021 – Injection"),
    ("ssti", ["CWE-94"], "A03:2021 – Injection"),
    ("template injection", ["CWE-94"], "A03:2021 – Injection"),
    ("xxe", ["CWE-611"], "A05:2021 – Security Misconfiguration"),
    ("xml external", ["CWE-611"], "A05:2021 – Security Misconfiguration"),
    ("ssrf", ["CWE-918"], "A10:2021 – Server-Side Request Forgery"),
    ("request smuggling", ["CWE-444"], "A05:2021 – Security Misconfiguration"),
    ("smuggling", ["CWE-444"], "A05:2021 – Security Misconfiguration"),
    ("broken access control", ["CWE-639", "CWE-285"],
     "A01:2021 – Broken Access Control"),
    ("bola", ["CWE-639"], "A01:2021 – Broken Access Control"),
    ("idor", ["CWE-639"], "A01:2021 – Broken Access Control"),
    ("mass assignment", ["CWE-915"], "A01:2021 – Broken Access Control"),
    ("authentication bypass", ["CWE-287"],
     "A07:2021 – Identification and Authentication Failures"),
    ("jwt", ["CWE-287"],
     "A07:2021 – Identification and Authentication Failures"),
    ("email security", ["CWE-290"],
     "A07:2021 – Identification and Authentication Failures"),
    ("spoof", ["CWE-290"],
     "A07:2021 – Identification and Authentication Failures"),
    # Full OWASP/class names used by the newer offensive modules, so their
    # findings carry CWE/OWASP into the report instead of resolving to nothing.
    ("path traversal", ["CWE-22"], "A01:2021 – Broken Access Control"),
    ("local file inclusion", ["CWE-98"], "A03:2021 – Injection"),
    ("crlf", ["CWE-93"], "A03:2021 – Injection"),
    ("header injection", ["CWE-93"], "A03:2021 – Injection"),
    ("server-side request forgery", ["CWE-918"],
     "A10:2021 – Server-Side Request Forgery"),
    ("remote code execution", ["CWE-94"], "A03:2021 – Injection"),
    ("authentication failures", ["CWE-287"],
     "A07:2021 – Identification and Authentication Failures"),
    ("known exploited", ["CWE-1395"],
     "A06:2021 – Vulnerable and Outdated Components"),
    ("known vulnerability", ["CWE-1395"],
     "A06:2021 – Vulnerable and Outdated Components"),
    ("credential exposure", ["CWE-200"],
     "A02:2021 – Cryptographic Failures"),
    ("sensitive data exposure", ["CWE-200"],
     "A02:2021 – Cryptographic Failures"),
    ("tls", ["CWE-327"], "A02:2021 – Cryptographic Failures"),
    ("crypto", ["CWE-327"], "A02:2021 – Cryptographic Failures"),
    ("certificate", ["CWE-295"], "A02:2021 – Cryptographic Failures"),
    ("cloud exposure", ["CWE-732"], "A01:2021 – Broken Access Control"),
    ("bucket", ["CWE-732"], "A01:2021 – Broken Access Control"),
    ("file upload", ["CWE-434"],
     "A08:2021 – Software and Data Integrity Failures"),
    ("unrestricted upload", ["CWE-434"],
     "A08:2021 – Software and Data Integrity Failures"),
    ("deserialization", ["CWE-502"],
     "A08:2021 – Software and Data Integrity Failures"),
    ("hardening deficiency", ["CWE-693"],
     "A05:2021 – Security Misconfiguration"),
    ("security headers", ["CWE-693"],
     "A05:2021 – Security Misconfiguration"),
    ("misconfiguration", ["CWE-16"],
     "A05:2021 – Security Misconfiguration"),
    ("network exposure", ["CWE-200"],
     "A05:2021 – Security Misconfiguration"),
    ("cdn bypass", ["CWE-200"],
     "A05:2021 – Security Misconfiguration"),
    ("origin", ["CWE-200"], "A05:2021 – Security Misconfiguration"),
    ("dns exposure", ["CWE-200"],
     "A05:2021 – Security Misconfiguration"),
    ("takeover", ["CWE-350"],
     "A05:2021 – Security Misconfiguration"),
    ("information disclosure", ["CWE-200"],
     "A05:2021 – Security Misconfiguration"),
    ("source exposure", ["CWE-200"],
     "A05:2021 – Security Misconfiguration"),
    ("exposure", ["CWE-200"], "A05:2021 – Security Misconfiguration"),
    ("api security", ["CWE-200"],
     "A05:2021 – Security Misconfiguration"),
    ("cors", ["CWE-942"], "A01:2021 – Broken Access Control"),
    ("open redirect", ["CWE-601"], "A01:2021 – Broken Access Control"),
    ("redirect", ["CWE-601"], "A01:2021 – Broken Access Control"),
    ("csrf", ["CWE-352"], "A01:2021 – Broken Access Control"),
    ("attack surface", [], "A05:2021 – Security Misconfiguration"),
    ("WAF", [], "A05:2021 – Security Misconfiguration"),
    ("defense", [], "A05:2021 – Security Misconfiguration"),
)


def classify(category: str) -> dict:
    """Resolve {"cwe": [...], "owasp": "..."} for a finding category."""
    lowered = str(category or "").lower()
    for keyword, cwe, owasp in CATEGORY_RULES:
        if keyword in lowered:
            return {"cwe": list(cwe), "owasp": owasp}
    return {"cwe": [], "owasp": ""}


# A finding's *vulnerability class* is coarser than its title: three modules
# found the same WordPress user list and filed "WP REST API: 2 Users
# Enumerated" (HIGH), "WordPress REST User Enumeration" (MEDIUM) and
# "WordPress Author Enumeration" (LOW) — one weakness, three report entries.
# Title-based dedup can't see that; a class signature can.
#
# The crucial distinction is scope. A *host-scoped* class is a property of
# the host — one entry per host is the correct count, so duplicates collapse.
# A *point-scoped* class (injection, IDOR, open redirect) is a property of a
# specific endpoint/parameter: "XSS on ?q" and "XSS on ?name" are two real
# findings and must never be merged. Only host-scoped classes are returned
# with collapse=True; everything else stays exactly as filed.
def vuln_class(title: str, category: str = "") -> "tuple[str | None, bool]":
    """Return (class_slug, host_scoped). (None, False) when unclassified.

    Conservative by construction: an unrecognised finding gets no class and
    is left on its exact-title dedup key, so this can only ever *reduce*
    duplicates of known posture classes, never fold distinct findings.
    """
    t = f"{title} {category}".lower()

    # Account/user enumeration — the proven triplicate. Requires an explicit
    # user/author signal so "Enumeration"-category file-existence findings
    # (which share the word "enumeration") are not swept in.
    if "enumerat" in t and any(
            k in t for k in ("user", "author", "username", "wp-json")):
        return "user-enumeration", True

    # Missing/weak security headers — a single header posture per host.
    if ("security header" in t or "missing header" in t
            or "missing security" in t):
        return "missing-security-headers", True

    # Directory listing enabled — one per host.
    if "directory listing" in t or "directory index" in t:
        return "directory-listing", True

    return None, False
