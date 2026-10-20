"""Technology profiles: detect a stack, then test it on its own terms.

A generic path list treats a Next.js app, a Laravel API and a WordPress blog
the same way, so it misses the checks that actually matter for each — the
Next.js middleware-auth bypass, Laravel's Ignition RCE and leaked `.env`,
Spring Boot's `/actuator/heapdump`, a React bundle's source maps. This module
is the opposite: a declarative registry where each technology carries its own
fingerprint signals, its own high-signal probes, and the CPE product names
that feed version-confirmed CVE correlation.

Adding a technology is adding a `TechProfile` — data, not code. The executor
that runs the probes lives in `modules/tech_playbook.py`; everything here is
pure and unit-testable.

Signals and probes are deliberately specific. A profile matches only on
strong, stack-unique evidence (a `__NEXT_DATA__` blob, an `X-Powered-By:
Express`, a Laravel session cookie), never on a word that could appear
anywhere, so one target does not light up five playbooks.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Signal:
    """One fingerprint rule. `where` names which blob to match against:
    header | body | cookie | hint (the coarse cms/framework tech_detect set).
    `weight` is how much a match counts toward the profile's confidence."""
    where: str
    pattern: str          # regex, matched case-insensitively
    weight: float = 1.0


@dataclass(frozen=True)
class Probe:
    """One technology-specific check.

    A GET (or `method`) to `path`; a finding fires when the status is in
    `status_in`, `body_regex` matches (if set) and `body_not_regex` does not
    (if set). `active=True` probes send a payload or a bypass header and run
    only under --active; passive probes are plain GETs to known paths.
    """
    path: str
    title: str
    severity: str
    category: str
    description: str
    remediation: str
    status_in: tuple = (200,)
    body_regex: "str | None" = None
    body_not_regex: "str | None" = None
    method: str = "GET"
    headers: "dict | None" = None
    data: "str | None" = None
    active: bool = False
    # When set, the probe fires only if its response differs from a baseline
    # request to the same path *without* `headers` — the response is 200 while
    # the baseline is an auth status (401/403/302). This is what makes an
    # auth-bypass check real instead of a false positive on a public page.
    differential: bool = False


@dataclass(frozen=True)
class TechProfile:
    name: str
    label: str
    signals: tuple
    probes: tuple = ()
    cpe_products: tuple = ()      # feeds NVD CPE version-range correlation
    # (ecosystem, package) pairs for live OSV / GHSA advisory lookup. These are
    # how the playbook pulls *current* CVEs for the detected stack+version
    # instead of a hard-coded handful. Ecosystem names are OSV's own.
    packages: tuple = ()
    min_confidence: float = 0.8


# ── Profiles ─────────────────────────────────────────────────────────

PROFILES: "list[TechProfile]" = [

    TechProfile(
        name="wordpress", label="WordPress",
        signals=(
            Signal("body", r"/wp-content/", 1.0),
            Signal("body", r"/wp-includes/", 1.0),
            Signal("hint", r"wordpress", 1.0),
            Signal("header", r"x-powered-by:.*w3[\s-]?total", 0.5),
            Signal("body", r'name="generator"[^>]*WordPress', 1.0),
        ),
        cpe_products=("wordpress",),
        probes=(
            Probe("/wp-json/wp/v2/users",
                  title="WordPress REST API user enumeration",
                  severity="MEDIUM", category="Information Disclosure",
                  description="GET /wp-json/wp/v2/users returns account slugs "
                              "without authentication — usernames for credential attacks.",
                  remediation="Restrict the users REST endpoint or strip it from the index.",
                  status_in=(200,), body_regex=r'"slug"'),
            Probe("/xmlrpc.php",
                  title="WordPress XML-RPC enabled",
                  severity="LOW", category="Attack Surface",
                  description="xmlrpc.php is reachable — enables pingback SSRF and "
                              "amplified credential brute force via system.multicall.",
                  remediation="Disable XML-RPC or block xmlrpc.php if unused.",
                  status_in=(200, 405), body_regex=r"XML-RPC server accepts"),
            Probe("/wp-config.php.bak",
                  title="WordPress config backup exposed",
                  severity="CRITICAL", category="Credential Exposure",
                  description="A wp-config backup is downloadable — contains DB "
                              "credentials and auth salts.",
                  remediation="Remove the backup and rotate all exposed secrets.",
                  status_in=(200,), body_regex=r"DB_PASSWORD|DB_NAME"),
        ),
    ),

    TechProfile(
        name="nextjs", label="Next.js",
        signals=(
            Signal("body", r"/_next/static/", 1.0),
            Signal("body", r"__NEXT_DATA__", 1.0),
            Signal("header", r"x-powered-by:\s*next\.js", 1.0),
            Signal("hint", r"next\.js", 1.0),
            Signal("header", r"x-nextjs-", 0.8),
        ),
        cpe_products=("next.js", "nextjs"),
        packages=(("npm", "next"),),
        probes=(
            Probe("/_next/static/",
                  title="Next.js build directory listing",
                  severity="LOW", category="Information Disclosure",
                  description="The /_next/static directory is browsable, exposing "
                              "chunk names and build structure.",
                  remediation="Disable directory listing on the static mount.",
                  status_in=(200,), body_regex=r"Index of|<a href="),
            # CVE-2025-29927: a crafted x-middleware-subrequest header skips
            # Next.js middleware, bypassing auth/authorization gates.
            Probe("/",
                  title="Next.js middleware auth bypass (CVE-2025-29927)",
                  severity="HIGH", category="Broken Access Control",
                  description="The server honoured x-middleware-subrequest, so "
                              "middleware (including auth) can be skipped on "
                              "protected routes.",
                  remediation="Upgrade Next.js to a patched release "
                              "(>=14.2.25 / >=15.2.3).",
                  method="GET",
                  headers={"x-middleware-subrequest":
                           "middleware:middleware:middleware:middleware:middleware"},
                  status_in=(200,), active=True, differential=True),
            # Image optimizer SSRF surface.
            Probe("/_next/image?url=https%3A%2F%2Fexample.com%2F&w=64&q=1",
                  title="Next.js image optimizer proxies remote URLs",
                  severity="MEDIUM", category="Server-Side Request Forgery",
                  description="/_next/image fetched an external URL — if "
                              "remotePatterns is permissive this is an SSRF/"
                              "open-proxy surface worth OOB testing.",
                  remediation="Restrict images.remotePatterns to trusted hosts.",
                  status_in=(200,), active=True),
        ),
    ),

    TechProfile(
        name="react_spa", label="React (SPA)",
        packages=(("npm", "react"), ("npm", "react-dom")),
        signals=(
            Signal("body", r"\bdata-reactroot\b", 1.0),
            Signal("body", r"\breact(?:-dom)?(?:\.production)?\.min\.js", 1.0),
            Signal("body", r'id="root"></div>', 0.6),
            Signal("hint", r"\breact\b", 0.8),
        ),
        probes=(
            Probe("/static/js/main.js.map",
                  title="React source maps exposed",
                  severity="LOW", category="Information Disclosure",
                  description="A production source map is downloadable, "
                              "reconstructing original source, comments and "
                              "sometimes endpoints or keys.",
                  remediation="Do not ship .map files to production.",
                  status_in=(200,), body_regex=r'"sources"|"mappings"'),
        ),
    ),

    TechProfile(
        name="laravel", label="Laravel",
        signals=(
            Signal("cookie", r"laravel_session", 1.0),
            Signal("cookie", r"XSRF-TOKEN", 0.6),
            Signal("body", r"Illuminate\\\\", 1.0),
            Signal("hint", r"laravel", 1.0),
        ),
        cpe_products=("laravel",),
        packages=(("Packagist", "laravel/framework"),),
        probes=(
            Probe("/.env",
                  title="Laravel .env exposed",
                  severity="CRITICAL", category="Credential Exposure",
                  description="The application .env is downloadable — APP_KEY, "
                              "DB and mail/service credentials in clear text.",
                  remediation="Block dotfiles at the web server; move .env "
                              "outside web root; rotate every exposed secret.",
                  status_in=(200,), body_regex=r"APP_KEY=|DB_PASSWORD="),
            Probe("/telescope/requests",
                  title="Laravel Telescope exposed",
                  severity="HIGH", category="Information Disclosure",
                  description="Telescope is reachable unauthenticated — requests, "
                              "queries, cache keys and auth tokens are visible.",
                  remediation="Gate Telescope behind auth or disable in production.",
                  status_in=(200,), body_regex=r"Telescope"),
            # Ignition debug-mode RCE (CVE-2021-3129).
            Probe("/_ignition/execute-solution",
                  title="Laravel Ignition reachable (CVE-2021-3129 surface)",
                  severity="HIGH", category="Remote Code Execution",
                  description="The Ignition debug endpoint answered — with debug "
                              "mode and a vulnerable facade/ignition version this "
                              "is a known RCE. Confirm version and debug state.",
                  remediation="Set APP_DEBUG=false in production; upgrade "
                              "facade/ignition; remove Ignition from prod.",
                  method="POST", status_in=(200, 422, 500),
                  body_regex=r"ignition|solution", active=True),
        ),
    ),

    TechProfile(
        name="spring_boot", label="Spring Boot",
        signals=(
            Signal("header", r"x-application-context", 1.0),
            Signal("body", r"Whitelabel Error Page", 1.0),
            Signal("hint", r"spring", 0.8),
        ),
        cpe_products=("spring_framework", "spring_boot"),
        packages=(("Maven", "org.springframework.boot:spring-boot"),),
        probes=(
            Probe("/actuator",
                  title="Spring Boot Actuator exposed",
                  severity="MEDIUM", category="Information Disclosure",
                  description="The actuator index is reachable; enumerate its "
                              "links for env, mappings and heapdump.",
                  remediation="Restrict actuator endpoints; expose only health.",
                  status_in=(200,), body_regex=r'"_links"|/actuator/'),
            Probe("/actuator/env",
                  title="Spring Boot /actuator/env exposed",
                  severity="HIGH", category="Credential Exposure",
                  description="Environment properties are readable — often "
                              "includes credentials and secrets in property keys.",
                  remediation="Disable or secure the env actuator endpoint.",
                  status_in=(200,), body_regex=r'"propertySources"'),
            Probe("/actuator/heapdump",
                  title="Spring Boot heap dump downloadable",
                  severity="CRITICAL", category="Credential Exposure",
                  description="/actuator/heapdump returns a memory dump — live "
                              "credentials, tokens and session data recoverable.",
                  remediation="Never expose heapdump; restrict all actuators.",
                  status_in=(200,)),
        ),
    ),

    TechProfile(
        name="django", label="Django",
        signals=(
            Signal("cookie", r"csrftoken", 0.7),
            Signal("cookie", r"sessionid", 0.4),
            Signal("body", r"csrfmiddlewaretoken", 1.0),
            Signal("hint", r"django", 1.0),
        ),
        cpe_products=("django",),
        packages=(("PyPI", "django"),),
        probes=(
            Probe("/__debug__/",
                  title="Django Debug Toolbar exposed",
                  severity="MEDIUM", category="Information Disclosure",
                  description="The debug toolbar responded — SQL, settings and "
                              "request internals are visible.",
                  remediation="Remove debug_toolbar from production INSTALLED_APPS.",
                  status_in=(200,), body_regex=r"djDebug|Debug Toolbar"),
            Probe("/nonexistent-" + "x" * 8,
                  title="Django DEBUG=True detailed error pages",
                  severity="HIGH", category="Information Disclosure",
                  description="A 404/500 returned a Django traceback page — DEBUG "
                              "is on, leaking settings, paths and SECRET_KEY hints.",
                  remediation="Set DEBUG=False in production.",
                  status_in=(404, 500),
                  body_regex=r"You're seeing this error because you have|"
                             r"Traceback <span|DjangoError"),
        ),
    ),

    TechProfile(
        name="rails", label="Ruby on Rails",
        signals=(
            Signal("header", r"x-runtime:", 0.6),
            Signal("cookie", r"_session_id|_rails|_app_session", 0.8),
            Signal("hint", r"rails", 1.0),
            Signal("body", r'csrf-param"\s*content="authenticity_token', 1.0),
        ),
        cpe_products=("rails", "ruby_on_rails"),
        packages=(("RubyGems", "rails"),),
        probes=(
            Probe("/rails/info/routes",
                  title="Rails route listing exposed",
                  severity="MEDIUM", category="Information Disclosure",
                  description="/rails/info/routes is reachable — the full route "
                              "map (an attack-surface index) is public.",
                  remediation="This path is dev-only; ensure RAILS_ENV=production.",
                  status_in=(200,), body_regex=r"Helper|Path / Url|Controller#Action"),
        ),
    ),

    TechProfile(
        name="express", label="Express / Node",
        signals=(
            Signal("header", r"x-powered-by:\s*express", 1.0),
            Signal("hint", r"express", 0.8),
        ),
        cpe_products=("express",),
        packages=(("npm", "express"),),
        probes=(),
    ),

    TechProfile(
        name="drupal", label="Drupal",
        signals=(
            Signal("body", r"/sites/default/files", 1.0),
            Signal("header", r"x-generator:\s*drupal", 1.0),
            Signal("hint", r"drupal", 1.0),
            Signal("body", r"Drupal\.settings", 1.0),
        ),
        cpe_products=("drupal",),
        probes=(
            Probe("/CHANGELOG.txt",
                  title="Drupal CHANGELOG.txt discloses version",
                  severity="LOW", category="Information Disclosure",
                  description="CHANGELOG.txt pins the exact Drupal version, "
                              "mapping directly to published CVEs.",
                  remediation="Remove or deny CHANGELOG.txt.",
                  status_in=(200,), body_regex=r"Drupal \d"),
        ),
    ),

    TechProfile(
        name="joomla", label="Joomla",
        signals=(
            Signal("body", r"/media/jui/|com_content|Joomla!", 1.0),
            Signal("hint", r"joomla", 1.0),
        ),
        cpe_products=("joomla",),
        probes=(
            Probe("/administrator/manifests/files/joomla.xml",
                  title="Joomla version manifest exposed",
                  severity="LOW", category="Information Disclosure",
                  description="The Joomla manifest pins the exact version for "
                              "CVE mapping.",
                  remediation="Deny access to administrator manifest files.",
                  status_in=(200,), body_regex=r"<version>"),
        ),
    ),

    TechProfile(
        name="angular", label="Angular",
        packages=(("npm", "@angular/core"),),
        signals=(
            Signal("body", r"\bng-version=", 1.0),
            Signal("hint", r"angular", 0.8),
        ),
        probes=(),
    ),

    TechProfile(
        name="vuejs", label="Vue.js",
        packages=(("npm", "vue"),),
        signals=(
            Signal("body", r"\bdata-v-[0-9a-f]{8}\b", 1.0),
            Signal("body", r"__VUE__|vue(?:\.runtime)?\.min\.js", 0.9),
            Signal("hint", r"\bvue\b", 0.8),
        ),
        probes=(),
    ),

    TechProfile(
        name="aspnet", label="ASP.NET",
        signals=(
            Signal("header", r"x-aspnet-version:", 1.0),
            Signal("header", r"x-powered-by:\s*asp\.net", 1.0),
            Signal("cookie", r"\.aspnet|asp\.net_sessionid", 0.8),
            Signal("hint", r"asp\.net", 1.0),
        ),
        cpe_products=(".net_framework", "asp.net"),
        probes=(
            Probe("/trace.axd",
                  title="ASP.NET trace.axd exposed",
                  severity="HIGH", category="Information Disclosure",
                  description="trace.axd is enabled — application trace, headers "
                              "and session detail are readable.",
                  remediation="Set <trace enabled=\"false\"/> in production.",
                  status_in=(200,), body_regex=r"Application Trace|Request Details"),
        ),
    ),
]


def _score(where: str, pattern: str, blobs: dict) -> bool:
    import re
    text = blobs.get(where, "") or ""
    try:
        return re.search(pattern, text, re.I) is not None
    except re.error:
        return False


def match_profiles(blobs: dict) -> list:
    """Return [(profile, confidence, matched_signal_patterns)] for every
    profile whose summed signal weight clears its `min_confidence`.

    `blobs` carries the evidence already in hand: {"header","body","cookie",
    "hint"}. No network here — the executor supplies the strings. Sorted by
    confidence, strongest first.
    """
    results = []
    for profile in PROFILES:
        score = 0.0
        matched = []
        for sig in profile.signals:
            if _score(sig.where, sig.pattern, blobs):
                score += sig.weight
                matched.append(sig.pattern)
        if score >= profile.min_confidence:
            results.append((profile, round(score, 2), matched))
    results.sort(key=lambda r: -r[1])
    return results


def get_profile(name: str) -> "TechProfile | None":
    for profile in PROFILES:
        if profile.name == name:
            return profile
    return None
