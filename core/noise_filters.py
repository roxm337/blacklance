"""Signal/noise predicates for asset extraction.

Recon scrapers cast wide regexes over whole HTML bodies, and a wide regex
over a WordPress homepage harvests cache-buster integers as "phone numbers",
footer plugin credits as "people", and `?ver=` on every static asset as a
"parameter". The report that results reads as a target with hundreds of
assets when it has a handful; the noise buries the two or three findings an
operator actually acts on.

These are the shared, deliberately conservative gates that keep that junk out
of the asset graph. Each one answers a single question — "is this plausibly a
real X?" — with a bias toward dropping ambiguous input, because a missed
footer credit costs nothing and a phantom one costs operator trust.
"""

import re
from urllib.parse import urlparse

# ── Phones ──────────────────────────────────────────────────────────

_PHONE_SEPARATORS = re.compile(r"[\s\-.()/]")


def is_probable_phone(raw: str) -> bool:
    """Does this look like a phone number a human transcribed, not an ID?

    The phone regex that feeds this matches any run of 9–15 digits with
    optional separators, which also matches Unix epoch timestamps
    (`1499763626209`), WordPress cache-busters (`?ver=1482404872`) and
    portfolio row IDs — all of which appear as bare digit runs in page
    markup. The distinguishing signal is formatting: a phone number a site
    publishes for humans carries a `+` or separators (`+33 1 44 90 25 55`,
    `(555) 123-4567`), while an ID is a naked integer. So a match with no
    `+` and no separator is rejected as an identifier.
    """
    raw = (raw or "").strip()
    if not raw:
        return False
    digits = re.sub(r"\D", "", raw)
    n = len(digits)
    # E.164 caps the subscriber number at 15 digits; below 7 is not dialable.
    if not (7 <= n <= 15):
        return False
    has_plus = raw.lstrip().startswith("+")
    has_separator = bool(_PHONE_SEPARATORS.search(raw))
    if not has_plus and not has_separator:
        # A naked digit run is an epoch, a row id, or a cache-buster.
        return False
    # A separator-bearing value that is still a 13-digit millisecond epoch
    # (e.g. "1,499,763,626,209") is an id dressed up; a real number that
    # long must be E.164 and therefore carry the leading "+".
    if n >= 13 and not has_plus:
        return False
    return True


# ── People ──────────────────────────────────────────────────────────

# Tokens that mark a capitalised two/three-word phrase as site chrome,
# tooling, or an org label rather than a person. A candidate is rejected
# when ANY of its words is one of these — "Page Builder", "Slider Plugin",
# "Google Analytics", "Cookie Policy" all die here.
_NON_PERSON_TOKENS = {
    # Web/CMS chrome and tooling.
    "plugin", "plugins", "builder", "slider", "theme", "themes", "widget",
    "menu", "footer", "header", "sidebar", "template", "layout", "block",
    "page", "pages", "post", "posts", "category", "archive", "sitemap",
    "analytics", "tag", "tags", "manager", "pixel", "tracker", "console",
    "dashboard", "cookie", "cookies", "policy", "privacy", "terms", "gdpr",
    "copyright", "rights", "reserved", "powered", "credits", "version",
    "wordpress", "woocommerce", "elementor", "yoast", "jetpack", "divi",
    # Vendors / platforms frequently title-cased in footers and scripts.
    "google", "facebook", "instagram", "youtube", "twitter", "linkedin",
    "microsoft", "adobe", "cloudflare", "amazon", "aws", "stripe", "paypal",
    # Generic business/section labels.
    "commission", "solution", "solutions", "service", "services", "product",
    "products", "company", "agency", "studio", "group", "team", "project",
    "contact", "about", "home", "news", "blog", "portfolio", "gallery",
}

# Connective lowercase words allowed inside a name without counting as a
# real "word" (de, van, von, la, le, du, des, di, da).
_NAME_PARTICLES = {"de", "van", "von", "la", "le", "du", "des", "di", "da",
                   "del", "der", "den", "el", "al"}


def is_probable_person_name(candidate: str) -> bool:
    """Is this capitalised phrase plausibly a human name, not a label?

    The name regex matches any sequence of 2–3 capitalised words, which is
    exactly the shape of footer credits ("Page Builder"), script attributions
    ("Google Analytics") and section headings ("Commission Nationale"). There
    is no cheap way to be certain a phrase names a person, so this errs toward
    rejection: any word drawn from the chrome/tooling/vendor stoplist, or a
    phrase with fewer than two real (non-particle) words, is dropped.
    """
    candidate = " ".join((candidate or "").split())
    if not (4 <= len(candidate) <= 40) or "@" in candidate:
        return False
    words = candidate.split()
    if any(w.lower() in _NON_PERSON_TOKENS for w in words):
        return False
    real_words = [w for w in words if w.lower() not in _NAME_PARTICLES]
    if len(real_words) < 2:
        return False
    # Each real word must open with a capital and be alphabetic (allowing
    # hyphenated and accented names). Rejects "Web2 Design", "SEO Report".
    for w in real_words:
        core = w.replace("-", "")
        if not core[:1].isupper() or not core.isalpha():
            return False
    return True


# ── Parameters ──────────────────────────────────────────────────────

# Query parameters that are cache-busters, asset versioning, or analytics
# plumbing — never an injectable application input. A `?ver=` on a stylesheet
# is not a test case; it is WordPress enqueue versioning.
_NOISE_PARAM_NAMES = {
    "ver", "v", "version", "rev", "cache", "cachebust", "nocache", "_",
    "t", "ts", "time", "timestamp", "cb", "r", "rand",
    # Analytics / ad attribution.
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "gclid", "fbclid", "mc_cid", "mc_eid", "msclkid", "dclid", "yclid",
}

_STATIC_ASSET_SUFFIXES = (
    ".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".webp", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4",
    ".webm", ".mp3", ".pdf", ".zip",
)


def is_noise_parameter(name: str, url: str = "") -> bool:
    """Is this (name, url) a non-testable parameter the injection modules
    would only waste budget on?

    Two independent noise sources: a known cache-buster/analytics name, or
    *any* parameter hanging off a static asset URL (a `?ver=` on a `.js` is
    versioning, not input). Either is enough to drop it before it becomes a
    sqlmap/XSS target.
    """
    lowered = str(name or "").strip().lower()
    if not lowered:
        return True
    if lowered in _NOISE_PARAM_NAMES:
        return True
    path = urlparse(str(url or "")).path.lower()
    if path.endswith(_STATIC_ASSET_SUFFIXES):
        return True
    return False


# ── JS files ────────────────────────────────────────────────────────

# Path fragments that mark a script as a third-party library or framework
# bundle rather than first-party application code worth analysing for
# secrets, endpoints, and DOM sinks.
_VENDOR_JS_MARKERS = (
    "/jquery", "jquery.", "/bootstrap", "bootstrap.", "/wp-includes/js/",
    "tweenlite", "tweenmax", "gsap", "modernizr", "underscore", "lodash",
    "/mootools", "prototype.js", "react.", "react-dom", "angular.",
    "vue.", "ember.", "backbone", "polyfill", "/swiper", "slick.",
    "owl.carousel", "fancybox", "magnific", "isotope", "masonry",
    "/mousewheel", "touchswipe", "waypoints", "stickykit", "/select2",
    "datatables", "fontawesome", "font-awesome", "/recaptcha",
    "googletagmanager", "google-analytics", "gtag", "/analytics.js",
    "zxcvbn", "/plugins.js", "layerslider", "revslider",
)


def is_vendor_js(url: str) -> bool:
    """Is this script a third-party library/framework, not app code?

    First-party JS is where endpoints, API keys and DOM-XSS sinks live;
    vendor bundles (jQuery, GSAP, WP core, analytics) are known quantities
    that only inflate the `js_file` inventory. Minified `.min.js` is a weak
    hint and is treated as vendor only when it also matches a known library
    name, so a minified app bundle is still analysed.
    """
    lowered = str(url or "").lower().split("?")[0]
    if any(marker in lowered for marker in _VENDOR_JS_MARKERS):
        return True
    return False
