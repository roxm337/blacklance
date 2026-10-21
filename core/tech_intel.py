"""Deep, per-technology intelligence extraction.

Path probes tell you a framework is present. These parsers tell you what it is
*leaking* — the red-team layer above "does /x exist":

  - Next.js embeds its entire server→client data bridge in `__NEXT_DATA__`;
    its build manifest lists every route; its `/_next/data/<buildId>/` JSON
    endpoints serve SSR props straight from the server. Parsing those turns a
    "Next.js detected" into "here is the buildId, here are 40 routes, and
    pageProps leaks a session token".
  - Laravel's debug page (Whoops/Ignition, when APP_DEBUG=true) prints the
    framework version, absolute paths and the entire environment — a single
    error response is a full configuration disclosure, and the version decides
    whether Ignition RCE applies.

Everything here is pure: HTML/JS/text in, structured findings out. The network
driver lives in `modules/tech_analyzers.py`.
"""

import json
import re

# High-signal key names that should never appear in a client-visible JSON blob.
_SENSITIVE_KEY = re.compile(
    r"(?i)(pass(word|wd)?|secret|token|api[_-]?key|access[_-]?key|"
    r"authorization|auth[_-]?token|bearer|credential|private[_-]?key|"
    r"client[_-]?secret|session|jwt|smtp|dsn|connection[_-]?string|"
    r"aws[_-]?(secret|access))")

# A handful of unmistakable secret *value* shapes (full catalogue lives in
# js_analysis; core stays dependency-free and keeps only the high-confidence
# ones that matter inside a data blob).
_VALUE_PATTERNS = (
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("bearer", re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{20,}")),
)


def scan_sensitive_json(obj, _path="$", _out=None, _depth=0) -> list:
    """Walk a decoded JSON object and report sensitive keys and secret values.

    Returns [{path, key, kind, preview}]. A hit is either a key whose *name*
    is sensitive with a non-trivial scalar value, or any string value matching
    a high-confidence secret pattern. Depth- and count-bounded so a huge blob
    can't run away.
    """
    out = [] if _out is None else _out
    if len(out) >= 60 or _depth > 8:
        return out
    if isinstance(obj, dict):
        for key, value in obj.items():
            here = f"{_path}.{key}"
            if _SENSITIVE_KEY.search(str(key)) and _is_scalarish(value):
                out.append({"path": here, "key": str(key), "kind": "sensitive_key",
                            "preview": _preview(value)})
            scan_sensitive_json(value, here, out, _depth + 1)
    elif isinstance(obj, list):
        for i, item in enumerate(obj[:50]):
            scan_sensitive_json(item, f"{_path}[{i}]", out, _depth + 1)
    elif isinstance(obj, str):
        for kind, pat in _VALUE_PATTERNS:
            if pat.search(obj):
                out.append({"path": _path, "key": "", "kind": kind,
                            "preview": _preview(obj)})
                break
    return out


def _is_scalarish(value) -> bool:
    return isinstance(value, (str, int, float)) and str(value).strip() not in (
        "", "0", "false", "true", "null", "None")


def _preview(value) -> str:
    text = str(value)
    return (text[:12] + "…" + text[-4:]) if len(text) > 24 else text


def extract_next_build_id(html: str) -> str:
    """The Next.js buildId from a page, for both routers.

    Appears in static asset URLs (`/_next/static/<buildId>/_buildManifest.js`)
    and, on the pages router, as a `buildId` field. The buildId keys the
    /_next/data/ and build-manifest endpoints.
    """
    m = re.search(
        r"/_next/static/([A-Za-z0-9_-]{6,})/(?:_buildManifest|_ssgManifest|_app|chunks)",
        html or "")
    if m:
        return m.group(1)
    m = re.search(r'"buildId"\s*:\s*"([^"]+)"', html or "")
    return m.group(1) if m else ""


def _rsc_flight_payloads(html: str) -> list:
    """Decode the strings pushed into the App Router's RSC flight stream.

    App Router (Next 13+) streams server→client data as
    `self.__next_f.push([1,"<escaped json>"])` instead of a single
    __NEXT_DATA__ blob. Each push carries a JSON-string chunk; decoding it is
    how server-component props (the App Router equivalent of the pageProps
    leak) become visible.
    """
    payloads = []
    for m in re.finditer(r'self\.__next_f\.push\(\[\d+\s*,\s*("(?:[^"\\]|\\.)*")',
                         html or ""):
        try:
            payloads.append(json.loads(m.group(1)))
        except (json.JSONDecodeError, ValueError):
            continue
    return payloads


def _maybe_json(text):
    """Return the decoded object if `text` is JSON, else the raw string."""
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError, TypeError):
        return text


def parse_next_data(html: str) -> dict:
    """Parse a Next.js page's data bridge — pages *and* App Router.

    Returns {found, router, build_id, page, leaked:[...]}. `leaked` is the
    sensitive-key/secret scan over the server→client data: `props.pageProps`
    on the pages router, the RSC flight stream on the App Router.
    """
    html = html or ""
    # Pages router: single __NEXT_DATA__ JSON blob.
    m = re.search(r'<script[^>]+id="__NEXT_DATA__"[^>]*>(.*?)</script>',
                  html, re.S | re.I)
    if m:
        try:
            data = json.loads(m.group(1).strip())
        except (json.JSONDecodeError, ValueError):
            return {"found": True, "router": "pages", "parse_error": True}
        return {
            "found": True, "router": "pages",
            "build_id": data.get("buildId", "") or extract_next_build_id(html),
            "page": data.get("page", ""),
            "leaked": scan_sensitive_json(data.get("props", {})),
        }

    # App Router: RSC flight stream, or at least Next static assets present.
    if "self.__next_f" in html or "/_next/static/" in html:
        leaked = []
        for payload in _rsc_flight_payloads(html):
            leaked.extend(scan_sensitive_json(_maybe_json(payload)))
        return {
            "found": True, "router": "app",
            "build_id": extract_next_build_id(html),
            "page": "/", "leaked": leaked[:40],
        }
    return {"found": False}


def extract_next_routes(build_manifest_js: str) -> list:
    """Route paths from a Next.js `_buildManifest.js`.

    The manifest maps every page route to its chunk list; the route keys are
    the application's page surface. Dynamic segments (`/blog/[slug]`) are kept
    as-is — they are templates to fill, which is exactly what a tester wants.
    """
    routes = set()
    for m in re.finditer(r'["\'](/[^"\']*)["\']\s*:', build_manifest_js or ""):
        route = m.group(1)
        # Skip static asset references; keep page routes.
        if re.search(r"\.(js|css|map|png|jpg|svg|woff2?|ico)$", route):
            continue
        routes.add(route)
    return sorted(routes)[:200]


def next_data_route(build_id: str, page: str) -> str:
    """The /_next/data JSON endpoint for a given page under a build id."""
    page = page or "/index"
    if page == "/":
        page = "/index"
    return f"/_next/data/{build_id}{page}.json"


# ── Laravel ──────────────────────────────────────────────────────────

def parse_laravel_debug(html: str) -> dict:
    """Pull disclosure out of a Laravel debug page (Whoops / Ignition).

    A debug page means APP_DEBUG=true in production — itself a finding — and
    its body leaks the framework/PHP version (which decides Ignition RCE),
    absolute application paths, and often environment values. Returns
    {is_debug, laravel_version, php_version, app_path, exception, env:[...]}.
    """
    text = html or ""
    lowered = text.lower()
    is_debug = any(s in lowered for s in (
        "whoops", "ignition", "illuminate\\", "laravel.log",
        "stack trace", "vendor/laravel/framework"))
    if not is_debug:
        return {"is_debug": False}

    def first(pattern):
        m = re.search(pattern, text, re.I)
        return m.group(1).strip() if m else ""

    env = []
    for m in re.finditer(r"(?m)^\s*([A-Z][A-Z0-9_]{2,40})\s*[=:]\s*([^\n<]{1,120})", text):
        key, value = m.group(1), m.group(2).strip()
        if _SENSITIVE_KEY.search(key) or key in (
                "APP_KEY", "APP_ENV", "APP_DEBUG", "DB_DATABASE",
                "DB_USERNAME", "AWS_ACCESS_KEY_ID"):
            env.append({"key": key, "value": _preview(value)})

    return {
        "is_debug": True,
        "laravel_version": first(r"laravel(?:/framework)?[ v]*(\d+\.\d+[\d.]*)"),
        "php_version": first(r"PHP[ /]*(\d+\.\d+[\d.]*)"),
        "app_path": first(r"((?:/var/www|/home/[^/\s]+|/app|/srv)/[^\s:\"'<]{0,80})"),
        "exception": first(r"([A-Za-z\\\\]+(?:Exception|Error))"),
        "env": env[:30],
    }


# ── .env ─────────────────────────────────────────────────────────────

_CRITICAL_ENV = re.compile(
    r"(?i)(APP_KEY|_SECRET|_PASSWORD|_TOKEN|PRIVATE_KEY|AWS_SECRET|"
    r"MAIL_PASSWORD|DB_PASSWORD|STRIPE_SECRET|JWT_SECRET)")


def parse_env_file(text: str) -> list:
    """Classify the lines of a leaked .env into credential findings.

    Returns [{key, value_preview, severity}]. Key-driven severity: anything
    naming a secret/password/key is CRITICAL; APP_DEBUG=true is flagged HIGH
    (debug in prod); other real values are MEDIUM configuration disclosure.
    """
    findings = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if not re.match(r"^[A-Z][A-Z0-9_]*$", key):
            continue
        if _CRITICAL_ENV.search(key) and value:
            sev = "CRITICAL"
        elif key == "APP_DEBUG" and value.lower() == "true":
            sev = "HIGH"
        elif value:
            sev = "MEDIUM"
        else:
            continue
        findings.append({"key": key, "value_preview": _preview(value),
                         "severity": sev})
    return findings
