"""Shared injection-point builder for testing modules.

Every active module used to mine its own points from its own favourite
asset types, which is how sqlmap ended up testing youtube.com and
`localhost:/8094` while `/rest/products/search?q=` sat untested in a
different asset table. One builder, one scope rule, every module.

A point is {"url", "param", "method", "source", "json_body"}. `url` may
carry an `{id}` path placeholder — `inject_param` fills those in place.
`json_body` lists body parameter names for POST/PUT/PATCH endpoints;
modules that only speak query strings ignore it.
"""

from urllib.parse import parse_qsl, urlparse


# Marker fragments our own probes leave in URLs. Crawlers record every
# URL they visit — including the ones earlier modules injected payloads
# into — and without this filter the graph treats a DOM-XSS probe URL
# as discovered attack surface and proposes probing the probe.
PROBE_MARKERS = (
    "osintxss", "hxprobe", "domxss", "redirect-probe", "hopefully404",
    "zz74x74zz", "zzz_no_such", "zxqseed9k", "onload=", "onerror=",
    "javascript:", "<svg", "<iframe", "%60", "`",
)


def is_probe_garbage(url: str) -> bool:
    """Was this URL manufactured by our own testing, not discovered?"""
    lowered = str(url or "").lower()
    if "${" in lowered:
        return True
    return any(marker in lowered for marker in PROBE_MARKERS)


LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def _host_key(value: str) -> str:
    """Return a bare lowercase host from a URL, host, or host:port."""
    text = str(value or "").strip().lower().rstrip(".")
    if not text:
        return ""
    if "://" in text:
        parsed = urlparse(text)
        return str(parsed.hostname or "").lower().rstrip(".")
    text = text.split("/", 1)[0]
    if text.startswith("["):
        return text.split("]", 1)[0].lstrip("[")
    if text.count(":") == 1:
        text = text.split(":", 1)[0]
    return text


def _same_host(candidate: str, *allowed: str) -> bool:
    """True when `candidate` is the target host or one of its subdomains.

    Apex/sibling handling is deliberately explicit: the engagement domain
    from config is the anchor, so `api.example.com` is allowed when the
    target is `www.example.com` and the configured domain is `example.com`.
    An unrelated host that merely shares a suffix (`example.com.evil.tld`)
    is not.
    """
    if not candidate:
        return False
    anchors = {_host_key(item) for item in allowed if _host_key(item)}
    if not anchors:
        return False
    if candidate in anchors:
        return True

    cand_loop = candidate in LOOPBACK_HOSTS
    if cand_loop and any(item in LOOPBACK_HOSTS for item in anchors):
        return True

    for anchor in anchors:
        if anchor in LOOPBACK_HOSTS:
            # `foo.localhost` is still local, but never `notlocalhost`.
            if candidate.endswith(".localhost"):
                return True
            continue
        # IPv6 literals do not have a useful parent/child relationship.
        if ":" in anchor or ":" in candidate:
            continue
        if candidate.endswith("." + anchor):
            return True
        # The configured base may itself be a subdomain.
        if anchor.endswith("." + candidate) and candidate.count(".") >= 1:
            return True
    return False


def confirmed_origin_ips(state) -> set[str]:
    """IPs already proven to be the target's own origin, not third parties.

    Port scans and crawl results can name a CDN edge, a shared host, or an
    unrelated service. Only an address the origin-discovery proof marked as
    the target's own gets the same scope treatment as the engagement domain.
    """
    ips: set[str] = set()
    for asset in state.get_assets_by_type("ip"):
        attrs = asset.get("attrs", {}) or {}
        if attrs.get("origin") is True:
            value = str(asset.get("value") or "").strip().lower()
            if value:
                ips.add(value)
    for asset in state.get_assets_by_type("origin_discovery"):
        attrs = asset.get("attrs", {}) or {}
        for value in attrs.get("confirmed_origins") or []:
            value = str(value or "").strip().lower()
            if value:
                ips.add(value)
    return ips


def in_scope_url(url: str, base_url: str, domain: str,
                 origin_ips: set[str] | None = None) -> bool:
    """Is this URL on the engagement's host, allowing siblings and ports?

    Recon legitimately finds alternate ports and subdomains of the target.
    Third-party CDNs, embeds, and archive noise are not the target and must
    never become active probe points: the old "any absolute URL" rule sent
    SQLMap to youtube.com and turned GitHub assets into findings.

    `origin_ips` lets a confirmed origin address (with any port) be in
    scope even when it is an IP rather than the domain. It is deliberately
    opt-in: an arbitrary scanned IP is still out of scope.
    """
    try:
        parsed = urlparse(str(url))
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return False
        # `localhost:` and `host:abc` parse a hostname but cannot be dialled.
        if parsed.netloc.endswith(":"):
            return False
        parsed.port  # raises ValueError for a non-numeric port
    except ValueError:
        return False
    host = str(parsed.hostname).strip().lower().rstrip(".")
    if _same_host(host, base_url, domain):
        return True
    return bool(host and host in (origin_ips or set()))


def iter_probe_points(state, base_url: str, domain: str,
                      max_points: int = 0) -> list:
    """Yield deduplicated (url, param, method, source, json_body) points.

    `max_points=0` means every point; a positive value keeps the old cap.
    """
    points = []
    seen = set()
    origin_ips = confirmed_origin_ips(state)

    def emit(url: str, param: str, method: str, source: str,
             json_body: list | None = None):
        if not url or not param:
            return
        key = (url, param, method)
        if key in seen:
            return
        seen.add(key)
        points.append({"url": url, "param": param, "method": method,
                       "source": source,
                       "json_body": list(json_body or [])})

    # 1. Parameter assets (crawl-mined, seeded, or swagger-derived).
    for asset in state.get_assets_by_type("parameter"):
        attrs = asset.get("attrs", {}) or {}
        url = str(attrs.get("url", "") or "").strip()
        param = str(asset.get("value", "") or "").strip()
        if not url or not param or not in_scope_url(url, base_url, domain, origin_ips):
            continue
        method = str(attrs.get("method", "GET") or "GET").upper()
        emit(url, param, method, "parameter_asset")

    # 2. Swagger-derived api_endpoint assets: query params plus methods.
    for asset in state.get_assets_by_type("api_endpoint"):
        url = str(asset.get("value", "") or "").strip()
        if not url or not in_scope_url(url, base_url, domain, origin_ips):
            continue
        attrs = asset.get("attrs", {}) or {}
        methods = [m for m in (attrs.get("methods") or ["GET"])
                   if m in ("GET", "POST", "PUT", "PATCH", "DELETE")]
        spec_params = attrs.get("params", []) or []
        query_params = [str(p).split(":", 1)[-1] for p in spec_params
                        if str(p).startswith("query:")]
        path_params = [str(p).split(":", 1)[-1] for p in spec_params
                        if str(p).startswith("path:")]
        body_params = [str(p).split(":", 1)[-1] for p in spec_params
                        if str(p).split(":", 1)[0] in ("body", "formData")]
        # {id} templates: inject_param fills path placeholders in place.
        if "{id}" in url or "{Id}" in url:
            for method in methods or ["GET"]:
                emit(url, "id", method, "swagger_template", body_params)
        for param in query_params:
            for method in methods or ["GET"]:
                emit(url, param, method, "swagger_param", body_params)
        # Bare query string already on the URL.
        try:
            query = urlparse(url).query
        except ValueError:
            query = ""
        for name, _ in parse_qsl(query, keep_blank_values=True):
            for method in methods or ["GET"]:
                emit(url, name, method, "swagger_url", body_params)
        # JSON-body endpoints with no query params: body-only points.
        if body_params and not query_params and "{id}" not in url:
            for method in methods:
                if method in ("POST", "PUT", "PATCH"):
                    emit(url, body_params[0], method, "swagger_body",
                         body_params)

    # 3. Crawled URLs carrying their own query strings.
    for asset_type in ("url", "endpoint", "web_path"):
        for asset in state.get_assets_by_type(asset_type):
            url = str(asset.get("value", "") or "").strip()
            if not url or not in_scope_url(url, base_url, domain, origin_ips):
                continue
            try:
                query = urlparse(url).query
            except ValueError:
                continue
            for name, _ in parse_qsl(query, keep_blank_values=True):
                emit(url, name, "GET", asset_type)

    # 4. Raw target URL itself, when parameterized.
    raw = str(base_url or "").strip()
    if raw:
        try:
            query = urlparse(raw).query
        except ValueError:
            query = ""
        for name, _ in parse_qsl(query, keep_blank_values=True):
            emit(raw, name, "GET", "raw_target")

    return points[:max_points] if max_points > 0 else points
