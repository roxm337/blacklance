"""Credential selection for HTTP transports, independent of target scope."""

from urllib.parse import urlsplit


_PUBLIC_HEADERS = frozenset({
    "accept", "accept-language", "accept-encoding", "user-agent",
    "content-type", "content-length", "cache-control", "pragma",
    "origin", "referer", "connection", "host",
})


def origin(value: str) -> tuple | None:
    try:
        parts = urlsplit(str(value))
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            return None
        host = parts.hostname.rstrip(".").encode("idna").decode().lower()
        return parts.scheme, host, parts.port or (443 if parts.scheme == "https" else 80)
    except (ValueError, UnicodeError):
        return None


def credential_header_names(headers: dict) -> set[str]:
    """Custom session headers are private unless known to be public metadata."""
    return {str(key).lower() for key in headers if str(key).lower() not in _PUBLIC_HEADERS}


def without_credentials(headers: dict, names=()) -> dict:
    private = {"authorization", "proxy-authorization", "cookie", "x-api-key"}
    private.update(str(name).lower() for name in names)
    return {key: value for key, value in headers.items() if str(key).lower() not in private}


def configured_origin(config: dict) -> tuple | None:
    target = config.get("target", {}) or {}
    auth = config.get("auth", {}) or {}
    value = auth.get("origin") or target.get("base_url") or target.get("raw_url")
    if not value and target.get("domain"):
        value = f"{target.get('scheme') or 'https'}://{target['domain']}"
    return origin(value or "")
