"""Shared redaction primitives (I1).

Extracted from ``core/audit_log`` (keyed sanitize + truncate) and
``core/validators`` (string scrub patterns) so traffic capture, mutation
records and operation rows all apply the same OPSEC treatment. The
extraction is behavior-preserving: the audit log imports these helpers
under its old names and its tests must pass unchanged.

Traffic capture additionally applies header allowlisting and JWT-shaped
token scrubbing (see :func:`redact_headers`, :func:`redact_jwt_like`).
"""

from __future__ import annotations

import re
from typing import Any

from core.validators import redact_for_log

SENSITIVE_KEYS = {
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "access_token", "refresh_token", "auth_token", "private_key",
    "cookie", "authorization", "auth", "bearer", "session",
    "sessionid", "session_id", "client_secret", "credential",
}


def sensitive_key(key: Any) -> bool:
    normalized = str(key).strip().lower().replace("-", "_")
    if normalized in SENSITIVE_KEYS:
        return True
    return normalized.endswith(("_password", "_secret", "_token", "_cookie",
                                "_credential", "_api_key"))


def sanitize(value: Any) -> Any:
    """Recursively redact keyed secrets and credentials embedded in strings."""
    if isinstance(value, dict):
        return {
            str(key): ("<redacted>" if sensitive_key(key) and item
                       else sanitize(item))
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple, set)):
        return [sanitize(item) for item in value]
    if isinstance(value, str):
        return redact_for_log(value)
    return value


def truncate(obj: Any, max_len: int = 2000) -> Any:
    if isinstance(obj, dict):
        return {k: truncate(v, max_len) for k, v in obj.items()}
    if isinstance(obj, list):
        return [truncate(v, max_len) for v in obj][:20]
    text = str(obj)
    return text[:max_len] if len(text) > max_len else text


# Headers that may carry live credentials. Traffic capture records only a
# safe subset of response headers and never persists these request headers.
CREDENTIAL_HEADERS = frozenset({
    "authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token",
    "proxy-authorization", "x-csrf-token",
})

# Response headers worth persisting: content negotiation only.
RESPONSE_HEADER_ALLOWLIST = frozenset({
    "content-type", "content-length",
})

_JWT_SHAPE = re.compile(
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b")


def redact_jwt_like(text: str) -> str:
    """Scrub JWT-shaped strings wherever they appear in a body."""
    return _JWT_SHAPE.sub("<redacted-jwt>", str(text or ""))


def redact_headers(headers: dict) -> dict:
    """Drop credential headers entirely and keep the rest as-is."""
    return {
        str(key): str(value)
        for key, value in (headers or {}).items()
        if str(key).strip().lower() not in CREDENTIAL_HEADERS
    }


def redact_body(body: str) -> str:
    """Full body redaction: keyed secrets + JWT shapes + string patterns.

    JSON bodies are parsed and sanitized structurally so ``{"password": …}``
    is scrubbed even when no string pattern matches; anything else falls
    back to the string scrubbers.
    """
    text = str(body or "")
    if not text:
        return text
    stripped = text.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            import json
            parsed = json.loads(text)
            cleaned = sanitize(parsed)
            # Keyed sanitize does not know every credential-shaped value;
            # JWT shapes are scrubbed wherever they appear, as promised by
            # the module docstring.
            return redact_jwt_like(json.dumps(cleaned, sort_keys=True))
        except (ValueError, TypeError):
            pass
    return redact_jwt_like(redact_for_log(text))
