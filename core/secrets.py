"""Credential references, expiry and revocation (R10).

Configuration should not carry live secrets. A credential value may be a
reference resolved at use time:

- ``env:NAME``        read the environment variable NAME
- ``file:/path``      read (and strip) the file at /path
- anything else       used literally, for backwards compatibility

Resolution happens in memory only. Reference strings — not resolved values
— are what callers may log or show in preflight output. Expiry metadata is
validated without touching the secret itself.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REFERENCE_PREFIXES = ("env:", "file:")


class SecretError(ValueError):
    """A credential reference cannot be resolved."""


def is_reference(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(REFERENCE_PREFIXES)


def resolve(value: Any, *, required: bool = True) -> str:
    """Resolve one reference. Literal values pass through unchanged."""
    text = str(value or "")
    if text.startswith("env:"):
        name = text[4:].strip()
        if not name:
            raise SecretError("empty environment credential reference")
        resolved = os.environ.get(name, "")
        if not resolved and required:
            raise SecretError(f"environment variable {name!r} is not set")
        return resolved
    if text.startswith("file:"):
        raw_path = text[5:].strip()
        if not raw_path:
            raise SecretError("empty file credential reference")
        path = Path(raw_path).expanduser()
        try:
            resolved = path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            if required:
                raise SecretError(
                    f"credential file {path} is unreadable") from exc
            return ""
        if not resolved and required:
            raise SecretError(f"credential file {path} is empty")
        return resolved
    return text


def resolve_tree(value: Any, *, required: bool = True) -> Any:
    """Resolve references inside dicts/lists; literals pass through."""
    if isinstance(value, dict):
        return {key: resolve_tree(item, required=required)
                for key, item in value.items()}
    if isinstance(value, list):
        return [resolve_tree(item, required=required) for item in value]
    if is_reference(value):
        return resolve(value, required=required)
    return value


def describe(value: Any) -> str:
    """A display-safe description of a credential value."""
    text = str(value or "")
    if text.startswith(("env:", "file:")):
        return text
    return "literal" if text else "missing"


def parse_expiry(value: Any) -> datetime | None:
    """Parse ISO-8601 or epoch seconds; naive values are treated as UTC."""
    if value in (None, "", 0, 0.0):
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    text = str(value).strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SecretError(
            f"invalid credential expiry {text!r}; use ISO-8601 or epoch") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def credential_state(expires_at: Any = None, revoked: bool = False,
                     now: datetime | None = None) -> dict:
    """Expiry/revocation status without exposing the credential."""
    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    expiry = parse_expiry(expires_at)
    expired = bool(expiry and moment >= expiry)
    return {
        "expired": expired,
        "revoked": bool(revoked),
        "expires_at": expiry.isoformat() if expiry else "",
        "usable": not expired and not revoked,
    }


def credential_fields(entry: dict) -> list[tuple[str, Any]]:
    """Named credential-bearing values from one identity config entry.

    Used by preflight to validate references and enforce the reference
    policy without resolving values into output.
    """
    fields: list[tuple[str, Any]] = []

    def add(name: str, value: Any) -> None:
        if value not in (None, "", {}, []):
            fields.append((name, value))

    add("bearer_token", entry.get("bearer_token") or entry.get("token"))
    add("basic_auth", entry.get("basic_auth") or entry.get("basic"))
    add("cookies", entry.get("cookies"))
    headers = entry.get("headers") or {}
    if isinstance(headers, dict):
        auth_headers = {k: v for k, v in headers.items()
                        if str(k).lower() in ("authorization", "cookie",
                                              "x-api-key")}
        add("headers", auth_headers)
    login = entry.get("login") or {}
    if isinstance(login, dict):
        add("login.data", login.get("data"))
    return fields


def literal_secret_fields(entry: dict) -> list[str]:
    """Credential fields whose configured value is not a reference."""
    names = []
    for name, value in credential_fields(entry):
        values = []
        if isinstance(value, dict):
            values = list(value.values())
        elif isinstance(value, (list, tuple)):
            values = list(value)
        else:
            values = [value]
        if any(str(item).strip() and not is_reference(item)
               for item in values):
            names.append(name)
    return names
