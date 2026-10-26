"""URL path arithmetic for the CSPT audit (I4).

Pure RFC 3986 §5.2.4 helpers: what path the server actually sees after
percent-decoding and dot-segment removal, whether a resolved path escaped
a stable prefix on SEGMENT boundaries (``/api/reports-archive`` is not an
escape from ``/api/reports``), and what segments the injected payload
contributed to the resolved path.

No network, no state — everything here is deterministic and unit-tested
against the RFC examples.
"""

from __future__ import annotations

import re
from urllib.parse import unquote, urlparse


def remove_dot_segments(path: str) -> str:
    """RFC 3986 §5.2.4 remove_dot_segments."""
    input_buffer = str(path or "")
    output: list[str] = []
    while input_buffer:
        if input_buffer.startswith("../"):
            input_buffer = input_buffer[3:]
        elif input_buffer.startswith("./"):
            input_buffer = input_buffer[2:]
        elif input_buffer.startswith("/./"):
            input_buffer = "/" + input_buffer[3:]
        elif input_buffer == "/.":
            input_buffer = "/"
        elif input_buffer.startswith("/../"):
            input_buffer = "/" + input_buffer[4:]
            if output:
                output.pop()
        elif input_buffer == "/..":
            input_buffer = "/"
            if output:
                output.pop()
        elif input_buffer in (".", ".."):
            input_buffer = ""
        else:
            slash = input_buffer.find("/", 1)
            if slash == -1:
                output.append(input_buffer)
                input_buffer = ""
            else:
                output.append(input_buffer[:slash])
                input_buffer = input_buffer[slash:]
    return "".join(output)


def server_view_path(url: str) -> str:
    """The path a server sees: decode escapes once, then resolve dots.

    ``%2e%2e%2f`` is decoded to ``../`` before dot-segment removal, which
    is what most servers and SPA routers end up doing at the fetch layer.
    """
    try:
        parsed = urlparse(str(url or ""))
        path = parsed.path or ""
    except ValueError:
        return ""
    decoded = unquote(path)
    return remove_dot_segments(decoded)


def path_segments(path: str) -> list[str]:
    return [segment for segment in str(path or "").split("/") if segment]


def stable_prefix(natural_path: str, token: str) -> list[str]:
    """Segments before the one carrying the token (the untainted prefix)."""
    segments = path_segments(natural_path)
    for index, segment in enumerate(segments):
        if token and token in segment:
            return segments[:index]
    return segments[:-1] if segments else []


def effect_segments(payload: str) -> list[str]:
    """Segments the payload itself contributes after its own resolution.

    ``../../admin/secrets`` contributes ``["admin", "secrets"]``: the dot
    segments are traversal machinery, not evidence of where the request
    went. Query/fragment parts are dropped before resolution.
    """
    decoded = unquote(str(payload or ""))
    decoded = re.split(r"[?#]", decoded, maxsplit=1)[0]
    candidate = remove_dot_segments("/" + decoded.lstrip("/"))
    out = []
    for segment in path_segments(candidate):
        if segment in (".", ".."):
            continue
        if "://" in segment or segment.startswith(("http:", "https:")):
            continue
        out.append(segment)
    return out


def escaped(prefix: list[str], resolved_path: str) -> bool:
    """Did the resolved path leave the prefix on a segment boundary?"""
    segments = path_segments(resolved_path)
    if not prefix:
        return bool(segments)
    if len(segments) < len(prefix):
        return True
    return segments[:len(prefix)] != list(prefix)


def has_traversal(payload: str) -> bool:
    """Does the payload carry actual traversal machinery?

    A plain sibling name ("reports-archive/1") changing the request path is
    input routing, not client-side path TRAVERSAL — only a payload with a
    literal ``..`` segment (after one decode) qualifies.
    """
    decoded = unquote(str(payload or "")).replace("\\", "/")
    return any(segment == ".." for segment in decoded.split("/"))


def templatize(natural_path: str, token: str) -> str:
    """Replace the token-bearing segment with ``{input}`` for stable ids."""
    segments = path_segments(natural_path)
    out = []
    replaced = False
    for segment in segments:
        if token and token in segment and not replaced:
            out.append("{input}")
            replaced = True
        else:
            out.append(segment)
    return "/" + "/".join(out) if out else "/"


_TOKEN_PARAM = re.compile(r"^(cspt|cz)")  # our own injected parameter names


def looks_like_canary_param(name: str) -> bool:
    return bool(_TOKEN_PARAM.match(str(name or "").lower()))
